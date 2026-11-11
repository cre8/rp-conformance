import type { DcqlQuery, Expectation, ExpectationCode, Ics, RelyingPartyResult, Verdict } from '@rp-conformance/core';
import { icsAnswer, statusMeanings } from './ics';

export interface Evaluation {
  verdict: Verdict;
  reason: string;
}

/** Technical claims of an SD-JWT VC that are not attributes of the subject (RFC 7519, SD-JWT VC, Token Status List). */
const TECHNICAL_CLAIMS = new Set(['iss', 'sub', 'iat', 'nbf', 'exp', 'jti', 'vct', 'vct#integrity', 'cnf', 'status', '_sd', '_sd_alg']);

const flatten = (value: unknown, prefix = ''): Record<string, unknown> => {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return prefix ? { [prefix]: value } : {};
  return Object.fromEntries(
    Object.entries(value as Record<string, unknown>).flatMap(([k, v]) => Object.entries(flatten(v, prefix ? `${prefix}.${k}` : k))),
  );
};

/**
 * `ACC` (harness design section 5): the verification result reports success and releases exactly the requested
 * attributes with the values of the presented credential. Technical claims an RP passes along are not attributes.
 */
export function evaluateAccept(
  result: RelyingPartyResult,
  query: DcqlQuery,
  issuedClaims: Record<string, unknown>,
  responseStatus: number | undefined,
  delivered = responseStatus !== undefined,
): Evaluation {
  if (!delivered) return { verdict: 'FAIL', reason: 'the Authorization Response was not delivered' };
  if (responseStatus !== undefined && responseStatus >= 400) return { verdict: 'FAIL', reason: `the Relying Party answered the Authorization Response with HTTP ${responseStatus}` };
  if (result.outcome !== 'success') return { verdict: 'FAIL', reason: `verification result is ${result.outcome}` };
  const requested = query.credentials.flatMap((c) => (c.claims ?? []).map((claim) => claim.path.map(String)));
  const released = Object.fromEntries(
    Object.entries(flatten(result.releasedAttributes ?? {})).filter(([key]) => !TECHNICAL_CLAIMS.has(key.split('.')[0])),
  );
  const expected: Record<string, unknown> = {};
  for (const path of requested) {
    let value: unknown = issuedClaims;
    for (const segment of path) value = (value as Record<string, unknown> | undefined)?.[segment];
    Object.assign(expected, flatten(value, path.join('.')));
  }
  const missing = Object.keys(expected).filter((key) => !(key in released));
  const wrong = Object.keys(expected).filter((key) => key in released && JSON.stringify(released[key]) !== JSON.stringify(expected[key]));
  const extra = Object.keys(released).filter((key) => !(key in expected));
  if (missing.length || wrong.length || extra.length) {
    return {
      verdict: 'FAIL',
      reason: [
        missing.length && `missing ${missing.join(', ')}`,
        wrong.length && `wrong values for ${wrong.join(', ')}`,
        extra.length && `released attributes that were not requested: ${extra.join(', ')}`,
      ]
        .filter(Boolean)
        .join('; '),
    };
  }
  return { verdict: 'PASS', reason: `accepted; released exactly ${Object.keys(expected).join(', ')}` };
}

/**
 * `REJ`: the verification result reports failure (or 4xx from the endpoint that received the Authorization Response),
 * never 5xx, no released attributes. Via the DC API the response is delivered when it reached the page; the HTTP
 * status is that of the request in which the page forwarded it, when the shim saw one.
 */
export function evaluateReject(result: RelyingPartyResult, responseStatus: number | undefined, delivered = responseStatus !== undefined): Evaluation {
  if (!delivered) return { verdict: 'INCONCLUSIVE', reason: 'the faulty Authorization Response was not delivered' };
  if (responseStatus !== undefined && responseStatus >= 500) return { verdict: 'FAIL', reason: `the Relying Party answered the Authorization Response with HTTP ${responseStatus}` };
  if (result.releasedAttributes && Object.keys(result.releasedAttributes).length > 0) {
    return { verdict: 'FAIL', reason: 'attributes were released' };
  }
  if (result.outcome === 'failure') return { verdict: 'PASS', reason: 'rejected: verification result reports failure' };
  if (responseStatus !== undefined && responseStatus >= 400) return { verdict: 'PASS', reason: `rejected: the Relying Party answered HTTP ${responseStatus}` };
  return { verdict: 'FAIL', reason: `verification result is ${result.outcome}` };
}

/** The credential categories of `NOSTAT`: a PID is always rejected, the others follow ICS RP.R.2. */
export type CredentialCategory = 'pid' | 'qeaa' | 'pub-eaa' | 'eaa';

/**
 * `NOSTAT` (catalogue decision 2): no reliable revocation status. A PID is rejected. Another category follows the
 * policy the ICS declares in RP.R.2: `Reject`, or accepted with `status-unknown` in the result's flags.
 */
export function evaluateNoStatus(args: EvaluationInput): Evaluation {
  if (args.category === 'pid') return withPrefix('PID without reliable status', evaluateReject(args.result, args.responseStatus, args.delivered));
  const policy = icsAnswer(args.ics, 'RP.R.2') ?? '';
  if (/^reject/i.test(policy)) return withPrefix(`RP.R.2 ${policy}`, evaluateReject(args.result, args.responseStatus, args.delivered));
  if (/^accept/i.test(policy)) {
    const accepted = evaluateAccept(args.result, args.query, args.issuedClaims, args.responseStatus, args.delivered);
    if (accepted.verdict !== 'PASS') return withPrefix(`RP.R.2 ${policy}`, accepted);
    if (!args.result.flags?.includes('status-unknown')) return { verdict: 'FAIL', reason: `RP.R.2 ${policy}: accepted without the flag status-unknown` };
    return { verdict: 'PASS', reason: `RP.R.2 ${policy}: accepted and flagged status-unknown` };
  }
  return { verdict: 'INCONCLUSIVE', reason: `RP.R.2 is not declared (${policy || 'missing'})` };
}

/** `POLICY`: compared with the ICS declaration the expectation names (RP.R.3 for an application-specific status). */
export function evaluatePolicy(expectation: Expectation, args: EvaluationInput): Evaluation {
  const policy = expectation.policy;
  if (!policy) return { verdict: 'INCONCLUSIVE', reason: 'the expected result names no ICS item' };
  const hex = `0x${policy.status.toString(16).padStart(2, '0')}`;
  const meaning = statusMeanings(args.ics).get(policy.status);
  if (meaning === undefined) return withPrefix(`${policy.item} declares no meaning for ${hex}`, evaluateReject(args.result, args.responseStatus, args.delivered));
  if (meaning === 'invalid') return withPrefix(`${policy.item} declares ${hex} invalid`, evaluateReject(args.result, args.responseStatus, args.delivered));
  if (meaning === 'valid') return withPrefix(`${policy.item} declares ${hex} valid`, evaluateAccept(args.result, args.query, args.issuedClaims, args.responseStatus, args.delivered));
  return { verdict: 'REVIEW', reason: `${policy.item} declares ${hex} as "${meaning}"; compare the verification result (${args.result.outcome}) by hand` };
}

const withPrefix = (prefix: string, evaluation: Evaluation): Evaluation => ({ ...evaluation, reason: `${prefix}: ${evaluation.reason}` });

export interface EvaluationInput {
  result: RelyingPartyResult;
  query: DcqlQuery;
  issuedClaims: Record<string, unknown>;
  /** HTTP status with which the Relying Party answered the Authorization Response, if the harness saw it. */
  responseStatus?: number;
  /** Whether the Authorization Response reached the Relying Party; default: a status was seen. */
  delivered?: boolean;
  ics: Ics;
  category: CredentialCategory;
  /** Requests the Test Status Provider logged for the step's status list URI, from the step's start to the verdict. */
  statusRequests: number;
}

const ORDER: Verdict[] = ['FAIL', 'INCONCLUSIVE', 'REVIEW', 'PASS'];

/** The worst of several verdicts. */
export function worst(verdicts: Verdict[]): Verdict {
  return [...verdicts].sort((a, b) => ORDER.indexOf(a) - ORDER.indexOf(b))[0] ?? 'INCONCLUSIVE';
}

/** Evaluates the codes of a presentation step (harness design section 5); the step's verdict is the worst of them. */
export function evaluate(expectation: Expectation, args: EvaluationInput): Evaluation {
  const evaluations = expectation.codes.map((code: ExpectationCode): Evaluation => {
    switch (code) {
      case 'ACC':
        return evaluateAccept(args.result, args.query, args.issuedClaims, args.responseStatus, args.delivered);
      case 'REJ':
        return evaluateReject(args.result, args.responseStatus, args.delivered);
      case 'NOSTAT':
        return evaluateNoStatus(args);
      case 'POLICY':
        return evaluatePolicy(expectation, args);
      case 'NOFETCH':
        return args.statusRequests === 0
          ? { verdict: 'PASS', reason: 'the status list was not retrieved' }
          : { verdict: 'FAIL', reason: `the Relying Party retrieved the status list ${args.statusRequests} time(s)` };
      case 'FETCHED':
        return args.statusRequests > 0
          ? { verdict: 'PASS', reason: `the status list was retrieved ${args.statusRequests} time(s)` }
          : { verdict: 'FAIL', reason: 'the Relying Party did not retrieve the status list' };
      default:
        return { verdict: 'INCONCLUSIVE', reason: `expected result ${code} does not apply to a presentation step` };
    }
  });
  const verdict = worst(evaluations.map((e) => e.verdict));
  return { verdict, reason: evaluations.map((e) => e.reason).join('; ') };
}
