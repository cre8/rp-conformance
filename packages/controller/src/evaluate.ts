import {
  type CredentialCategory,
  type DcqlQuery,
  durationMs,
  type Expectation,
  type ExpectationCode,
  type Ics,
  type PolicyReference,
  type RelyingPartyResult,
  type Verdict,
} from '@rp-conformance/core';
import { icsAnswer, statusMeanings } from './ics';

export interface Evaluation {
  verdict: Verdict;
  reason: string;
}

/** Technical claims of an SD-JWT VC that are not attributes of the subject (RFC 7519, SD-JWT VC, Token Status List). */
const TECHNICAL_CLAIMS = new Set(['iss', 'sub', 'iat', 'nbf', 'exp', 'jti', 'vct', 'vct#integrity', 'cnf', 'status', '_sd', '_sd_alg']);

// An empty object is a value of its own, not nothing: an RP that releases an mdoc CBOR map as `{}` must show up as a
// wrong or extra attribute, not vanish (RP_WS_DM_IdentifyingData_001b, spec review 2026-11-20).
const flatten = (value: unknown, prefix = ''): Record<string, unknown> => {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return prefix ? { [prefix]: value } : {};
  if (prefix && Object.keys(value as Record<string, unknown>).length === 0) return { [prefix]: value };
  return Object.fromEntries(
    Object.entries(value as Record<string, unknown>).flatMap(([k, v]) => Object.entries(flatten(v, prefix ? `${prefix}.${k}` : k))),
  );
};

/**
 * `ACC` (harness design section 5): the verification result reports success and releases exactly the requested
 * attributes with the values of the presented credential. Technical claims an RP passes along are not attributes, and
 * neither are claims the credential discloses with every presentation (`alwaysDisclosed`, the plain claims of an
 * SD-JWT VC's issuer-signed JWT): the wallet cannot withhold them (OpenID4VP 1.0 section 6.4), so an RP that passes
 * one along is not judged on it (RP_WS_DM_IdentifyingData_007a, spec review 2026-11-20).
 */
export function evaluateAccept(
  result: RelyingPartyResult,
  query: DcqlQuery,
  issuedClaims: Record<string, unknown>,
  responseStatus: number | undefined,
  delivered = responseStatus !== undefined,
  alwaysDisclosed: readonly string[] = [],
): Evaluation {
  if (!delivered) return { verdict: 'FAIL', reason: 'the Authorization Response was not delivered' };
  if (responseStatus !== undefined && responseStatus >= 400) return { verdict: 'FAIL', reason: `the Relying Party answered the Authorization Response with HTTP ${responseStatus}` };
  if (result.outcome !== 'success') return { verdict: 'FAIL', reason: `verification result is ${result.outcome}` };
  const requested = query.credentials.flatMap((c) => (c.claims ?? []).map((claim) => claim.path.map(String)));
  const requestedTop = new Set(requested.map((path) => path[0]));
  const plain = new Set(alwaysDisclosed.filter((claim) => !requestedTop.has(claim)));
  const released = Object.fromEntries(
    Object.entries(flatten(result.releasedAttributes ?? {})).filter(([key]) => !TECHNICAL_CLAIMS.has(key.split('.')[0]) && !plain.has(key.split('.')[0])),
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

/**
 * `REJ_OR_ACC`: a rejection passes as for `REJ`; an acceptance passes as for `ACC`, so it must release exactly the
 * requested attributes with the issued values (DeviceBinding_011: a device-signed value released instead fails).
 */
export function evaluateRejectOrAccept(args: EvaluationInput): Evaluation {
  const rejected = args.result.outcome === 'failure' || (args.responseStatus !== undefined && args.responseStatus >= 400 && args.responseStatus < 500);
  return rejected
    ? withPrefix('rejected', evaluateReject(args.result, args.responseStatus, args.delivered))
    : withPrefix('not rejected', evaluateAccept(args.result, args.query, args.issuedClaims, args.responseStatus, args.delivered, args.alwaysDisclosed));
}

/**
 * `NOSTAT` (catalogue decision 2): no reliable revocation status. A PID is rejected. Another category follows the
 * policy the ICS declares in RP.R.2: `Reject`, or accepted with `status-unknown` in the result's flags.
 */
export function evaluateNoStatus(args: EvaluationInput): Evaluation {
  if (args.category === 'pid') return withPrefix('PID without reliable status', evaluateReject(args.result, args.responseStatus, args.delivered));
  const policy = icsAnswer(args.ics, 'RP.R.2') ?? '';
  if (/^reject/i.test(policy)) return withPrefix(`RP.R.2 ${policy}`, evaluateReject(args.result, args.responseStatus, args.delivered));
  if (/^accept/i.test(policy)) {
    const accepted = evaluateAccept(args.result, args.query, args.issuedClaims, args.responseStatus, args.delivered, args.alwaysDisclosed);
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
  if (policy.item !== 'RP.R.3') return evaluateDeclaredPolicy(policy, args);
  const hex = `0x${policy.status.toString(16).padStart(2, '0')}`;
  const meaning = statusMeanings(args.ics).get(policy.status);
  if (meaning === undefined) return withPrefix(`${policy.item} declares no meaning for ${hex}`, evaluateReject(args.result, args.responseStatus, args.delivered));
  if (meaning === 'invalid') return withPrefix(`${policy.item} declares ${hex} invalid`, evaluateReject(args.result, args.responseStatus, args.delivered));
  if (meaning === 'valid') return withPrefix(`${policy.item} declares ${hex} valid`, evaluateAccept(args.result, args.query, args.issuedClaims, args.responseStatus, args.delivered, args.alwaysDisclosed));
  return { verdict: 'REVIEW', reason: `${policy.item} declares ${hex} as "${meaning}"; compare the verification result (${args.result.outcome}) by hand` };
}

/**
 * `REJ_OR_INVALID` (IdentifyingData_004): an attribute value of the wrong data type is not accepted silently. A
 * rejection passes as for `REJ`; an acceptance passes only when the verification result flags an attribute as invalid
 * (`attribute-invalid` in its flags).
 */
export function evaluateRejectOrInvalid(args: EvaluationInput): Evaluation {
  const rejected = args.result.outcome === 'failure' || (args.responseStatus !== undefined && args.responseStatus >= 400 && args.responseStatus < 500);
  const delivered = args.delivered ?? args.responseStatus !== undefined;
  if (!delivered) return evaluateReject(args.result, args.responseStatus, delivered);
  if (rejected) return withPrefix('rejected', evaluateReject(args.result, args.responseStatus, delivered));
  if (args.result.outcome !== 'success') return { verdict: 'FAIL', reason: `verification result is ${args.result.outcome}` };
  if (args.result.flags?.includes('attribute-invalid')) return { verdict: 'PASS', reason: 'accepted and flagged attribute-invalid' };
  return { verdict: 'FAIL', reason: 'accepted without rejecting or flagging the attribute of the wrong data type (attribute-invalid)' };
}

const withPrefix = (prefix: string, evaluation: Evaluation): Evaluation => ({ ...evaluation, reason: `${prefix}: ${evaluation.reason}` });

export interface EvaluationInput {
  result: RelyingPartyResult;
  query: DcqlQuery;
  issuedClaims: Record<string, unknown>;
  /** Top-level claims the presented credentials disclose with every presentation (not selectively disclosable). */
  alwaysDisclosed?: string[];
  /** HTTP status with which the Relying Party answered the Authorization Response, if the harness saw it. */
  responseStatus?: number;
  /** Whether the Authorization Response reached the Relying Party; default: a status was seen. */
  delivered?: boolean;
  ics: Ics;
  category: CredentialCategory;
  /** Requests the Test Status Provider logged for the step's status list URI, from the step's start to the verdict. */
  statusRequests: number;
  /** Where the Authorization Response was delivered: `response_uri` (redirects) or the page's forwarding (DC API). */
  responseEndpoint?: 'response_uri' | 'dc-api-forward';
  /** The body of the answer to the Authorization Response, if the harness saw it. */
  responseBody?: string;
  /** Via the DC API: the network error with which the page's request forwarding the response failed, if it did. */
  forwardError?: string;
  /** The requests the Test Status Provider logged for the step's status list, with method, target and headers. */
  statusEntries?: { method: string; url: string; target?: string; headers: Record<string, string | string[] | undefined> }[];
  /** The Relying Party's identifier of the transaction. */
  transactionId?: string;
  /** The format of the step's Status List Token. */
  statusFormat?: 'jwt' | 'cwt';
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
        return evaluateAccept(args.result, args.query, args.issuedClaims, args.responseStatus, args.delivered, args.alwaysDisclosed);
      case 'REJ':
        if (expectation.forwardFailureRejects && args.responseEndpoint === 'dc-api-forward' && args.forwardError && !Object.keys(args.result.releasedAttributes ?? {}).length) {
          return { verdict: 'PASS', reason: `rejected: the page's request forwarding the response failed (${args.forwardError}), and no attributes were released` };
        }
        return evaluateReject(args.result, args.responseStatus, args.delivered);
      case 'REJ_OR_ACC':
        return evaluateRejectOrAccept(args);
      case 'NOSTAT':
        return evaluateNoStatus(args);
      case 'REJ_OR_INVALID':
        return evaluateRejectOrInvalid(args);
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
      case 'STALE':
        return args.result.flags?.includes('trust-list-stale')
          ? { verdict: 'PASS', reason: 'the verification result signals trust-list-stale' }
          : { verdict: 'FAIL', reason: 'the verification result does not signal trust-list-stale' };
      case 'HTTP_4XX':
        return evaluateClientError(args);
      case 'NO_DETAILS':
        return evaluateNoDetails(args);
      case 'STATUS_REQUEST':
        return evaluateStatusRequest(args);
      case 'INFO':
        return evaluateInfo(args);
      default:
        return { verdict: 'INCONCLUSIVE', reason: `expected result ${code} does not apply to a presentation step` };
    }
  });
  const verdict = worst(evaluations.map((e) => e.verdict));
  return { verdict, reason: evaluations.map((e) => e.reason).join('; ') };
}

/**
 * `HTTP_4XX` (RP_WS_SH_Encoding_001): the `response_uri` answers the faulty Authorization Response with HTTP 4xx. Via
 * the W3C Digital Credentials API the response returns to the Relying Party's page, and how the page passes it on to its
 * backend is the Relying Party's own matter (OpenID4VP 1.0 Appendix A), so the code applies to redirects only.
 */
export function evaluateClientError(args: EvaluationInput): Evaluation {
  if (args.responseEndpoint === 'dc-api-forward') return { verdict: 'PASS', reason: 'via the DC API the status of the page forwarding the response is not evaluated' };
  if (args.delivered === false || args.responseStatus === undefined) return { verdict: 'INCONCLUSIVE', reason: 'the harness saw no answer to the Authorization Response' };
  if (args.responseStatus >= 400 && args.responseStatus < 500) return { verdict: 'PASS', reason: `the response_uri answered HTTP ${args.responseStatus}` };
  return { verdict: 'FAIL', reason: `the response_uri answered HTTP ${args.responseStatus}, not 4xx` };
}

/**
 * Marks of internal details in an error answer (RP_WS_SH_Encoding_007, OpenID4VP section 15.9): stack frames of
 * JavaScript, Java, Python, .NET and Go, source file paths with a line number, module directories, exception class
 * names followed by their message, and SQL error states.
 */
export const INTERNAL_DETAILS: { name: string; pattern: RegExp }[] = [
  { name: 'a JavaScript stack frame', pattern: /\bat (?:async )?[\w$.<>[\]]+ \(?[^\s()]+:\d+:\d+\)?/ },
  { name: 'a Java or .NET stack frame', pattern: /\bat [\w$.]+\([\w$]*\.(?:java|kt|scala|cs):\d+\)/ },
  { name: 'a Python traceback', pattern: /Traceback \(most recent call last\)/ },
  { name: 'a Go panic', pattern: /\bgoroutine \d+ \[/ },
  { name: 'a source file with a line number', pattern: /[\w./-]+\.(?:[cm]?[jt]s|java|kt|py|rb|go|cs|php):\d+/ },
  { name: 'a module directory', pattern: /\b(?:node_modules|site-packages|vendor\/bundle)\// },
  { name: 'a stack member', pattern: /"stack(?:Trace)?"\s*:/ },
  { name: 'an exception class with its message', pattern: /\b(?:[A-Z]\w*(?:Error|Exception)): / },
  { name: 'an SQL error state', pattern: /\bSQLSTATE\b|\bQueryFailedError\b/ },
];

/**
 * `NO_DETAILS` (RP_WS_SH_Encoding_007): the answer to the faulty Authorization Response reveals no internal details.
 * Via the W3C Digital Credentials API the answer goes to the Relying Party's own page, not to the wallet.
 */
export function evaluateNoDetails(args: EvaluationInput): Evaluation {
  if (args.responseEndpoint === 'dc-api-forward') return { verdict: 'PASS', reason: 'via the DC API no answer of the Relying Party reaches the wallet' };
  if (args.delivered === false || args.responseStatus === undefined) return { verdict: 'INCONCLUSIVE', reason: 'the harness saw no answer to the Authorization Response' };
  const body = args.responseBody ?? '';
  const found = INTERNAL_DETAILS.filter(({ pattern }) => pattern.test(body)).map(({ name, pattern }) => `${name} (${pattern.exec(body)?.[0]})`);
  if (found.length) return { verdict: 'FAIL', reason: `the answer reveals internal details: ${found.join('; ')}` };
  return { verdict: 'PASS', reason: `the answer (HTTP ${args.responseStatus}, ${body.length} characters) reveals no internal details` };
}

/**
 * `STATUS_REQUEST` (RP_PP_IA_Supportive_001, Token Status List section 8.1, ARF VCR_16): every logged request for the
 * step's status list is a `GET` of exactly its URI (no query component), carries no `Authorization` or `Cookie` header
 * and not the transaction's identifier, and has an `Accept` header, if any, that admits the token's media type.
 */
export function evaluateStatusRequest(args: EvaluationInput): Evaluation {
  const entries = args.statusEntries ?? [];
  if (entries.length === 0) return { verdict: 'FAIL', reason: 'the Relying Party did not retrieve the status list' };
  const mediaType = `application/statuslist+${args.statusFormat ?? 'jwt'}`;
  const problems = entries.flatMap((entry, i) => {
    const found: string[] = [];
    const header = (name: string) => entry.headers[name];
    if (entry.method !== 'GET') found.push(`method ${entry.method}`);
    if (entry.target !== undefined && entry.target.includes('?')) found.push(`a query component (${entry.target})`);
    if (header('authorization') !== undefined) found.push('an Authorization header');
    if (header('cookie') !== undefined) found.push('a Cookie header');
    const accept = header('accept');
    const types = (Array.isArray(accept) ? accept.join(',') : (accept ?? '')).split(',').map((t) => t.split(';')[0]?.trim().toLowerCase());
    if (accept !== undefined && !types.some((t) => t === mediaType || t === '*/*' || t === 'application/*')) found.push(`Accept ${String(accept)}`);
    const id = args.transactionId;
    if (id && (entry.target?.includes(id) || Object.values(entry.headers).some((v) => String(v).includes(id)))) found.push('the transaction identifier');
    return found.map((f) => `request ${i + 1}: ${f}`);
  });
  if (problems.length) return { verdict: 'FAIL', reason: `the status list request carries ${problems.join('; ')}` };
  const accepts = [...new Set(entries.map((e) => String(e.headers.accept ?? '(none)')))].join(', ');
  return { verdict: 'PASS', reason: `${entries.length} GET request(s) of the status URI without authentication or transaction data (Accept: ${accepts})` };
}

/**
 * `POLICY` against the ICS items of issue 32: `RP.R.7`, the maximum age of a Status List Token (a token at least that
 * old gives no reliable status, `NOSTAT`; `None` or a longer age accepts); `RP.R.8`, whether a token issued in the future
 * is refused (`Yes`: `NOSTAT`, `No`: accepted); `RP.P.12`, a PID whose administrative expiry date has passed (`Reject`
 * or `Accept`); `RP.T.4`, a trust list whose new version failed its seal (`Keep` the last valid version: accepted,
 * `Discard`: rejected); `RP.P.13` and `RP.P.14`, whether the Relying Party applies a check (`Yes`: rejected, `No`:
 * accepted).
 */
export function evaluateDeclaredPolicy(policy: Exclude<PolicyReference, { item: 'RP.R.3' }>, args: EvaluationInput): Evaluation {
  const declared = String(icsAnswer(args.ics, policy.item) ?? '').trim();
  const accept = (why: string) => withPrefix(`${policy.item} ${why}`, evaluateAccept(args.result, args.query, args.issuedClaims, args.responseStatus, args.delivered, args.alwaysDisclosed));
  const refuse = (why: string) => withPrefix(`${policy.item} ${why}`, evaluateNoStatus(args));
  const undeclared = (): Evaluation => ({ verdict: 'INCONCLUSIVE', reason: `${policy.item} is not declared (${declared || 'missing'})` });
  switch (policy.item) {
    case 'RP.R.7': {
      if (/^none$/i.test(declared)) return accept('declares no maximum age');
      const maxMs = durationMs(declared);
      if (maxMs === undefined) return undeclared();
      return maxMs <= policy.ageSeconds * 1000 ? refuse(`declares a maximum age of ${declared}`) : accept(`declares a maximum age of ${declared}, more than the token's`);
    }
    case 'RP.R.8':
      if (/^yes$/i.test(declared)) return refuse('Yes');
      if (/^no$/i.test(declared)) return accept('No');
      return undeclared();
    case 'RP.P.12':
      if (/^reject/i.test(declared)) return withPrefix(`${policy.item} ${declared}`, evaluateReject(args.result, args.responseStatus, args.delivered));
      if (/^accept/i.test(declared)) return accept(declared);
      return undeclared();
    case 'RP.T.4':
      // Keep: the last valid version stays in force, the presentation is accepted. Discard: the list is unusable and a
      // presentation that depends on it is rejected (fail-closed). No specification prescribes either (spec review
      // 2026-11-20).
      if (/^keep/i.test(declared)) return accept(declared);
      if (/^discard/i.test(declared)) return withPrefix(`${policy.item} ${declared}`, evaluateReject(args.result, args.responseStatus, args.delivered));
      return undeclared();
    case 'RP.P.13':
    case 'RP.P.14':
      // Issue 10: the Relying Party applies the check (Yes, rejected) or not (No, accepted); the traces in
      // rp-test-catalogue.md section 8.4 find no requirement for it.
      if (/^yes$/i.test(declared)) return withPrefix(`${policy.item} Yes`, evaluateReject(args.result, args.responseStatus, args.delivered));
      if (/^no$/i.test(declared)) return accept('No');
      return undeclared();
  }
}

/**
 * `INFO` (RP_WS_SM_Validity_004): the outcome is recorded without a verdict on it. The step passes whenever the Relying
 * Party decided without an HTTP 5xx; an answer that never arrived leaves it inconclusive.
 */
export function evaluateInfo(args: EvaluationInput): Evaluation {
  if (args.delivered === false) return { verdict: 'INCONCLUSIVE', reason: 'the Authorization Response was not delivered' };
  if (args.responseStatus !== undefined && args.responseStatus >= 500) return { verdict: 'FAIL', reason: `the Relying Party answered HTTP ${args.responseStatus}` };
  const outcome = args.result.outcome === 'success' ? 'accepted' : args.result.outcome === 'failure' ? 'rejected' : 'left pending';
  return { verdict: 'PASS', reason: `recorded: the Relying Party ${outcome} the presentation${args.responseStatus !== undefined ? ` (HTTP ${args.responseStatus})` : ''}` };
}
