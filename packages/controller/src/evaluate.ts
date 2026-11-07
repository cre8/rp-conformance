import type { DcqlQuery, ExpectationCode, RelyingPartyResult, Verdict } from '@rp-conformance/core';

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
): Evaluation {
  if (responseStatus === undefined) return { verdict: 'FAIL', reason: 'the Authorization Response was not delivered' };
  if (responseStatus >= 400) return { verdict: 'FAIL', reason: `response_uri answered HTTP ${responseStatus}` };
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

/** `REJ`: the verification result reports failure (or 4xx at `response_uri`), never 5xx, no released attributes. */
export function evaluateReject(result: RelyingPartyResult, responseStatus: number | undefined): Evaluation {
  if (responseStatus === undefined) return { verdict: 'INCONCLUSIVE', reason: 'the faulty Authorization Response was not delivered' };
  if (responseStatus >= 500) return { verdict: 'FAIL', reason: `response_uri answered HTTP ${responseStatus}` };
  if (result.releasedAttributes && Object.keys(result.releasedAttributes).length > 0) {
    return { verdict: 'FAIL', reason: 'attributes were released' };
  }
  if (result.outcome === 'failure') return { verdict: 'PASS', reason: 'rejected: verification result reports failure' };
  if (responseStatus >= 400) return { verdict: 'PASS', reason: `rejected: response_uri answered HTTP ${responseStatus}` };
  return { verdict: 'FAIL', reason: `verification result is ${result.outcome}` };
}

export function evaluate(
  codes: ExpectationCode[],
  args: { result: RelyingPartyResult; query: DcqlQuery; issuedClaims: Record<string, unknown>; responseStatus?: number },
): Evaluation {
  const evaluations = codes.map((code) => {
    switch (code) {
      case 'ACC':
        return evaluateAccept(args.result, args.query, args.issuedClaims, args.responseStatus);
      case 'REJ':
        return evaluateReject(args.result, args.responseStatus);
      default:
        return { verdict: 'INCONCLUSIVE' as const, reason: `expected result ${code} is not implemented in Phase 0` };
    }
  });
  const order: Verdict[] = ['FAIL', 'INCONCLUSIVE', 'REVIEW', 'PASS'];
  evaluations.sort((a, b) => order.indexOf(a.verdict) - order.indexOf(b.verdict));
  return evaluations[0];
}
