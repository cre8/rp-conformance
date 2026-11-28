// The evaluators of `ISS` and `REJ` (issuer harness design section 6.3), and how the runner turns the issuance
// client's evidence into what they read.
import type { CheckResult } from '@eudi-pcaf/core';
import { describe, expect, it } from 'vitest';
import { evaluateIssuance, evaluateIssued, evaluateRejected, type IssuanceObservation, type ObservedExchange } from '../src/issuer/evaluate';
import { observationOf } from '../src/issuer/runner';

const ok = (step: string): ObservedExchange => ({ step, status: 200 });
const flow = ['metadata', 'metadata-jwt', 'token', 'nonce'].map(ok);
const passing: CheckResult[] = ['format', 'issuer-trust', 'issuer-signature', 'disclosures', 'validity', 'holder-binding', 'status-reference', 'status'].map((check) => ({
  check: check as CheckResult['check'],
  status: 'pass',
}));

const issued = (checks = passing): IssuanceObservation => ({ exchanges: [...flow, ok('credential')], tokenIssued: true, credentials: [{ checks }] });
const rejectedAt = (step: string, status: number, error?: string, tokenIssued = false): IssuanceObservation => ({
  exchanges: [...flow.slice(0, ['metadata', 'metadata-jwt', 'token', 'nonce', 'credential'].indexOf(step)), { step, status, ...(error ? { error } : {}) }],
  tokenIssued,
  credentials: [],
  error: `${step} request: HTTP ${status}`,
});

describe('ISS', () => {
  it('passes when every credential passes every check', () => {
    expect(evaluateIssued(issued())).toMatchObject({ verdict: 'PASS', reason: expect.stringContaining('holder-binding') });
  });

  it('fails when a check fails, naming the check', () => {
    const checks = passing.map((c) => (c.check === 'holder-binding' ? { ...c, status: 'fail' as const, detail: 'cnf.jwk is none of the proof keys' } : c));
    expect(evaluateIssued(issued(checks))).toMatchObject({ verdict: 'FAIL', reason: expect.stringContaining('holder-binding failed (cnf.jwk is none of the proof keys)') });
  });

  it('fails when a check the test case names did not run', () => {
    expect(evaluateIssued(issued(), ['dm-pid-claims'])).toMatchObject({ verdict: 'FAIL', reason: expect.stringContaining('dm-pid-claims') });
  });

  it('fails when the Provider rejects instead of issuing', () => {
    expect(evaluateIssued(rejectedAt('credential', 400, 'invalid_proof', true))).toMatchObject({ verdict: 'FAIL', reason: expect.stringContaining('credential HTTP 400 error invalid_proof') });
  });

  it('fails on a server error, even when a credential arrived', () => {
    const observation = issued();
    observation.exchanges[1] = { step: 'metadata-jwt', status: 500 };
    expect(evaluateIssued(observation)).toMatchObject({ verdict: 'FAIL', reason: expect.stringContaining('server error: metadata-jwt HTTP 500') });
  });

  it('is INCONCLUSIVE when the Provider did not answer', () => {
    expect(evaluateIssued({ exchanges: [{ step: 'metadata', transportError: 'fetch failed' }], tokenIssued: false, credentials: [] }).verdict).toBe('INCONCLUSIVE');
  });
});

describe('REJ', () => {
  it('passes for a 4xx with an error object at the faulty request, recording the code', () => {
    expect(evaluateRejected(rejectedAt('token', 401, 'invalid_client'))).toEqual({ verdict: 'PASS', reason: 'rejected at token: HTTP 401, error invalid_client' });
  });

  it('passes for a rejected credential request after a valid token request', () => {
    expect(evaluateRejected(rejectedAt('credential', 400, 'invalid_proof', true)).verdict).toBe('PASS');
  });

  it('fails when a credential was issued', () => {
    expect(evaluateRejected(issued())).toMatchObject({ verdict: 'FAIL', reason: 'the Provider issued 1 credential(s)' });
  });

  it('fails on HTTP 5xx', () => {
    expect(evaluateRejected(rejectedAt('token', 500, 'server_error'))).toMatchObject({ verdict: 'FAIL', reason: expect.stringContaining('server error') });
  });

  it('fails on a 4xx without an error object', () => {
    expect(evaluateRejected(rejectedAt('token', 400))).toMatchObject({ verdict: 'FAIL', reason: expect.stringContaining('without an OAuth or OpenID4VCI error object') });
  });

  it('fails when the request was not rejected', () => {
    expect(evaluateRejected(rejectedAt('nonce', 200)).verdict).toBe('FAIL');
  });

  it('REJ:<code> requires that code', () => {
    expect(evaluateRejected(rejectedAt('credential', 400, 'invalid_proof', true), 'invalid_nonce')).toMatchObject({ verdict: 'FAIL', reason: expect.stringContaining('expected invalid_nonce') });
    expect(evaluateIssuance({ codes: ['REJ:invalid_proof'], text: '' }, rejectedAt('credential', 400, 'invalid_proof', true)).verdict).toBe('PASS');
  });

  it('is INCONCLUSIVE when the Provider did not answer the faulty request', () => {
    expect(evaluateRejected({ exchanges: [ok('metadata'), { step: 'token', transportError: 'ECONNRESET' }], tokenIssued: false, credentials: [] }).verdict).toBe('INCONCLUSIVE');
  });
});

describe('observationOf', () => {
  it('reads status and OAuth error of every exchange, from the body or WWW-Authenticate', () => {
    const exchange = (step: 'token' | 'credential', status: number, body: string, headers: Record<string, string> = {}) => ({
      step,
      attempt: 1,
      at: '',
      request: { method: 'POST', url: 'https://pp.example/x', headers: {} },
      response: { status, headers, body },
    });
    const observation = observationOf(
      { exchanges: [exchange('token', 200, '{"access_token":"a"}'), exchange('credential', 401, '', { 'www-authenticate': 'DPoP error="invalid_dpop_proof"' })], token: { accessToken: 'a', tokenType: 'DPoP', response: {} } },
      [],
    );
    expect(observation.exchanges).toEqual([
      { step: 'token', status: 200 },
      { step: 'credential', status: 401, error: 'invalid_dpop_proof' },
    ]);
    expect(observation.tokenIssued).toBe(true);
  });
});

// Issue 20: the authorization endpoint, `CONF` on the authorization response.
describe('authorization endpoint', () => {
  const at = (status: number, error?: string): IssuanceObservation => ({
    exchanges: [ok('metadata'), ok('par'), { step: 'authorization', status, ...(error ? { error } : {}) }],
    tokenIssued: false,
    credentials: [],
  });

  it('REJ passes for a redirect with error, or an error page without an error object', () => {
    expect(evaluateRejected(at(302, 'invalid_request_uri'))).toMatchObject({ verdict: 'PASS', reason: expect.stringContaining('redirect with error invalid_request_uri') });
    expect(evaluateRejected(at(409))).toMatchObject({ verdict: 'PASS', reason: expect.stringContaining('error page') });
  });

  it('REJ fails for a redirect with a code, and REJ:<code> needs the error object', () => {
    expect(evaluateRejected(at(302)).verdict).toBe('FAIL');
    expect(evaluateRejected(at(400), 'invalid_request').verdict).toBe('FAIL');
  });

  it('observationOf reads the error from the redirect to the wallet', () => {
    const observation = observationOf(
      {
        exchanges: [
          {
            step: 'authorization',
            attempt: 1,
            at: '',
            request: { method: 'GET', url: 'https://pp.example/authorize', headers: {} },
            response: { status: 302, headers: { location: 'https://wallet.example/cb?error=access_denied&state=s' }, body: '' },
          },
        ],
      },
      [],
    );
    expect(observation.exchanges).toEqual([{ step: 'authorization', status: 302, error: 'access_denied' }]);
  });

  it('CONF passes when every named check passed, fails naming a failed one, and is INCONCLUSIVE when one was not captured', () => {
    const conformance: CheckResult[] = [
      { check: 'authorization-response-state', status: 'pass' },
      { check: 'authorization-response-iss', status: 'fail', detail: 'no iss' },
    ];
    const expectation = (checks: string[]) => ({ codes: ['CONF' as const], text: '', checks });
    const observation = { ...at(302), conformance };
    expect(evaluateIssuance(expectation(['authorization-response-state']), observation).verdict).toBe('PASS');
    expect(evaluateIssuance(expectation(['authorization-response-iss']), observation)).toMatchObject({ verdict: 'FAIL', reason: expect.stringContaining('no iss') });
    expect(evaluateIssuance(expectation(['authorization-response-code']), observation).verdict).toBe('INCONCLUSIVE');
  });
});

describe('CONF on an issuance step with output checks', () => {
  const named = (status: CheckResult['status'], detail = 'detail'): CheckResult => ({ check: 'pid-attributes', status, detail });

  it('passes when every check and the named check pass, and fails naming the named check', () => {
    expect(evaluateIssuance({ codes: ['CONF'], text: '', checks: ['pid-attributes'] }, issued([...passing, named('pass')])).verdict).toBe('PASS');
    expect(evaluateIssuance({ codes: ['CONF'], text: '', checks: ['pid-attributes'] }, issued([...passing, named('fail', 'birth_date is a text string')]))).toMatchObject({
      verdict: 'FAIL',
      reason: expect.stringContaining('pid-attributes failed (birth_date is a text string)'),
    });
  });

  it('judges a step check (pid-formats) on the step, not on each credential', () => {
    const both: IssuanceObservation = { ...issued(), credentials: [{ checks: passing }, { checks: passing }] };
    expect(evaluateIssuance({ codes: ['CONF'], text: '', checks: ['pid-formats'] }, { ...both, stepChecks: [{ check: 'pid-formats', status: 'pass' }] }).verdict).toBe('PASS');
    expect(
      evaluateIssuance({ codes: ['CONF'], text: '', checks: ['pid-formats'] }, { ...both, stepChecks: [{ check: 'pid-formats', status: 'fail', detail: 'given_name differs' }] }),
    ).toMatchObject({ verdict: 'FAIL', reason: expect.stringContaining('pid-formats failed on the step (given_name differs)') });
  });
});
