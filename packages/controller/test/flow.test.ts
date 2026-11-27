import type { Expectation, RelyingPartyResult } from '@eudi-pcaf/core';
import { describe, expect, it } from 'vitest';
import { evaluateFlowCodes, type FlowEvaluationInput, forgedRedirectUri, responseCodeOf, type TransactionTrace, unknownRequestUri } from '../src/flow';

// The flow codes of RP_WS_IA_ProtocolFlow fail for each way a Relying Party can get the flow wrong, so a PASS against
// the reference Relying Party (reference-run.test.ts) is not vacuous.

const expectation = (...codes: Expectation['codes']): Expectation => ({ codes, text: '' });
const CODE = 'qGmZ9rT3c1yUv0pXwKk7HdNnLf5bQe2aSiOjWlRz8Ys';
const json = (body: unknown, status = 200, contentType = 'application/json') => ({ method: 'POST', url: 'https://rp.example/response', status, contentType, body: JSON.stringify(body) });
const success: RelyingPartyResult = { outcome: 'success', releasedAttributes: { family_name: 'Mustermann' }, raw: {} };
const trace = (redirectUri?: string): TransactionTrace => ({ transactionId: 't1', query: 'default_query_pid', invocationUri: 'openid4vp://', redirectUri, result: success });
const verdictOf = (codes: Expectation['codes'], input: Partial<FlowEvaluationInput>) => evaluateFlowCodes(expectation(...codes), { earlier: [], ...input })?.verdict;

describe('REDIRECT', () => {
  const redirect = (uri: string) => json({ redirect_uri: uri });
  it('passes a 200 application/json answer whose redirect_uri carries a fresh response code of 128 bits', () => {
    expect(verdictOf(['REDIRECT'], { response: redirect(`https://rp.example/done?response_code=${CODE}`) })).toBe('PASS');
    expect(verdictOf(['REDIRECT'], { response: redirect(`https://rp.example/done#response_code=${CODE}`) })).toBe('PASS');
  });
  it.each([
    ['no redirect_uri', json({})],
    ['no response_code', redirect('https://rp.example/done')],
    ['a short response_code', redirect('https://rp.example/done?response_code=1234')],
    ['HTTP 201', json({ redirect_uri: `https://rp.example/done?response_code=${CODE}` }, 201)],
    ['text/html', json({ redirect_uri: `https://rp.example/done?response_code=${CODE}` }, 200, 'text/html')],
  ])('fails %s', (_name, response) => {
    expect(verdictOf(['REDIRECT'], { response })).toBe('FAIL');
  });
  it('fails a response code an earlier transaction carried', () => {
    const uri = `https://rp.example/done?response_code=${CODE}`;
    expect(verdictOf(['REDIRECT'], { response: redirect(uri), earlier: [trace(uri)] })).toBe('FAIL');
  });
});

describe('front end, request_uri, error and resend codes', () => {
  it('RELEASED needs the attributes of the verification result; WITHHELD none', () => {
    const released = { released: true, attributes: { family_name: 'Mustermann' }, status: 200, raw: {} };
    const nothing = { released: false, status: 400, raw: {} };
    expect(verdictOf(['RELEASED'], { trace: trace(), frontEnd: released })).toBe('PASS');
    expect(verdictOf(['RELEASED'], { trace: trace(), frontEnd: { ...released, attributes: { family_name: 'Other' } } })).toBe('FAIL');
    expect(verdictOf(['RELEASED'], { trace: trace(), frontEnd: nothing })).toBe('FAIL');
    expect(verdictOf(['WITHHELD'], { frontEnd: nothing })).toBe('PASS');
    expect(verdictOf(['WITHHELD'], { frontEnd: released })).toBe('FAIL');
    expect(verdictOf(['WITHHELD'], { frontEnd: { released: false, status: 500, raw: {} } })).toBe('FAIL');
  });
  it('REQUEST_REFUSED needs a 4xx without a request object', () => {
    const fetched = (status: number, body: string) => ({ method: 'GET', url: 'https://rp.example/request', status, body });
    expect(verdictOf(['REQUEST_REFUSED'], { requestFetch: fetched(404, '{"error":"not_found"}') })).toBe('PASS');
    expect(verdictOf(['REQUEST_REFUSED'], { requestFetch: fetched(200, 'eyJhbGciOiJFUzI1NiJ9.eyJhIjoxfQ.c2ln') })).toBe('FAIL');
    expect(verdictOf(['REQUEST_REFUSED'], { requestFetch: fetched(400, 'eyJhbGciOiJFUzI1NiJ9.eyJhIjoxfQ.c2ln') })).toBe('FAIL');
    expect(verdictOf(['REQUEST_REFUSED'], { requestFetch: fetched(500, '') })).toBe('FAIL');
  });
  it('ERROR_ACK needs HTTP 200 application/json', () => {
    expect(verdictOf(['ERROR_ACK'], { response: json({}) })).toBe('PASS');
    expect(verdictOf(['ERROR_ACK'], { response: json({}, 400) })).toBe('FAIL');
  });
  it('RESEND_REJ needs a 4xx and the first result unchanged', () => {
    expect(verdictOf(['RESEND_REJ'], { response: json({}, 400), trace: trace(), result: success })).toBe('PASS');
    expect(verdictOf(['RESEND_REJ'], { response: json({}, 200), trace: trace(), result: success })).toBe('FAIL');
    expect(verdictOf(['RESEND_REJ'], { response: json({}, 400), trace: trace(), result: { outcome: 'failure', raw: {} } })).toBe('FAIL');
  });
});

describe('forged values', () => {
  it('an unknown request_uri replaces the parts in which two transactions differ, in the same shape', () => {
    const a = 'https://rp.example/presentations/6f1c2d3e-0000-4abc-8def-0123456789ab/oid4vp/request';
    const b = 'https://rp.example/presentations/7a2b3c4d-1111-4abc-8def-fedcba987654/oid4vp/request';
    const unknown = unknownRequestUri(a, b);
    expect(unknown).not.toBe(a);
    expect(unknown).toMatch(/^https:\/\/rp\.example\/presentations\/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\/oid4vp\/request$/);
    expect(unknownRequestUri('https://rp.example/r?tx=abcDEF123456', 'https://rp.example/r?tx=xyzUVW987654')).toMatch(/^https:\/\/rp\.example\/r\?tx=[a-z]{3}[A-Z]{3}[0-9]{6}$/);
    expect(() => unknownRequestUri(a, a)).toThrow(/do not differ/);
  });
  it('a forged redirect_uri carries another response code of the same length', () => {
    const forged = forgedRedirectUri(`https://rp.example/done/1?response_code=${CODE}`);
    expect(responseCodeOf(forged)).toHaveLength(CODE.length);
    expect(responseCodeOf(forged)).not.toBe(CODE);
  });
});
