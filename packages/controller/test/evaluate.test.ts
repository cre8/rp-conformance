import { acc, all, fetched, nofetch, nostat, policyApplicationSpecificStatus, rej } from '@rp-conformance/core';
import { PID_QUERY } from '@rp-conformance/forge';
import { describe, expect, it } from 'vitest';
import { evaluate, evaluateAccept, type EvaluationInput, evaluateReject } from '../src/evaluate';

const query = PID_QUERY;
const issued = { iss: 'https://pp-a.rp-test', family_name: 'Mustermann', given_name: 'Erika', birthdate: '1964-08-12', nationalities: ['DE'] };
const released = { family_name: 'Mustermann', given_name: 'Erika', birthdate: '1964-08-12' };

describe('ACC', () => {
  it('passes when exactly the requested attributes are released with the issued values', () => {
    expect(evaluateAccept({ outcome: 'success', releasedAttributes: released, raw: {} }, query, issued, 200).verdict).toBe('PASS');
  });

  it('ignores technical claims the Relying Party passes along', () => {
    const withTechnical = { ...released, iss: 'https://pp-a.rp-test', vct: 'urn:eudi:pid:1', iat: 1, exp: 2 };
    expect(evaluateAccept({ outcome: 'success', releasedAttributes: withTechnical, raw: {} }, query, issued, 200).verdict).toBe('PASS');
  });

  it.each([
    ['a missing attribute', { family_name: 'Mustermann', given_name: 'Erika' }, /missing birthdate/],
    ['a wrong value', { ...released, given_name: 'Max' }, /wrong values for given_name/],
    ['an attribute that was not requested', { ...released, nationalities: ['DE'] }, /not requested: nationalities/],
  ])('fails for %s', (_name, attributes, reason) => {
    const evaluation = evaluateAccept({ outcome: 'success', releasedAttributes: attributes, raw: {} }, query, issued, 200);
    expect(evaluation.verdict).toBe('FAIL');
    expect(evaluation.reason).toMatch(reason);
  });

  it('fails when the result is not success, or response_uri answered 4xx', () => {
    expect(evaluateAccept({ outcome: 'failure', raw: {} }, query, issued, 200).verdict).toBe('FAIL');
    expect(evaluateAccept({ outcome: 'success', releasedAttributes: released, raw: {} }, query, issued, 400).verdict).toBe('FAIL');
  });
});

describe('REJ', () => {
  it('passes for a reported failure or HTTP 4xx at response_uri', () => {
    expect(evaluateReject({ outcome: 'failure', raw: {} }, 200).verdict).toBe('PASS');
    expect(evaluateReject({ outcome: 'pending', raw: {} }, 400).verdict).toBe('PASS');
  });

  it('fails for HTTP 5xx, released attributes or success', () => {
    expect(evaluateReject({ outcome: 'failure', raw: {} }, 500).verdict).toBe('FAIL');
    expect(evaluateReject({ outcome: 'failure', releasedAttributes: released, raw: {} }, 400).verdict).toBe('FAIL');
    expect(evaluateReject({ outcome: 'success', raw: {} }, 200).verdict).toBe('FAIL');
  });

  it('is inconclusive when the faulty response was not delivered', () => {
    expect(evaluateReject({ outcome: 'pending', raw: {} }, undefined).verdict).toBe('INCONCLUSIVE');
  });
});

const input = (overrides: Partial<EvaluationInput>): EvaluationInput => ({
  result: { outcome: 'failure', raw: {} },
  query,
  issuedClaims: issued,
  responseStatus: 400,
  ics: { items: { 'RP.R.2': 'Reject', 'RP.R.3': 'None' } },
  category: 'pid',
  statusRequests: 0,
  ...overrides,
});
const success = { outcome: 'success' as const, releasedAttributes: released, raw: {} };

describe('NOFETCH and FETCHED', () => {
  it('read the Test Status Provider log of the step', () => {
    expect(evaluate(all(rej(), nofetch()), input({})).verdict).toBe('PASS');
    expect(evaluate(all(rej(), nofetch()), input({ statusRequests: 1 })).verdict).toBe('FAIL');
    expect(evaluate(all(acc(), fetched()), input({ result: success, responseStatus: 200, statusRequests: 1 })).verdict).toBe('PASS');
    expect(evaluate(all(acc(), fetched()), input({ result: success, responseStatus: 200 })).verdict).toBe('FAIL');
  });
});

describe('NOSTAT', () => {
  it('rejects a PID whatever the declared policy', () => {
    expect(evaluate(nostat(), input({ ics: { items: { 'RP.R.2': 'Accept and flag as status unknown' } } })).verdict).toBe('PASS');
    expect(evaluate(nostat(), input({ result: success, responseStatus: 200 })).verdict).toBe('FAIL');
  });

  it('follows RP.R.2 for other categories, and an accepted credential must be flagged status-unknown', () => {
    const accept = { items: { 'RP.R.2': 'Accept and flag as status unknown' } };
    expect(evaluate(nostat(), input({ category: 'qeaa', ics: accept, result: { ...success, flags: ['status-unknown'] }, responseStatus: 200 })).verdict).toBe('PASS');
    expect(evaluate(nostat(), input({ category: 'qeaa', ics: accept, result: success, responseStatus: 200 })).verdict).toBe('FAIL');
    expect(evaluate(nostat(), input({ category: 'eaa' })).verdict).toBe('PASS');
  });
});

describe('POLICY (RP.R.3)', () => {
  const policy = policyApplicationSpecificStatus('0x03');
  it('rejects when no meaning is declared', () => {
    expect(evaluate(policy, input({})).verdict).toBe('PASS');
    expect(evaluate(policy, input({ result: success, responseStatus: 200 })).verdict).toBe('FAIL');
  });

  it('accepts or rejects as declared, and leaves other meanings to review', () => {
    expect(evaluate(policy, input({ ics: { items: { 'RP.R.3': '0x03=valid' } }, result: success, responseStatus: 200 })).verdict).toBe('PASS');
    expect(evaluate(policy, input({ ics: { items: { 'RP.R.3': '0x03=invalid' } } })).verdict).toBe('PASS');
    expect(evaluate(policy, input({ ics: { items: { 'RP.R.3': '0x03=step-up authentication' } } })).verdict).toBe('REVIEW');
  });
});
