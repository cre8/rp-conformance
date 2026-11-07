import { DEFAULT_QUERIES } from '@rp-conformance/forge';
import { describe, expect, it } from 'vitest';
import { evaluateAccept, evaluateReject } from '../src/evaluate';

const query = DEFAULT_QUERIES.default_query_pid;
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
