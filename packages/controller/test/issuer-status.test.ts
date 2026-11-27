// The evaluators of the lifecycle steps (issue 22; issuer harness design section 6.3): `REVOKED(t)`, `UNCHANGED`,
// `CONF` over a published status list, and `ACC` / `REJ` of a presentation to the reference Relying Party.
import type { IssuerIcs } from '@eudi-pcaf/core';
import { executableIssuerDefinitions } from '@eudi-pcaf/issuer-definitions';
import { describe, expect, it } from 'vitest';
import {
  declaredFormats,
  evaluateObservation,
  evaluatePresentation,
  evaluatePublication,
  evaluateRevoked,
  evaluateUnchanged,
  type ObservedCredential,
  type PolledStatus,
  pollIntervalMs,
  type StatusObservation,
  waits,
  windowMs,
} from '../src/issuer/status';

const EVENT = '2026-11-20T12:00:00.000Z';
const at = (seconds: number) => new Date(Date.parse(EVENT) + seconds * 1000).toISOString();
const poll = (seconds: number, value: number | undefined, iat = 0): PolledStatus => ({ at: at(seconds), uri: 'https://pp.test/sl/1', idx: 3, status: 200, iat, ...(value !== undefined ? { value } : { error: 'HTTP 503' }) });

const credential = (polls: PolledStatus[], checks: ObservedCredential['checks'] = []): ObservedCredential => ({
  step: 1,
  configuration: 'pid-sd-jwt-vc',
  format: 'dc+sd-jwt',
  reference: { uri: 'https://pp.test/sl/1', idx: 3 },
  polls,
  checks,
});

const observation = (credentials: ObservedCredential[], event = true): StatusObservation => ({
  window: { from: EVENT, until: at(60), intervalMs: 3000, t: 'T_rev' },
  ...(event ? { event: { step: 3, at: EVENT, status: 'revoked' } } : {}),
  credentials,
});

const ics: IssuerIcs = { profiles: [], items: { 'ICS-06.T_rev': 'PT1M', 'ICS-05.token_formats': ['jwt', 'cwt'] } };

describe('REVOKED(t)', () => {
  it('passes when revoked within t and in every later version', () => {
    const result = evaluateRevoked(observation([credential([poll(0, 0), poll(3, 1, 1), poll(6, 1, 1), poll(62, 1, 2)])]), 60_000);
    expect(result).toMatchObject({ verdict: 'PASS', reason: expect.stringContaining('3.0 s after the event') });
  });

  it('fails when the list shows the credential revoked only after t', () => {
    expect(evaluateRevoked(observation([credential([poll(0, 0), poll(61, 1)])]), 60_000)).toMatchObject({ verdict: 'FAIL', reason: expect.stringContaining('after the deadline') });
  });

  it('fails when the credential is never shown revoked', () => {
    expect(evaluateRevoked(observation([credential([poll(0, 0), poll(30, 0)])]), 60_000).verdict).toBe('FAIL');
  });

  it('fails when a later version shows it valid again', () => {
    expect(evaluateRevoked(observation([credential([poll(1, 1), poll(30, 0)])]), 60_000)).toMatchObject({ verdict: 'FAIL', reason: expect.stringContaining('then 0x00') });
  });

  it('ignores a poll without an answer, and needs an event', () => {
    expect(evaluateRevoked(observation([credential([poll(1, 1), poll(30, undefined), poll(33, 1)])]), 60_000).verdict).toBe('PASS');
    expect(evaluateRevoked(observation([credential([poll(1, 1)])], false), 60_000).verdict).toBe('INCONCLUSIVE');
  });
});

// Issue 26: suspension and reinstatement within T_rev (PP_WS_SM_Revocation_005).
describe('CONF sl-suspended and sl-reinstated', () => {
  const conf = (check: string) => ({ codes: ['CONF' as const], checks: [check], text: '' });
  it('passes when the entry reaches the value within T_rev and keeps it', () => {
    expect(evaluateObservation(conf('sl-suspended'), observation([credential([poll(0, 0), poll(5, 2), poll(40, 2)])]), ics)).toMatchObject({ verdict: 'PASS', reason: expect.stringContaining('suspended (0x02)') });
    expect(evaluateObservation(conf('sl-reinstated'), observation([credential([poll(0, 2), poll(5, 0), poll(40, 0)])]), ics).verdict).toBe('PASS');
  });

  it('fails when the value is never reached, or left again', () => {
    expect(evaluateObservation(conf('sl-suspended'), observation([credential([poll(0, 0), poll(40, 0)])]), ics).verdict).toBe('FAIL');
    expect(evaluateObservation(conf('sl-suspended'), observation([credential([poll(5, 2), poll(40, 1)])]), ics).verdict).toBe('FAIL');
  });
});

describe('UNCHANGED', () => {
  it('passes when valid in every poll and fails on any other value', () => {
    expect(evaluateUnchanged(observation([credential([poll(0, 0), poll(3, 0)])])).verdict).toBe('PASS');
    expect(evaluateUnchanged(observation([credential([poll(0, 0), poll(3, 2)])]))).toMatchObject({ verdict: 'FAIL', reason: expect.stringContaining('0x02') });
    expect(evaluateUnchanged(observation([credential([poll(0, undefined)])])).verdict).toBe('FAIL');
  });
});

describe('CONF over a published list', () => {
  const checks: ObservedCredential['checks'] = [
    { check: 'sl-uri', status: 'pass' },
    { check: 'sl-cache', status: 'fail', detail: 'the response sets neither Cache-Control nor Expires' },
    { check: 'sl-continuity', status: 'skip', detail: 'no poll after the first version' },
    { check: 'status-list-trust', status: 'skip', detail: 'requires status-list-format' },
  ];

  it('passes when the named checks pass, whatever the others did', () => {
    expect(evaluatePublication(observation([credential([poll(0, 0)], checks)]), ['sl-uri']).verdict).toBe('PASS');
  });

  it('fails on a named check that failed or could not run for a failed prerequisite', () => {
    expect(evaluatePublication(observation([credential([poll(0, 0)], checks)]), ['sl-cache'])).toMatchObject({ verdict: 'FAIL', reason: expect.stringContaining('neither Cache-Control') });
    expect(evaluatePublication(observation([credential([poll(0, 0)], checks)]), ['status-list-trust']).verdict).toBe('FAIL');
  });

  it('is INCONCLUSIVE when a named check does not apply or did not run', () => {
    expect(evaluatePublication(observation([credential([poll(0, 0)], checks)]), ['sl-continuity']).verdict).toBe('INCONCLUSIVE');
    expect(evaluatePublication(observation([credential([poll(0, 0)], checks)]), ['identifier-status']).verdict).toBe('INCONCLUSIVE');
  });

  it('fails for a credential without status reference', () => {
    const { reference: _, ...withoutReference } = credential([]);
    expect(evaluatePublication(observation([withoutReference]), ['sl-uri']).verdict).toBe('FAIL');
  });

  it('is evaluated with the other codes of an observe-status step', () => {
    const result = evaluateObservation({ codes: ['CONF', 'UNCHANGED'], checks: ['sl-uri'], text: '' }, observation([credential([poll(0, 0)], checks)]), ics);
    expect(result.verdict).toBe('PASS');
  });
});

describe('ACC and REJ of a presentation', () => {
  const status = { check: 'status' as const, status: 'fail' as const, detail: 'status 0x01 at index 3 (INVALID)' };

  it('ACC passes on success and fails on a rejection, naming the checks', () => {
    expect(evaluatePresentation({ codes: ['ACC'], text: '' }, { status: 'success', failed: [] }).verdict).toBe('PASS');
    expect(evaluatePresentation({ codes: ['ACC'], text: '' }, { status: 'failure', failed: [status] })).toMatchObject({ verdict: 'FAIL', reason: expect.stringContaining('status failed') });
  });

  it('REJ passes only when the presentation is rejected for its status alone', () => {
    expect(evaluatePresentation({ codes: ['REJ'], text: '' }, { status: 'failure', failed: [status] }).verdict).toBe('PASS');
    expect(evaluatePresentation({ codes: ['REJ'], text: '' }, { status: 'success', failed: [] }).verdict).toBe('FAIL');
    expect(evaluatePresentation({ codes: ['REJ'], text: '' }, { status: 'failure', failed: [{ check: 'key-binding', status: 'fail' }] }).verdict).toBe('FAIL');
    expect(evaluatePresentation({ codes: ['REJ'], text: '' }, { status: 'failure', failed: [status, { check: 'validity', status: 'fail' }] }).verdict).toBe('FAIL');
  });

  it('is INCONCLUSIVE when nothing was presented or no result came', () => {
    expect(evaluatePresentation({ codes: ['ACC'], text: '' }, { status: 'not-sent', error: 'no credential', failed: [] }).verdict).toBe('INCONCLUSIVE');
    expect(evaluatePresentation({ codes: ['REJ'], text: '' }, { status: 'pending', failed: [] }).verdict).toBe('INCONCLUSIVE');
  });
});

describe('observe-status window and scheduling', () => {
  it('reads t from a duration, the ICS or the first exp, and polls every min(t / 20, 30 s)', () => {
    expect(windowMs('PT0S', ics)).toBe(0);
    expect(windowMs('T_rev', ics)).toBe(60_000);
    expect(windowMs('exp', ics)).toBe('exp');
    expect(() => windowMs('T_chain', ics)).toThrow(/declares no duration/);
    expect(pollIntervalMs(60_000)).toBe(3000);
    expect(pollIntervalMs(24 * 60 * 60 * 1000)).toBe(30_000);
    expect(pollIntervalMs(0)).toBe(1000);
    expect(declaredFormats(ics)).toEqual(['jwt', 'cwt']);
    expect(declaredFormats({ profiles: [], items: {} })).toEqual(['jwt']);
  });

  it('schedules the test cases that wait after the others', () => {
    const waiting = executableIssuerDefinitions.filter((d) => waits(d.steps)).map((d) => d.id);
    expect(waiting).toEqual(expect.arrayContaining(['PP_WS_SM_Revocation_003', 'PP_RP_SM_Revocation_005', 'PP_RP_SM_Revocation_008']));
    expect(waiting).not.toContain('PP_RP_SM_Revocation_001');
  });
});
