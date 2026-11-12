import { DOMParser } from '@xmldom/xmldom';
import { describe, expect, it } from 'vitest';
import { junitXml } from '../src/junit';
import { type KnownFinding, runOutcome } from '../src/known-findings';
import type { RunReport, TestCaseRecord } from '../src/runner';

const record = (testCase: string, flow: TestCaseRecord['flow'], verdict: TestCaseRecord['verdict'], extra: Partial<TestCaseRecord> = {}): TestCaseRecord => ({
  testCase,
  flow,
  verdict,
  control: null,
  steps: [],
  durationMs: 1500,
  ...extra,
});

const report = (results: TestCaseRecord[], error?: string): RunReport => ({
  run: {
    id: 'r1',
    startedAt: '2026-11-12T00:00:00.000Z',
    adapter: 'eudiplo',
    rp: { version: '9.1.0-main.d3cf4ab', revision: 'd3cf4abd0' },
    flows: ['redirect', 'dc-api'],
    ics: { items: {} },
    harness: { name: 'rp-conformance', phase: 4, node: 'v22', libraries: { '@openid4vc/openid4vp': '0', playwright: '0' } },
    environment: { namespace: 'r1', statusProvider: '', trustInfrastructure: '', trustLists: [], listOfTrustedLists: { url: '', pointers: [] } },
    summary: {},
    ...(error ? { error } : {}),
  },
  results,
});

const KNOWN: KnownFinding[] = [{ testCase: 'RP_WS_SM_Validity_005b_UF', finding: 'fetches the status list of an expired mdoc', reference: 'PR description' }];

const failed = record('RP_WS_SM_Validity_005b_UF', 'redirect', 'FAIL', {
  knownFinding: 'fetches the status list of an expired mdoc (PR description)',
  steps: [
    {
      step: 1,
      action: 'presentation',
      text: '',
      expected: 'REJ + NOFETCH',
      expectedResult: '',
      fault: 'credential-mdoc.valid-until-past',
      statusLog: [],
      artifacts: [],
      verdict: 'FAIL',
      reason: 'the Relying Party retrieved the status list 1 time(s) & <more>',
    },
  ],
});

describe('JUnit XML of a run', () => {
  it('has one suite per flow; FAIL is a failure, INCONCLUSIVE and REVIEW are errors, NOT APPLICABLE is skipped', () => {
    const xml = junitXml(
      report([
        record('RP_WS_IA_MainInteraction_001a', 'redirect', 'PASS'),
        failed,
        record('RP_WS_SM_TrustMechanisms_010a', 'redirect', 'NOT APPLICABLE', { reason: 'profile not met: RP.G.3 is No' }),
        record('RP_WS_IA_MainInteraction_001a', 'dc-api', 'PASS'),
        record('RP_PP_SM_Revocation_016a_UF', 'dc-api', 'INCONCLUSIVE', { reason: 'fetch failed' }),
        record('RP_WS_SM_Revocation_011a', 'dc-api', 'REVIEW', { reason: 'compare by hand' }),
      ]),
    );
    const document = new DOMParser().parseFromString(xml, 'application/xml');
    const root = document.documentElement;
    expect(root?.tagName).toBe('testsuites');
    expect(['tests', 'failures', 'errors', 'skipped'].map((a) => root?.getAttribute(a))).toEqual(['6', '1', '2', '1']);
    const suites = Array.from(document.getElementsByTagName('testsuite'));
    expect(suites.map((s) => [s.getAttribute('name'), s.getAttribute('tests')])).toEqual([
      ['eudiplo redirect', '3'],
      ['eudiplo dc-api', '3'],
    ]);
    const properties = Array.from(suites[0].getElementsByTagName('property')).map((p) => [p.getAttribute('name'), p.getAttribute('value')]);
    expect(properties).toContainEqual(['rp.revision', 'd3cf4abd0']);
    const failure = document.getElementsByTagName('failure')[0];
    expect(failure.getAttribute('type')).toBe('known-finding');
    expect(failure.getAttribute('message')).toMatch(/^known finding: fetches the status list/);
    expect(failure.textContent).toContain('retrieved the status list 1 time(s) & <more>');
    const testcase = failure.parentNode as unknown as Element;
    expect([testcase.getAttribute('classname'), testcase.getAttribute('name'), testcase.getAttribute('time')]).toEqual([
      'RP_WS_SM.Validity',
      'RP_WS_SM_Validity_005b_UF [redirect]',
      '1.500',
    ]);
    expect(Array.from(document.getElementsByTagName('error')).map((e) => e.getAttribute('type'))).toEqual(['INCONCLUSIVE', 'REVIEW']);
    expect(document.getElementsByTagName('skipped')[0].getAttribute('message')).toBe('NOT APPLICABLE: profile not met: RP.G.3 is No');
  });
});

describe('outcome of a run with known findings', () => {
  it('passes when every FAIL is a known finding, and names known findings that passed', () => {
    const outcome = runOutcome(
      report([failed, record('RP_WS_SM_Validity_005b_UF', 'dc-api', 'PASS'), record('RP_WS_SM_TrustMechanisms_010a', 'redirect', 'NOT APPLICABLE')]),
      KNOWN,
    );
    expect(outcome).toEqual({
      ok: true,
      unexpected: [],
      known: ['RP_WS_SM_Validity_005b_UF [redirect]: fetches the status list of an expired mdoc (PR description)'],
      resolved: ['RP_WS_SM_Validity_005b_UF [dc-api]'],
    });
  });

  it('fails on another FAIL, an INCONCLUSIVE or REVIEW result, a known finding outside its flows, and a run error', () => {
    const results = [
      record('RP_WS_SM_Validity_001a_UF', 'redirect', 'FAIL'),
      record('RP_WS_SM_Validity_005b_UF', 'dc-api', 'FAIL'),
      record('RP_WS_IA_MainInteraction_001a', 'redirect', 'INCONCLUSIVE'),
      record('RP_WS_SM_Revocation_011a', 'redirect', 'REVIEW'),
    ];
    const outcome = runOutcome(report(results, 'adapter set-up failed'), [{ ...KNOWN[0], flows: ['redirect'] }]);
    expect(outcome.ok).toBe(false);
    expect(outcome.unexpected).toEqual([
      'run error: adapter set-up failed',
      'RP_WS_SM_Validity_001a_UF [redirect] FAIL',
      'RP_WS_SM_Validity_005b_UF [dc-api] FAIL',
      'RP_WS_IA_MainInteraction_001a [redirect] INCONCLUSIVE',
      'RP_WS_SM_Revocation_011a [redirect] REVIEW',
    ]);
  });
});
