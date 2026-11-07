import { acc, defineTestCase, ics, pid, presentation, step } from '@rp-conformance/core';
import { describe, expect, it } from 'vitest';
import { applicability } from '../src/ics';
import { selectTestCases } from '../src/runner';

const make = (id: string, control?: string) =>
  defineTestCase({
    id,
    objective: '',
    references: [],
    profile: [ics.requestsSdJwtVc],
    relevancy: '',
    technology: [],
    preconditions: [],
    control,
    steps: [step({ text: '', expectedText: '', run: presentation({ query: 'default_query_pid', credential: pid.sdJwtVc() }), expect: acc() })],
  });

const all = [make('RP_WS_SM_Validity_001a', 'CONTROL_a'), make('CONTROL_a'), make('RP_WS_SM_Validity_002a', 'CONTROL_a')];

describe('selection', () => {
  it('adds the positive control of a selected test case and runs it first', () => {
    expect(selectTestCases(all, ['RP_WS_SM_Validity_002a']).map((d) => d.id)).toEqual(['CONTROL_a', 'RP_WS_SM_Validity_002a']);
  });

  it('accepts patterns', () => {
    expect(selectTestCases(all, ['RP_WS_SM_Validity_*']).map((d) => d.id)).toEqual(['CONTROL_a', 'RP_WS_SM_Validity_001a', 'RP_WS_SM_Validity_002a']);
  });

  it('refuses a selection that matches nothing', () => {
    expect(() => selectTestCases(all, ['nothing'])).toThrow(/no test case matches/);
  });

  it('marks a test case not applicable when the ICS does not meet its profile', () => {
    expect(applicability(all[0], { items: { 'RP.G.1': 'Yes' } })).toEqual([]);
    expect(applicability(all[0], { items: { 'RP.G.1': 'No' } })[0]).toMatch(/RP.G.1/);
  });
});
