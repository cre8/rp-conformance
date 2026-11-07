import { acc, defineTestCase, ics, pid, preconditions, presentationStep, relevancy, step } from '@rp-conformance/core';
import { describe, expect, it } from 'vitest';
import { applicability } from '../src/ics';
import { selectTestCases } from '../src/runner';

const CONTROL_A = 'RP_WS_IA_MainInteraction_001a';
const CONTROL_B = 'RP_WS_IA_MainInteraction_001b';

const make = (id: string, control?: string | [string, string]) =>
  defineTestCase({
    id,
    objective: '',
    references: [],
    profile: [ics.requestsSdJwtVc],
    relevancy: relevancy.genericRequired,
    technology: [],
    preconditions: [
      ...preconditions.base,
      ...(typeof control === 'string' ? [preconditions.control(control)] : control ? [preconditions.controlOfFlow(control)] : []),
    ],
    control,
    steps: [step({ ...presentationStep.valid({ query: 'default_query_pid', credential: pid.sdJwtVc() }), expect: acc() })],
  });

const all = [make('RP_WS_SM_Validity_001a_UF', CONTROL_A), make(CONTROL_A), make('RP_WS_SM_Validity_002a', CONTROL_A)];

describe('selection', () => {
  it('adds the positive control of a selected test case and runs it first', () => {
    expect(selectTestCases(all, ['RP_WS_SM_Validity_002a']).map((d) => d.id)).toEqual([CONTROL_A, 'RP_WS_SM_Validity_002a']);
  });

  it('accepts patterns', () => {
    expect(selectTestCases(all, ['RP_WS_SM_Validity_*']).map((d) => d.id)).toEqual([CONTROL_A, 'RP_WS_SM_Validity_001a_UF', 'RP_WS_SM_Validity_002a']);
  });

  it('adds every defined alternative of a control', () => {
    const encryption = make('RP_WS_SM_SessionEncryption_001a_UF', [CONTROL_A, CONTROL_B]);
    expect(selectTestCases([...all, encryption], ['RP_WS_SM_SessionEncryption_*']).map((d) => d.id)).toEqual([
      CONTROL_A,
      'RP_WS_SM_SessionEncryption_001a_UF',
    ]);
  });

  it('refuses a selection that matches nothing', () => {
    expect(() => selectTestCases(all, ['nothing'])).toThrow(/no test case matches/);
  });

  it('refuses a control that the preconditions do not name, and the reverse', () => {
    expect(() => defineTestCase({ ...make('RP_WS_SM_Validity_003a'), control: CONTROL_A })).toThrow(/control/);
    expect(() =>
      defineTestCase({ ...make('RP_WS_SM_Validity_003a'), preconditions: [...preconditions.base, preconditions.control(CONTROL_A)] }),
    ).toThrow(/control/);
  });

  it('marks a test case not applicable when the ICS does not meet its profile', () => {
    expect(applicability(all[0], { items: { 'RP.G.1': 'Yes' } })).toEqual([]);
    expect(applicability(all[0], { items: { 'RP.G.1': 'No' } })[0]).toMatch(/RP.G.1/);
  });
});
