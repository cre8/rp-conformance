// Selection of the issuer suite (`eudi-pcaf issuer`): patterns, positive controls first, one definition per
// variant, `--list`, the usage, and the applicability of a definition and its variant to the Provider's ICS.
import { defineIssuerTestCase, type IssuerIcs, type IssuerTestCaseDefinition, relevancy } from '@eudi-pcaf/core';
import { issuance, iss, pidProfile, preconditions, rej } from '@eudi-pcaf/issuer-definitions';
import { describe, expect, it } from 'vitest';
import { issuerMain, listIssuerTestCases } from '../src/issuer/cli';
import { issuerApplicability, resolveConfigurations, usesTxCode } from '../src/issuer/ics';
import { selectIssuerTestCases } from '../src/issuer/runner';

const CONTROL = 'PP_WS_IA_MainInteraction_001';

const make = (id: string, variants: ['SD' | 'MD', 'PA' | 'AC'], control?: string): IssuerTestCaseDefinition =>
  defineIssuerTestCase({
    id,
    variants,
    objective: '',
    references: [],
    profile: pidProfile(...variants),
    relevancy: relevancy.specificRequired,
    technology: [],
    preconditions: [...preconditions.base, ...(control ? [preconditions.control(control)] : [])],
    ...(control ? { control } : {}),
    steps: [{ text: '', run: issuance(...variants), expect: control ? rej() : iss(variants[0]) }],
  });

const all = [
  make('PP_WS_SM_KeyAttestation_004_UF', ['SD', 'PA'], CONTROL),
  make(CONTROL, ['SD', 'PA']),
  make(CONTROL, ['MD', 'PA']),
  make('PP_WS_SM_ProofOfPossession_001_UF', ['SD', 'PA'], CONTROL),
];

const textOnly: IssuerTestCaseDefinition = { ...make('PP_WS_IA_MainInteraction_002', ['SD', 'PA']), steps: [{ text: '', expect: iss('SD') }] };

describe('issuer selection', () => {
  it('adds the positive control in every variant and runs controls first', () => {
    expect(selectIssuerTestCases(all, ['PP_WS_SM_KeyAttestation_004_UF']).map((d) => `${d.id} ${d.variants?.join('+')}`)).toEqual([
      `${CONTROL} SD+PA`,
      `${CONTROL} MD+PA`,
      'PP_WS_SM_KeyAttestation_004_UF SD+PA',
    ]);
  });

  it('selects by pattern', () => {
    expect(selectIssuerTestCases(all, ['PP_WS_SM_*']).map((d) => d.id)).toEqual([CONTROL, CONTROL, 'PP_WS_SM_KeyAttestation_004_UF', 'PP_WS_SM_ProofOfPossession_001_UF']);
  });

  it('selects every executable definition without --only and leaves text-only ones out', () => {
    expect(selectIssuerTestCases([...all, textOnly])).toHaveLength(4);
  });

  it('refuses a pattern that matches nothing executable, naming text-only matches', () => {
    expect(() => selectIssuerTestCases([...all, textOnly], ['PP_WS_IA_MainInteraction_002'])).toThrow(/text only: PP_WS_IA_MainInteraction_002/);
  });

  it('lists one line per test case and variant', () => {
    expect(listIssuerTestCases([all[1], all[0], textOnly])).toEqual([
      `${CONTROL} [SD+PA] (positive control)`,
      'PP_WS_SM_KeyAttestation_004_UF [SD+PA]',
      'PP_WS_IA_MainInteraction_002 [SD+PA] (positive control, text only)',
    ]);
  });

  it('issuer --list prints the issuer definitions; run without an adapter prints the usage', async () => {
    let out = '';
    let err = '';
    const io = { out: (text: string) => void (out += text), err: (text: string) => void (err += text) };
    expect(await issuerMain(['--list'], io)).toBe(0);
    expect(out).toContain(`${CONTROL} [SD+PA] (positive control)`);
    expect(await issuerMain(['run'], io)).toBe(2);
    expect(err).toContain('eudi-pcaf issuer run --adapter <eudiplo|path>');
  });
});

describe('issuer ICS', () => {
  const ics: IssuerIcs = { profiles: ['P-PID', 'P-SD', 'P-PA'], items: { 'ICS-02.SD': 'pid-sd-jwt-vc', 'ICS-03.tx_code': 'with and without' } };

  it('applies a variant the ICS declares, not one it does not', () => {
    expect(issuerApplicability(all[1], ics)).toEqual([]);
    expect(issuerApplicability(all[2], ics).join()).toContain('P-MD');
  });

  it('resolves configuration references against ICS-02', () => {
    expect(resolveConfigurations(['ICS-02.SD', 'literal-id'], ics)).toEqual(['pid-sd-jwt-vc', 'literal-id']);
    expect(() => resolveConfigurations(['ICS-02.MD'], ics)).toThrow(/ICS-02.MD/);
  });

  it('uses a tx_code unless the Provider declares offers without one only', () => {
    expect(usesTxCode(ics)).toBe(true);
    expect(usesTxCode({ ...ics, items: { 'ICS-03.tx_code': 'without' } })).toBe(false);
  });
});

// Issue 27: the ICS of the Provider instance of each category.
describe('category ICS', () => {
  it('takes the top level for its category, and a categories entry over the top level items for another', async () => {
    const { categoryIcs, providerCategories } = await import('../src/issuer/ics');
    const ics: IssuerIcs = {
      profiles: ['P-PID', 'P-SD', 'P-PA'],
      items: { 'ICS-02.SD': 'pid-sd', 'ICS-07': 'Yes', 'ICS-14.T_skew': 'PT5S' },
      categories: { Q: { profiles: ['P-Q', 'P-SD', 'P-PA', 'P-NDB'], items: { 'ICS-02.SD': 'qeaa-sd', 'ICS-07': 'No' } } },
    };
    expect(providerCategories(ics)).toEqual(['PID', 'Q']);
    expect(categoryIcs(ics, 'PID')?.items['ICS-02.SD']).toBe('pid-sd');
    expect(categoryIcs(ics, 'Q')).toEqual({ profiles: ['P-Q', 'P-SD', 'P-PA', 'P-NDB'], items: { 'ICS-02.SD': 'qeaa-sd', 'ICS-07': 'No', 'ICS-14.T_skew': 'PT5S' } });
    expect(categoryIcs(ics, 'E')).toBeUndefined();
    expect(resolveConfigurations(['ICS-02.SD'], categoryIcs(ics, 'Q') as IssuerIcs)).toEqual(['qeaa-sd']);
  });
});

// Issue 27: POLICY (ICS-18) for an unobtainable WIA or KA status, and POLICY (ICS-07) for revocation chaining.
describe('POLICY of an Attestation Provider', () => {
  const expect18 = { codes: ['POLICY' as const], policy: 'ICS-18' as const, text: '' };
  const expect07 = { codes: ['POLICY' as const], policy: 'ICS-07' as const, text: '' };

  it('gives REJ for reject, ISS for accept, and REJ for a PID Provider whatever it declares', async () => {
    const { unobtainableStatusPolicy } = await import('../src/issuer/trust');
    expect(unobtainableStatusPolicy(expect18, { profiles: ['P-Q'], items: { 'ICS-18': 'reject' } }).expect.codes).toEqual(['REJ']);
    expect(unobtainableStatusPolicy(expect18, { profiles: ['P-E'], items: { 'ICS-18': 'accept, with a warning' } }).expect.codes).toEqual(['ISS']);
    expect(unobtainableStatusPolicy(expect18, { profiles: ['P-PID'], items: { 'ICS-18': 'accept' } }).expect.codes).toEqual(['REJ']);
    expect(() => unobtainableStatusPolicy(expect18, { profiles: ['P-PB'], items: {} })).toThrow(/declared policy/);
  });

  it('gives REVOKED(T_chain) for a Provider that chains and UNCHANGED for one that does not', async () => {
    const { chainingPolicy } = await import('../src/issuer/trust');
    expect(chainingPolicy(expect07, { profiles: ['P-Q', 'P-CHAIN'], items: { 'ICS-07': 'Yes', 'ICS-07.T_chain': 'PT7M' } })?.expect.codes).toEqual(['REVOKED(T_chain)']);
    expect(chainingPolicy(expect07, { profiles: ['P-E'], items: { 'ICS-07': 'No' } })?.expect.codes).toEqual(['UNCHANGED']);
    expect(chainingPolicy({ codes: ['UNCHANGED'], text: '' }, { profiles: [], items: {} })).toBeUndefined();
  });
});
