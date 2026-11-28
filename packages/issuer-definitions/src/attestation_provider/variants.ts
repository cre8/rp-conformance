// Issue 27: the category variants `Q`, `PB` and `E` of the `PP_*` test cases (issuer catalogue sections 2.1, 2.3 and
// 5.4): "Every `PP_*` objective not marked **PID only** applies to `AP_*` with the same number and the category variant
// `Q`, `PB` or `E`." The `AP_*` definitions are derived from the PID Provider definitions, which stay the source: the
// same steps, faults and expected results, with the Provider enrolled as `QP-T`, `PB-T` or `EP-T` and FCAF
// `default_credential_A` as what it issues. The configuration references (`ICS-02.SD`, ...) resolve against the ICS of
// the Provider instance of the category, so the steps need no change; the texts are reworded for the category.
import {
  type AttestationCategory,
  ATTESTATION_CATEGORIES,
  CATEGORY_PROFILES,
  type IssuerExpectation,
  type IssuerStepDefinition,
  type IssuerTestCaseDefinition,
  defineIssuerTestCase,
  issuerProfiles,
} from '@eudi-pcaf/core';

/**
 * The objectives the catalogue marks **PID only** (sections 5.1.1 to 5.1.4): an Attestation Provider has its own in
 * `AP_WS_*` from 100, or the objective is about the PID itself. `PP_WS_DM_*` is the PID Rulebook (section 5.1.4: "All
 * **PID only**").
 */
export const PID_ONLY = new Set([
  'PP_WS_MS_Metadata_006',
  'PP_WS_IA_MainInteraction_003',
  'PP_WS_SM_ClientAttestation_015',
  'PP_WS_SM_ClientAttestation_016_UF',
  'PP_WS_SM_KeyAttestation_002_UF',
  'PP_WS_SM_KeyAttestation_010_UF',
  'PP_WS_SM_KeyAttestation_011',
  'PP_WS_SM_Revocation_006',
  'PP_WS_SM_Revocation_007',
]);

export const isPidOnly = (id: string) => PID_ONLY.has(id) || id.startsWith('PP_WS_DM_');

/**
 * The test cases whose status list stimuli make the WIA or KA status unobtainable: a PID Provider rejects (decision
 * 2), an Attestation Provider follows the policy it declares in ICS-18 (`POLICY`).
 */
const STATUS_POLICY = new Set(['PP_WS_SM_ClientAttestation_013_UF', 'PP_WS_SM_KeyAttestation_009_UF']);

interface Wording {
  provider: string;
  /** The enrolled entity and where its anchors are published. */
  where: string;
  entity: string;
  list: string;
  /** The kind of attestation. */
  attestation: string;
}

/** How a text names the Provider of each category. */
export const CATEGORY_WORDING: Record<AttestationCategory, Wording> = {
  Q: { provider: 'QEAA Provider', where: '`QP-T` with its granted qualified EAA service on `TL-QEAA`', entity: '`QP-T`', list: '`TL-QEAA`', attestation: 'QEAA' },
  PB: { provider: 'PuB-EAA Provider', where: '`PB-T` on `TL-PUB`', entity: '`PB-T`', list: '`TL-PUB`', attestation: 'PuB-EAA' },
  E: { provider: 'non-qualified EAA Provider', where: '`EP-T` under the anchor `CA-EP-T` that the rulebook of `default_credential_A` defines (`TA-EAA`)', entity: '`EP-T`', list: 'the rulebook anchors (`TA-EAA`)', attestation: 'non-qualified EAA' },
};

/** The wording of texts every variant of an `AP_*` test case shares (preconditions, comments). */
const NEUTRAL: Wording = {
  provider: 'Attestation Provider',
  where: 'the entity of its category (`QP-T` with a granted qualified EAA service on `TL-QEAA`, `PB-T` on `TL-PUB`, or `EP-T` under the rulebook anchor `CA-EP-T`)',
  entity: 'the entity of its category',
  list: 'the list of its category',
  attestation: 'attestation',
};

/** Rewords a text of a PID Provider test case for an Attestation Provider of a category. */
export function reword(text: string, w: Wording): string {
  return (
    text
      .replace('A PID Provider rejects (decision 2); an Attestation Provider follows its ICS-18 policy (`POLICY`).', 'An Attestation Provider follows the policy it declares in ICS-18 (`POLICY`): it rejects, or issues, as it declares.')
      .replaceAll('`PP-T` on `TL-PID`', w.where)
      .replaceAll('`PP-T`', w.entity)
      // `PP-A`'s issuance CA in `TL-PID` is a wrong anchor for a WIA or KA, whatever the Provider's category.
      .replace(/(?<!`PP-A`'s issuance CA in )`TL-PID`/g, w.list)
      .replaceAll('PID Rulebook', 'rulebook of `default_credential_A`')
      .replaceAll('`pid-values`', '`attestation-values`')
      .replace(/\bPID Providers\b/g, `${w.provider}s`)
      .replace(/\bPID Provider\b/g, w.provider)
      .replace(/\ba PID\b/g, 'an attestation')
      .replace(/\bPIDs\b/g, 'attestations')
      .replace(/\bPID\b/g, 'attestation')
      .replace(/`PP_(WS|RP|Inf)_/g, '`AP_$1_')
  );
}

const rewordExpectation = (expect: IssuerExpectation, w: Wording): IssuerExpectation => ({
  ...expect,
  text: reword(expect.text, w),
  ...(expect.checks ? { checks: expect.checks.map((c) => (c === 'pid-values' ? 'attestation-values' : c)) } : {}),
});

/** `POLICY` (ICS-18) in place of `REJ` on an issuance step whose WIA or KA status cannot be obtained. */
const STATUS_POLICY_EXPECTATION: IssuerExpectation = {
  codes: ['POLICY'],
  policy: 'ICS-18',
  text: 'The outcome follows the policy the Provider declares in ICS-18 for a WIA or KA whose status cannot be obtained: with `reject` it issues no credential and answers with HTTP 4xx and an OAuth or OpenID4VCI error object (never HTTP 5xx); with `accept` it issues the attestation and it passes every check of `ISS`.',
};

/** The `AP_*` ID of a `PP_*` ID. */
export const apIdOf = (id: string) => id.replace(/^PP_/, 'AP_');

/** The variant of a PID Provider definition for an Attestation Provider of a category. */
export function categoryVariant(definition: IssuerTestCaseDefinition, category: AttestationCategory): IssuerTestCaseDefinition {
  const w = CATEGORY_WORDING[category];
  const profile = definition.profile.some((c) => c.equals === 'P-PID')
    ? definition.profile.map((c) => (c.equals === 'P-PID' ? issuerProfiles[CATEGORY_PROFILES[category]] : c))
    : [issuerProfiles[CATEGORY_PROFILES[category]], ...definition.profile];
  const control = definition.control === undefined ? undefined : Array.isArray(definition.control) ? definition.control.map(apIdOf) : apIdOf(definition.control);
  const steps: IssuerStepDefinition[] = definition.steps.map((step) => ({
    ...step,
    text: reword(step.text, w),
    expect:
      STATUS_POLICY.has(definition.id) && step.run?.kind === 'issuance' && step.expect.codes.every((c) => c.startsWith('REJ'))
        ? STATUS_POLICY_EXPECTATION
        : rewordExpectation(step.expect, w),
  }));
  return defineIssuerTestCase({
    ...definition,
    id: apIdOf(definition.id),
    variants: [...(definition.variants ?? []), category],
    objective: STATUS_POLICY.has(definition.id)
      ? reword(definition.objective, w).replace(' issues no attestation ', ' follows the policy it declares in ICS-18 (it rejects, or issues, as declared) ')
      : reword(definition.objective, w),
    profile,
    preconditions: definition.preconditions.map((p) => reword(p, NEUTRAL)),
    ...(definition.comments ? { comments: definition.comments.map((c) => reword(c, NEUTRAL)) } : {}),
    ...(control !== undefined ? { control } : {}),
    steps,
  });
}

/** The `Q`, `PB` and `E` variants of every PID Provider definition the catalogue does not mark **PID only**. */
export function attestationVariants(definitions: IssuerTestCaseDefinition[]): IssuerTestCaseDefinition[] {
  const applicable = definitions.filter((d) => /^PP_(WS|RP|Inf)_/.test(d.id) && !isPidOnly(d.id));
  return ATTESTATION_CATEGORIES.flatMap((category) => applicable.map((d) => categoryVariant(d, category)));
}
