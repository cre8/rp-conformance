// PP_WS_SM_Unlinkability (issue 26; issuer catalogue section 5.1.3): what makes two credentials of the Provider linkable.
// `_001` and `_002` compare 20 issuances to `CW-1` and `CW-2`, `_003` and `_004` batches, `_005` one credential with the
// WIA and KA it was issued for. Each runs in `SD` and `MD`, in `PA` (`AC` follows with the authorization code flow).
import { defineIssuerTestCase, type FormatVariant, type IssuerInspectionCheck, type IssuerStepDefinition, issuerProfiles, relevancy } from '@eudi-pcaf/core';
import { inspected, inspectStep, unitIssuance } from '../../inspection';
import { FORMAT_NAMES, pidProfile, preconditions, technologyOf } from '../../wording';

const FORMATS: FormatVariant[] = ['SD', 'MD'];
/** Issuances of `_001` and `_002`. */
const ISSUANCES = 20;
/** Proofs per batch of `_003` and `_004`: the batch size of `default_configuration_PP_1`, at least 2 (ICS-08). */
const BATCH = 2;
const range = (n: number, from = 1) => Array.from({ length: n }, (_, i) => from + i);
const twoUnits = 'Wallet Unit `CW-2` of `WP-A` (section 3.4).';

const twenty = (format: FormatVariant): IssuerStepDefinition[] => range(ISSUANCES).map((n) => unitIssuance(format, n % 2 ? 'CW-1' : 'CW-2', { why: `issuance ${n} of ${ISSUANCES}` }));

const definition = (
  id: string,
  format: FormatVariant,
  spec: { objective: string; references: string[]; steps: IssuerStepDefinition[]; checks: IssuerInspectionCheck[]; what: string; extraProfiles?: ('P-REV' | 'P-BATCH')[]; extraPreconditions?: string[]; optional?: boolean; comments?: string[] },
) =>
  defineIssuerTestCase({
    id,
    variants: [format, 'PA'],
    objective: spec.objective,
    references: spec.references,
    profile: [...pidProfile(format, 'PA'), ...(spec.extraProfiles ?? []).map((p) => issuerProfiles[p])],
    relevancy: spec.optional ? relevancy.specificOptional : relevancy.specificRequired,
    technology: technologyOf(format),
    preconditions: [...preconditions.base, ...(spec.extraPreconditions ?? [])],
    steps: [...spec.steps, inspectStep(range(spec.steps.length), `The harness compares the credentials of steps 1 to ${spec.steps.length}.`, inspected(spec.checks, spec.what))],
    comments: ['Execute this test case once for each format the Provider issues and each grant it declares in its ICS (ICS-02, ICS-03).', ...(spec.comments ?? [])],
  });

const unlinkability001 = (format: FormatVariant) =>
  definition('PP_WS_SM_Unlinkability_001', format, {
    objective: `Verify that across ${ISSUANCES} issuances of the ${FORMAT_NAMES[format]} PID to \`CW-1\` and \`CW-2\` no salt, digest, status index, device key or signature value repeats.`,
    references: ['[ARF] Annex 2, ISSU_35'],
    steps: twenty(format),
    checks: ['unique-salts', 'unique-digests', 'unique-status-index', 'unique-device-key', 'unique-signature'],
    what: 'No value that a Relying Party sees in a presentation links two of the credentials.',
    extraPreconditions: [twoUnits],
  });

const unlinkability002 = (format: FormatVariant) =>
  definition('PP_WS_SM_Unlinkability_002', format, {
    objective: `Verify that the Provider assigns the status indices of the ${FORMAT_NAMES[format]} PID neither sequentially nor in another predictable order.`,
    references: ['[ARF] Annex 2, VCR_17', '[HAIP] section 6.1'],
    steps: twenty(format),
    checks: ['status-index-order'],
    what: `The ${ISSUANCES} indices, in issuance order, show no monotonic or arithmetic run.`,
    extraProfiles: ['P-REV'],
    extraPreconditions: [twoUnits],
    comments: ['OIDF `batch-issuance` covers this objective partly (issuer catalogue section 7).'],
  });

const batchIssuance = (format: FormatVariant, unit: 'CW-1' | 'CW-2') => unitIssuance(format, unit, { batchSize: BATCH });

const unlinkability003 = (format: FormatVariant) =>
  definition('PP_WS_SM_Unlinkability_003', format, {
    objective: `Verify that the timestamps of the ${FORMAT_NAMES[format]} PID (${format === 'SD' ? '`iat`, `nbf`, `exp`' : 'MSO `signed`, `validFrom`, `validUntil`'}) do not reveal batch membership: two batches issued to \`CW-1\` and \`CW-2\` within the declared precision share them.`,
    references: ['[ARF] Annex 2, ISSU_36'],
    steps: [batchIssuance(format, 'CW-1'), batchIssuance(format, 'CW-2')],
    checks: ['batch-timestamps'],
    what: 'At the timestamp precision the Provider declares (ICS-16), the timestamps of both batches are equal.',
    extraProfiles: ['P-BATCH'],
    extraPreconditions: [twoUnits, `The Provider issues in batches (ICS-08, \`P-BATCH\`) of at least ${BATCH} and declares its timestamp precision (ICS-16).`],
    comments: ['OIDF `batch-issuance` covers this objective partly (issuer catalogue section 7).', 'Batches received in different precision windows are compared only within their window.'],
  });

const unlinkability004 = (format: FormatVariant) =>
  definition('PP_WS_SM_Unlinkability_004', format, {
    objective: `Verify that the ${FORMAT_NAMES[format]} credentials of one batch are spread over the status list, not on adjacent indices.`,
    references: ['[ARF] Annex 2, VCR_17', '[ARF] Annex 2, ISSU_36'],
    steps: [batchIssuance(format, 'CW-1')],
    checks: ['batch-spread'],
    what: 'No two credentials of the batch are on adjacent indices.',
    extraProfiles: ['P-BATCH', 'P-REV'],
    extraPreconditions: [`The Provider issues in batches (ICS-08, \`P-BATCH\`) of at least ${BATCH}.`],
    optional: true,
    comments: ['OIDF `batch-issuance` covers this objective partly (issuer catalogue section 7).'],
  });

const unlinkability005 = (format: FormatVariant) =>
  definition('PP_WS_SM_Unlinkability_005', format, {
    objective: `Verify that the ${FORMAT_NAMES[format]} PID contains no identifier of the Wallet Instance, its WIA or its KA.`,
    references: ['[ARF] Annex 2, WUA_08', '[ARF] Annex 2, ISSU_35b'],
    steps: [unitIssuance(format)],
    checks: ['no-wallet-identifier'],
    what: 'The device key the KA attests binds the credential; nothing else of the WIA or KA appears in it.',
  });

export const definitions = [
  ...FORMATS.map(unlinkability001),
  ...FORMATS.map(unlinkability002),
  ...FORMATS.map(unlinkability003),
  ...FORMATS.map(unlinkability004),
  ...FORMATS.map(unlinkability005),
];
