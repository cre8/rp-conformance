// Issue 27: the objectives specific to Attestation Providers, numbered from 100 (issuer catalogue section 5.4):
// `AP_WS_MS_Metadata_100` to `_103`, `AP_WS_SM_KeyAttestation_100` to `_103`, `AP_WS_SM_Revocation_100` to `_103` and
// `AP_WS_DM_Rulebook_100` to `_102`. One definition per test case and variant; every test case runs in the categories
// its `Var` column allows, `Q`, `PB` and `E` unless it names some. The attestation is FCAF `default_credential_A`; a
// configuration that is not device-bound is named in the ICS under `ICS-04.NDB.SD` (ICS-04, `P-NDB`), and the
// configuration whose embedded disclosure policy `AP_WS_SM_Revocation_102` changes under `ICS-19.EDP.SD` (ICS-19, `P-EDP`).
import {
  type AttestationCategory,
  ATTESTATION_CATEGORIES,
  CATEGORY_PROFILES,
  defineIssuerTestCase,
  type FormatVariant,
  type IssuanceAction,
  type IssuerExpectation,
  type IssuerFaultId,
  type IssuerProfile,
  type IssuerStepDefinition,
  type IssuerTestCaseDefinition,
  issuerFaultInfo,
  issuerProfiles,
  type Relevancy,
  relevancy,
} from '@eudi-pcaf/core';
import { definitions as clientAttestation } from '../pid_provider/SecurityMechanisms/ClientAttestation';
import { conf } from '../pid_provider/MessageStructure/conf';
import { revokedWithin } from '../inspection';
import { FORMAT_NAMES, issuance, technologyOf } from '../wording';
import { apIdOf, CATEGORY_WORDING, reword } from './variants';

const CONTROL = 'AP_WS_IA_MainInteraction_001';
/** The configuration of the attestation that is not device-bound (ICS-04, `P-NDB`); SD-JWT VC, since an mdoc always is. */
export const NDB_CONFIGURATION = 'ICS-04.NDB.SD';
/**
 * The configuration `AP_WS_SM_Revocation_102` issues from and changes the embedded disclosure policy of (ICS-19,
 * `P-EDP`): one no other test case issues from, since EDP_11 revokes every attestation issued under the old policy.
 */
export const EDP_CONFIGURATION = 'ICS-19.EDP.SD';

/** Preconditions of every `AP_*` test case (catalogue sections 3.3 to 3.5, for an Attestation Provider). */
export const apPreconditions = [
  'The Provider is enrolled by the Test Registrar (issuer catalogue section 3.3) as the entity of its category: its credential signer under `QP-T` (a granted qualified EAA service on `TL-QEAA`), `PB-T` (on `TL-PUB`) or `EP-T` (under the rulebook anchor `CA-EP-T`), its status list signer under the revocation anchor of that entity, its access and registration certificates.',
  'The Provider is configured as `default_configuration_PP_1` (section 3.5) with FCAF `default_credential_A` as its attestation, and trusts `TL-WP` for Wallet Providers.',
  'Wallet Unit `CW-1` of `WP-A` (section 3.4): a valid WIA and a valid KA with `iso_18045_high`, neither revoked.',
  'The adapter can create an offer for `SUBJ-1` (ICS-17).',
];
const ufPreconditions = [...apPreconditions, `The positive control \`${CONTROL}\` passed in the same variant.`];

const ISS_TEXT = (format: FormatVariant) =>
  `The Provider issues the attestation (HTTP 200) in ${FORMAT_NAMES[format]} format. It passes format, \`issuer-trust\` to the entity of the Provider's category, \`issuer-signature\`, \`disclosures\`, \`validity\`, \`holder-binding\` (bound to a proof key the KA attests) and \`status-reference\`, and the Status List Token it references passes the status list checks.`;

const issAp = (format: FormatVariant): IssuerExpectation => ({ codes: ['ISS'], text: ISS_TEXT(format) });

/** `CONF` on an issuance step: `ISS`, and the named output checks of the reference validator. */
const confIssued = (format: FormatVariant, checks: string[], what: string): IssuerExpectation => ({
  codes: ['CONF'],
  checks,
  text: `${ISS_TEXT(format)} ${what}`,
});

const scnI = (format: FormatVariant, configuration = `the attestation configuration in ${FORMAT_NAMES[format]} format`) =>
  `The adapter creates a credential offer for \`SUBJ-1\` and ${configuration}, pre-authorized code. \`CW-1\` runs \`SCN-I\`: token request with WIA, PoP and DPoP proof, nonce request, credential request`;

interface Options {
  number: string;
  layer: 'MS_Metadata' | 'SM_KeyAttestation' | 'SM_Revocation' | 'DM_Rulebook';
  objective: (category: AttestationCategory) => string;
  references: string[];
  profile?: IssuerProfile[];
  format?: FormatVariant;
  categories?: readonly AttestationCategory[];
  relevancy?: Relevancy;
  technology?: string[];
  steps: (category: AttestationCategory) => IssuerStepDefinition[];
  comments?: string[];
  preconditions?: string[];
}

/** One definition per category of an `AP_*` test case, in the format variant (and `PA`) when it names one. */
function apTestCase(options: Options): IssuerTestCaseDefinition[] {
  const id = `AP_WS_${options.layer}_${options.number}`;
  const uf = id.endsWith('_UF');
  return (options.categories ?? ATTESTATION_CATEGORIES).map((category) =>
    defineIssuerTestCase({
      id,
      variants: [...(options.format ? ([options.format, 'PA'] as const) : []), category],
      objective: options.objective(category),
      references: options.references,
      profile: [
        issuerProfiles[CATEGORY_PROFILES[category]],
        ...(options.format ? [issuerProfiles[`P-${options.format}`], issuerProfiles['P-PA']] : []),
        ...(options.profile ?? []).map((p) => issuerProfiles[p]),
      ],
      relevancy: options.relevancy ?? relevancy.specificRequired,
      technology: options.technology ?? (options.format ? technologyOf(options.format) : ['OpenID4VCI', 'HAIP']),
      preconditions: [...(uf ? ufPreconditions : apPreconditions), ...(options.preconditions ?? [])],
      ...(uf ? { control: CONTROL } : {}),
      steps: options.steps(category),
      ...(options.comments ? { comments: options.comments } : {}),
    }),
  );
}

const provider = (category: AttestationCategory) => `the ${CATEGORY_WORDING[category].provider}`;

const SCN_M =
  'The Conformance Wallet runs `SCN-M`: it takes the Credential Issuer identifier from an offer the adapter creates, fetches the Credential Issuer metadata as JSON and with `Accept: application/jwt`, and the metadata of every Authorization Server it names.';
const metadataStep = (checks: Parameters<typeof conf>[0]): IssuerStepDefinition => ({ text: SCN_M, run: { kind: 'metadata' }, expect: conf(checks) });

// ------------------------------------------------------------------------------------------- AP_WS_MS_Metadata

const metadata = [
  ...apTestCase({
    number: '100',
    layer: 'MS_Metadata',
    objective: (c) => `Verify that a configuration of ${provider(c)} that is not device-bound states that it needs no KA: it declares no cryptographic binding and offers no proof type that requires one.`,
    references: ['[ARF] Annex 2, WUA_10a', '[OpenID4VCI] section 12.2.4'],
    profile: ['P-NDB'],
    steps: () => [
      metadataStep({
        'metadata-no-key-binding':
          'at least one configuration has no `cryptographic_binding_methods_supported`, and none of them lists `proof_types_supported` or `key_attestations_required`',
      }),
    ],
  }),
  ...apTestCase({
    number: '101',
    layer: 'MS_Metadata',
    objective: (c) => `Verify that every device-bound configuration of ${provider(c)} states the \`key_storage\` and \`user_authentication\` levels it requires of the KA.`,
    references: ['[ARF] Annex 2, ISSU_27d', '[OpenID4VCI] Appendix D and section 12.2.4'],
    profile: ['P-DB'],
    steps: () => [
      metadataStep({
        'metadata-key-attestation-levels':
          'every configuration with `cryptographic_binding_methods_supported` lists `proof_types_supported`, and each proof type carries `key_attestations_required` with a non-empty list of levels in `key_storage` and in `user_authentication`',
      }),
    ],
  }),
  ...apTestCase({
    number: '102',
    layer: 'MS_Metadata',
    objective: (c) => `Verify that the embedded disclosure policy of each configuration of ${provider(c)} is included by value in its metadata.`,
    references: ['[ARF] Annex 2, EDP_09', '[ETSI TS 119 472-3]'],
    profile: ['P-EDP'],
    relevancy: relevancy.specificOptional,
    steps: () => [
      metadataStep({
        'metadata-disclosure-policy':
          'the configurations with an embedded disclosure policy carry it by value, as an object in `disclosure_policy`, `policy` or `credential_metadata.policy`, and none only by reference (`policy_uri`)',
      }),
    ],
    comments: ['No profile names the metadata member of an embedded disclosure policy yet; the check accepts `disclosure_policy`, `policy` or `credential_metadata.policy` of the configuration until one does.'],
  }),
  ...apTestCase({
    number: '103',
    layer: 'MS_Metadata',
    objective: (c) => `Verify that every configuration of ${provider(c)} is in SD-JWT VC or mdoc format.`,
    references: ['[ARF] Annex 2, ARB_01', '[OpenID4VCI] Appendix A'],
    categories: ['Q', 'PB'],
    steps: () => [metadataStep({ 'metadata-attestation-formats': 'the `format` of every configuration in `credential_configurations_supported` is `dc+sd-jwt` or `mso_mdoc`' })],
  }),
];

// --------------------------------------------------------------------------------------- AP_WS_SM_KeyAttestation

const faultStep = (format: FormatVariant, fault: IssuerFaultId, expect: IssuerExpectation, action: Partial<IssuanceAction> = {}): IssuerStepDefinition => ({
  text: `${scnI(format)} with an \`openid4vci-proof+jwt\` that carries the KA, all valid except that ${issuerFaultInfo(fault).text}.`,
  run: issuance(format, 'PA', { ...action, faults: [fault] }),
  expect,
});

const invalidProof: IssuerExpectation = {
  codes: ['REJ:invalid_proof'],
  text: 'The Provider issues no credential for the request and answers with HTTP 4xx and an OAuth or OpenID4VCI error object with `error` `invalid_proof`; never HTTP 5xx.',
};

/** The CA faults of `PP_WS_SM_ClientAttestation_002_UF` to `_012_UF` (SD+PA), as `AP_WS_SM_KeyAttestation_103` reuses them. */
function clientAttestationStimuli(category: AttestationCategory): IssuerStepDefinition[] {
  const ids = Array.from({ length: 11 }, (_, i) => `PP_WS_SM_ClientAttestation_${String(i + 2).padStart(3, '0')}_UF`);
  return ids.flatMap((id) => {
    const definition = clientAttestation.find((d) => d.id === id && d.variants?.join('+') === 'SD+PA');
    if (!definition) throw new Error(`${id} [SD+PA] has no definition`);
    return definition.steps.map((step) => ({
      ...step,
      text: `${reword(step.text, CATEGORY_WORDING[category]).replace('the attestation configuration in SD-JWT VC format', 'the attestation configuration that is not device-bound (`ICS-04.NDB.SD`)')} (stimulus of \`${apIdOf(id)}\`)`,
      ...(step.run?.kind === 'issuance' ? { run: { ...step.run, configurations: [NDB_CONFIGURATION] } } : {}),
      expect: { ...step.expect, text: reword(step.expect.text, CATEGORY_WORDING[category]) },
    }));
  });
}

const ndbIssuance = (why: string, action: Partial<IssuanceAction> = {}): IssuerStepDefinition => ({
  text: `${scnI('SD', 'the attestation configuration that is not device-bound (`ICS-04.NDB.SD`)')} ${why}.`,
  run: issuance('SD', 'PA', { configurations: [NDB_CONFIGURATION], ...action }),
  expect: {
    codes: ['ISS'],
    text: 'The Provider issues the attestation (HTTP 200) in SD-JWT VC format, bound to no key (no `cnf`), as the configuration declares. It passes format, `issuer-trust` to the entity of its category, `issuer-signature`, `disclosures`, `validity`, `holder-binding` (no binding) and `status-reference`, and the status list checks.',
  },
});

const LEVEL_FAULTS = ['ka.key-storage-moderate', 'ka.key-storage-basic', 'ka.user-authentication-moderate', 'ka.user-authentication-basic'] as const;

const keyAttestation = [
  ...apTestCase({
    number: '100',
    layer: 'SM_KeyAttestation',
    format: 'SD',
    objective: (c) => `Verify that ${provider(c)} binds a device-bound attestation to a key the KA of \`CW-1\` attests (as \`AP_WS_SM_KeyAttestation_001\`).`,
    references: ['[ARF] Annex 2, ISSU_27, ISSU_30, WUA_09a', '[OpenID4VCI] Appendix D and F.1'],
    profile: ['P-DB'],
    steps: () => [{ text: `${scnI('SD')} with an \`openid4vci-proof+jwt\` that carries the KA, all valid.`, run: issuance('SD', 'PA'), expect: { ...issAp('SD'), text: `${ISS_TEXT('SD')} \`cnf.jwk\` is the proof key, and the KA lists it in \`attested_keys\`.` } }],
  }),
  ...apTestCase({
    number: '101_UF',
    layer: 'SM_KeyAttestation',
    format: 'SD',
    objective: (c) => `Verify that ${provider(c)} rejects a KA whose \`key_storage\` or \`user_authentication\` is one level below what the configuration's metadata requires (\`key_attestations_required\`, declared in ICS-04).`,
    references: ['[ARF] Annex 2, ISSU_27d, WUA_05a', '[OpenID4VCI] Appendix D'],
    profile: ['P-DB'],
    steps: () => LEVEL_FAULTS.map((fault) => faultStep('SD', fault, invalidProof)),
    comments: [
      'A level the Provider accepts (ICS-04.key_storage, ICS-04.user_authentication) is not below what it requires: the step with that level is NOT APPLICABLE, and the steps with the levels below the lowest accepted one decide the verdict.',
    ],
  }),
  ...apTestCase({
    number: '102',
    layer: 'SM_KeyAttestation',
    format: 'SD',
    objective: (c) => `Verify that ${provider(c)} issues an attestation that is not device-bound with the WIA only, and that a KA sent anyway does not change the result.`,
    references: ['[ARF] Annex 2, WUA_10a, ISSU_30a', '[OpenID4VCI] section 8.2'],
    profile: ['P-NDB'],
    steps: () => [
      ndbIssuance('without key proof and without KA', { proof: 'never' }),
      ndbIssuance('with an `openid4vci-proof+jwt` that carries the KA anyway', { proof: 'always' }),
    ],
  }),
  ...apTestCase({
    number: '103',
    layer: 'SM_KeyAttestation',
    format: 'SD',
    objective: (c) => `Verify that ${provider(c)} still requires a valid, non-revoked WIA of a Wallet Provider on \`TL-WP\` for an attestation that is not device-bound: the stimuli of \`AP_WS_SM_ClientAttestation_002_UF\` to \`_012_UF\` are rejected.`,
    references: ['[ARF] Annex 2, ISSU_30a, WUA_25', '[Attestation-Based Client Auth]'],
    profile: ['P-NDB'],
    technology: ['OpenID4VCI', 'SD-JWT VC', 'Attestation-Based Client Authentication'],
    steps: (c) => [ndbIssuance('without key proof and without KA, all valid (the valid half of this test case)', { proof: 'never' }), ...clientAttestationStimuli(c)],
    comments: [
      'The stimuli of `AP_WS_SM_ClientAttestation_012_UF` (revoked WIA) run last, since they revoke the Wallet Instance of `CW-1` for the rest of the test case.',
      'The stimuli concern the WIA and its PoP at the token endpoint, before any credential request; where the Provider\'s metadata lists proof types for the configuration, the Conformance Wallet sends a key proof as the metadata asks.',
    ],
  }),
];

// ------------------------------------------------------------------------------------------ AP_WS_SM_Revocation

const walletEvent = (text: string, run: Extract<IssuerStepDefinition['run'], { kind: 'wallet-event' }>): IssuerStepDefinition => ({
  text,
  run: run as IssuerStepDefinition['run'],
  expect: { codes: ['INFO'], text: 'What the Test Wallet Provider served, and when, is recorded.' },
});

const validIssuance = (format: FormatVariant, why = ''): IssuerStepDefinition => ({
  text: `${scnI(format)} with an \`openid4vci-proof+jwt\` that carries the KA, all valid${why}.`,
  run: issuance(format, 'PA'),
  expect: issAp(format),
});

const maintenanceConf = (format: FormatVariant, of: 'WIA' | 'KA'): IssuerExpectation =>
  confIssued(format, ['maintenance-period'], `Its \`exp\` is no later than the \`exp\` of the ${of === 'WIA' ? '`client_status`' : '`key_storage_status`'} claim of the ${of} it was issued for (\`maintenance-period\`).`);

const LONG_RUNNING = 'Long running: the steps that wait run after the other test cases, in parallel (issuer harness design section 6.3).';

const revocation = [
  ...(['SD', 'MD'] as const).flatMap((format) =>
    apTestCase({
      number: '100',
      layer: 'SM_Revocation',
      format,
      objective: (c) => `Verify that ${provider(c)} follows the revocation chaining policy it declares (ICS-07): when the Test Wallet Provider revokes the Wallet Instance of \`CW-1\`, the attestation in ${FORMAT_NAMES[format]} format issued to it is revoked within \`T_chain\` if the Provider chains, and stays valid if it does not.`,
      references: ['[ARF] Annex 2, WURevocation_19, VCR_07d', '[TS3] section 2.5'],
      profile: ['P-REV'],
      relevancy: relevancy.specificOptional,
      technology: [...technologyOf(format), 'Token Status List'],
      preconditions: ['The Provider declares in ICS-07 whether it chains revocation (WURevocation_19), and `T_chain` when it does.'],
      steps: () => [
        walletEvent(
          "The Test Wallet Provider serves `SL-WP-A` for this test case under a URL of its own, every entry valid, and the WIA of `CW-1` in the following steps refers to it with the unit's Wallet Instance entry.",
          { kind: 'wallet-event', event: 'status-list', walletUnit: 'CW-1', statusList: { id: 'SL-WP-A', faults: [], of: 'wia' } },
        ),
        validIssuance(format, ' (the WIA refers to the list of step 1)'),
        walletEvent(
          "The Test Wallet Provider revokes the Wallet Instance of `CW-1`: it serves a new version of the list of step 1, under the same URL, with the unit's Wallet Instance entry `0x01` (INVALID) and every other entry unchanged.",
          { kind: 'wallet-event', event: 'revoke-instance', walletUnit: 'CW-1' },
        ),
        {
          text: 'The harness polls the status list of the credential of step 2 anonymously every `min(T_chain / 20, 30 s)` until `T_chain` (ICS-07; for a Provider that does not chain, the `T_chain` of the suite\'s default, the declared value of the ICS) after the revocation of the Wallet Instance, keeping every version.',
          run: { kind: 'observe-status', ofSteps: [2], t: 'T_chain' },
          expect: {
            codes: ['POLICY'],
            policy: 'ICS-07',
            text: 'The outcome follows ICS-07: a Provider that chains shows the entry as `0x01` (INVALID) no later than `T_chain` after the revocation, and in every later version polled (`REVOKED(T_chain)`); one that does not chain shows it as `0x00` (VALID) in every version polled (`UNCHANGED`).',
          },
        },
      ],
      comments: [LONG_RUNNING, 'The catalogue names `P-CHAIN` in the `Var` column, but the objective covers both answers of ICS-07 (`POLICY`), so the test case applies to every Attestation Provider.'],
    }),
  ),
  ...apTestCase({
    number: '101',
    layer: 'SM_Revocation',
    format: 'SD',
    objective: (c) => `Verify that ${provider(c)}, which chains revocation, issues the attestation with an expiry no later than the end of the revocation maintenance period of the WIA and of the KA, when that period ends in 31 days.`,
    references: ['[ARF] Annex 2, ISSU_12d', '[TS3] section 2.4.1', '[TS3] section 2.4.2'],
    profile: ['P-CHAIN'],
    steps: () => [faultStep('SD', 'wia.maintenance-31-days', maintenanceConf('SD', 'WIA')), faultStep('SD', 'ka.maintenance-31-days', maintenanceConf('SD', 'KA'))],
    comments: ['Each step shortens the maintenance period of one attestation; the other keeps its period of more than a year, so only the shortened one bounds the expiry.', 'The stimulus is 31 days, the remaining period TS3 section 2.4.2 guarantees a Wallet Unit can always present; it was 30 days before the spec review of 2026-11-20 (as PP_WS_SM_ClientAttestation_015 and PP_WS_SM_KeyAttestation_011).'],
  }),
  ...apTestCase({
    number: '102',
    layer: 'SM_Revocation',
    format: 'SD',
    objective: (c) => `Verify that ${provider(c)} revokes the attestations issued under an embedded disclosure policy within \`T_rev\` when that policy changes.`,
    references: ['[ARF] Annex 2, EDP_11', '[TokenStatusList] section 7.1'],
    profile: ['P-EDP', 'P-REV'],
    technology: [...technologyOf('SD'), 'Token Status List'],
    steps: () => [
      {
        text: `${scnI('SD', 'the attestation configuration with an embedded disclosure policy that only this test case issues from (`ICS-19.EDP.SD`)')} with an \`openid4vci-proof+jwt\` that carries the KA, all valid.`,
        run: issuance('SD', 'PA', { configurations: [EDP_CONFIGURATION] }),
        expect: issAp('SD'),
      },
      {
        text: 'The adapter changes the embedded disclosure policy of the configuration of step 1 (`changeDisclosurePolicy`) and reports when the Provider has done so (`OBS-ADM`).',
        run: { kind: 'issuer-event', event: 'change-disclosure-policy', ofStep: 1 },
        expect: { codes: ['INFO'], text: 'The time the adapter reports is recorded; the window of the next step counts from it.' },
      },
      revokedWithin([1], 'T_rev', 'the reported change of the policy'),
    ],
    comments: [
      LONG_RUNNING,
      'The configuration of `ICS-19.EDP.SD` is one no other test case issues from: a Provider that meets EDP_11 revokes every attestation issued under the old policy, which would revoke the attestations of test cases running at the same time.',
    ],
  }),
  ...(['SD', 'MD'] as const).flatMap((format) =>
    apTestCase({
      number: '103',
      layer: 'SM_Revocation',
      format,
      categories: ['E'],
      objective: () => `Verify that the non-qualified EAA Provider follows the revocation method the rulebook of \`default_credential_A\` prescribes for the attestation in ${FORMAT_NAMES[format]} format: a Token Status List reference, or a validity period of at most 24 hours.`,
      references: ['[ARF] Annex 2, VCR_01, VCR_02', '[TokenStatusList] section 6'],
      technology: [...technologyOf(format), 'Token Status List'],
      steps: () => [{ ...validIssuance(format), expect: confIssued(format, ['revocation-method'], 'It references a Token Status List, or its validity period is at most 24 hours (`revocation-method`).') }],
      comments: ['The suite reads the rulebook of `default_credential_A` (FCAF defaults) as prescribing the methods of VCR_01: a Token Status List for an attestation valid for more than 24 hours.'],
    }),
  ),
];

// -------------------------------------------------------------------------------------------- AP_WS_DM_Rulebook

const rulebook = [
  ...(['SD', 'MD'] as const).flatMap((format) =>
    apTestCase({
      number: '100',
      layer: 'DM_Rulebook',
      format,
      objective: (c) => `Verify that the ${CATEGORY_WORDING[c].attestation} in ${FORMAT_NAMES[format]} format conforms to its rulebook, FCAF \`default_credential_A\`: type identifier, mandatory attributes and their encodings, and the values of \`SUBJ-1\`.`,
      references: ['[ARF] Annex 2, ISSU_25', '[Issuer catalogue] section 5.4, FCAF `default_credential_A`'],
      steps: () => [
        {
          ...validIssuance(format),
          expect: confIssued(
            format,
            ['attestation-type', 'attestation-attributes', 'attestation-values'],
            `${format === 'SD' ? '`vct` is `urn:rp-conformance:credential_a:1`' : 'docType and namespace are `test.rp-conformance.credential_a.1`, no element outside it'} (\`attestation-type\`); \`attribute_A\` is a positive number, \`attribute_B\` a non-empty Latin-1 string of at most 64 characters, \`attribute_C\` a valid date in the past${format === 'MD' ? ' as `full-date`' : ''} (\`attestation-attributes\`); every attribute has the value of \`SUBJ-1\` (\`attestation-values\`).`,
          ),
        },
      ],
    }),
  ),
  ...apTestCase({
    number: '101',
    layer: 'DM_Rulebook',
    format: 'SD',
    objective: (c) => `Verify that the selective disclosure of the ${CATEGORY_WORDING[c].attestation} in SD-JWT VC format follows the rulebook of \`default_credential_A\`: each attribute can be disclosed on its own, and no claim SD-JWT VC forbids is selectively disclosable.`,
    references: ['[ARF] Annex 2, ARB_30', '[SD-JWT VC] section 3.2.2.2'],
    steps: () => [
      {
        ...validIssuance('SD'),
        expect: confIssued('SD', ['attestation-disclosure'], '`attribute_A`, `attribute_B` and `attribute_C` are each in a disclosure of their own, none in the clear, and `iss`, `nbf`, `exp`, `cnf`, `vct`, `status` and `iat` are not selectively disclosable (`attestation-disclosure`).'),
      },
    ],
    comments: ['The FCAF defaults name no disclosure rule per attribute; the suite reads the rulebook as allowing each attribute to be disclosed on its own (MAY), which the Provider meets by making each one selectively disclosable.'],
  }),
  ...(['SD', 'MD'] as const).flatMap((format) =>
    apTestCase({
      number: '102',
      layer: 'DM_Rulebook',
      format,
      categories: ['Q'],
      objective: () => `Verify that the QEAA in ${FORMAT_NAMES[format]} format is signed under a granted qualified EAA service (\`EAA/Q\`) in the Trusted List reached via the LOTL (\`TL-QEAA\`).`,
      references: ['[ARF] Annex 2, ISSU_08, ISSU_70, OIA_13', '[ETSI TS 119 612] section 5.5'],
      steps: () => [
        {
          ...validIssuance(format),
          expect: confIssued(format, ['qualified-service'], 'The signing certificate chains to the anchor of a service of type `http://uri.etsi.org/TrstSvc/Svctype/EAA/Q` with status granted, of `QP-T` in `TL-QEAA`, which the LOTL points to (`qualified-service`).'),
        },
      ],
      comments: ['The qualified electronic seal itself (a QSCD-held key, ETSI EN 319 412-3) is a property of the signing key the test book covers (`PP_TB_002`); the protocol shows the qualified service the signer chains to.'],
    }),
  ),
];

export const definitions: IssuerTestCaseDefinition[] = [...metadata, ...keyAttestation, ...revocation, ...rulebook];
