// PP_Inf_SM_TrustMechanisms (issue 26; issuer catalogue section 5.3, `SCN-T`): the Provider's use of the Wallet
// Provider LoTE `TL-WP`, and its signers under the anchors published for it. A `trust-list` step publishes a version
// of `TL-WP` with the changes of the catalogue and at most one of the RP harness's trust-list faults; the Provider
// refreshes, then `SCN-I` shows what it trusts. After each test case the harness publishes the default `TL-WP` again
// under a higher sequence number. Each runs in `SD` and `MD` and in both grants: the Provider checks the WIA at the
// token endpoint in `PA`, at PAR in `AC`.
import { defineIssuerTestCase, type FormatVariant, type GrantVariant, type IssuerExpectation, type IssuerStepDefinition, relevancy, type WalletUnit } from '@eudi-pcaf/core';
import { inspected, inspectStep, trustListStep, unitIssuance } from '../../inspection';
import { rejected } from '../../pid_provider/SecurityMechanisms/attestations';
import { FORMAT_NAMES, GRANT_NAMES, issuance, pidProfile, preconditions, technologyOf } from '../../wording';

const FORMATS: FormatVariant[] = ['SD', 'MD'];
const CONTROL = 'PP_WS_IA_MainInteraction_001';
const TRUST = 'The Provider trusts `TL-WP` for Wallet Providers through its scheme operator certificate only (catalogue section 3.2), and reads it again on `refreshTrust` or after `T_refresh` (ICS-15).';
const RESTORED = 'After the test case the harness publishes the default `TL-WP` (`WP-A`, `WP-B` granted, `WP-W` withdrawn) under a higher sequence number and the Provider refreshes again. Test cases with a `trust-list` step run one at a time.';

/** `SCN-I` of a Wallet Unit that the Provider must refuse at the token endpoint (`invalid_client`, decision 1). */
const refused = (format: FormatVariant, grant: GrantVariant, unit: WalletUnit, why: string): IssuerStepDefinition => ({
  text: `The adapter creates a credential offer for \`SUBJ-1\`, PID configuration in ${FORMAT_NAMES[format]} format, ${GRANT_NAMES[grant]}; \`${unit}\` runs \`SCN-I\` without mutation (${why}).`,
  run: issuance(format, grant, { walletUnit: unit }),
  expect: rejected('invalid_client'),
});

/** `PP_Inf_SM_TrustMechanisms_004_UF`: the issuance after a version of `TL-WP` whose seal fails, as ICS-15 declares. */
const afterBadSeal = (format: FormatVariant): IssuerExpectation => ({
  codes: ['POLICY'],
  policy: 'ICS-15',
  text: `As the Provider declares in ICS-15.invalid_version: \`keep\` (the previous \`TL-WP\` stays in force) gives \`ISS\` of the ${FORMAT_NAMES[format]} PID; \`discard\` (no list is used until a valid version arrives) gives \`REJ\`. Undeclared counts as \`keep\`.`,
});

const trust = (
  id: string,
  format: FormatVariant,
  grant: GrantVariant,
  spec: { objective: string; references: string[]; steps: IssuerStepDefinition[]; optional?: boolean; units?: string; comments?: string[] },
) => {
  const uf = id.endsWith('_UF');
  return defineIssuerTestCase({
    id,
    variants: [format, grant],
    objective: spec.objective,
    references: spec.references,
    profile: pidProfile(format, grant),
    relevancy: spec.optional ? relevancy.specificOptional : relevancy.specificRequired,
    technology: [...technologyOf(format), 'ETSI TS 119 602 LoTE'],
    preconditions: [...preconditions.base, TRUST, ...(spec.units ? [spec.units] : []), ...(uf ? [preconditions.control(CONTROL)] : [])],
    ...(uf ? { control: CONTROL } : {}),
    steps: spec.steps,
    comments: [RESTORED, ...(spec.comments ?? [])],
  });
};

export const definitions = FORMATS.flatMap((format) => (['PA', 'AC'] as GrantVariant[]).map((grant) => [
  trust('PP_Inf_SM_TrustMechanisms_001', format, grant, {
    objective: `Verify that the Provider reads the Wallet Provider anchors from the LoTE \`TL-WP\` per ETSI TS 119 602: after a refresh of an unchanged list it issues the ${FORMAT_NAMES[format]} PID to Wallet Units of both granted Wallet Providers.`,
    references: ['[ARF] Annex 2, ISSU_19, ISSU_19b, ISSU_28a', '[ETSI TS 119 602]'],
    units: 'Wallet Unit `CW-B` of `WP-B` (section 3.4).',
    steps: [trustListStep('the default entities, unchanged'), unitIssuance(format, 'CW-1', { grant, why: 'a Wallet Unit of `WP-A`' }), unitIssuance(format, 'CW-B', { grant, why: 'a Wallet Unit of `WP-B`' })],
  }),
  trust('PP_Inf_SM_TrustMechanisms_002_UF', format, grant, {
    objective: `Verify that a Wallet Provider removed from \`TL-WP\`, or whose issuance services are withdrawn, is no longer accepted after the refresh: \`CW-1\` of \`WP-A\` gets no ${FORMAT_NAMES[format]} PID.`,
    references: ['[ARF] Annex 2, ISSU_30a', '[ARF] Annex 2, WPNot_04'],
    steps: [
      trustListStep('`WP-A` removed', { remove: ['WP-A'] }),
      refused(format, grant, 'CW-1', '`WP-A` is no longer on `TL-WP`'),
      trustListStep('`WP-A` listed, its WIA and KA issuance services withdrawn (left out, as for `WP-W`; ETSI TS 119 602 Annex D has no status value for them)', { withdraw: ['WP-A'] }),
      refused(format, grant, 'CW-1', "`WP-A`'s issuance services are withdrawn"),
    ],
  }),
  trust('PP_Inf_SM_TrustMechanisms_003', format, grant, {
    objective: `Verify that a Wallet Provider added to \`TL-WP\` is accepted after the refresh: \`CW-C\` of \`WP-C\` gets the ${FORMAT_NAMES[format]} PID.`,
    references: ['[ARF] Annex 2, ISSU_28', '[ARF] Annex 2, WPNot_04'],
    units: 'Wallet Unit `CW-C` of `WP-C`, a Wallet Provider the default `TL-WP` does not list (issuer harness design section 5.2).',
    steps: [refused(format, grant, 'CW-C', '`WP-C` is not on the default `TL-WP` yet'), trustListStep('`WP-C` added as a granted Wallet Provider', { add: ['WP-C'] }), unitIssuance(format, 'CW-C', { grant, why: '`WP-C` is now on `TL-WP`' })],
  }),
  trust('PP_Inf_SM_TrustMechanisms_004_UF', format, grant, {
    objective: `Verify that a \`TL-WP\` with an invalid seal, or sealed by an untrusted scheme operator, is not used, and that the Provider then acts as it declares (ICS-15.invalid_version): with \`keep\` the previous list stays in force and \`CW-1\` still gets the ${FORMAT_NAMES[format]} PID; with \`discard\` it uses no list and issues none.`,
    references: ['[ETSI TS 119 602]', '[ARF] Annex 2, WPNot_04'],
    steps: [
      trustListStep('`WP-A` removed', { remove: ['WP-A'], faults: ['trust-list.seal-bitflip'] }),
      { ...unitIssuance(format, 'CW-1', { grant, why: 'the list with the broken seal must not apply' }), expect: afterBadSeal(format) },
      trustListStep('`WP-A` removed', { remove: ['WP-A'], faults: ['trust-list.sealed-by-ca-x'] }),
      { ...unitIssuance(format, 'CW-1', { grant, why: 'the list sealed under `CA-X` must not apply' }), expect: afterBadSeal(format) },
    ],
    comments: [
      'The bad version removes `WP-A`, so a Provider that used it would refuse `CW-1`. A Provider that keeps the previous list issues the PID; one that discards the list and uses none until a valid version arrives (fail-closed) refuses it. Both conform: ETSI TS 119 602 and the ARF require the seal to be verified before a list is used, not a last-known-good list, so steps 2 and 4 are `POLICY` (ICS-15.invalid_version) since the spec review of 2026-11-20 (issuer catalogue section 8.3). For EUDIPLO the adapter\'s `refreshTrust` (`DELETE /api/cache/trust-list`) itself empties the cache, so `keep` could not be observed through it in any case.',
    ],
  }),
  trust('PP_Inf_SM_TrustMechanisms_005_UF', format, grant, {
    objective: `Verify that a \`TL-WP\` older than the one in use (rollback) is not used: a version with a lower sequence number in which \`WP-W\` is granted gives \`CW-W\` of \`WP-W\` no ${FORMAT_NAMES[format]} PID.`,
    references: ['[ETSI TS 119 602]'],
    units: 'Wallet Unit `CW-W` of the withdrawn `WP-W` (issuer harness design section 5.2).',
    steps: [
      refused(format, grant, 'CW-W', "`WP-W`'s issuance service is withdrawn on the current `TL-WP`"),
      trustListStep('`WP-W` granted (its issuance service listed again)', { restoreIssuance: ['WP-W'], faults: ['trust-list.rollback'] }),
      refused(format, grant, 'CW-W', 'the rolled back version that grants `WP-W` must not be used'),
    ],
  }),
  trust('PP_Inf_SM_TrustMechanisms_006_UF', format, grant, {
    objective: `Verify that a \`TL-WP\` past its \`NextUpdate\`, with no newer list, is handled as the Provider declares its grace period (ICS-15): beyond it the list is not used and \`CW-1\` gets no ${FORMAT_NAMES[format]} PID; within it, it does.`,
    references: ['[ETSI TS 119 602]'],
    optional: true,
    steps: [
      trustListStep('the default entities', { faults: ['trust-list.stale-after-grace'] }),
      {
        text: `The adapter creates a credential offer for \`SUBJ-1\`, PID configuration in ${FORMAT_NAMES[format]} format; \`CW-1\` runs \`SCN-I\` without mutation.`,
        run: issuance(format, grant),
        expect: {
          codes: ['POLICY'],
          policy: 'ICS-15',
          text: 'As the grace period after `NextUpdate` the Provider declares (ICS-15) gives: `NextUpdate` lies the grace period plus one hour in the past, so the list is not used, the Wallet Provider is not trusted, and the Provider rejects (`REJ`); a list still within the grace period would give `ISS`.',
        },
      },
    ],
  }),
  trust('PP_Inf_SM_TrustMechanisms_007', format, grant, {
    objective: `Verify that the ${FORMAT_NAMES[format]} PID, its status list and the access certificate validate under the anchors \`TL-PID\` and \`TL-AC\` publish for the Provider, each for its service: issuance, revocation, access.`,
    references: ['[ARF] Annex 2, PPNot_03, PPNot_03a, PPNot_04', '[ARF] Annex 2, PuBPNot_04, PuBPNot_05', '[ARF] Annex 2, RPACANot_03, RPACANot_03a'],
    steps: [
      unitIssuance(format, 'CW-1', { grant }),
      inspectStep(
        [1],
        'The harness inspects the credential of step 1, the Status List Token it references, and the signed Credential Issuer metadata of the issuance (`Accept: application/jwt`).',
        inspected(['anchor-issuance', 'anchor-revocation', 'anchor-access'], 'Each artifact chains to the anchor of its service.'),
      ),
    ],
    comments: ['The access certificate is observed where the Provider uses it towards a wallet: the signature of its signed Credential Issuer metadata.'],
  }),
  trust('PP_Inf_SM_TrustMechanisms_008', format, grant, {
    objective: 'Verify that the requests the Provider sends to `TL-WP` and to the Test Status Provider carry no data about the User or the transaction.',
    references: ['[ARF] Annex 2, VCR_16 (analogue)', '[ARF] Annex 2, ISSU_35b'],
    steps: [
      trustListStep('the default entities, unchanged (so that the Provider fetches it during the test case)'),
      unitIssuance(format, 'CW-1', { grant }),
      inspectStep([2], 'The harness inspects every request the Test Trust Infrastructure (`TL-WP`) and the Test Status Provider logged from the Provider since the test case began (`OBS-NET`).', inspected(['outbound-privacy'], 'The Provider fetches lists anonymously.')),
    ],
  }),
]).flat());
