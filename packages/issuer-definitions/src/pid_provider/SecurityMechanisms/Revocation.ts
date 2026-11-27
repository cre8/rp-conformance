// PP_WS_SM_Revocation_001 to _003 (issuer catalogue section 5.1.3, `SCN-L`, `P-REV`, `P-HOOK`): the status reference of
// what the Provider issues, and revocation through the adapter. `_001` names `SD`, `_002` names `MD`; `_003` names no
// format and runs in `SD` until the mdoc PID lands (issue 21). The grant does not change what is published, so each runs
// in `PA`; `AC` follows with the authorization code flow.
import { defineIssuerTestCase, type FormatVariant, issuerProfiles, relevancy } from '@eudi-pcaf/core';
import { fetchStep, issueStep, LIST_FORMAT, published, revokedStep, revokeStep } from '../../status';
import { FORMAT_NAMES, pidProfile, preconditions, technologyOf } from '../../wording';

const REFERENCE_CHECKS = [
  'sl-uri',
  'status-list-fetch',
  'status-list-format',
  'status-list-type',
  'status-list-trust',
  'status-list-signature',
  'status-list-subject',
  'status-index',
];

const statusReference = (id: 'PP_WS_SM_Revocation_001' | 'PP_WS_SM_Revocation_002', format: FormatVariant) =>
  defineIssuerTestCase({
    id,
    variants: [format, 'PA'],
    objective:
      format === 'SD'
        ? 'Verify that the SD-JWT VC PID carries `status.status_list` with `idx` and an https `uri`, and that the `uri` resolves to a Status List Token of the Provider.'
        : "Verify that the mdoc PID's MSO carries a `status` element whose `status_list` points to a Status List Token of the Provider.",
    references: [
      format === 'SD' ? '[ARF] Annex 2, VCR_11a' : '[ARF] Annex 2, VCR_11',
      format === 'SD' ? '[TokenStatusList] section 6.2' : '[ISO/IEC 18013-5] second edition, section 12.3.6',
    ],
    profile: [...pidProfile(format, 'PA'), issuerProfiles['P-REV']],
    relevancy: relevancy.specificRequired,
    technology: [...technologyOf(format), 'Token Status List'],
    preconditions: preconditions.base,
    steps: [
      issueStep(format),
      fetchStep(
        format,
        [1],
        published(
          REFERENCE_CHECKS,
          `The ${FORMAT_NAMES[format]} carries a status reference to a status list; its \`uri\` answers with a Status List Token in ${LIST_FORMAT[format]} signed by the Provider, covering the credential's index.`,
        ),
      ),
    ],
    comments: [
      'The status reference itself is also part of `ISS` (`status-reference`); this test case adds that the reference resolves to a list of the Provider (`OBS-SL`).',
      'OIDF `happy-flow` covers this objective partly (issuer catalogue section 7).',
    ],
  });

const revocation003 = (format: FormatVariant) =>
  defineIssuerTestCase({
    id: 'PP_WS_SM_Revocation_003',
    variants: [format, 'PA'],
    objective: `Verify that after the adapter revokes a ${FORMAT_NAMES[format]} PID, the status list the Provider publishes shows it revoked within \`T_rev\`, and never valid again.`,
    references: ['[ARF] Annex 2, VCR_03, VCR_04', '[ETSI EN 319 411-1] REV-6.2.4-03A', '[TokenStatusList] section 7.1'],
    profile: [...pidProfile(format, 'PA'), issuerProfiles['P-REV'], issuerProfiles['P-HOOK']],
    relevancy: relevancy.specificRequired,
    technology: [...technologyOf(format), 'Token Status List'],
    preconditions: [...preconditions.base, 'The adapter can revoke an issued credential and report when it has done so (ICS-06, `P-HOOK`); `T_rev` is declared, at most 24 hours (decision 3).'],
    steps: [
      issueStep(format),
      fetchStep(format, [1], { codes: ['UNCHANGED'], text: "The list shows the credential's entry as `0x00` (VALID) before the revocation." }),
      revokeStep(1),
      revokedStep(1),
    ],
    comments: [
      'Long running: the step that waits `T_rev` runs after the other test cases (issuer harness design section 6.3). The nightly job runs with declared values of minutes (decision 3).',
      '"Never valid again" is checked over every version polled until `T_rev` has passed; `PP_TB_003` covers the policy that a revocation is never reversed.',
    ],
  });

export const definitions = [statusReference('PP_WS_SM_Revocation_001', 'SD'), statusReference('PP_WS_SM_Revocation_002', 'MD'), revocation003('SD')];
