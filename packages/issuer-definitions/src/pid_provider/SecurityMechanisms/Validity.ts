// PP_WS_SM_Validity: the validity period of what the Provider issues (issuer catalogue section 5.1.3). Every test case
// runs `SCN-I` without mutation and checks the issued credential (`CONF`), in each format and grant.
import { defineIssuerTestCase, type FormatVariant, type GrantVariant, relevancy } from '@eudi-pcaf/core';
import { conf, expand, OUTPUT_COMMENTS, shortConfigurationOf, shortPidProfile } from '../../output';
import { FORMAT_NAMES, GRANT_NAMES, issuance, pidProfile, preconditions, technologyOf } from '../../wording';

const scn = (format: FormatVariant, grant: GrantVariant, configuration = 'PID configuration') =>
  `The adapter creates a credential offer for \`SUBJ-1\` and the ${configuration} in ${FORMAT_NAMES[format]} format; \`CW-1\` runs \`SCN-I\` in the ${GRANT_NAMES[grant]} without mutation.`;

const validity001 = (format: FormatVariant, grant: GrantVariant) =>
  defineIssuerTestCase({
    id: 'PP_WS_SM_Validity_001',
    variants: [format, grant],
    objective: `Verify that the PID in ${FORMAT_NAMES[format]} format carries a validity period (${format === 'SD' ? '`iat`, `exp`, optionally `nbf`' : 'the MSO `validityInfo`'}) and is valid at the time of issuance within \`T_skew\`.`,
    references: ['[SD-JWT VC] section 3.2.2', '[ISO/IEC 18013-5] section 9.1.2.4'],
    profile: pidProfile(format, grant),
    relevancy: relevancy.genericRequired,
    technology: technologyOf(format),
    preconditions: preconditions.base,
    steps: [
      {
        text: scn(format, grant),
        run: issuance(format, grant),
        expect: conf(
          ['validity-period'],
          format === 'SD'
            ? '`iat` and `exp` are present as NumericDate, `nbf` if present too, `exp` lies after `nbf` (or `iat`), and the credential is valid at the time of issuance within `T_skew`'
            : '`validityInfo` carries `signed`, `validFrom` and `validUntil`, `validUntil` lies after `validFrom`, and the mdoc is valid at the time of issuance within `T_skew`',
          format,
        ),
      },
    ],
    comments: [...OUTPUT_COMMENTS, '`T_skew` is the cap of the catalogue (section 3.5), 5 minutes.'],
  });

const validity002 = (format: FormatVariant, grant: GrantVariant) =>
  defineIssuerTestCase({
    id: 'PP_WS_SM_Validity_002',
    variants: [format, grant],
    objective: `Verify that a PID in ${FORMAT_NAMES[format]} format without a status reference is valid for 24 hours or less.`,
    references: ['[ARF] Annex 2, VCR_01, VCR_01b'],
    profile: shortPidProfile(format, grant),
    relevancy: relevancy.specificRequired,
    technology: technologyOf(format),
    preconditions: [...preconditions.base, 'The Provider declares a short-lived configuration of the PID (ICS-05, `P-SHORT`).'],
    steps: [
      {
        text: scn(format, grant, 'short-lived PID configuration (ICS-05)'),
        run: issuance(format, grant, { configurations: [shortConfigurationOf(format)] }),
        expect: conf(['status-reference'], 'a credential without a status reference has a validity period of at most 24 hours', format),
      },
    ],
    comments: OUTPUT_COMMENTS,
  });

const validity003 = (format: FormatVariant, grant: GrantVariant) =>
  defineIssuerTestCase({
    id: 'PP_WS_SM_Validity_003',
    variants: [format, grant],
    objective: `Verify that a PID in ${FORMAT_NAMES[format]} format valid for more than 24 hours carries a status reference.`,
    references: ['[ARF] Annex 2, VCR_01, VCR_01b, VCR_02'],
    profile: pidProfile(format, grant),
    relevancy: relevancy.specificRequired,
    technology: technologyOf(format),
    preconditions: preconditions.base,
    steps: [
      {
        text: scn(format, grant),
        run: issuance(format, grant),
        expect: conf(
          ['status-reference'],
          `a credential whose validity period exceeds 24 hours carries a status reference (${format === 'SD' ? '`status.status_list` with `idx` and `uri`' : 'the MSO `status` with a `status_list` or `identifier_list` entry'})`,
          format,
        ),
      },
    ],
    comments: OUTPUT_COMMENTS,
  });

const validity004 = (format: FormatVariant, grant: GrantVariant) =>
  defineIssuerTestCase({
    id: 'PP_WS_SM_Validity_004',
    variants: [format, grant],
    objective: `Verify that the validity period of the PID in ${FORMAT_NAMES[format]} format matches what the ICS declares for the configuration.`,
    references: ['[ARF] Annex 2, ISSU_38'],
    profile: pidProfile(format, grant),
    relevancy: relevancy.specificOptional,
    technology: technologyOf(format),
    preconditions: [...preconditions.base, 'The ICS declares the validity period of the PID configuration (`ICS-05.validity_period`) and its timestamp precision (`ICS-16.timestamp_precision`).'],
    steps: [
      {
        text: scn(format, grant),
        run: issuance(format, grant),
        expect: conf(
          ['validity-declared'],
          `the validity period (${format === 'SD' ? '`exp` minus `nbf`, or `iat`' : '`validUntil` minus `validFrom`'}) equals the declared one within twice the declared timestamp precision, since the issuance time may be rounded down and the expiry up`,
          format,
        ),
      },
    ],
    comments: OUTPUT_COMMENTS,
  });

export const definitions = [...expand(['SD', 'MD'], validity001), ...expand(['SD', 'MD'], validity002), ...expand(['SD', 'MD'], validity003), ...expand(['SD', 'MD'], validity004)];
