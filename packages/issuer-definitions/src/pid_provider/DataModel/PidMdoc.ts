// PP_WS_DM_PidMdoc: the PID in mdoc format against the PID Rulebook, ARF Annex 3.01 chapter 4 (issuer catalogue section
// 5.1.4). Every test case runs `SCN-I` for the mdoc PID without mutation and checks one rule (`CONF`); `_006` obtains
// both formats in one issuance and compares them.
import {
  defineIssuerTestCase,
  type FormatVariant,
  type GrantVariant,
  type IssuerOutputCheck,
  issuerProfiles,
  relevancy,
  type Relevancy,
} from '@eudi-pcaf/core';
import { conf, expand, GRANTS, OUTPUT_COMMENTS } from '../../output';
import { configurationOf, GRANT_NAMES, issuance, pidProfile, preconditions, technologyOf } from '../../wording';

interface Rule {
  number: number;
  objective: string;
  references: string[];
  relevancy: Relevancy;
  check: IssuerOutputCheck;
  rule: string;
  comments?: string[];
}

const RULES: Rule[] = [
  {
    number: 1,
    objective:
      'Verify that the docType and namespace of the PID in mdoc format are `eu.europa.ec.eudi.pid.1`, and that domestic attributes are only in a domestic namespace.',
    references: ['[ARF] Annex 2, PID_04, PID_05, PID_06', '[ARF] Annex 3.01 (PID Rulebook), chapter 4'],
    relevancy: relevancy.specificRequired,
    check: 'pid-type',
    rule: 'the MSO docType is `eu.europa.ec.eudi.pid.1`, the PID attributes are in namespace `eu.europa.ec.eudi.pid.1`, every element of that namespace is an attribute of the Rulebook, and any other namespace is a domestic one (`eu.europa.ec.eudi.pid.<country>.<n>`)',
  },
  {
    number: 2,
    objective:
      'Verify that the PID in mdoc format carries every mandatory attribute and metadata of the PID Rulebook section 3.1.2 as issuer-signed items, with the CBOR types of its table.',
    references: ['[ARF] Annex 2, PID_08, PID_09, PID_10', '[PID rulebook] v1.7, section 3.1.2', '[RFC8943]'],
    relevancy: relevancy.specificRequired,
    check: 'pid-attributes',
    rule: '`family_name`, `given_name`, `birth_date`, `place_of_birth`, `nationality`, `expiry_date`, `issuing_authority` and `issuing_country` are issuer-signed items, and every attribute of the Rulebook has its CBOR type: `tstr`, `birth_date` as `full-date` (tag 1004), `expiry_date` and `issuance_date` as `tdate` or `full-date`, `place_of_birth` as a map, `nationality` as a non-empty array of ISO 3166-1 alpha-2 codes, `portrait` as `bstr`, `age_over_NN` as `bool`, `sex`, `age_in_years` and `age_birth_year` as `uint`',
  },
  {
    number: 3,
    objective: 'Verify that each attribute identifier of the PID in mdoc format appears at most once.',
    references: ['[ARF] Annex 2, PID_11'],
    relevancy: relevancy.specificRequired,
    check: 'pid-unique',
    rule: 'no element identifier appears twice in a namespace of `nameSpaces`',
  },
  {
    number: 4,
    objective: "Verify that the values of the PID in mdoc format equal `SUBJ-1`'s data and are valid at `validFrom`, the age attributes included.",
    references: ['[ARF] Annex 2, PID_12'],
    relevancy: relevancy.specificRequired,
    check: 'pid-values',
    rule: "`family_name`, `given_name`, `birth_date`, `place_of_birth` and `nationality` equal `SUBJ-1`'s data, and `age_over_NN`, `age_in_years` and `age_birth_year`, where present, hold for `SUBJ-1`'s birth date at `validFrom`",
  },
  {
    number: 5,
    objective: 'Verify that `issuance_date` and `expiry_date` of the PID in mdoc format, if present, are consistent with `validFrom` and `validUntil`.',
    references: ['[ARF] Annex 2, PID_13'],
    relevancy: relevancy.specificRequired,
    check: 'pid-dates',
    rule: 'the mdoc is not valid before the day of `issuance_date` (`validFrom` not before its start) and not beyond the day of `expiry_date` (`validUntil` not after its end), within `T_skew`',
    comments: [
      'The policy checked is the one the PID Rulebook implies for the administrative dates: the technical validity period lies within the administrative one. A Provider that declares another policy is reviewed against it.',
    ],
  },
];

const pidMdoc = (rule: Rule) => (_format: FormatVariant, grant: GrantVariant) =>
  defineIssuerTestCase({
    id: `PP_WS_DM_PidMdoc_${String(rule.number).padStart(3, '0')}`,
    variants: ['MD', grant],
    objective: rule.objective,
    references: rule.references,
    profile: pidProfile('MD', grant),
    relevancy: rule.relevancy,
    technology: technologyOf('MD'),
    preconditions: preconditions.base,
    steps: [
      {
        text: `The adapter creates a credential offer for \`SUBJ-1\` and the PID configuration in mdoc format; \`CW-1\` runs \`SCN-I\` in the ${GRANT_NAMES[grant]} without mutation.`,
        run: issuance('MD', grant),
        expect: conf([rule.check], rule.rule, 'MD'),
      },
    ],
    comments: [...(rule.comments ?? []), ...OUTPUT_COMMENTS],
  });

/** `_006`: both formats of one issuance, one access token and two credential requests, compared value by value. */
const pidMdoc006 = (grant: GrantVariant) =>
  defineIssuerTestCase({
    id: 'PP_WS_DM_PidMdoc_006',
    variants: ['SD', 'MD', grant],
    objective: 'Verify that the values in the mdoc and in the SD-JWT VC of the same issuance are the same.',
    references: ['[ARF] Annex 2, ISSU_12, PID_02'],
    profile: [issuerProfiles['P-PID'], issuerProfiles['P-SD'], issuerProfiles['P-MD'], issuerProfiles[`P-${grant}`]],
    relevancy: relevancy.specificRequired,
    technology: ['OpenID4VCI', 'SD-JWT VC', 'ISO/IEC 18013-5 mdoc'],
    preconditions: preconditions.base,
    steps: [
      {
        text: `The adapter creates one credential offer for \`SUBJ-1\` and the PID configurations in SD-JWT VC and mdoc format; \`CW-1\` runs \`SCN-I\` in the ${GRANT_NAMES[grant]} without mutation and requests both credentials with the one access token.`,
        run: issuance('SD', grant, { configurations: [configurationOf('SD'), configurationOf('MD')] }),
        expect: conf(
          ['pid-formats'],
          'every attribute of the Rulebook present in one format is present in the other with the same value, under the name the Rulebook gives it there (for example `birthdate` and `birth_date`, `age_equal_or_over.18` and `age_over_18`; the portrait only for presence)',
        ),
      },
    ],
    comments: ['Execute this test case once for each grant the Provider declares in its ICS (ICS-03).'],
  });

export const definitions = [...RULES.flatMap((rule) => expand(['MD'], pidMdoc(rule))), ...GRANTS.map(pidMdoc006)];
