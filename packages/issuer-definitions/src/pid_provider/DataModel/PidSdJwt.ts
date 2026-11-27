// PP_WS_DM_PidSdJwt: the PID in SD-JWT VC format against the PID Rulebook, ARF Annex 3.01 chapter 5 (issuer catalogue
// section 5.1.4). Every test case runs `SCN-I` for the SD-JWT VC PID without mutation and checks one rule (`CONF`).
import { defineIssuerTestCase, type FormatVariant, type GrantVariant, type IssuerOutputCheck, relevancy, type Relevancy } from '@eudi-pcaf/core';
import { conf, expand, OUTPUT_COMMENTS } from '../../output';
import { GRANT_NAMES, issuance, pidProfile, preconditions, technologyOf } from '../../wording';

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
    objective: 'Verify that the `vct` of the PID in SD-JWT VC format is `urn:eudi:pid:1`, or a domestic type in the `urn:eudi:pid:` namespace that extends it.',
    references: ['[ARF] Annex 2, PID_14', '[ARF] Annex 3.01 (PID Rulebook), chapter 5'],
    relevancy: relevancy.specificRequired,
    check: 'pid-type',
    rule: '`vct` is `urn:eudi:pid:1` or in the `urn:eudi:pid:` namespace',
  },
  {
    number: 2,
    objective:
      'Verify that the PID in SD-JWT VC format carries every mandatory attribute and metadata of the PID Rulebook section 5.2, with the claim names and encodings of its tables.',
    references: ['[ARF] Annex 2, PID_17, PID_18, ISSU_14', '[ARF] Annex 3.01 (PID Rulebook), section 5.2'],
    relevancy: relevancy.specificRequired,
    check: 'pid-attributes',
    rule: '`family_name`, `given_name`, `birthdate`, `place_of_birth`, `nationalities`, `issuing_authority` and `issuing_country` are present, and every claim of the Rulebook has its JSON type: strings, `birthdate` and the dates as `full-date` strings, `place_of_birth` and `address` as objects, `nationalities` as a non-empty array of ISO 3166-1 alpha-2 codes, `age_equal_or_over` as an object of booleans, `sex`, `age_in_years` and `age_birth_year` as unsigned integers',
  },
  {
    number: 3,
    objective: "Verify that the values of the PID in SD-JWT VC format equal `SUBJ-1`'s data, and that every value, including the age claims, is valid at `nbf` or `iat`.",
    references: ['[ARF] Annex 2, PID_19, ISSU_14'],
    relevancy: relevancy.specificRequired,
    check: 'pid-values',
    rule: "`family_name`, `given_name`, `birthdate`, `place_of_birth` and `nationalities` equal `SUBJ-1`'s data, and `age_equal_or_over`, `age_in_years` and `age_birth_year`, where present, hold for `SUBJ-1`'s birth date at `nbf` (or `iat`)",
  },
  {
    number: 4,
    objective: 'Verify that `date_of_issuance` and `date_of_expiry` of the PID in SD-JWT VC format, if present, are consistent with `iat`/`nbf` and `exp`.',
    references: ['[ARF] Annex 2, PID_20'],
    relevancy: relevancy.specificRequired,
    check: 'pid-dates',
    rule: 'the credential is not valid before the day of `date_of_issuance` (`nbf`, or `iat`, not before its start) and not beyond the day of `date_of_expiry` (`exp` not after its end), within `T_skew`',
    comments: [
      'The policy checked is the one the PID Rulebook implies for the administrative dates: the technical validity period lies within the administrative one. A Provider that declares another policy is reviewed against it.',
    ],
  },
  {
    number: 5,
    objective: "Verify that a domestic extension's claims of the PID in SD-JWT VC format are documented in a published rulebook.",
    references: ['[ARF] Annex 2, PID_16'],
    relevancy: relevancy.specificOptional,
    check: 'pid-extension',
    rule: 'every claim outside the PID Rulebook belongs to a domestic `vct` whose published rulebook documents it; under `urn:eudi:pid:1` there is no such claim',
  },
  {
    number: 6,
    objective: 'Verify that the Type Metadata for the `vct` of the PID in SD-JWT VC format is retrievable and, if `vct#integrity` is present, matches it.',
    references: ['[SD-JWT VC] section 6'],
    relevancy: relevancy.genericOptional,
    check: 'type-metadata',
    rule: 'for an https `vct` the Type Metadata is retrieved from its well-known URL, names the same `vct`, and matches `vct#integrity` when present; for a URN `vct`, for which SD-JWT VC defines no retrieval, that is recorded',
  },
];

const pidSdJwt = (rule: Rule) => (_format: FormatVariant, grant: GrantVariant) =>
  defineIssuerTestCase({
    id: `PP_WS_DM_PidSdJwt_${String(rule.number).padStart(3, '0')}`,
    variants: ['SD', grant],
    objective: rule.objective,
    references: rule.references,
    profile: pidProfile('SD', grant),
    relevancy: rule.relevancy,
    technology: technologyOf('SD'),
    preconditions: preconditions.base,
    steps: [
      {
        text: `The adapter creates a credential offer for \`SUBJ-1\` and the PID configuration in SD-JWT VC format; \`CW-1\` runs \`SCN-I\` in the ${GRANT_NAMES[grant]} without mutation.`,
        run: issuance('SD', grant),
        expect: conf([rule.check], rule.rule, 'SD'),
      },
    ],
    comments: [...(rule.comments ?? []), ...OUTPUT_COMMENTS],
  });

export const definitions = RULES.flatMap((rule) => expand(['SD'], pidSdJwt(rule)));
