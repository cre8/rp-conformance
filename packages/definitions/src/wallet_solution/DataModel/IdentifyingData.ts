// RP_WS_DM_IdentifyingData: the PID attributes the Relying Party releases, their values and their data types.
import {
  acc,
  comments,
  type DefaultQueryId,
  defineTestCase,
  type Expectation,
  type FaultId,
  faultInfo,
  type FormatWording,
  type Relevancy,
  formats,
  PID,
  pid,
  pidQueryOf,
  positiveControlOf,
  preconditions,
  presentation,
  presentationStep,
  rej,
  relevancy,
  scenario,
  type StepDefinition,
  step,
  testCaseId,
} from '@eudi-pcaf/core';

const sdJwtVc = formats.sdJwtVc;
const mdoc = formats.mdoc;

/** The variant of `default_query_pid` a step is presented for, as the test case names it. */
const VARIANT = 'the variant of `default_query_pid` named in the preconditions';

/** The mandatory attributes of the PID rulebook, by format. */
const MANDATORY = {
  a: '`family_name`, `given_name`, `birthdate`, `place_of_birth`, `nationalities`, `date_of_expiry`, `issuing_authority` and `issuing_country`',
  b: '`family_name`, `given_name`, `birth_date`, `place_of_birth`, `nationality`, `expiry_date`, `issuing_authority` and `issuing_country`',
};

/** The preconditions that configure a variant of `default_query_pid`. */
export const queryVariant = {
  mandatory: (format: FormatWording) =>
    `The Relying Party is configured with a variant of \`default_query_pid\` in ${format.name} format that requests every mandatory attribute of the PID rulebook: ${MANDATORY[format.letter]}.`,
  ageOver18: (format: FormatWording, values?: boolean) =>
    `The Relying Party is configured with a variant of \`default_query_pid\` in ${format.name} format that requests only ${format === sdJwtVc ? 'the member `18` of the claim `age_equal_or_over` (claims path `["age_equal_or_over", "18"]`)' : 'the element `age_over_18`'}${values ? ', with `values` `[true]`' : ''}.`,
  address: 'The Relying Party is configured with a variant of `default_query_pid` in SD-JWT VC format that requests only the members `locality`, `postal_code` and `country` of the claim `address` (claims paths `["address", "locality"]`, `["address", "postal_code"]` and `["address", "country"]`).',
};

/** The fault of each format: the attribute variants of the PID differ in name between SD-JWT VC and mdoc. */
type Pair = { a: FaultId; b?: FaultId };
const faultOf = (pair: Pair, format: FormatWording) => {
  const fault = format === sdJwtVc ? pair.a : pair.b;
  if (!fault) throw new Error(`no ${format.name} variant of ${pair.a}`);
  return fault;
};

/**
 * A presentation of the attribute variant `fault` of the PID, for the query the fault names (`default_query_pid` when it
 * names none); the text names the variant of `default_query_pid` when the query is one.
 */
const variantStep = (fault: FaultId, format: FormatWording, expect: (query?: string) => Expectation): StepDefinition => {
  const query: DefaultQueryId = faultInfo(fault).query ?? pidQueryOf(format.credentialFormat);
  const named = faultInfo(fault).query ? VARIANT : undefined;
  return step({
    text: scenario.credentialVariant(faultInfo(fault).text, named ? { query: named } : {}),
    run: presentation({ query, credential: pid.of(format.credentialFormat, { faults: [fault] }) }),
    expect: expect(named),
  });
};

/**
 * `INFO` (spec review 2026-11-20): how the Relying Party handles a value of the wrong data type is recorded. Rejecting
 * it, or accepting it and flagging the attribute (`attribute-invalid`), is the hardened behaviour; no specification
 * requires a Relying Party to validate attribute types.
 */
const typeInfo = (attribute: string): Expectation => ({
  codes: ['INFO'],
  text: `Whether the Relying Party rejects the presentation, flags \`${attribute}\` as invalid (\`attribute-invalid\`), or accepts it as it is, is recorded; HTTP 5xx fails.`,
});

interface Options {
  number: number;
  format: FormatWording;
  unhappyFlow?: boolean;
  objective: string;
  references: string[];
  relevancy?: Relevancy;
  preconditions?: string[];
  steps: StepDefinition[];
  comments?: string[];
}

const identifyingData = (options: Options) =>
  defineTestCase({
    id: testCaseId('WS', 'DM', 'IdentifyingData', options.number, options.format.letter, options.unhappyFlow ?? false),
    objective: options.objective,
    references: [...options.references, CIR_PRESENTATION],
    profile: [options.format.profile],
    relevancy: options.relevancy ?? relevancy.specificRequired,
    technology: [options.format.technology],
    preconditions: [...preconditions.base, preconditions.control(positiveControlOf(options.format)), ...(options.preconditions ?? [])],
    control: positiveControlOf(options.format),
    steps: options.steps,
    comments: [...(options.comments ?? []), comments.flow],
  });

const PID_RULEBOOK = '[PID rulebook]';
/** The EUDI anchor of the presentation test cases. */
export const CIR_PRESENTATION = '[CIR 2024/2982 amended] Annex II';

const forFormat = (format: FormatWording) => {
  const name = format.name;
  const birthDate = format === sdJwtVc ? '`birthdate`' : '`birth_date`';
  return [
    identifyingData({
      number: 1,
      format,
      objective: `Verify that the Relying Party releases every mandatory attribute of a PID in ${name} format with its value and data type, including names with characters outside Latin-1.`,
      references: [PID_RULEBOOK, '[ARF] Annex 2, ARB_06', ...(format === sdJwtVc ? ['[SD-JWT VC] section 2.2'] : ['[ISO/IEC 18013-5] section 8.3.2.1.2.2'])],
      preconditions: [queryVariant.mandatory(format)],
      steps: [
        variantStep(faultOf({ a: 'credential.pid-mandatory-utf8', b: 'mdoc.pid-mandatory-utf8' }, format), format, (query) =>
          acc({
            credential: 'the presented variant',
            query,
            extra: 'Each value equals the issued one exactly: the names as the same sequence of Unicode characters, the dates as `YYYY-MM-DD` text, the nationalities as an array of country codes and the place of birth as an object.',
          }),
        ),
      ],
    }),
    identifyingData({
      number: 2,
      format,
      objective: `Verify that the Relying Party accepts a PID in ${name} format that carries no attribute besides the requested ones.`,
      references: [PID_RULEBOOK, '[ARF] Annex 2, ARB_09'],
      steps: [variantStep(faultOf({ a: 'credential.pid-requested-only', b: 'mdoc.pid-requested-only' }, format), format, () => acc({ credential: 'the presented variant' }))],
      comments: [
        `\`default_credential_pid\` carries none of the optional attributes of the PID rulebook. The variant also leaves out every attribute that \`default_query_pid\` does not request, so no attribute the Relying Party did not ask for can make up for one it expects.`,
      ],
    }),
    identifyingData({
      number: 3,
      format,
      unhappyFlow: true,
      relevancy: relevancy.genericRequired,
      objective: `Verify that the Relying Party rejects a presentation of a PID in ${name} format that does not disclose a requested claim.`,
      references: ['[OpenID4VP] section 6.4, 8.6'],
      steps: [step({ ...presentationStep.presentationFault('presentation.family-name-withheld', { format: format.credentialFormat }), expect: rej() })],
      comments: ['`default_query_pid` requests every claim it names: it has no `claim_sets`, so a presentation without `family_name` does not satisfy it.'],
    }),
    identifyingData({
      number: 4,
      format,
      unhappyFlow: true,
      relevancy: relevancy.specificOptional,
      objective: `Record how the Relying Party handles PID attributes in ${name} format whose values have the wrong data type.`,
      references: [PID_RULEBOOK, '[ISO 8601-1:2019]', ...(format === mdoc ? ['[RFC8943]'] : []), '[OpenID4VP] section 8.6'],
      preconditions: [queryVariant.mandatory(format)],
      steps: [
        variantStep(faultOf({ a: 'credential.birthdate-integer', b: 'mdoc.birth-date-integer' }, format), format, () => typeInfo(birthDate.slice(1, -1))),
        variantStep(faultOf({ a: 'credential.nationalities-string', b: 'mdoc.nationality-string' }, format), format, () =>
          typeInfo(format === sdJwtVc ? 'nationalities' : 'nationality'),
        ),
      ],
      comments: [
        'Informational since the spec review of 2026-11-20 (catalogue section 8.3): the PID Rulebook and ISO 8601-1 bind the issuer of the value; neither OpenID4VP 1.0 section 8.6 nor the ARF requires a Relying Party to validate the data type of an attribute. Rejecting the presentation or flagging the attribute invalid is the hardened behaviour.',
      ],
    }),
    identifyingData({
      number: 5,
      format,
      objective: `Verify that the Relying Party releases the age-over attribute of a PID in ${name} format as a boolean with its value.`,
      references: [PID_RULEBOOK],
      preconditions: [queryVariant.ageOver18(format)],
      steps: [
        variantStep(faultOf({ a: 'credential.age-over-18-true', b: 'mdoc.age-over-18-true' }, format), format, (query) =>
          acc({ credential: 'the presented variant', query, extra: 'The released value is the boolean `true`.' }),
        ),
        variantStep(faultOf({ a: 'credential.age-over-18-false', b: 'mdoc.age-over-18-false' }, format), format, (query) =>
          acc({ credential: 'the presented variant', query, extra: 'The released value is the boolean `false`.' }),
        ),
      ],
    }),
  ];
};

export const definitions = [
  ...forFormat(sdJwtVc),
  ...forFormat(mdoc),
  identifyingData({
    number: 6,
    format: sdJwtVc,
    objective: 'Verify that the Relying Party releases the disclosed members of a structured PID attribute in SD-JWT VC format with their values.',
    references: [PID_RULEBOOK, '[RFC9901] section 4.2.6, 7.1', '[OpenID4VP] section 7'],
    preconditions: [queryVariant.address],
    steps: [
      variantStep('credential.address-structured', sdJwtVc, (query) =>
        acc({
          credential: 'the presented variant',
          query,
          extra: 'It releases `locality`, `postal_code` and `country` of the address, and not `street_address` or `house_number`, which the Conformance Wallet does not disclose.',
        }),
      ),
    ],
    comments: [
      'The Conformance Wallet discloses `address` with only the disclosures of the three requested members. The PID in mdoc format has no structured address: the PID rulebook encodes its address as separate data elements (`resident_city`, `resident_postal_code`, …), which `RP_WS_DM_IdentifyingData_001b` covers as any other element.',
    ],
  }),
  identifyingData({
    number: 7,
    format: sdJwtVc,
    relevancy: relevancy.genericRequired,
    objective: 'Verify that the Relying Party accepts a PID in SD-JWT VC format that carries a claim it does not know.',
    references: ['[SD-JWT VC] section 2.2.2', '[OpenID4VP] section 6.4, 8.6'],
    steps: [
      variantStep('credential.private-claim', sdJwtVc, () =>
        acc({ credential: 'the presented variant', extra: 'Whether it also passes the unknown claim along is not judged: the claim is not selectively disclosable.' }),
      ),
    ],
    comments: [
      'The claim is not selectively disclosable, so it reaches the Relying Party with every presentation. An mdoc has no such element: the Conformance Wallet presents only requested elements, and a presentation with an element the query does not request is `RP_WS_DM_CredentialMetadata_001b_UF`.',
      'Since the spec review of 2026-11-20 (catalogue section 8.3) the step checks acceptance only: a claim that is always disclosed cannot be withheld (OpenID4VP 1.0 section 6.4 lets a presentation contain claims that "are not selectively disclosable"), so it is treated like the technical claims (`iss`, `vct`, …) when the released attributes are compared.',
    ],
  }),
];
