// RP_WS_UC_Presentation: combined presentations. The Relying Party requests a PID and an EAA (`default_query_pid_eaa`),
// or one of them with `credential_sets` (`default_query_pid_or_eaa`), and the Conformance Wallet answers with several
// credentials in one Authorization Response. Each step applies at most one fault: to one of the credentials (its status),
// to the `vp_token` (an entry left out, an entry for an unknown query id, two presentations for one query, one
// DeviceResponse for both queries), or presents the credentials of a credential set option.
//
// Not written: `_012_UF` (no cryptographic binding scheme for combined presentations is specified, catalogue section
// 8.2), `_020` and `_021` (intermediaries: they need a second Relying Party behind the SUT, ICS-13).
import {
  acc,
  type AttestationOptions,
  attestation,
  type CredentialSpec,
  comments,
  credentials,
  type DefaultQueryId,
  defineTestCase,
  type FaultId,
  type FormatWording,
  formats,
  ics,
  item,
  type IcsCondition,
  PID,
  pid,
  preconditions,
  presentation,
  type Relevancy,
  rej,
  rejOrAcc,
  relevancy,
  type StepDefinition,
  statusListFormatOf,
  statusListToken,
  step,
  testCaseId,
} from '@eudi-pcaf/core';

const sdJwtVc = formats.sdJwtVc;
const mdoc = formats.mdoc;

const QUERY_PID_EAA = item('default_query_pid_eaa');
const QUERY_PID_OR_EAA = item('default_query_pid_or_eaa');
const QUERY_IDENTIFYING = item('default_query_pid_eaa_identifying');
const EAA = credentials.eaa;
const PUB_EAA = credentials.pubEaa;

const queryOf = (base: 'default_query_pid_eaa' | 'default_query_pid_or_eaa' | 'default_query_pid_eaa_identifying', format: FormatWording) =>
  `${base}${format === mdoc ? '_mdoc' : ''}` as DefaultQueryId;

/** The positive control of the combined presentations in a format: `RP_WS_UC_Presentation_001a` or `_001b`. */
const controlOf = (format: FormatWording) => `RP_WS_UC_Presentation_001${format.letter}`;

const OID4VP = '[OpenID4VP] section 6, 8.6';

interface PresentationTestCase {
  number: number;
  format: FormatWording;
  /** Variant letter; default the format's letter. `_009_UF` is for mdoc only and has none. */
  variant?: string;
  unhappyFlow?: boolean;
  objective: string;
  references: string[];
  relevancy: Relevancy;
  /** ICS conditions besides the format's. */
  profile?: IcsCondition[];
  /** The positive control; default `_001` of the format for an unhappy-flow test case, none for a positive one. */
  control?: string | null;
  /** Precondition texts besides the base and the control. */
  preconditions?: string[];
  steps: StepDefinition[];
  comments?: string[];
}

const ucPresentation = (testCase: PresentationTestCase) => {
  const unhappyFlow = testCase.unhappyFlow ?? false;
  const control = testCase.control === undefined ? (unhappyFlow ? controlOf(testCase.format) : null) : testCase.control;
  return defineTestCase({
    id: testCaseId('WS', 'UC', 'Presentation', testCase.number, testCase.variant ?? testCase.format.letter, unhappyFlow),
    objective: testCase.objective,
    references: [...testCase.references, '[CIR 2024/2982 amended] Annex II'],
    profile: [testCase.format.profile, ics.requestsEaa, ...(testCase.profile ?? [])],
    relevancy: testCase.relevancy,
    technology: [testCase.format.technology],
    preconditions: [...preconditions.base, ...(control ? [preconditions.control(control)] : []), ...(testCase.preconditions ?? [])],
    ...(control ? { control } : {}),
    steps: testCase.steps,
    comments: [...(testCase.comments ?? []), comments.flow],
  });
};

const eaa = (format: FormatWording, options: AttestationOptions = {}): CredentialSpec => attestation.of('eaa', format.credentialFormat, options);

/** A presentation for `default_query_pid_eaa` of the PID (`pid`) and `default_credential_eaa` (`eaa`), with at most one fault. */
const pidAndEaa = (
  format: FormatWording,
  options: { fault?: FaultId; eaaStatus?: number; query?: DefaultQueryId; identifying?: 'holder' | 'other-person' } = {},
) =>
  presentation({
    query: options.query ?? queryOf('default_query_pid_eaa', format),
    credential: pid.of(format.credentialFormat),
    answers: 'pid',
    alongside: [
      {
        answers: 'eaa',
        credential: eaa(format, options.identifying ? { identifying: options.identifying } : {}),
        ...(options.eaaStatus !== undefined ? { statusList: statusListToken.of(statusListFormatOf(format.credentialFormat), { status: options.eaaStatus }) } : {}),
      },
    ],
    ...(options.fault ? { response: { faults: [options.fault] } } : {}),
  });

const both = (format: FormatWording) => `${PID} and ${EAA} in ${format.name} format`;

/** UC_Presentation_001: the positive control of the combined presentations. */
const accepted = (format: FormatWording) =>
  ucPresentation({
    number: 1,
    format,
    relevancy: relevancy.genericRequired,
    objective: `Verify that the Relying Party accepts a valid combined presentation of a PID and an EAA in ${format.name} format for a DCQL query that requests both.`,
    references: [OID4VP],
    steps: [
      step({
        text: `Perform a presentation for ${QUERY_PID_EAA} in which the Conformance Wallet presents ${both(format)}, each for its credential query, in a valid Authorization Response.`,
        run: pidAndEaa(format),
        expect: acc({ query: QUERY_PID_EAA, credential: `${PID} and ${EAA}` }),
      }),
    ],
    comments: [
      `This test case is the positive control for the unhappy-flow test cases of \`RP_WS_UC_Presentation\` in ${format.name} format. When it fails, those test cases cannot produce a meaningful verdict in the same environment.`,
    ],
  });

/** A combined presentation for `default_query_pid_eaa` that is valid except for `difference`. */
const combinedVariant = (difference: string) =>
  `Perform a presentation for ${QUERY_PID_EAA} in which the Conformance Wallet presents ${PID} and ${EAA}, each for its credential query, in an Authorization Response that is valid except that ${difference}.`;

const revokedEaa = (format: FormatWording) =>
  ucPresentation({
    number: 2,
    format,
    unhappyFlow: true,
    relevancy: relevancy.genericRequired,
    objective: `Verify that the Relying Party rejects a combined presentation in ${format.name} format of which one required credential is invalid, and does not release the valid part as verified.`,
    references: ['[OpenID4VP] section 8.6'],
    preconditions: [preconditions.freshStatusList],
    steps: [
      step({
        text: combinedVariant(`the status list referenced by ${EAA} holds the value 0x01 (INVALID) at the credential's index, while ${PID} is valid`),
        run: pidAndEaa(format, { eaaStatus: 1 }),
        expect: rej(),
      }),
    ],
    comments: [
      'The rejected presentation must not release the attributes of the valid PID either: an OpenID4VP Verifier rejects the whole VP Token when a required credential query is not satisfied by a valid presentation.',
    ],
  });

const vpTokenFault = (number: number, format: FormatWording, fault: FaultId, objective: string, references: string[], extra: Partial<PresentationTestCase> = {}) =>
  ucPresentation({
    number,
    format,
    unhappyFlow: true,
    relevancy: relevancy.genericRequired,
    objective,
    references,
    steps: [step({ text: combinedVariant(FAULT_TEXT[fault] ?? fault), run: pidAndEaa(format, { fault }), expect: rej() })],
    ...extra,
  });

/** The scenario wording of the vp_token faults, after "except that". */
const FAULT_TEXT: Partial<Record<FaultId, string>> = {
  'vp-token.entry-missing': 'its `vp_token` has no entry for the credential query `pid`, so it carries only the presentation of the EAA',
  'vp-token.unknown-id':
    'its `vp_token` additionally holds an entry with the key `x`, which is the `id` of no credential query of the request, with a valid presentation of the same PID that discloses every attribute of the PID',
  'vp-token.two-presentations': 'the entry of its `vp_token` for the credential query `pid`, which does not set `multiple`, holds two valid presentations of the PID',
  'vp-token.combined-device-response':
    'the entries of its `vp_token` for both credential queries hold one and the same DeviceResponse, which carries the documents of both credentials, each with a valid device signature',
};

const missingEntry = (format: FormatWording) =>
  vpTokenFault(
    3,
    format,
    'vp-token.entry-missing',
    `Verify that the Relying Party rejects a presentation in ${format.name} format that leaves out a required credential query.`,
    ['[OpenID4VP] section 6.4, 8.6'],
  );

const unknownId = (format: FormatWording) =>
  ucPresentation({
    number: 4,
    format,
    unhappyFlow: true,
    relevancy: relevancy.genericRequired,
    objective: `Verify that the Relying Party releases nothing from a \`vp_token\` entry in ${format.name} format whose key is the \`id\` of no credential query of the request.`,
    references: ['[OpenID4VP] section 8.1'],
    steps: [
      step({
        text: combinedVariant(FAULT_TEXT['vp-token.unknown-id'] as string),
        run: pidAndEaa(format, { fault: 'vp-token.unknown-id' }),
        expect: rejOrAcc({
          query: QUERY_PID_EAA,
          credential: `${PID} and ${EAA}`,
          extra: 'In particular, it releases no attribute of the PID that only the entry `x` discloses.',
        }),
      }),
    ],
    comments: [
      'Rejecting the response and ignoring the entry `x` both pass, as long as nothing from that entry is released as verified (decision 7 of the test catalogue). The entry discloses attributes that `default_query_pid_eaa` does not request, so a release of its content is visible in the verification result.',
    ],
  });

const twoPresentations = (format: FormatWording) =>
  vpTokenFault(
    5,
    format,
    'vp-token.two-presentations',
    `Verify that the Relying Party rejects a presentation in ${format.name} format with more than one presentation for a credential query that does not allow \`multiple\`.`,
    ['[OpenID4VP] section 6.1, 8.1'],
  );

/** UC_Presentation_006 to _008: presentations for `default_query_pid_or_eaa`, of the credentials of one option. */
const credentialSet = (
  number: number,
  format: FormatWording,
  options: { credential: CredentialSpec; answers: string; text: string; accepted: boolean; objective: string },
) =>
  ucPresentation({
    number,
    format,
    unhappyFlow: !options.accepted,
    relevancy: relevancy.genericRequired,
    objective: options.objective,
    references: ['[OpenID4VP] section 6.2, 6.4.2'],
    profile: [ics.requestsPubEaa],
    steps: [
      step({
        text: `Perform a presentation for ${QUERY_PID_OR_EAA} in which the Conformance Wallet presents ${options.text}, for its credential query, in a valid Authorization Response.`,
        run: presentation({ query: queryOf('default_query_pid_or_eaa', format), credential: options.credential, answers: options.answers }),
        expect: options.accepted ? acc({ query: `the credential query \`${options.answers}\` of ${QUERY_PID_OR_EAA}`, credential: options.text.split(' in ')[0] }) : rej(),
      }),
    ],
    comments: [
      '`default_query_pid_or_eaa` has a required credential set with the options `pid` and `eaa`, and an optional credential set with the option `pubeaa`.',
    ],
  });

const alternativeOption = (format: FormatWording) =>
  credentialSet(6, format, {
    credential: eaa(format),
    answers: 'eaa',
    text: `${EAA} in ${format.name} format`,
    accepted: true,
    objective: `Verify that the Relying Party accepts a presentation in ${format.name} format that satisfies the second option of a required credential set.`,
  });

const noOption = (format: FormatWording) =>
  credentialSet(7, format, {
    credential: attestation.of('pub-eaa', format.credentialFormat),
    answers: 'pubeaa',
    text: `only ${PUB_EAA} in ${format.name} format, which satisfies no option of the required credential set`,
    accepted: false,
    objective: `Verify that the Relying Party rejects a presentation in ${format.name} format that satisfies no option of a required credential set.`,
  });

const optionalOmitted = (format: FormatWording) =>
  credentialSet(8, format, {
    credential: pid.of(format.credentialFormat),
    answers: 'pid',
    text: `${PID} in ${format.name} format, without ${PUB_EAA} of the optional credential set`,
    accepted: true,
    objective: `Verify that the Relying Party accepts a presentation in ${format.name} format that leaves out the credential query of an optional credential set.`,
  });

const combinedDeviceResponse = () =>
  vpTokenFault(
    9,
    mdoc,
    'vp-token.combined-device-response',
    'Verify that the Relying Party rejects two mdocs returned in one DeviceResponse for two credential queries.',
    ['[HAIP] section 5.3.1', '[OpenID4VP] section 8.6'],
    {
      variant: '',
      relevancy: relevancy.genericOptional,
      comments: [
        '[HAIP] section 5.3.1 requires each mdoc to be returned in a separate DeviceResponse matching its credential query, and a Verifier rejects a VP Token that fails a check of the VP Token as a whole ([OpenID4VP] section 8.6). The DeviceResponse is otherwise valid: each document carries its own valid device signature over the SessionTranscript of the request.',
      ],
    },
  );

const binding = (format: FormatWording, same: boolean) =>
  ucPresentation({
    number: same ? 10 : 11,
    format,
    unhappyFlow: !same,
    relevancy: relevancy.specificOptional,
    objective: same
      ? `Verify that the Relying Party accepts a combined presentation in ${format.name} format of a PID and an EAA whose identifying attributes match.`
      : `Verify that the Relying Party rejects a combined presentation in ${format.name} format of a PID and an EAA of different persons when it binds the credentials of a combined presentation by their identifying attributes.`,
    references: ['[ARF] section 6.6.3.10'],
    profile: [ics.bindsByAttributes],
    control: same ? null : `RP_WS_UC_Presentation_010${format.letter}`,
    steps: [
      step({
        text: `Perform a presentation for ${QUERY_IDENTIFYING} in which the Conformance Wallet presents ${PID} and a variant of ${EAA} that additionally carries the family name, the given name and the birth date ${same ? 'of the holder of the PID, with the same values as the PID' : 'of another person (`Musterfrau`, `Gabriele`, `1971-03-05`)'}, each for its credential query, in a valid Authorization Response.`,
        run: pidAndEaa(format, { query: queryOf('default_query_pid_eaa_identifying', format), identifying: same ? 'holder' : 'other-person' }),
        expect: same ? acc({ query: QUERY_IDENTIFYING, credential: `${PID} and the EAA` }) : rej(),
      }),
    ],
    comments: [
      same
        ? 'This test case is the positive control of `RP_WS_UC_Presentation_011` in the same format.'
        : 'Both credentials are valid and bound to the same Wallet Unit key; only their identifying attributes differ.',
    ],
  });

export const definitions = [
  accepted(sdJwtVc),
  accepted(mdoc),
  revokedEaa(sdJwtVc),
  revokedEaa(mdoc),
  missingEntry(sdJwtVc),
  missingEntry(mdoc),
  unknownId(sdJwtVc),
  unknownId(mdoc),
  twoPresentations(sdJwtVc),
  twoPresentations(mdoc),
  alternativeOption(sdJwtVc),
  alternativeOption(mdoc),
  noOption(sdJwtVc),
  noOption(mdoc),
  optionalOmitted(sdJwtVc),
  optionalOmitted(mdoc),
  combinedDeviceResponse(),
  binding(sdJwtVc, true),
  binding(mdoc, true),
  binding(sdJwtVc, false),
  binding(mdoc, false),
];
