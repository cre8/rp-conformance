// RP_WS_IA_MainInteraction: the positive controls of the unhappy-flow test cases, one per credential format, and the
// positive baseline of the other credential categories and of selective disclosure.
import {
  acc,
  attestation,
  comments,
  credentials,
  defineTestCase,
  type FormatWording,
  formats,
  ics,
  PID,
  pid,
  preconditions,
  presentation,
  presentationStep,
  queries,
  queryOf,
  relevancy,
  scenario,
  step,
  testCaseId,
} from '@eudi-pcaf/core';

const references = (format: FormatWording) => [
  `[ARF] Annex 2, ${format === formats.sdJwtVc ? 'OIA_03c, OIA_08a, OIA_12' : 'OIA_03b, OIA_08, OIA_12'}`,
  `[HAIP] section 5, ${format === formats.sdJwtVc ? '6.1' : '5.3.1'}`,
  '[OpenID4VP] section 8.6',
  '[CIR 2024/2982 amended] Annex II',
];

const mainInteraction = (format: FormatWording) =>
  defineTestCase({
    id: testCaseId('WS', 'IA', 'MainInteraction', 1, format.letter),
    objective: `Verify that the Relying Party accepts a valid presentation of a PID in ${format.name} format and releases exactly the requested attributes.`,
    references: references(format),
    profile: [format.profile],
    relevancy: relevancy.specificRequired,
    technology: [format.technology],
    preconditions: preconditions.base,
    steps: [step({ ...presentationStep.valid({ credential: pid.of(format.credentialFormat) }), expect: acc({ credential: PID }) })],
    comments: [comments.positiveControl(format), comments.flow],
  });

// RP_WS_IA_MainInteraction_002 to _004: the positive baseline of the other credential categories, the attestation
// `default_credential_A` issued as a QEAA, a PuB-EAA or a non-qualified EAA, presented for the category's default query.
const CATEGORIES = [
  [2, 'qeaa', 'QEAA', ics.requestsQeaa, credentials.qeaa, queries.qeaa, 'OIA_13'],
  [3, 'pub-eaa', 'PuB-EAA', ics.requestsPubEaa, credentials.pubEaa, queries.pubEaa, 'OIA_14'],
  [4, 'eaa', 'non-qualified EAA', ics.requestsEaa, credentials.eaa, queries.eaa, 'OIA_15'],
] as const;

const attestationInteraction = (format: FormatWording, [number, category, name, profile, credential, query, arf]: (typeof CATEGORIES)[number]) =>
  defineTestCase({
    id: testCaseId('WS', 'IA', 'MainInteraction', number, format.letter),
    objective: `Verify that the Relying Party accepts a valid presentation of a ${name} in ${format.name} format and releases exactly the requested attributes.`,
    references: [`[ARF] Annex 2, ${arf}`, `[HAIP] section 5, ${format === formats.sdJwtVc ? '6.1' : '5.3.1'}`, '[OpenID4VP] section 8.6', '[CIR 2024/2982 amended] Annex II'],
    profile: [format.profile, profile],
    relevancy: relevancy.specificRequired,
    technology: [format.technology],
    preconditions: preconditions.base,
    steps: [
      step({
        text: scenario.valid({ credential, query }),
        run: presentation({ query: queryOf(category, format.credentialFormat), credential: attestation.of(category, format.credentialFormat) }),
        expect: acc({ credential, query }),
      }),
    ],
    comments: [
      `This test case is the positive baseline for ${name}s in ${format.name} format. \`RP_WS_SM_TrustMechanisms_0${number === 2 ? 10 : number === 3 ? 12 : 14}${format.letter}\` presents the same credential to verify the root of trust of the category.`,
      comments.flow,
    ],
  });

/** The PID attributes a presentation for `default_query_pid` leaves undisclosed, by format. */
const UNDISCLOSED = {
  a: '`place_of_birth` and `nationalities`',
  b: '`place_of_birth`, `nationality`, `issuing_authority`, `issuing_country` and `expiry_date`',
};

// RP_WS_IA_MainInteraction_005: selective disclosure. `default_query_pid` requests three of the PID's attributes; the
// others are selectively disclosable (SD-JWT VC) or separate data elements (mdoc), and the wallet does not disclose them.
const selectiveDisclosure = (format: FormatWording) =>
  defineTestCase({
    id: testCaseId('WS', 'IA', 'MainInteraction', 5, format.letter),
    objective: `Verify that the Relying Party releases only the requested attributes of a PID in ${format.name} format whose other attributes are not disclosed.`,
    references: [
      '[ARF] Annex 2, OIA_07',
      format === formats.sdJwtVc ? '[RFC9901] section 7.1' : '[ISO/IEC 18013-5] section 8.3.2.1.2.2',
      '[OpenID4VP] section 6.4, 8.6',
      '[CIR 2024/2982 amended] Annex II',
    ],
    profile: [format.profile],
    relevancy: relevancy.genericRequired,
    technology: [format.technology],
    preconditions: preconditions.base,
    steps: [
      step({
        ...presentationStep.valid({
          credential: pid.of(format.credentialFormat),
          text: { extra: `, in which it discloses only the requested attributes and not ${UNDISCLOSED[format.letter]}` },
        }),
        expect: acc({ credential: PID, extra: `In particular, ${UNDISCLOSED[format.letter]} are absent from the verification result.` }),
      }),
    ],
    comments: [comments.flow],
  });

/** The positive controls, part of the baseline. */
export const definitions = [mainInteraction(formats.sdJwtVc), mainInteraction(formats.mdoc)];

/** The other test cases of the area, beyond the baseline. */
export const furtherDefinitions = [
  ...CATEGORIES.flatMap((category) => [attestationInteraction(formats.sdJwtVc, category), attestationInteraction(formats.mdoc, category)]),
  selectiveDisclosure(formats.sdJwtVc),
  selectiveDisclosure(formats.mdoc),
];
