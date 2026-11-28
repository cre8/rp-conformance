// RP_PP_SM_Revocation_014 and _031: optional checks of a Status List Token. `_014` presents a token issued in the
// future or 30 days ago, whose handling the freshness policy the Relying Party declares decides (ICS RP.R.7, RP.R.8);
// `_031` an mdoc whose MSO status element names the certificate that signs its Status List Token.
import {
  acc,
  all,
  comments,
  defineTestCase,
  type Expectation,
  fetched,
  type FormatWording,
  formats,
  ics,
  PID,
  positiveControlOf,
  preconditions,
  presentationStep,
  relevancy,
  step,
  testCaseId,
} from '@eudi-pcaf/core';

const sdJwtVc = formats.sdJwtVc;
const mdoc = formats.mdoc;
const REJECTS =
  'it makes no positive status statement: its verification result reports a failure and releases no attribute value from the presentation, and the endpoint receiving the Authorization Response does not answer with HTTP status 5xx';

/** The age of the old Status List Token, seconds (packages/forge/src/policy-faults.ts). */
const OLD_TOKEN_AGE = 30 * 24 * 3600;

const futureIat = (): Expectation => ({
  codes: ['POLICY'],
  policy: { item: 'RP.R.8' },
  text: `If the Relying Party declares in its ICS that it refuses a Status List Token whose \`iat\` lies in the future (RP.R.8 Yes), ${REJECTS}. Otherwise it accepts the presentation and releases exactly the attributes requested in \`default_query_pid\`, with the values of ${PID}.`,
});

const oldIat = (): Expectation => ({
  codes: ['POLICY'],
  policy: { item: 'RP.R.7', ageSeconds: OLD_TOKEN_AGE },
  text: `If the maximum age of a Status List Token the Relying Party declares in its ICS (RP.R.7) is 30 days or less, ${REJECTS}. If it declares no maximum age, or a longer one, it accepts the presentation and releases exactly the attributes requested in \`default_query_pid\`, with the values of ${PID}.`,
});

const freshness = (format: FormatWording) =>
  defineTestCase({
    id: testCaseId('PP', 'SM', 'Revocation', 14, format.letter, true),
    objective: `Verify that the Relying Party handles a Status List Token in ${format === sdJwtVc ? 'JWT' : 'CWT'} format that was issued in the future, or longer ago than the maximum age it declares, as its declared freshness policy says.`,
    references: [
      format === sdJwtVc ? '[Token Status List] section 5.1, 8.3' : '[Token Status List] section 5.2, 8.3',
      '[ARF] Annex 2, VCR_14',
      '[CIR 2024/2979 amended] Annex II',
    ],
    profile: [format.profile, ics.checksPidRevocation],
    relevancy: relevancy.genericOptional,
    technology: [format.technology, format.statusListTechnology],
    preconditions: [...preconditions.base, preconditions.control(positiveControlOf(format)), preconditions.freshStatusList],
    control: positiveControlOf(format),
    steps: [
      step({ ...presentationStep.statusListFault(format === sdJwtVc ? 'status-list.iat-future' : 'status-list-cwt.iat-future'), expect: futureIat() }),
      step({ ...presentationStep.statusListFault(format === sdJwtVc ? 'status-list.iat-old' : 'status-list-cwt.iat-old'), expect: oldIat() }),
    ],
    comments: [
      '[Token Status List] section 8.3 leaves the freshness of a Status List Token to the policy of the Relying Party; the ICS items RP.R.7 and RP.R.8 declare it. A refused token leaves no reliable revocation status.',
      comments.nostat,
      comments.flow,
    ],
  });

export const definitions = [
  freshness(sdJwtVc),
  freshness(mdoc),
  defineTestCase({
    id: testCaseId('PP', 'SM', 'Revocation', 31),
    objective:
      'Verify that the Relying Party accepts a credential in mdoc format whose MSO status element names the certificate that signs the referenced Status List Token, and validates the token against that certificate.',
    references: ['[ISO/IEC 18013-5 ed2]', '[Token Status List] section 5.2, 8.3', '[RFC8392] section 7.2', '[CIR 2024/2979 amended] Annex II'],
    profile: [mdoc.profile, ics.checksPidRevocation],
    relevancy: relevancy.genericOptional,
    technology: [mdoc.technology, mdoc.statusListTechnology],
    preconditions: [...preconditions.base, preconditions.control(positiveControlOf(mdoc)), preconditions.freshStatusList, preconditions.statusValid],
    control: positiveControlOf(mdoc),
    steps: [step({ ...presentationStep.credentialFault('mdoc.status-certificate'), expect: all(acc({ credential: PID }), fetched()) })],
    comments: [
      'The Status List Token is signed by the certificate the status element names, which is issued under the revocation anchor of `PP-A`. A Relying Party that ignores the element accepts the presentation too, so the test case shows that it accepts a valid credential that carries the element, not that it uses it.',
      comments.flow,
    ],
  }),
];
