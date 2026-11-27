// RP_WS_SM_Validity_004 and _020: an SD-JWT VC issued in the future, whose handling is only recorded (catalogue
// decision 5), and a PID whose administrative expiry date has passed, handled as the Relying Party declares (ICS RP.P.12).
import {
  comments,
  defineTestCase,
  type Expectation,
  type FormatWording,
  formats,
  item,
  PID,
  pid,
  positiveControlOf,
  preconditions,
  presentation,
  presentationStep,
  relevancy,
  scenario,
  step,
  testCaseId,
} from '@eudi-pcaf/core';

const sdJwtVc = formats.sdJwtVc;
const mdoc = formats.mdoc;

/** `INFO`: the outcome is recorded, without a verdict on it. */
const info = (): Expectation => ({
  codes: ['INFO'],
  text: 'The outcome, acceptance or rejection, is recorded in the report; this test case has no verdict on it. The endpoint receiving the Authorization Response does not answer with HTTP status 5xx.',
});

/** The administrative expiry date of the PID in each format (PID Rulebook). */
const expiryClaim = (format: FormatWording) => (format === sdJwtVc ? '`date_of_expiry`' : '`expiry_date`');

const expiryPolicy = (format: FormatWording): Expectation => ({
  codes: ['POLICY'],
  policy: { item: 'RP.P.12' },
  text: `If the Relying Party declares in its ICS that it rejects such a PID (RP.P.12 Reject), it rejects the presentation: its verification result reports a failure and releases no attribute value from the presentation, and the endpoint receiving the Authorization Response does not answer with HTTP status 5xx. If it declares that it accepts it (RP.P.12 Accept), it accepts the presentation: its verification result reports success and releases exactly the attributes requested, ${expiryClaim(format)} included, with the values of the presented credential.`,
});

const administrativeExpiry = (format: FormatWording) =>
  defineTestCase({
    id: testCaseId('WS', 'SM', 'Validity', 20, format.letter),
    objective: `Verify that the Relying Party handles a PID in ${format.name} format whose administrative expiry date has passed, while its technical validity has not ended, as the policy it declares says.`,
    references: ['[PID rulebook]', '[ARF] section 5', format === sdJwtVc ? '[SD-JWT VC] section 2.4' : '[ISO/IEC 18013-5] section 9.3.1', '[CIR 2024/2982 amended] Annex II'],
    profile: [format.profile],
    relevancy: relevancy.specificOptional,
    technology: [format.technology],
    preconditions: [
      ...preconditions.base,
      preconditions.control(positiveControlOf(format)),
      `The Relying Party is configured to request, with ${item('default_query_pid')} in ${format.name} format, also the administrative expiry date of the PID, ${expiryClaim(format)}.`,
    ],
    control: positiveControlOf(format),
    steps: [
      step({
        text: scenario.credentialVariant(
          `its ${expiryClaim(format)} lies seven days in the past, while its technical validity (${format === sdJwtVc ? '`exp`' : '`validUntil`'}) has not ended`,
        ),
        run: presentation({
          query: format === sdJwtVc ? 'default_query_pid_expiry_date' : 'default_query_pid_mdoc_expiry_date',
          credential: { ...pid.of(format.credentialFormat), expiryDatePast: true },
        }),
        expect: expiryPolicy(format),
      }),
    ],
    comments: [
      'The PID Rulebook distinguishes the administrative validity of the PID (its expiry date) from the technical validity of the credential. Whether a PID past its expiry date is still acceptable is a decision of the relying service; the ICS item RP.P.12 declares it. A PID whose expiry date is not requested never reaches the Relying Party, since the Conformance Wallet discloses only the requested attributes.',
      comments.flow,
    ],
  });

export const definitions = [
  defineTestCase({
    id: testCaseId('WS', 'SM', 'Validity', 4),
    objective: 'Record how the Relying Party handles a credential in SD-JWT VC format whose issuance time lies in the future.',
    references: ['[RFC7519] section 4.1.6', '[RFC9901] section 7.1', '[SD-JWT VC] section 2.4', '[CIR 2024/2982 amended] Annex II'],
    profile: [sdJwtVc.profile],
    relevancy: relevancy.genericUndefined,
    technology: [sdJwtVc.technology],
    preconditions: [...preconditions.base, preconditions.control(positiveControlOf(sdJwtVc))],
    control: positiveControlOf(sdJwtVc),
    steps: [step({ ...presentationStep.credentialFault('credential.iat-future'), expect: info() })],
    comments: [
      '[RFC7519] section 4.1.6 attaches no processing rule to `iat`, so the catalogue records the outcome instead of judging it (decision 5).',
      comments.flow,
    ],
  }),
  administrativeExpiry(sdJwtVc),
  administrativeExpiry(mdoc),
];
