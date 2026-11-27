// RP_WS_DM_CredentialMetadata: attributes beyond the query, and values the query does not allow.
import {
  comments,
  defineTestCase,
  faultInfo,
  type FormatWording,
  formats,
  pid,
  positiveControlOf,
  preconditions,
  presentation,
  presentationStep,
  rej,
  relevancy,
  scenario,
  step,
  testCaseId,
} from '@eudi-pcaf/core';
import { CIR_PRESENTATION, queryVariant } from './IdentifyingData';

const sdJwtVc = formats.sdJwtVc;

const base = (format: FormatWording) => ({
  profile: [format.profile],
  technology: [format.technology],
  control: positiveControlOf(format),
});

const unrequested = (format: FormatWording) =>
  defineTestCase({
    id: testCaseId('WS', 'DM', 'CredentialMetadata', 1, format.letter, true),
    ...base(format),
    objective: `Record whether the Relying Party releases attributes of a PID in ${format.name} format that were disclosed without being requested.`,
    references: ['[OpenID4VP] section 6.4', '[GDPR] Art. 5(1)(c)', CIR_PRESENTATION],
    relevancy: relevancy.specificOptional,
    preconditions: [...preconditions.base, preconditions.control(positiveControlOf(format))],
    steps: [
      step({
        ...presentationStep.presentationFault('presentation.unrequested-disclosed', { format: format.credentialFormat }),
        expect: {
          codes: ['INFO'],
          text: `Whether the Relying Party rejects the presentation, or accepts it and releases \`place_of_birth\` or \`${format === sdJwtVc ? 'nationalities' : 'nationality'}\` besides the requested attributes, is recorded; HTTP 5xx fails.`,
        },
      }),
    ],
    comments: [
      'Informational since the spec review of 2026-11-20 (catalogue section 8.3): OpenID4VP 1.0 section 6.4 ("Wallets MUST NOT send selectively disclosable claims that have not been selected") binds the wallet, not the Relying Party. ARF OIA_16 is about discarding unique elements and timestamps, and OpenID4VP section 15.4.2 about which claims a Verifier requests; neither says what a Relying Party does with claims it did not request. Not releasing them is the data-minimising behaviour (GDPR Art. 5(1)(c)).',
      'Whether the Relying Party retains the extra attributes cannot be observed at its interfaces; the test book item `RP_TB_001` covers retention.',
      comments.flow,
    ],
  });

const valuesConstraint = (format: FormatWording) => {
  const fault = format === sdJwtVc ? 'credential.age-over-18-false-required-true' : 'mdoc.age-over-18-false-required-true';
  const query = faultInfo(fault).query;
  if (!query) throw new Error(`${fault} names no query`);
  return defineTestCase({
    id: testCaseId('WS', 'DM', 'CredentialMetadata', 2, format.letter, true),
    ...base(format),
    objective: `Verify that the Relying Party rejects a PID in ${format.name} format whose claim value violates the \`values\` constraint of the query.`,
    references: ['[OpenID4VP] section 6.3, 14.9, 15.4.1', CIR_PRESENTATION],
    relevancy: relevancy.genericRequired,
    preconditions: [...preconditions.base, preconditions.control(positiveControlOf(format)), queryVariant.ageOver18(format, true)],
    steps: [
      step({
        text: scenario.credentialVariant(faultInfo(fault).text, { query: 'the variant of `default_query_pid` named in the preconditions' }),
        run: presentation({ query, credential: pid.of(format.credentialFormat, { faults: [fault] }) }),
        expect: rej(),
      }),
    ],
    comments: [comments.flow],
  });
};

export const definitions = [unrequested(formats.sdJwtVc), unrequested(formats.mdoc), valuesConstraint(formats.sdJwtVc), valuesConstraint(formats.mdoc)];
