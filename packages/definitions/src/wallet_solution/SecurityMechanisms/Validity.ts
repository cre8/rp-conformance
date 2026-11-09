// RP_WS_SM_Validity: the validity period of the credential.
import {
  acc,
  all,
  comments,
  defineTestCase,
  type FormatWording,
  type FaultId,
  formats,
  ics,
  nofetch,
  positiveControlOf,
  preconditions,
  rej,
  relevancy,
  presentationStep,
  scenario,
  step,
  testCaseId,
} from '@rp-conformance/core';

const SD_JWT_VC_REFERENCES = ['[RFC9901] section 7.1', '[SD-JWT VC] section 2.4', '[OpenID4VP] section 8.6', '[CIR 2024/2982 amended] Annex II'];
const MDOC_REFERENCES = ['[ISO/IEC 18013-5] section 9.3.1', '[OpenID4VP] section 8.6', '[HAIP] section 5.3.1', '[CIR 2024/2982 amended] Annex II'];
const referencesOf = (format: FormatWording) => (format === formats.sdJwtVc ? SD_JWT_VC_REFERENCES : MDOC_REFERENCES);

const sdJwtVc = formats.sdJwtVc;
const mdoc = formats.mdoc;
const base = (format: FormatWording) => ({
  relevancy: relevancy.genericRequired,
  technology: [format.technology],
  control: positiveControlOf(format),
});

const STATUS_BEFORE_VALIDITY =
  '[Token Status List] section 8.3 requires the validation of the credential itself to precede any evaluation of its status, and states that status list procedures, such as fetching the Status List Token, must not be performed once the credential is found invalid, unless the use case requires further evaluation. Presenting a PID does not.';

/** The scenario of a credential fault: executable for SD-JWT VC, text only for mdoc until Phase 2. */
const credentialFault = (format: FormatWording, fault: FaultId, mdocDifference: string) =>
  format === sdJwtVc ? presentationStep.credentialFault(fault) : { text: scenario.credentialVariant(mdocDifference) };

const expired = (format: FormatWording) =>
  credentialFault(
    format,
    'credential.exp-past',
    'the `validUntil` value in the `validityInfo` of its MSO is set to the current time minus `T_skew` minus one hour',
  );

const badSignature = (format: FormatWording) =>
  credentialFault(format, 'credential.signature-bitflip', 'one bit of the signature value of its `IssuerAuth` structure is flipped');

const expiredWithValidStatus = (format: FormatWording) =>
  defineTestCase({
    id: testCaseId('WS', 'SM', 'Validity', 5, format.letter, true),
    objective: `Verify that the Relying Party rejects an expired credential in ${format.name} format whose revocation status is VALID, without retrieving its status list.`,
    references: ['[Token Status List] section 7.1, 8.3', '[ARF] Annex 2, VCR_13', ...referencesOf(format), '[CIR 2024/2979 amended] Annex II'],
    profile: [format.profile, ics.checksPidRevocation],
    ...base(format),
    preconditions: [
      ...preconditions.base,
      preconditions.control(positiveControlOf(format)),
      preconditions.freshStatusList,
      preconditions.statusValid,
    ],
    steps: [step({ ...expired(format), expect: all(rej(), nofetch()) })],
    comments: [STATUS_BEFORE_VALIDITY, comments.flow],
  });

const badSignatureNoFetch = (format: FormatWording) =>
  defineTestCase({
    id: testCaseId('WS', 'SM', 'Validity', 6, format.letter, true),
    objective: `Verify that the Relying Party does not retrieve the status list of a credential in ${format.name} format whose issuer signature is invalid.`,
    references: [
      '[Token Status List] section 8.3',
      format === sdJwtVc ? '[RFC9901] section 7.1' : '[ISO/IEC 18013-5] section 9.3.1',
      '[CIR 2024/2979 amended] Annex II',
    ],
    profile: [format.profile, ics.checksPidRevocation],
    ...base(format),
    preconditions: [...preconditions.base, preconditions.control(positiveControlOf(format)), preconditions.freshStatusList],
    steps: [step({ ...badSignature(format), expect: all(rej(), nofetch()) })],
    comments: [comments.flow],
  });

const sdJwtVcOnly = [
  defineTestCase({
    id: testCaseId('WS', 'SM', 'Validity', 1, '', true),
    objective: 'Verify that the Relying Party rejects a credential in SD-JWT VC format whose expiration time has passed.',
    references: ['[RFC7519] section 4.1.4', ...SD_JWT_VC_REFERENCES],
    profile: [sdJwtVc.profile],
    ...base(sdJwtVc),
    preconditions: [...preconditions.base, preconditions.control(positiveControlOf(sdJwtVc))],
    steps: [step({ ...presentationStep.credentialFault('credential.exp-past'), expect: rej() })],
    comments: [comments.flow],
  }),
  defineTestCase({
    id: testCaseId('WS', 'SM', 'Validity', 2),
    objective:
      'Verify that the Relying Party accepts a credential in SD-JWT VC format whose expiration time has passed by less than the declared clock tolerance.',
    references: ['[RFC7519] section 4.1.4', ...SD_JWT_VC_REFERENCES],
    profile: [sdJwtVc.profile, ics.appliesClockTolerance],
    ...base(sdJwtVc),
    preconditions: [...preconditions.base, preconditions.control(positiveControlOf(sdJwtVc))],
    steps: [step({ ...presentationStep.credentialFault('credential.exp-within-skew'), expect: acc() })],
    comments: [comments.flow],
  }),
  defineTestCase({
    id: testCaseId('WS', 'SM', 'Validity', 3, '', true),
    objective: 'Verify that the Relying Party rejects a credential in SD-JWT VC format that is not yet valid.',
    references: ['[RFC7519] section 4.1.5', ...SD_JWT_VC_REFERENCES],
    profile: [sdJwtVc.profile],
    ...base(sdJwtVc),
    preconditions: [...preconditions.base, preconditions.control(positiveControlOf(sdJwtVc))],
    steps: [step({ ...presentationStep.credentialFault('credential.nbf-future'), expect: rej() })],
    comments: [comments.flow],
  }),
];

const mdocOnly = (
  [
    [
      10,
      'the `validUntil` value in the `validityInfo` of its MSO is set to the current time minus `T_skew` minus one hour',
      rej(),
      'Verify that the Relying Party rejects a credential in mdoc format whose validity period has ended.',
    ],
    [
      11,
      'the `validFrom` value in the `validityInfo` of its MSO is set to the current time plus `T_skew` plus one hour',
      rej(),
      'Verify that the Relying Party rejects a credential in mdoc format whose validity period has not started.',
    ],
    [
      12,
      'the `expectedUpdate` value in the `validityInfo` of its MSO lies one day in the past, while `validUntil` lies in the future',
      acc(),
      'Verify that the Relying Party accepts a credential in mdoc format whose expected update time has passed while its validity period has not ended.',
    ],
  ] as const
).map(([number, difference, expect, objective]) =>
  defineTestCase({
    id: testCaseId('WS', 'SM', 'Validity', number, '', expect.codes[0] === 'REJ'),
    objective,
    references: number === 12 ? ['[ISO/IEC 18013-5] section 9.1.2.4', ...MDOC_REFERENCES] : MDOC_REFERENCES,
    profile: [mdoc.profile],
    ...base(mdoc),
    preconditions: [...preconditions.base, preconditions.control(positiveControlOf(mdoc))],
    steps: [step({ text: scenario.credentialVariant(difference), expect })],
    comments: [comments.flow],
  }),
);

export const definitions = [
  ...sdJwtVcOnly,
  ...[sdJwtVc, mdoc].flatMap((format) => [expiredWithValidStatus(format), badSignatureNoFetch(format)]),
  ...mdocOnly,
];
