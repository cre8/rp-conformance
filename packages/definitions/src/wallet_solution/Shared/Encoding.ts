// RP_WS_SH_Encoding: robustness against malformed encodings of the Authorization Response, the presentation and the
// credential, oversized responses and excessive certificate chains, and error answers that reveal nothing internal.
import {
  acc,
  all,
  comments,
  defineTestCase,
  type Expectation,
  type FaultId,
  faultInfo,
  type FormatWording,
  flows,
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
const CONTROLS: [string, string] = [positiveControlOf(sdJwtVc), positiveControlOf(mdoc)];
const PRESENTATION = '[CIR 2024/2982 amended] Annex II';

/** `HTTP_4XX`: the `response_uri` answers with HTTP 4xx (redirects only). */
const http4xx = (): Expectation => ({
  codes: ['HTTP_4XX'],
  text: 'Via redirects, the `response_uri` answers the Authorization Response with an HTTP status 4xx.',
});

/** `NO_DETAILS`: the answer to the Authorization Response reveals no internal details (redirects only). */
const noDetails = (): Expectation => ({
  codes: ['NO_DETAILS'],
  text: 'Via redirects, the body of the answer of the `response_uri` reveals no internal details of the Relying Party: no stack trace, source file path, module directory, exception class name or database error.',
});

/** A presentation of `default_credential_pid` in SD-JWT VC format whose Authorization Response has a fault, in either flow. */
const responseFault = (fault: FaultId) => ({
  text: scenario.presentation(faultInfo(fault).text),
  run: presentation({ query: pidQueryOf('dc+sd-jwt'), credential: pid.sdJwtVc(), response: { faults: [fault] } }),
});

/** A step with a fault of the credential or of the presentation, in the format the fault applies to. */
const faultStep = (fault: FaultId) =>
  faultInfo(fault).point === 'credential' ? presentationStep.credentialFault(fault) : presentationStep.presentationFault(fault);

/** The valid presentation right after a step that tried to exhaust the Relying Party's resources. */
const stillAvailable = (format: FormatWording): StepDefinition =>
  step({
    ...presentationStep.valid({
      credential: pid.of(format.credentialFormat),
      text: { credential: `a newly issued ${PID}`, extra: ', immediately after the previous step' },
    }),
    expect: acc({ credential: 'the newly issued credential' }),
  });

const AVAILABLE =
  'The last step shows that the Relying Party stays available: a Relying Party that crashed or exhausted its resources on the previous step cannot accept it.';

const formatNeutral = {
  profile: [],
  relevancy: relevancy.genericRequired,
  technology: [],
  preconditions: [...preconditions.base, preconditions.controlOfFlow(CONTROLS)],
  control: CONTROLS,
};

const ofFormat = (format: FormatWording) => ({
  profile: [format.profile],
  relevancy: relevancy.genericRequired,
  technology: [format.technology],
  preconditions: [...preconditions.base, preconditions.control(positiveControlOf(format))],
  control: positiveControlOf(format),
});

const excessiveChain = (format: FormatWording) =>
  defineTestCase({
    id: testCaseId('WS', 'SH', 'Encoding', 6, format.letter, true),
    objective: `Verify that the Relying Party rejects a credential in ${format.name} format whose ${format === sdJwtVc ? '`x5c` header' : '`x5chain`'} carries an excessive number of certificates, and stays available.`,
    references: [
      '[RFC5280] section 6.1',
      ...(format === sdJwtVc ? ['[RFC7515] section 4.1.6', '[SD-JWT VC] section 2.5', '[HAIP] section 6.1'] : ['[ISO/IEC 18013-5] section 9.3.1']),
      PRESENTATION,
    ],
    ...ofFormat(format),
    steps: [step({ ...presentationStep.credentialFault(format === sdJwtVc ? 'credential.x5c-50' : 'mdoc.x5chain-50'), expect: rej() }), stillAvailable(format)],
    comments: [
      'The 49 additional certificates do not certify the signing certificate, so no certification path through them exists; a Relying Party that bounds the chain it processes rejects it before validating any of them.',
      AVAILABLE,
      comments.flow,
    ],
  });

export const definitions = [
  defineTestCase({
    id: testCaseId('WS', 'SH', 'Encoding', 1, '', true),
    objective:
      'Verify that the Relying Party rejects an Authorization Response whose `response` is not a well-formed compact JWE, answering via redirects with an HTTP status 4xx that reveals no internal details.',
    references: ['[RFC7516] section 7.1, 9', '[OpenID4VP] section 8.3.1', '[HAIP] section 5', PRESENTATION],
    ...formatNeutral,
    steps: (['response.jwe-four-segments', 'response.jwe-not-base64url'] as const).map((fault) =>
      step({ ...responseFault(fault), expect: all(rej(), http4xx(), noDetails()) }),
    ),
    comments: [
      comments.encryptionFormat,
      'Via the W3C Digital Credentials API the response returns to the Relying Party\'s own page, which passes it on to its back end in a way OpenID4VP leaves to the Relying Party; there the HTTP status and the body of that answer are not evaluated.',
      comments.flow,
    ],
  }),
  defineTestCase({
    id: testCaseId('WS', 'SH', 'Encoding', 2, '', true),
    objective:
      'Verify that the Relying Party rejects a presentation in SD-JWT VC format that is not a well-formed SD-JWT: a missing separator, an empty disclosure, a disclosure that is not valid JSON, or a KB-JWT whose payload is not valid JSON.',
    references: ['[RFC9901] section 4, 7.1, 7.3', '[RFC8259] section 2', '[RFC7519] section 7.2', PRESENTATION],
    ...ofFormat(sdJwtVc),
    steps: (
      ['presentation.sd-jwt-no-separator', 'presentation.sd-jwt-empty-disclosure', 'credential.disclosure-invalid-json', 'presentation.kb-payload-nan'] as const
    ).map((fault) => step({ ...faultStep(fault), expect: rej() })),
    comments: [
      'In the fourth step the invalid JSON is in the KB-JWT rather than in the SD-JWT itself; JSON has no `NaN` ([RFC8259] section 6).',
      comments.flow,
    ],
  }),
  defineTestCase({
    id: testCaseId('WS', 'SH', 'Encoding', 3, '', true),
    objective:
      'Verify that the Relying Party rejects a presentation in mdoc format whose DeviceResponse is not well-formed CBOR or not of the structure ISO/IEC 18013-5 defines, or whose COSE structures break the encoding rules of their format: a repeated header label, an MSO not wrapped in tag 24, a device signature that carries its payload.',
    references: ['[RFC8949] section 3, 5.3', '[RFC9052] section 3, 4.1', '[ISO/IEC 18013-5] section 8.3.2.1.2.2, 9.1.2, 9.1.3', '[OpenID4VP] section B.2', PRESENTATION],
    ...ofFormat(mdoc),
    steps: (
      [
        'presentation.device-response-truncated',
        'presentation.device-response-documents-map',
        'presentation.device-response-deep-nesting',
        'presentation.device-response-unterminated',
        'mdoc.issuer-auth-duplicate-label',
        'mdoc.mso-not-tag24',
        'presentation.device-signature-not-detached',
      ] as const
    ).map((fault) => step({ ...faultStep(fault), expect: rej() })),
    comments: [
      'An indefinite-length map is well-formed CBOR, so the fourth step leaves out its `break` byte: the item never ends ([RFC8949] section 3.2.1).',
      comments.flow,
    ],
  }),
  defineTestCase({
    id: testCaseId('WS', 'SH', 'Encoding', 4, '', true),
    objective:
      'Verify that the Relying Party rejects an Authorization Response larger than the maximum size it declares, without exhausting its resources, and stays available.',
    references: ['[OpenID4VP] section 8.3.1', '[HAIP] section 5', PRESENTATION],
    ...formatNeutral,
    steps: [
      step({
        ...responseFault('response.oversized'),
        expect: {
          ...rej(),
          forwardFailureRejects: true,
          text: `${rej().text} Via the DC API, the Relying Party's page receiving HTTP 4xx, or its request forwarding the response failing with a network error, also counts as the rejection: the verification result need not report a failure.`,
        },
      }),
      stillAvailable(sdJwtVc),
    ],
    comments: [
      'The maximum response size is the value the Relying Party declares in its ICS (RP.P.11). The padding is a member of the encrypted payload, so a Relying Party without a size limit decrypts the response and accepts it.',
      'Via the DC API the response reaches the Relying Party through its own page. A back end that refuses the oversized body (for example HTTP 413 from its body parser) may do so before setting CORS headers, so the page sees only a network error, and the transaction stays open. Either is a rejection; the step does not require a failed verification result (spec review 2026-11-20, catalogue section 8.3).',
      AVAILABLE,
      comments.encryptionFormat,
      comments.flow,
    ],
  }),
  defineTestCase({
    id: testCaseId('WS', 'SH', 'Encoding', 5, '', true),
    objective: 'Verify that the Relying Party rejects a KB-JWT whose header or payload carries a member name twice.',
    references: ['[RFC7515] section 4', '[RFC7519] section 4', '[RFC8259] section 4', '[RFC9901] section 7.3', PRESENTATION],
    ...ofFormat(sdJwtVc),
    steps: (['presentation.kb-duplicate-alg', 'presentation.kb-duplicate-nonce'] as const).map((fault) => step({ ...faultStep(fault), expect: rej() })),
    comments: [
      '[RFC7515] section 4 lets a parser either reject duplicate member names or use the lexically last one. The last value of each duplicate is the wrong one, so both conforming behaviours reject the presentation; a parser that keeps the first value accepts it.',
      comments.flow,
    ],
  }),
  excessiveChain(sdJwtVc),
  excessiveChain(mdoc),
  defineTestCase({
    id: testCaseId('WS', 'SH', 'Encoding', 7),
    objective: 'Verify that the answers of the Relying Party to faulty Authorization Responses reveal no internal details to the wallet.',
    references: ['[OpenID4VP] section 8.3.1, 15.9', '[HAIP] section 5.1', PRESENTATION],
    profile: [sdJwtVc.profile, flows.redirect.profile],
    relevancy: relevancy.genericOptional,
    technology: [sdJwtVc.technology, flows.redirect.technology],
    preconditions: [...preconditions.base, preconditions.control(positiveControlOf(sdJwtVc))],
    control: positiveControlOf(sdJwtVc),
    steps: (
      [
        'response.jwe-four-segments',
        'response.jwe-not-base64url',
        'presentation.sd-jwt-no-separator',
        'presentation.kb-duplicate-nonce',
        'credential.x5c-50',
      ] as const
    ).map((fault) =>
      step({ ...(faultInfo(fault).point === 'response' ? responseFault(fault) : faultStep(fault)), expect: all(rej(), noDetails()) }),
    ),
    comments: [
      'The steps repeat stimuli of `RP_WS_SH_Encoding_001_UF`, `_002_UF`, `_005_UF` and `_006a_UF`. Only the answer to the wallet is examined: the verification result the Relying Party hands to its relying service may carry any detail it wants.',
    ],
  }),
];
