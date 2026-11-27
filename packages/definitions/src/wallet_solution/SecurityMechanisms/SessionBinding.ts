// RP_WS_SM_SessionBinding: a presentation is bound to the request it answers, through the `nonce` and `aud` of the
// KB-JWT (SD-JWT VC) or the SessionTranscript of the device signature (mdoc), so a presentation made for another Relying
// Party, another transaction or another time is rejected. `RP_WS_SM_SessionBinding_010_UF` (proximity) is not written:
// the harness has no ISO/IEC 18013-5 proximity flow.
import {
  acc,
  type FormatWording,
  faultInfo,
  formats,
  PID,
  pid,
  pidQueryOf,
  presentation,
  QUERY_PID,
  rej,
  step,
} from '@rp-conformance/core';
import { bindingTestCase, oidf, rejected } from './binding';

const sdJwtVc = formats.sdJwtVc;
const mdoc = formats.mdoc;
const sessionBinding = (testCase: Parameters<typeof bindingTestCase>[1]) => bindingTestCase('SessionBinding', testCase);

const KB_JWT = ['[RFC9901] section 7.3'];
const DEVICE_AUTH = ['[OpenID4VP] section B.2.6', '[ISO/IEC 18013-5] section 9.1.3'];

/** SessionBinding_005: the presentation the Relying Party accepted in T1, sent again in T2. */
const replay = (format: FormatWording) =>
  sessionBinding({
    number: 5,
    variant: format.letter,
    format,
    objective: `Verify that the Relying Party rejects a valid presentation in ${format.name} format that was made for an earlier transaction and is sent again in a later one.`,
    references: ['[OpenID4VP] section 14.1, 14.1.2', ...(format === sdJwtVc ? KB_JWT : DEVICE_AUTH)],
    steps: [
      step({
        text: `Perform a presentation for ${QUERY_PID} (transaction T1) in which the Conformance Wallet presents ${PID} in a valid Authorization Response.`,
        run: presentation({ query: pidQueryOf(format.credentialFormat), credential: pid.of(format.credentialFormat) }),
        expect: acc({ credential: PID }),
      }),
      step({
        text: `Perform a presentation for ${QUERY_PID} (transaction T2) in which the Conformance Wallet sends an Authorization Response that is valid except that ${faultInfo('presentation.replay').text}.`,
        run: presentation({
          query: pidQueryOf(format.credentialFormat),
          credential: pid.of(format.credentialFormat),
          response: { faults: ['presentation.replay'], presentationOfStep: 1 },
        }),
        expect: rej(),
      }),
    ],
    comments: [
      `The presentation sent in T2 is the one the Relying Party accepted in T1, so ${format === sdJwtVc ? 'the `nonce` of its KB-JWT is that of the request of T1' : 'its device signature covers the SessionTranscript of T1'}. Only the transaction differs.`,
    ],
  });

export const definitions = [
  sessionBinding({
    number: 1,
    format: sdJwtVc,
    objective: 'Verify that the Relying Party rejects a presentation in SD-JWT VC format whose KB-JWT carries a `nonce` other than that of its request.',
    references: ['[OpenID4VP] section 14.1.2, B.3.6', ...KB_JWT],
    steps: [rejected('presentation.kb-nonce-other'), rejected('presentation.kb-nonce-missing')],
    comments: [oidf('invalid-kb-jwt-nonce')],
  }),
  sessionBinding({
    number: 2,
    format: sdJwtVc,
    flow: 'redirect',
    objective:
      'Verify that the Relying Party rejects a presentation in SD-JWT VC format via redirects whose KB-JWT is not addressed to its full Client Identifier.',
    references: ['[OpenID4VP] section 5.9.3, 14.1.2, 14.8, B.3.6', ...KB_JWT],
    steps: [
      rejected('presentation.kb-aud-other-client', 'redirect'),
      rejected('presentation.kb-aud-no-prefix', 'redirect'),
      rejected('presentation.kb-aud-missing', 'redirect'),
      rejected('presentation.kb-aud-array', 'redirect'),
    ],
    comments: ['The OIDF verifier test module `oid4vp-1final-verifier-invalid-kb-jwt-aud` covers the first step.'],
  }),
  sessionBinding({
    number: 3,
    format: sdJwtVc,
    objective: 'Verify that the Relying Party rejects a presentation in SD-JWT VC format whose KB-JWT was issued longer ago than the freshness window `T_kb`.',
    references: [...KB_JWT, '[OpenID4VP] section 14.1.2'],
    steps: [rejected('presentation.kb-iat-past')],
    comments: [oidf('kb-jwt-iat-in-past')],
  }),
  sessionBinding({
    number: 4,
    format: sdJwtVc,
    objective:
      'Verify that the Relying Party rejects a presentation in SD-JWT VC format whose KB-JWT issuance time lies further in the future than the clock tolerance `T_skew`.',
    references: [...KB_JWT, '[OpenID4VP] section 14.1.2'],
    steps: [rejected('presentation.kb-iat-future')],
    comments: [oidf('kb-jwt-iat-in-future')],
  }),
  replay(sdJwtVc),
  replay(mdoc),
  sessionBinding({
    number: 6,
    format: sdJwtVc,
    flow: 'dc-api',
    objective:
      'Verify that the Relying Party rejects a presentation in SD-JWT VC format via the W3C Digital Credentials API whose KB-JWT is addressed to its Client Identifier instead of the Origin of its page.',
    references: ['[OpenID4VP] section 5.9.3, A.4, B.3.6', ...KB_JWT],
    steps: [rejected('presentation.kb-aud-client-id', 'dc-api')],
  }),
  sessionBinding({
    number: 7,
    format: sdJwtVc,
    flow: 'dc-api',
    objective:
      'Verify that the Relying Party rejects a presentation in SD-JWT VC format via the W3C Digital Credentials API whose KB-JWT is addressed to the Origin of another page.',
    references: ['[OpenID4VP] section 5.9.3, A.4, B.3.6', ...KB_JWT],
    steps: [rejected('presentation.kb-aud-other-origin', 'dc-api')],
  }),
  sessionBinding({
    number: 8,
    format: mdoc,
    flow: 'redirect',
    objective:
      'Verify that the Relying Party rejects a presentation in mdoc format via redirects whose device signature covers a SessionTranscript that does not match its request.',
    references: DEVICE_AUTH,
    steps: [
      rejected('presentation.transcript-nonce', 'redirect'),
      rejected('presentation.transcript-client-id', 'redirect'),
      rejected('presentation.transcript-response-uri', 'redirect'),
      rejected('presentation.transcript-jwk-thumbprint', 'redirect'),
      rejected('presentation.transcript-client-id-no-prefix', 'redirect'),
      rejected('presentation.transcript-jwk-thumbprint-null', 'redirect'),
    ],
    comments: ['The OIDF verifier test module `oid4vp-1final-verifier-invalid-session-transcript` covers one of these steps.'],
  }),
  sessionBinding({
    number: 9,
    format: mdoc,
    flow: 'dc-api',
    objective:
      'Verify that the Relying Party rejects a presentation in mdoc format via the W3C Digital Credentials API whose device signature covers a SessionTranscript that does not match its request.',
    references: ['[OpenID4VP] section A.4', ...DEVICE_AUTH],
    steps: [
      rejected('presentation.transcript-origin', 'dc-api'),
      rejected('presentation.transcript-nonce', 'dc-api'),
      rejected('presentation.transcript-jwk-thumbprint', 'dc-api'),
      rejected('presentation.transcript-origin-prefixed', 'dc-api'),
    ],
  }),
  // Issue 10: the handover of the other flow, and an `exp` of the KB-JWT that is not a NumericDate.
  sessionBinding({
    number: 11,
    format: mdoc,
    flow: 'redirect',
    objective:
      'Verify that the Relying Party rejects a presentation in mdoc format via redirects whose device signature covers a SessionTranscript with the handover of the W3C Digital Credentials API (`OpenID4VPDCAPIHandover`) instead of `OpenID4VPHandover`.',
    references: ['[OpenID4VP] section B.2.6.1', ...DEVICE_AUTH],
    steps: [rejected('presentation.transcript-dcapi-handover', 'redirect')],
  }),
  sessionBinding({
    number: 12,
    format: mdoc,
    flow: 'dc-api',
    objective:
      'Verify that the Relying Party rejects a presentation in mdoc format via the W3C Digital Credentials API whose device signature covers a SessionTranscript with the handover of redirects (`OpenID4VPHandover`) instead of `OpenID4VPDCAPIHandover`.',
    references: ['[OpenID4VP] section B.2.6.2', ...DEVICE_AUTH],
    steps: [rejected('presentation.transcript-redirect-handover', 'dc-api')],
  }),
  sessionBinding({
    number: 13,
    format: sdJwtVc,
    objective: 'Verify that the Relying Party rejects a presentation in SD-JWT VC format whose KB-JWT carries an `exp` claim that is a string instead of a NumericDate.',
    references: ['[RFC7519] section 2, 4.1.4', ...KB_JWT],
    steps: [rejected('presentation.kb-exp-string')],
  }),
];
