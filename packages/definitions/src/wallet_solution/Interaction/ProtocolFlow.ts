// RP_WS_IA_ProtocolFlow: how the Relying Party handles the steps of a presentation around the presentation itself
// (catalogue scenario SCN-F): its `request_uri` (content type, retrieved twice, with POST and `wallet_nonce`, of a
// finished or unknown transaction), the same-device redirect with its response code (single use, forged, another user
// session, not followed), the wallet's error responses, a late response, a second response, and the `state`. The
// request-side test cases capture the requests without answering them, as in `RP_WS_MS_*`; the others are gated on the
// positive control `RP_WS_IA_MainInteraction_001a`.
import {
  acc,
  comments,
  defineTestCase,
  type ErrorResponseAction,
  type Expectation,
  type Flow,
  type FlowAction,
  faultInfo,
  flows,
  type IcsCondition,
  ics,
  PID,
  pid,
  pidQueryOf,
  preconditions,
  presentation,
  QUERY_PID,
  type Relevancy,
  rej,
  relevancy,
  type StepDefinition,
  step,
  testCaseId,
  type WalletBehaviour,
} from '@eudi-pcaf/core';
import { requestTestCase } from '../requests';

const CONTROL = 'RP_WS_IA_MainInteraction_001a';
const SD_JWT_VC = 'Presentation of a credential in IETF SD-JWT VC format.';

const requestSide = (testCase: Omit<Parameters<typeof requestTestCase>[0], 'layer' | 'area'>) =>
  requestTestCase({ layer: 'IA', area: 'ProtocolFlow', ...testCase });

interface FlowTestCase {
  number: number;
  unhappyFlow: boolean;
  /** The flow the objective is about; left out when it applies to every flow. */
  flow?: Flow;
  objective: string;
  references: string[];
  relevancy?: Relevancy;
  profile?: IcsCondition[];
  preconditions?: string[];
  steps: StepDefinition[];
  comments?: string[];
}

/** A flow test case: a presentation of `default_credential_pid` in SD-JWT VC format and the steps that continue it. */
const flowTestCase = (testCase: FlowTestCase) =>
  defineTestCase({
    id: testCaseId('WS', 'IA', 'ProtocolFlow', testCase.number, '', testCase.unhappyFlow),
    objective: testCase.objective,
    references: [...testCase.references, '[CIR 2024/2982 amended] Annex II'],
    profile: [ics.requestsSdJwtVc, ...(testCase.flow ? [flows[testCase.flow].profile] : []), ...(testCase.profile ?? [])],
    relevancy: testCase.relevancy ?? relevancy.genericRequired,
    technology: [SD_JWT_VC, ...(testCase.flow ? [flows[testCase.flow].technology] : [])],
    preconditions: [...preconditions.base, ...(testCase.unhappyFlow ? [preconditions.control(CONTROL)] : []), ...(testCase.preconditions ?? [])],
    ...(testCase.unhappyFlow ? { control: CONTROL } : {}),
    steps: testCase.steps,
    comments: [...(testCase.comments ?? []), ...(testCase.flow ? [] : [comments.flow])],
  });

/** A valid presentation of `default_credential_pid` in SD-JWT VC format, with the wallet's deviation from the plain flow. */
const valid = (wallet?: WalletBehaviour) => presentation({ query: pidQueryOf('dc+sd-jwt'), credential: pid.sdJwtVc(), ...(wallet ? { wallet } : {}) });
const continues = (ofStep: number, behaviour: FlowAction['behaviour']): FlowAction => ({ kind: 'flow', ofStep, behaviour });
const errorResponse = (error: ErrorResponseAction['error']): ErrorResponseAction => ({ kind: 'error-response', query: 'default_query_pid', error });

/** A presentation via redirects whose `redirect_uri` the Conformance Wallet does not open, as text. */
const presentedT = (transaction: string) =>
  `Perform a presentation for ${QUERY_PID} via redirects (transaction ${transaction}) in which the Conformance Wallet presents ${PID} in a valid Authorization Response, and does not open the \`redirect_uri\` the Relying Party returns.`;

const accepted = acc({ credential: PID });

const redirectWithCode = (): Expectation => ({
  codes: ['REDIRECT'],
  text: 'The `response_uri` answers with HTTP status 200 and `Content-Type` `application/json`, with a `redirect_uri` that carries a `response_code` of at least 22 characters from the base64url alphabet (at least 128 bits) that differs from that of every earlier transaction of the test case.',
});
const released = (transaction: string): Expectation => ({
  codes: ['RELEASED'],
  text: `The front end of the Relying Party shows the user agent the result of ${transaction}: it releases the attributes of its verification result.`,
});
const withheld = (transaction: string): Expectation => ({
  codes: ['WITHHELD'],
  text: `The front end of the Relying Party releases no attribute of ${transaction} to the user agent, and does not answer with HTTP status 5xx.`,
});
const requestRefused = (): Expectation => ({
  codes: ['REQUEST_REFUSED'],
  text: 'The `request_uri` answers with an HTTP status 4xx and does not return a request object.',
});
const errorAcknowledged = (): Expectation => ({
  codes: ['ERROR_ACK', 'REJ'],
  text: 'The `response_uri` answers with HTTP status 200 and `Content-Type` `application/json`. The verification result of the transaction reports a failure and releases no attribute value.',
});
const resendRejected = (): Expectation => ({
  codes: ['RESEND_REJ'],
  text: 'The `response_uri` answers the second Authorization Response with an HTTP status 4xx, and the verification result of T1 still reports success with the attributes released in step 1.',
});

const RESPONSE_CODE = ['[OpenID4VP] section 8.2, 13.3', '[HAIP] section 5.1'];
const FRONT_END: IcsCondition[] = [ics.redeemsResponseCode];
const FRONT_END_TEXT =
  'The response code protects against session fixation: only the user agent in which the transaction was started, and which the wallet sends back with the `redirect_uri`, receives the result. The front end of the Relying Party is opened in the user agent that started the transaction, which keeps its session (for example a cookie), or in a fresh user agent without it.';

export const definitions = [
  requestSide({
    number: 1,
    flow: 'redirect',
    objective: 'Verify that the `request_uri` of the Relying Party returns the request object with the media type `application/oauth-authz-req+jwt`.',
    references: ['[RFC9101] section 5.2', '[OpenID4VP] section 5.10.1'],
    checks: ['request-uri-content-type'],
    rule: 'The `request_uri` answers with `Content-Type` `application/oauth-authz-req+jwt`.',
  }),
  requestSide({
    number: 2,
    flow: 'redirect',
    objective: 'Verify that the request object of the Relying Party can be retrieved from its `request_uri` more than once.',
    references: ['[OpenID4VP] section 5.10', '[RFC9101] section 5.2'],
    checks: ['request-uri-refetch'],
    rule: 'The second retrieval returns HTTP status 200 with a request object of the same `client_id`.',
    requestUri: {
      method: 'twice',
      text: `Start a presentation for ${QUERY_PID} via redirects; the Conformance Wallet retrieves the request object from the \`request_uri\` with GET, and then a second time with GET, without answering the request.`,
    },
    comments: [comments.oidf('oid4vp-1final-verifier-request-uri-fetched-twice')],
  }),
  requestSide({
    number: 3,
    flow: 'redirect',
    relevancy: relevancy.genericOptional,
    profile: [ics.usesRequestUriPost],
    objective: 'Verify that the Relying Party, when it sets `request_uri_method` to `post`, returns the `wallet_nonce` the wallet posts in the signed request object.',
    references: ['[OpenID4VP] section 5.10, 5.10.1'],
    checks: ['wallet-nonce'],
    rule: 'The invocation URI carries `request_uri_method` `post`, and the request object returned to the POST carries the posted `wallet_nonce`.',
    requestUri: {
      method: 'post',
      text: `Start a presentation for ${QUERY_PID} via redirects; the Conformance Wallet retrieves the request object with an HTTP POST to the \`request_uri\` that carries \`wallet_metadata\` and a newly generated \`wallet_nonce\`, without answering the request.`,
    },
    comments: [comments.oidf('oid4vp-1final-verifier-request-uri-method-post')],
  }),
  flowTestCase({
    number: 4,
    unhappyFlow: true,
    flow: 'redirect',
    objective: 'Verify that the `request_uri` of the Relying Party returns no request object for a completed transaction or an unknown one.',
    references: ['[OpenID4VP] section 5.10, 14.1'],
    steps: [
      step({
        text: `Perform a presentation for ${QUERY_PID} via redirects (transaction T1) in which the Conformance Wallet presents ${PID} in a valid Authorization Response.`,
        run: valid(),
        expect: accepted,
      }),
      step({ text: 'Retrieve the `request_uri` of T1 again with GET.', run: continues(1, 'request-uri-again'), expect: requestRefused() }),
      step({
        text: 'Start a second presentation (transaction T2) without retrieving its request, and retrieve with GET a `request_uri` that equals that of T1 except that every part in which the `request_uri`s of T1 and T2 differ is replaced by a random value of the same form.',
        run: continues(1, 'request-uri-unknown'),
        expect: requestRefused(),
      }),
    ],
    comments: [
      'An expired transaction is not part of this test case: `RP_WS_IA_ProtocolFlow_011_UF` covers what the Relying Party accepts after the transaction lifetime.',
    ],
  }),
  flowTestCase({
    number: 5,
    unhappyFlow: false,
    flow: 'redirect',
    objective: 'Verify that the Relying Party answers a valid Authorization Response via redirects with a `redirect_uri` that carries a fresh response code.',
    references: [...RESPONSE_CODE, '[OpenID4VP] section 14.2'],
    steps: [
      step({ text: presentedT('T1'), run: valid({ redirect: 'none' }), expect: { ...accepted, codes: ['ACC', 'REDIRECT'], text: `${accepted.text} ${redirectWithCode().text}` } }),
      step({ text: presentedT('T2'), run: valid({ redirect: 'none' }), expect: { ...accepted, codes: ['ACC', 'REDIRECT'], text: `${accepted.text} ${redirectWithCode().text}` } }),
    ],
    comments: [
      'The response code is read from the `response_code` parameter of the `redirect_uri`. Its entropy is judged by its length and alphabet, as for `nonce` and `state` in `RP_WS_MS_ProtocolMessages_003` and `_004`.',
    ],
  }),
  flowTestCase({
    number: 6,
    unhappyFlow: true,
    flow: 'redirect',
    profile: FRONT_END,
    objective: 'Verify that the Relying Party does not complete a transaction via redirects towards the user when the wallet does not open the `redirect_uri`.',
    references: RESPONSE_CODE,
    steps: [
      step({ text: presentedT('T1'), run: valid({ redirect: 'none' }), expect: accepted }),
      step({
        text: 'In the user agent that started T1, open the front end of the Relying Party for T1 without the `redirect_uri`.',
        run: continues(1, 'front-end'),
        expect: withheld('T1'),
      }),
      step({ text: 'In the user agent that started T1, open the `redirect_uri` of T1.', run: continues(1, 'redirect-same'), expect: released('T1') }),
    ],
    comments: [FRONT_END_TEXT, 'Step 3 shows that the front end releases the result once the `redirect_uri` is opened.'],
  }),
  flowTestCase({
    number: 7,
    unhappyFlow: true,
    flow: 'redirect',
    profile: FRONT_END,
    objective: 'Verify that the front end of the Relying Party releases no result when the `redirect_uri` of a transaction is opened in another user session.',
    references: [...RESPONSE_CODE, '[OpenID4VP] section 14.2'],
    steps: [
      step({ text: presentedT('T1'), run: valid({ redirect: 'none' }), expect: accepted }),
      step({
        text: 'Open the `redirect_uri` of T1 in a fresh user agent, which has no session of the user agent that started T1.',
        run: continues(1, 'redirect-fresh'),
        expect: withheld('T1'),
      }),
    ],
    comments: [FRONT_END_TEXT],
  }),
  flowTestCase({
    number: 8,
    unhappyFlow: true,
    flow: 'redirect',
    profile: FRONT_END,
    objective: 'Verify that the front end of the Relying Party redeems a response code once only.',
    references: RESPONSE_CODE,
    steps: [
      step({ text: presentedT('T1'), run: valid({ redirect: 'none' }), expect: accepted }),
      step({ text: 'In the user agent that started T1, open the `redirect_uri` of T1.', run: continues(1, 'redirect-same'), expect: released('T1') }),
      step({ text: 'In the same user agent, open the `redirect_uri` of T1 a second time.', run: continues(1, 'redirect-same'), expect: withheld('T1') }),
    ],
    comments: [FRONT_END_TEXT],
  }),
  flowTestCase({
    number: 9,
    unhappyFlow: true,
    flow: 'redirect',
    profile: FRONT_END,
    objective: 'Verify that the front end of the Relying Party releases no result for a forged response code.',
    references: RESPONSE_CODE,
    steps: [
      step({ text: presentedT('T1'), run: valid({ redirect: 'none' }), expect: accepted }),
      step({
        text: 'In the user agent that started T1, open the `redirect_uri` of T1 with its `response_code` replaced by a random value of the same length and alphabet.',
        run: continues(1, 'redirect-forged'),
        expect: withheld('T1'),
      }),
    ],
    comments: [FRONT_END_TEXT],
  }),
  flowTestCase({
    number: 10,
    unhappyFlow: false,
    flow: 'redirect',
    objective: 'Verify that the Relying Party ends a transaction as failed when the wallet answers with an Authorization Error Response, and acknowledges it with HTTP status 200.',
    references: ['[OpenID4VP] section 8.2, 8.3.1, 8.5'],
    steps: [
      step({
        text: `Start a presentation for ${QUERY_PID} via redirects; the Conformance Wallet answers with an unencrypted Authorization Error Response with \`error\` \`access_denied\` and the \`state\` of the request, posted to the \`response_uri\`.`,
        run: errorResponse('access_denied'),
        expect: errorAcknowledged(),
      }),
      step({
        text: `Start a second presentation for ${QUERY_PID} via redirects; the Conformance Wallet answers it in the same way with \`error\` \`invalid_request\`.`,
        run: errorResponse('invalid_request'),
        expect: errorAcknowledged(),
      }),
    ],
    comments: [
      '[OpenID4VP] section 8.3.1 permits the wallet to send an error response unencrypted even when the request asks for response mode `direct_post.jwt`.',
    ],
  }),
  flowTestCase({
    number: 11,
    unhappyFlow: true,
    objective: 'Verify that the Relying Party rejects an Authorization Response that arrives after the lifetime of its transaction.',
    references: ['[OpenID4VP] section 14.1'],
    preconditions: ['The Relying Party declares its transaction lifetime `T_tx` in its ICS (RP.P.7).'],
    steps: [
      step({
        text: `Start a presentation for ${QUERY_PID}; the Conformance Wallet retrieves the request at once, and sends a valid Authorization Response that presents ${PID} only when \`T_tx\` plus 2 seconds have passed since the start.`,
        run: valid({ late: true }),
        expect: rej(),
      }),
    ],
  }),
  flowTestCase({
    number: 12,
    unhappyFlow: true,
    flow: 'redirect',
    objective: 'Verify that the Relying Party rejects a second Authorization Response for a completed transaction and keeps the result of the first.',
    references: ['[OpenID4VP] section 14.1, 14.3.2'],
    steps: [
      step({
        text: `Perform a presentation for ${QUERY_PID} via redirects (transaction T1) in which the Conformance Wallet presents ${PID} in a valid Authorization Response.`,
        run: valid(),
        expect: accepted,
      }),
      step({ text: 'Post the identical Authorization Response of step 1 to the `response_uri` of T1 again.', run: continues(1, 'resend'), expect: resendRejected() }),
    ],
  }),
  flowTestCase({
    number: 13,
    unhappyFlow: true,
    flow: 'redirect',
    relevancy: relevancy.genericOptional,
    objective: 'Verify that the Relying Party rejects an Authorization Response whose `state` is not that of its request, or is missing, when the request carries a `state`.',
    references: ['[OpenID4VP] section 5.2, 14.3.2'],
    preconditions: ['The requests of the Relying Party via redirects carry a `state`.'],
    steps: (['response.state-other', 'response.state-missing'] as const).map((fault) =>
      step({
        text: `Perform a presentation for ${QUERY_PID} via redirects in which the Conformance Wallet presents ${PID} in an Authorization Response that is valid except that ${faultInfo(fault).text}.`,
        run: presentation({ query: pidQueryOf('dc+sd-jwt'), credential: pid.sdJwtVc(), response: { faults: [fault] } }),
        expect: rej(),
      }),
    ),
    comments: ['A Relying Party whose requests carry no `state` does not meet the precondition, and the test case does not apply to it.'],
  }),
  flowTestCase({
    number: 14,
    unhappyFlow: false,
    flow: 'dc-api',
    objective: 'Verify that the Relying Party ends a transaction via the W3C Digital Credentials API as failed when the wallet returns an error object.',
    references: ['[OpenID4VP] section A.4'],
    steps: [
      step({
        text: `Start a presentation for ${QUERY_PID} via the W3C Digital Credentials API; the Conformance Wallet resolves the request and returns the \`data\` object \`{"error": "access_denied"}\` to the page.`,
        run: errorResponse('access_denied'),
        expect: rej(),
      }),
    ],
    comments: [
      'A cancelled request (the promise of `navigator.credentials.get` rejected) reaches only the page of the Relying Party; neither OpenID4VP nor HAIP defines what the page reports to its back end, so this test case does not cover it.',
    ],
  }),
];
