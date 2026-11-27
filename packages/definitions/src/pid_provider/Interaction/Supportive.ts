// RP_PP_IA_Supportive: how the Relying Party retrieves status lists from the Test Status Provider: the request itself,
// caching within `ttl`, a fresh retrieval after `ttl`, endpoints that fail, redirect loops, and status URIs that point
// to a link-local address. Variant `a` is SD-JWT VC with a Status List Token in JWT format, `b` mdoc with CWT.
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
  nofetch,
  nostat,
  PID,
  pid,
  pidQueryOf,
  positiveControlOf,
  preconditions,
  presentation,
  presentationStep,
  QUERY_PID,
  rej,
  type Relevancy,
  relevancy,
  type StatusEndpoint,
  type StepDefinition,
  statusListFormatOf,
  statusListToken,
  step,
  testCaseId,
} from '@eudi-pcaf/core';

const sdJwtVc = formats.sdJwtVc;
const mdoc = formats.mdoc;

const mediaType = (format: FormatWording) => (format === sdJwtVc ? 'application/statuslist+jwt' : 'application/statuslist+cwt');
const tokenFormat = (format: FormatWording) => (format === sdJwtVc ? 'JWT' : 'CWT');
const COMMON_REFERENCES = ['[ARF] Annex 2, VCR_13, VCR_14', '[CIR 2024/2979 amended] Annex II'];

/** The `ttl` of the Status List Token in `_003`, seconds: the shortest the claim can carry. */
const SHORT_TTL = 1;
/** How long `_003` waits before its second presentation, seconds: past `ttl` with a margin for the clocks. */
const AFTER_TTL = SHORT_TTL + 4;
/** The index of the credentials of `_003`, which share one status list. */
const SHARED_INDEX = 5;
/** The link-local address of `_006`: the instance metadata address of most cloud providers. */
export const LINK_LOCAL_STATUS_URI = 'http://169.254.169.254/latest/meta-data/rp-conformance/status';

/**
 * `STATUS_REQUEST`: every request the Relying Party sent for the step's status list is a plain retrieval that carries
 * no authentication and nothing that identifies the user or the transaction.
 */
const statusRequest = (format: FormatWording): Expectation => ({
  codes: ['STATUS_REQUEST'],
  text: `Every request the Test Status Provider logs from the Relying Party for that status list is an HTTP \`GET\` of exactly the status \`uri\` of the credential, without a query component, without \`Authorization\` and \`Cookie\` headers, without the identifier of the transaction in its URI or headers, and with an \`Accept\` header, if it sends one, that admits \`${mediaType(format)}\`.`,
});

/** A presentation of `default_credential_pid` in `format` whose status list is served as `options` say. */
const withList = (format: FormatWording, options: Parameters<typeof statusListToken.jwt>[0] = {}, delaySeconds?: number) =>
  presentation({
    query: pidQueryOf(format.credentialFormat),
    credential: pid.of(format.credentialFormat),
    statusList: statusListToken.of(statusListFormatOf(format.credentialFormat), options),
    ...(delaySeconds ? { delaySeconds } : {}),
  });

/** A step whose status list endpoint fails as `endpoint` says, with the text of that failure. */
const failingEndpoint = (format: FormatWording, endpoint: StatusEndpoint, difference: string): StepDefinition =>
  step({
    text: `Perform a presentation for ${QUERY_PID} in which the Conformance Wallet presents ${PID} in a valid Authorization Response, while ${difference}.`,
    run: withList(format, { endpoint }),
    expect: nostat(),
  });

const stillAvailable = (format: FormatWording): StepDefinition =>
  step({
    ...presentationStep.valid({
      credential: pid.of(format.credentialFormat),
      text: {
        credential: `a newly issued ${PID}`,
        extra: ', immediately after the previous step, while the Test Status Provider serves a valid Status List Token for it that holds the value 0x00 at its index',
      },
    }),
    expect: acc({ credential: 'the newly issued credential' }),
  });

interface SupportiveTestCase {
  number: number;
  unhappyFlow: boolean;
  relevancy: Relevancy;
  objective: (format: FormatWording) => string;
  references: string[];
  steps: (format: FormatWording) => StepDefinition[];
  caching?: boolean;
  /** Replaces the precondition that every credential references a status list URI new to the Relying Party. */
  sharedList?: string;
  comments?: string[];
}

const supportive = (testCase: SupportiveTestCase) =>
  [sdJwtVc, mdoc].map((format) =>
    defineTestCase({
      id: testCaseId('PP', 'IA', 'Supportive', testCase.number, format.letter, testCase.unhappyFlow),
      objective: testCase.objective(format),
      references: [...testCase.references, ...COMMON_REFERENCES],
      profile: [format.profile, ics.checksPidRevocation, ...(testCase.caching ? [ics.cachesStatusLists] : [])],
      relevancy: testCase.relevancy,
      technology: [format.technology, format.statusListTechnology],
      preconditions: [
        ...preconditions.base,
        preconditions.control(positiveControlOf(format)),
        testCase.sharedList ?? preconditions.freshStatusList,
      ],
      control: positiveControlOf(format),
      steps: testCase.steps(format),
      comments: [...(testCase.comments ?? []), comments.flow],
    }),
  );

export const definitions = [
  ...supportive({
    number: 1,
    unhappyFlow: false,
    relevancy: relevancy.genericRequired,
    objective: (format) =>
      `Verify that the Relying Party retrieves a Status List Token in ${tokenFormat(format)} format with an HTTP \`GET\` of its URI, without authentication and without data that identifies the user or the transaction.`,
    references: ['[Token Status List] section 8.1, 8.3, 12', '[ARF] Annex 2, VCR_16'],
    steps: (format) => [
      step({
        ...presentationStep.valid({ credential: pid.of(format.credentialFormat) }),
        expect: all(acc({ credential: PID }), fetched(), statusRequest(format)),
      }),
    ],
    comments: [
      "[Token Status List] section 8.1 lets the Relying Party leave out the `Accept` header when the token's media type is known out of band, so its absence is no failure.",
    ],
  }),
  ...supportive({
    number: 2,
    unhappyFlow: false,
    relevancy: relevancy.specificOptional,
    caching: true,
    objective: (format) =>
      `Verify that the Relying Party that caches Status List Tokens retrieves a Status List Token in ${tokenFormat(format)} format at most once for two presentations that reference it within its \`ttl\`.`,
    references: ['[Token Status List] section 8.3, 11.5, 13.7', '[ARF] Annex 2, VCR_15'],
    sharedList:
      'The credential of the first step references a status list URI from which the Relying Party has not retrieved a status list before; the credential of the second step references the same status list at another index.',
    steps: (format) => [
      step({
        text: `Perform a presentation for ${QUERY_PID} in which the Conformance Wallet presents ${PID} in a valid Authorization Response, while the Test Status Provider serves a valid Status List Token for it with a \`ttl\` of 300 seconds that holds the value 0x00 at every index.`,
        run: withList(format, { ttl: 300 }),
        expect: all(acc({ credential: PID }), fetched()),
      }),
      step({
        text: `Immediately after the previous step, perform a presentation for ${QUERY_PID} in which the Conformance Wallet presents a newly issued ${PID} that references the same status list, in a valid Authorization Response.`,
        run: withList(format, { ttl: 300, uriOfStep: 1 }),
        expect: all(acc({ credential: 'the newly issued credential' }), nofetch()),
      }),
    ],
  }),
  ...supportive({
    number: 3,
    unhappyFlow: false,
    relevancy: relevancy.genericRequired,
    caching: true,
    objective: (format) =>
      `Verify that the Relying Party retrieves a fresh Status List Token in ${tokenFormat(format)} format once the \`ttl\` of the token it retrieved before has passed, and detects a revocation made in between.`,
    references: ['[Token Status List] section 8.3, 13.7', '[ARF] Annex 2, VCR_15'],
    sharedList: `Both credentials of this test case reference the same status list URI, from which the Relying Party has not retrieved a status list before, at the index ${SHARED_INDEX}.`,
    steps: (format) => [
      step({
        text: `Perform a presentation for ${QUERY_PID} in which the Conformance Wallet presents ${PID} in a valid Authorization Response, while the Test Status Provider serves a valid Status List Token for it with a \`ttl\` of ${SHORT_TTL} second that holds the value 0x00 at the credential's index.`,
        run: withList(format, { ttl: SHORT_TTL, index: SHARED_INDEX }),
        expect: all(acc({ credential: PID }), fetched()),
      }),
      step({
        text: `Let the Test Status Provider serve, at the same URI, a new Status List Token with a \`ttl\` of ${SHORT_TTL} second that holds the value 0x01 (INVALID) at that index; wait ${AFTER_TTL} seconds, longer than the \`ttl\`; then perform a presentation for ${QUERY_PID} in which the Conformance Wallet presents a newly issued ${PID} with the same status list reference in a valid Authorization Response.`,
        run: withList(format, { ttl: SHORT_TTL, index: SHARED_INDEX, status: 1, uriOfStep: 1 }, AFTER_TTL),
        expect: all(rej(), fetched()),
      }),
    ],
    comments: [
      `The token carries the shortest \`ttl\` the claim can express, ${SHORT_TTL} second, so the test case does not wait out a longer cache period. The second credential stands for the first one presented again: the Relying Party sees the same status list URI and index.`,
    ],
  }),
  ...supportive({
    number: 4,
    unhappyFlow: true,
    relevancy: relevancy.specificRequired,
    objective: (format) =>
      `Verify that the Relying Party makes no positive status statement when the endpoint of a Status List Token in ${tokenFormat(format)} format does not answer in time, refuses the connection or answers with an error, and decides within its declared timeout.`,
    references: ['[Token Status List] section 8.1, 8.3'],
    steps: (format) => [
      failingEndpoint(
        format,
        { kind: 'slow' },
        'the Test Status Provider answers the request for the referenced status list with a valid Status List Token holding the value 0x00 only after the timeout the Relying Party declares in its ICS plus ten seconds',
      ),
      failingEndpoint(
        format,
        { kind: 'refused' },
        'the status list `uri` of the credential names a port of the Test Status Provider host on which no server listens, so the connection is refused',
      ),
      failingEndpoint(format, { kind: 'status', status: 404 }, 'the Test Status Provider answers the request for the referenced status list with HTTP status 404'),
      failingEndpoint(format, { kind: 'status', status: 500 }, 'the Test Status Provider answers the request for the referenced status list with HTTP status 500'),
      failingEndpoint(
        format,
        { kind: 'status', status: 503, contentType: 'text/html', body: '<!doctype html><title>Service Unavailable</title><p>Service Unavailable</p>' },
        'the Test Status Provider answers the request for the referenced status list with HTTP status 503 and an HTML page instead of a Status List Token',
      ),
    ],
    comments: [
      'In the first step the Test Status Provider eventually serves a valid Status List Token, so a Relying Party that waits longer than its declared timeout (ICS RP.R.6) accepts the presentation.',
      comments.nostat,
    ],
  }),
  ...supportive({
    number: 5,
    unhappyFlow: true,
    relevancy: relevancy.genericRequired,
    objective: (format) =>
      `Verify that the Relying Party follows a redirect loop at the endpoint of a Status List Token in ${tokenFormat(format)} format only a bounded number of times, makes no positive status statement, and stays available.`,
    references: ['[Token Status List] section 8.1, 11.4'],
    steps: (format) => [
      failingEndpoint(
        format,
        { kind: 'redirect-loop' },
        'the Test Status Provider answers every request for the referenced status list with HTTP status 302 and a `Location` header naming that same URI',
      ),
      stillAvailable(format),
    ],
    comments: [
      'The Test Status Provider logs every request of the loop; the report shows how many redirects the Relying Party followed.',
      comments.nostat,
    ],
  }),
  ...supportive({
    number: 6,
    unhappyFlow: true,
    relevancy: relevancy.genericRequired,
    objective: (format) =>
      `Verify that the Relying Party rejects a credential in ${format.name} format whose status list \`uri\` points to a link-local address.`,
    references: ['[Token Status List] section 6.2, 8.1, 11.4'],
    steps: (format) => [
      step({
        text: `Perform a presentation for ${QUERY_PID} in which the Conformance Wallet presents, in an otherwise valid Authorization Response, a variant of ${PID} whose status list \`uri\` is \`${LINK_LOCAL_STATUS_URI}\`.`,
        run: withList(format, { endpoint: { kind: 'address', uri: LINK_LOCAL_STATUS_URI } }),
        expect: rej(),
      }),
    ],
    comments: [
      'The harness never sends a request to the link-local address, and cannot observe whether the Relying Party does; the report records the outcome only. A Relying Party configured to reach private networks, as test set-ups of the harness often are, may try the address and fail on it.',
    ],
  }),
];
