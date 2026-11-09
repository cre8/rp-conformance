// RP_WS_SM_SessionEncryption: encryption of the Authorization Response. Variant `a` is redirects with
// `direct_post.jwt`, variant `b` the W3C Digital Credentials API with `dc_api.jwt`; the credential format does not matter.
import {
  acc,
  comments,
  defineTestCase,
  encryptionKeyOf,
  type Expectation,
  type Flow,
  flows,
  PID,
  positiveControlOf,
  formats,
  preconditions,
  QUERY_PID,
  rej,
  relevancy,
  scenario,
  type StepDefinition,
  step,
  testCaseId,
} from '@rp-conformance/core';

const REFERENCES: Record<Flow, string[]> = {
  redirect: ['[HAIP] section 5, 5.1', '[OpenID4VP] section 8.3, 8.3.1'],
  'dc-api': ['[HAIP] section 5, 5.2', '[OpenID4VP] section 8.3, A.4'],
};
const ARF: Record<Flow, string> = { redirect: '[ARF] Annex 2, OIA_03b, OIA_03c', 'dc-api': '[ARF] Annex 2, OIA_08, OIA_08a' };
const referencesOf = (flow: Flow, ...extra: string[]) => [...REFERENCES[flow], ...extra, ARF[flow], '[CIR 2024/2982 amended] Annex II'];

const CONTROLS: [string, string] = [positiveControlOf(formats.sdJwtVc), positiveControlOf(formats.mdoc)];

const via = (flow: Flow) => flows[flow].via;
/** Where the encrypted response travels. */
const responseOf = (flow: Flow) => (flow === 'redirect' ? 'the `response` parameter' : 'the `response` member of the returned `data` object');
const rejected = (flow: Flow, differences: string[]) =>
  differences.map((difference) => step({ text: scenario.encryption(flow, difference), expect: rej() }));

interface EncryptionTestCase {
  number: number;
  flows: Flow[];
  unhappyFlow: boolean;
  objective: (flow: Flow) => string;
  steps: (flow: Flow) => StepDefinition[];
  references?: string[];
}

const sessionEncryption = (testCase: EncryptionTestCase) =>
  testCase.flows.map((flow) =>
    defineTestCase({
      id: testCaseId('WS', 'SM', 'SessionEncryption', testCase.number, testCase.flows.length > 1 ? flows[flow].letter : '', testCase.unhappyFlow),
      objective: testCase.objective(flow),
      references: referencesOf(flow, ...(testCase.references ?? [])),
      profile: [flows[flow].profile],
      relevancy: relevancy.genericRequired,
      technology: [flows[flow].technology],
      preconditions: [...preconditions.base, preconditions.controlOfFlow(CONTROLS)],
      control: CONTROLS,
      steps: testCase.steps(flow),
      comments: [comments.encryptionFormat],
    }),
  );

const BOTH: Flow[] = ['redirect', 'dc-api'];
const accepted = (text: string): StepDefinition => step({ text, expect: acc({ credential: PID }) as Expectation });

export const definitions = [
  ...(['A128GCM', 'A256GCM'] as const).flatMap((enc, i) =>
    sessionEncryption({
      number: i + 1,
      flows: BOTH,
      unhappyFlow: false,
      objective: (flow) => `Verify that the Relying Party accepts an Authorization Response ${via(flow)} encrypted with \`ECDH-ES\` on P-256 and \`${enc}\`.`,
      steps: (flow) => [
        accepted(
          `Perform a presentation for ${QUERY_PID} ${via(flow)} in which the Conformance Wallet presents ${PID} in a valid Authorization Response, encrypted as a JWE with \`alg\` \`ECDH-ES\` (P-256) and \`enc\` \`${enc}\` to the encryption key from the \`client_metadata\` of the request.`,
        ),
      ],
      references: ['[RFC7516] section 5.2', '[RFC7518] section 4.6, 5.3'],
    }),
  ),
  ...sessionEncryption({
    number: 3,
    flows: ['redirect'],
    unhappyFlow: true,
    objective: () => 'Verify that the Relying Party rejects an unencrypted Authorization Response when it requested response mode `direct_post.jwt`.',
    steps: (flow) =>
      rejected(flow, [
        'it is not encrypted: the Conformance Wallet posts `vp_token` and `state` as form parameters to the `response_uri`, as in response mode `direct_post`',
      ]),
  }),
  ...sessionEncryption({
    number: 4,
    flows: BOTH,
    unhappyFlow: true,
    objective: (flow) => `Verify that the Relying Party rejects an Authorization Response ${via(flow)} encrypted to a key it did not issue.`,
    steps: (flow) =>
      rejected(flow, [
        "it is encrypted to a newly generated P-256 key that the Relying Party did not issue, while the JWE header carries the `kid` of the Relying Party's encryption key",
      ]),
  }),
  ...sessionEncryption({
    number: 5,
    flows: BOTH,
    unhappyFlow: true,
    objective: (flow) => `Verify that the Relying Party rejects an Authorization Response ${via(flow)} encrypted to the ephemeral key of another transaction.`,
    steps: (flow) => [
      step({
        text: `Start a presentation for ${QUERY_PID} ${via(flow)} (transaction T1) and record the encryption key from the \`client_metadata\` of its request. Send no response for T1.`,
        expect: encryptionKeyOf('T1'),
      }),
      step({
        text: `Perform a presentation for ${QUERY_PID} ${via(flow)} (transaction T2) in which the Conformance Wallet encrypts an otherwise valid Authorization Response for T2 to the encryption key recorded for T1, with the \`kid\` of that key.`,
        expect: rej(),
      }),
    ],
  }),
  ...sessionEncryption({
    number: 6,
    flows: BOTH,
    unhappyFlow: true,
    objective: (flow) =>
      `Verify that the Relying Party rejects an Authorization Response ${via(flow)} encrypted with a key management algorithm other than \`ECDH-ES\`.`,
    steps: (flow) =>
      rejected(flow, [
        "its JWE uses `alg` `ECDH-ES+A128KW` with the Relying Party's encryption key",
        "its JWE uses `alg` `ECDH-ES+A256KW` with the Relying Party's encryption key",
      ]),
    references: ['[RFC7518] section 4.6'],
  }),
  ...sessionEncryption({
    number: 7,
    flows: BOTH,
    unhappyFlow: true,
    objective: (flow) => `Verify that the Relying Party rejects an Authorization Response ${via(flow)} encrypted with a content encryption algorithm it did not list.`,
    steps: (flow) => rejected(flow, ['its JWE uses `enc` `A128CBC-HS256`']),
    references: ['[RFC7518] section 5.2'],
  }),
  ...sessionEncryption({
    number: 8,
    flows: BOTH,
    unhappyFlow: true,
    objective: (flow) => `Verify that the Relying Party rejects an Authorization Response ${via(flow)} whose JWE was modified.`,
    steps: (flow) => rejected(flow, ['one bit of its JWE ciphertext is flipped', 'one bit of its JWE authentication tag is flipped']),
    references: ['[RFC7516] section 5.2'],
  }),
  ...sessionEncryption({
    number: 9,
    flows: BOTH,
    unhappyFlow: true,
    objective: (flow) => `Verify that the Relying Party rejects an Authorization Response ${via(flow)} whose ephemeral public key is not a valid P-256 point.`,
    steps: (flow) =>
      rejected(flow, [
        'the `epk` header of its JWE holds coordinates that are not a point on P-256',
        'the `epk` header of its JWE holds a key on curve P-384',
      ]),
    references: ['[RFC7518] section 4.6', '[RFC8725] section 3.4'],
  }),
  ...sessionEncryption({
    number: 10,
    flows: BOTH,
    unhappyFlow: true,
    objective: (flow) => `Verify that the Relying Party rejects an Authorization Response ${via(flow)} that is signed or unsecured instead of encrypted.`,
    steps: (flow) =>
      rejected(flow, [
        `${responseOf(flow)} is a JWS signed with a key of the Conformance Wallet instead of a JWE`,
        `${responseOf(flow)} is an unsecured JWT with \`alg\` \`none\` instead of a JWE`,
      ]),
    references: ['[RFC8725] section 3.1'],
  }),
  ...sessionEncryption({
    number: 11,
    flows: ['dc-api'],
    unhappyFlow: true,
    objective: () => 'Verify that the Relying Party rejects an unencrypted Authorization Response via the W3C Digital Credentials API.',
    steps: (flow) =>
      rejected(flow, [
        'it is not encrypted: the `data` object returned through the Digital Credentials API carries the `vp_token` directly instead of an encrypted `response`',
      ]),
  }),
  ...sessionEncryption({
    number: 12,
    flows: BOTH,
    unhappyFlow: false,
    objective: (flow) => `Verify that the Relying Party ignores unrecognised members in a decrypted Authorization Response ${via(flow)}.`,
    steps: (flow) => [
      accepted(
        `Perform a presentation for ${QUERY_PID} ${via(flow)} in which the Conformance Wallet presents ${PID} in a valid Authorization Response whose decrypted payload additionally contains the member \`foo\` with the value \`bar\`.`,
      ),
    ],
    references: ['[OpenID4VP] section 8.1'],
  }),
];
