// RP_WS_SM_SessionEncryption: encryption of the Authorization Response. Variant `a` is redirects with
// `direct_post.jwt`, variant `b` the W3C Digital Credentials API with `dc_api.jwt`; the credential format does not matter.
import {
  acc,
  comments,
  defineTestCase,
  encryptionKeyOf,
  type Expectation,
  type FaultId,
  type Flow,
  flows,
  PID,
  positiveControlOf,
  formats,
  pid,
  preconditions,
  presentation,
  presentationStep,
  QUERY_PID,
  rej,
  relevancy,
  scenario,
  type StepDefinition,
  faultInfo,
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

/** Steps with a response fault; `text` replaces the scenario text where the DC API variant words the fault differently. */
const faulty = (flow: Flow, faults: FaultId[], text?: (fault: FaultId) => string) =>
  faults.map((fault) => step({ ...presentationStep.encryptionFault(flow, fault, text ? { text: text(fault) } : {}), expect: rej() }));

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
/** A step expected to be accepted, with the given response. */
const accepted = (text: string, response: { enc?: 'A128GCM' | 'A256GCM'; faults?: FaultId[] }): StepDefinition =>
  step({
    text,
    run: presentation({ query: 'default_query_pid', credential: pid.sdJwtVc(), response: { faults: [], ...response } }),
    expect: acc({ credential: PID }) as Expectation,
  });

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
          { enc },
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
    steps: (flow) => faulty(flow, ['response.unencrypted']),
  }),
  ...sessionEncryption({
    number: 4,
    flows: BOTH,
    unhappyFlow: true,
    objective: (flow) => `Verify that the Relying Party rejects an Authorization Response ${via(flow)} encrypted to a key it did not issue.`,
    steps: (flow) => faulty(flow, ['response.foreign-key']),
  }),
  ...sessionEncryption({
    number: 5,
    flows: BOTH,
    unhappyFlow: true,
    objective: (flow) => `Verify that the Relying Party rejects an Authorization Response ${via(flow)} encrypted to the ephemeral key of another transaction.`,
    steps: (flow) => [
      step({
        text: `Start a presentation for ${QUERY_PID} ${via(flow)} (transaction T1) and record the encryption key from the \`client_metadata\` of its request. Send no response for T1.`,
        run: { kind: 'start', query: 'default_query_pid' },
        expect: encryptionKeyOf('T1'),
      }),
      step({
        text: `Perform a presentation for ${QUERY_PID} ${via(flow)} (transaction T2) in which ${faultInfo('response.other-transaction-key').text}.`,
        run: presentation({ query: 'default_query_pid', credential: pid.sdJwtVc(), response: { faults: ['response.other-transaction-key'], keyOfStep: 1 } }),
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
    steps: (flow) => faulty(flow, ['response.alg-ecdh-es-a128kw', 'response.alg-ecdh-es-a256kw']),
    references: ['[RFC7518] section 4.6'],
  }),
  ...sessionEncryption({
    number: 7,
    flows: BOTH,
    unhappyFlow: true,
    objective: (flow) => `Verify that the Relying Party rejects an Authorization Response ${via(flow)} encrypted with a content encryption algorithm it did not list.`,
    steps: (flow) => faulty(flow, ['response.enc-a128cbc-hs256']),
    references: ['[RFC7518] section 5.2'],
  }),
  ...sessionEncryption({
    number: 8,
    flows: BOTH,
    unhappyFlow: true,
    objective: (flow) => `Verify that the Relying Party rejects an Authorization Response ${via(flow)} whose JWE was modified.`,
    steps: (flow) => faulty(flow, ['response.ciphertext-bitflip', 'response.tag-bitflip']),
    references: ['[RFC7516] section 5.2'],
  }),
  ...sessionEncryption({
    number: 9,
    flows: BOTH,
    unhappyFlow: true,
    objective: (flow) => `Verify that the Relying Party rejects an Authorization Response ${via(flow)} whose ephemeral public key is not a valid P-256 point.`,
    steps: (flow) => faulty(flow, ['response.epk-off-curve', 'response.epk-p384']),
    references: ['[RFC7518] section 4.6', '[RFC8725] section 3.4'],
  }),
  ...sessionEncryption({
    number: 10,
    flows: BOTH,
    unhappyFlow: true,
    objective: (flow) => `Verify that the Relying Party rejects an Authorization Response ${via(flow)} that is signed or unsecured instead of encrypted.`,
    // The fault wording names the `response` parameter of the redirect flow; via the DC API it is a member of `data`.
    steps: (flow) =>
      faulty(flow, ['response.jws', 'response.alg-none'], (fault) =>
        scenario.encryption(flow, faultInfo(fault).text.replace('the `response` parameter', responseOf(flow))),
      ),
    references: ['[RFC8725] section 3.1'],
  }),
  ...sessionEncryption({
    number: 11,
    flows: ['dc-api'],
    unhappyFlow: true,
    objective: () => 'Verify that the Relying Party rejects an unencrypted Authorization Response via the W3C Digital Credentials API.',
    steps: (flow) => faulty(flow, ['response.dc-api-unencrypted']),
  }),
  ...sessionEncryption({
    number: 12,
    flows: BOTH,
    unhappyFlow: false,
    objective: (flow) => `Verify that the Relying Party ignores unrecognised members in a decrypted Authorization Response ${via(flow)}.`,
    steps: (flow) => [
      accepted(
        `Perform a presentation for ${QUERY_PID} ${via(flow)} in which the Conformance Wallet presents ${PID} in a valid Authorization Response whose ${faultInfo('response.extra-member').text.replace(/^its /, '')}.`,
        { faults: ['response.extra-member'] },
      ),
    ],
    references: ['[OpenID4VP] section 8.1'],
  }),
];
