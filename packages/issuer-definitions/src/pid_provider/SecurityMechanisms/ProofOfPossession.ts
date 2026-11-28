// PP_WS_SM_ProofOfPossession: the key proofs (`openid4vci-proof+jwt`) at the credential endpoint, issuer catalogue
// section 5.1.3. One definition per test case and variant; the variants run so far are `SD` × `PA`, as for the
// positive control `PP_WS_IA_MainInteraction_001`, and `SD` × `AC` for `_007_UF`, which the catalogue restricts to the
// authorization code flow.
import { type FormatVariant, type GrantVariant, type IssuerTestCaseDefinition, issuerProfiles, relevancy } from '@eudi-pcaf/core';
import { FORMAT_NAMES, GRANT_NAMES, iss, pidProfile } from '../../wording';
import { faultStep, rejected, validStep, securityTestCase } from './attestations';

const F1 = '[OpenID4VCI] Appendix F.1';

const testCase = securityTestCase({ relevancy: relevancy.genericRequired });

const invalidProof = rejected('invalid_proof');

/**
 * `REJ:<code>, then ISS`: the faulty request is refused, the same request with a fresh `c_nonce` succeeds. A proof
 * without `nonce` is `invalid_proof`, a proof with a wrong one `invalid_nonce` (OpenID4VCI 1.0 section 8.3.1.2).
 */
const refusedThenIssued = (format: FormatVariant, code: 'invalid_nonce' | 'invalid_proof') => ({
  codes: [`REJ:${code}` as const, 'ISS' as const],
  text: `The Provider refuses the credential request with HTTP 4xx and \`error\` \`${code}\`, never HTTP 5xx. The Conformance Wallet then fetches a fresh \`c_nonce\` from the nonce endpoint and sends the request again with a valid proof over it, with the same access token: ${iss(format).text}`,
});

function proofOfPossession(format: FormatVariant, grant: GrantVariant): IssuerTestCaseDefinition[] {
  const id = (n: string) => `PP_WS_SM_ProofOfPossession_${n}`;
  const where = `at the credential endpoint in the ${GRANT_NAMES[grant]}`;
  return [
    testCase(format, grant, {
      id: id('001_UF'),
      objective: `Verify that the PID Provider rejects a key proof with an invalid signature ${where}.`,
      references: [F1, '[OpenID4VCI] Appendix F.4'],
      steps: [faultStep(format, grant, 'proof.signature-bitflip', invalidProof)],
    }),
    testCase(format, grant, {
      id: id('002_UF'),
      objective: `Verify that the PID Provider rejects a key proof with \`alg\` \`none\`, a MAC algorithm, or an algorithm outside the ECCG agreed cryptographic mechanisms ${where}.`,
      references: [F1, '[ARF] Annex 2, OIA_03', '[RFC8725] section 3.1'],
      relevancy: relevancy.specificRequired,
      steps: (['proof.alg-none', 'proof.hs256', 'proof.es256k'] as const).map((fault) => faultStep(format, grant, fault, invalidProof)),
    }),
    testCase(format, grant, {
      id: id('003_UF'),
      objective: `Verify that the PID Provider rejects a key proof whose \`typ\` is not \`openid4vci-proof+jwt\` ${where}.`,
      references: [F1],
      steps: [faultStep(format, grant, 'proof.typ-jwt', invalidProof), faultStep(format, grant, 'proof.typ-missing', invalidProof)],
    }),
    testCase(format, grant, {
      id: id('004_UF'),
      objective: `Verify that the PID Provider rejects a key proof whose \`aud\` is not its Credential Issuer identifier ${where}.`,
      references: [F1],
      steps: [faultStep(format, grant, 'proof.aud-other', invalidProof), faultStep(format, grant, 'proof.aud-missing', invalidProof)],
    }),
    testCase(format, grant, {
      id: id('005_UF'),
      objective: `Verify that the PID Provider rejects a key proof with a missing, unknown or already used \`nonce\` with \`invalid_nonce\` ${where}, and issues when the request is sent again with a fresh \`c_nonce\`.`,
      references: ['[OpenID4VCI] sections 7 and 8.3.1.2', F1],
      profile: [...pidProfile(format, grant), issuerProfiles['P-DPN']],
      steps: [
        validStep(format, grant, { why: 'its `c_nonce` is replayed in the last step' }),
        faultStep(format, grant, 'proof.nonce-missing', refusedThenIssued(format, 'invalid_proof'), { retryWithFreshNonce: true }),
        ...(['proof.nonce-random', 'proof.nonce-replayed'] as const).map((fault) =>
          faultStep(format, grant, fault, refusedThenIssued(format, 'invalid_nonce'), { retryWithFreshNonce: true }),
        ),
      ],
      comments: [
        'The catalogue names `invalid_nonce` for all three stimuli. OpenID4VCI 1.0 section 8.3.1.2 makes a key proof without a `c_nonce` an `invalid_proof` and only a proof with an invalid `c_nonce` an `invalid_nonce`; the step without `nonce` follows the specification.',
      ],
    }),
    testCase(format, grant, {
      id: id('006_UF'),
      objective: `Verify that the PID Provider rejects a key proof whose \`iat\` is outside \`T_proof\` ${where}: one hour too old, or one hour in the future.`,
      references: [F1],
      steps: [faultStep(format, grant, 'proof.iat-past', invalidProof), faultStep(format, grant, 'proof.iat-future', invalidProof)],
      comments: ['`T_proof` and `T_skew` are those the Provider declares (ICS-14), capped at 5 minutes each (catalogue section 3.5).'],
    }),
    ...(grant === 'AC'
      ? [
          testCase(format, grant, {
            id: id('007_UF'),
            objective: `Record how the PID Provider treats a key proof whose \`iss\` differs from the \`client_id\` ${where}.`,
            references: [F1, '[OpenID4VCI] Appendix F.4'],
            relevancy: relevancy.genericOptional,
            steps: [
              faultStep(format, grant, 'proof.iss-other', {
                codes: ['INFO'],
                text: 'Whether the Provider rejects the request (`invalid_proof`) or issues the PID is recorded; HTTP 5xx fails. The proof violates Appendix F.1 ("The value of this claim MUST be the `client_id` of the Client making the Credential request"), but the checks a Credential Issuer MUST make in Appendix F.4 do not include `iss`.',
              }),
            ],
            comments: [
              'Informational since the spec review of 2026-11-20 (issuer catalogue section 8.3): F.1 binds the wallet, and F.4 lists no `iss` check. Rejecting the proof is the hardened behaviour.',
            ],
          }),
        ]
      : []),
    testCase(format, grant, {
      id: id('008_UF'),
      objective: `Verify that the PID Provider rejects a key proof whose \`jwk\` header carries a private key, or which carries more than one of \`jwk\`, \`kid\` and \`x5c\`, ${where}.`,
      references: [F1, '[RFC7517] section 4'],
      steps: [faultStep(format, grant, 'proof.jwk-private', invalidProof), faultStep(format, grant, 'proof.jwk-and-x5c', invalidProof)],
    }),
    testCase(format, grant, {
      id: id('009_UF'),
      objective: `Verify that the PID Provider rejects a key proof whose key is not a point on its curve, or is on a curve the Provider does not advertise (P-521), ${where}.`,
      references: [F1, '[RFC8725] section 3.4'],
      steps: [faultStep(format, grant, 'proof.off-curve', invalidProof), faultStep(format, grant, 'proof.p521', invalidProof)],
      comments: [
        'The P-521 step applies where the credential configuration does not list `ES512` in `proof_signing_alg_values_supported` of the `jwt` proof type; otherwise the harness records it as NOT APPLICABLE and the test case is judged on its other step.',
      ],
    }),
    testCase(format, grant, {
      id: id('010'),
      objective: `Verify that the PID Provider binds the PID in ${FORMAT_NAMES[format]} format to the key of the key proof: ${format === 'SD' ? '`cnf.jwk`' : '`deviceKeyInfo`'} equals the proof key.`,
      references: ['[ARF] Annex 2, ISSU_17, WUA_09a', F1],
      relevancy: relevancy.specificRequired,
      steps: [
        {
          ...validStep(format, grant),
          expect: {
            codes: ['CONF'],
            checks: ['holder-binding'],
            text: `The Provider issues the PID; it passes every check of \`ISS\`, and its ${format === 'SD' ? '`cnf.jwk`' : '`deviceKeyInfo`'} is the public key of the key proof (\`holder-binding\`).`,
          },
        },
      ],
    }),
  ];
}

export const definitions = [...proofOfPossession('SD', 'PA'), ...proofOfPossession('SD', 'AC').filter((d) => d.id.endsWith('_007_UF'))];
