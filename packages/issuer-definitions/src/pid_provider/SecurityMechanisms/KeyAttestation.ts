// PP_WS_SM_KeyAttestation: the KA at the credential endpoint, in the `key_attestation` header of the key proof and as
// the `attestation` proof type, issuer catalogue section 5.1.3. One definition per test case and variant; the variants
// run so far are `SD` × `PA`, as for the positive control `PP_WS_IA_MainInteraction_001`.
import { type FormatVariant, type GrantVariant, type IssuerExpectation, type IssuerTestCaseDefinition, issuerProfiles, relevancy } from '@eudi-pcaf/core';
import { FORMAT_NAMES, GRANT_NAMES, iss, pidProfile } from '../../wording';
import { faultStep, issuanceStep, maintenanceConf, rejected, revocationStep, STATUS_LIST_FAULTS, STATUS_LIST_HTTP, statusListSteps, validStep, securityTestCase } from './attestations';

const OPENID4VCI = '[OpenID4VCI] Appendix D';

const testCase = securityTestCase({ relevancy: relevancy.specificRequired });

const invalidProof = rejected('invalid_proof');

/** `PP_WS_SM_KeyAttestation_007_UF` steps 3 and 4: the `nonce` of a KA in a `jwt` proof is not checked by a rule of the Credential Issuer. */
const jwtNonceInfo: IssuerExpectation = {
  codes: ['INFO'],
  text: 'Whether the Provider rejects the request or issues the PID is recorded; HTTP 5xx fails. OpenID4VCI 1.0 Appendix F.4 and TS3 section 2.2.2.2 require the `c_nonce` in the `jwt` proof, which carries it, not in its KA.',
};

function keyAttestation(format: FormatVariant, grant: GrantVariant): IssuerTestCaseDefinition[] {
  const id = (n: string) => `PP_WS_SM_KeyAttestation_${n}`;
  const where = `at the credential endpoint in the ${GRANT_NAMES[grant]}`;
  return [
    testCase(format, grant, {
      id: id('001'),
      objective: `Verify that the PID Provider accepts a valid KA from the Wallet Provider \`WP-A\` ${where}, in the key proof's \`key_attestation\` header and as the \`attestation\` proof type, and binds every credential to one of its \`attested_keys\`.`,
      references: ['[ARF] Annex 2, WUA_09a, WUA_11a, WUA_12', '[OpenID4VCI] Appendix D, Appendix F.1 and F.3'],
      steps: [
        validStep(format, grant),
        issuanceStep(
          format,
          grant,
          'all valid except that the credential request carries the KA, with the `c_nonce` in its `nonce` claim, as the only proof of proof type `attestation` instead of a `jwt` proof',
          { ...iss(format), text: `${iss(format).text} The credential is bound to the key the KA attests.` },
          { proofType: 'attestation' },
        ),
      ],
      comments: [
        'The `attestation` proof type is run where the Provider\'s metadata lists it in `proof_types_supported` of the configuration; EUDIPLO does.',
        'The valid half of every `PP_WS_SM_KeyAttestation_*_UF` test case of the same variant; `holder-binding` of `ISS` checks the binding to an attested key.',
      ],
    }),
    testCase(format, grant, {
      id: id('002_UF'),
      objective: `Verify that the PID Provider rejects a PID request without KA ${where}.`,
      references: ['[ARF] Annex 2, WUA_05, WUA_11a, ISSU_21', OPENID4VCI],
      steps: [faultStep(format, grant, 'ka.missing', invalidProof)],
      comments: ['PID only.'],
    }),
    testCase(format, grant, {
      id: id('003_UF'),
      objective: `Verify that the PID Provider rejects a KA with an invalid signature ${where}.`,
      references: ['[ARF] Annex 2, WUA_11a', '[OpenID4VCI] Appendix D and F.4'],
      steps: [faultStep(format, grant, 'ka.signature-bitflip', invalidProof)],
    }),
    testCase(format, grant, {
      id: id('004_UF'),
      objective: `Verify that the PID Provider rejects a KA signed under an anchor that \`TL-WP\` does not publish ${where}: \`CA-X\`, \`PP-A\`, the withdrawn \`WP-W\`; and record how it treats a KA under \`WP-A\`'s WIA CA.`,
      references: ['[ARF] Annex 2, ISSU_21, ISSU_28, ISSU_30', '[TS3] section 2.2.2.2', '[ETSI TS 119 602]'],
      steps: [
        ...(['ka.signer-ca-x', 'ka.signer-pp-a', 'ka.signer-wp-w'] as const).map((fault) => faultStep(format, grant, fault, invalidProof)),
        faultStep(format, grant, 'ka.signer-wia-ca', {
          codes: ['INFO'],
          text: 'Whether the Provider rejects the KA or issues the PID is recorded; HTTP 5xx fails. Both conform: TS3 section 2.2.2.2 requires a chain to "a trust anchor found on the Trusted List for Wallet Providers", which the WIA CA of `WP-A` is.',
        }),
      ],
      comments: [
        'Stimulus (d) is informational since the spec review of 2026-11-20 (issuer catalogue section 8.3): TS3 and ARF ISSU_28 and ISSU_30 bind the anchors to the Wallet Provider, not to one of its services, and TS3 section 3.2, which is informative, maps no KA field to a service.',
      ],
    }),
    testCase(format, grant, {
      id: id('005_UF'),
      objective: `Verify that the PID Provider rejects an expired KA ${where}.`,
      references: [OPENID4VCI, '[RFC7519] section 4.1.4'],
      relevancy: relevancy.genericRequired,
      steps: [faultStep(format, grant, 'ka.exp-past', invalidProof)],
    }),
    testCase(format, grant, {
      id: id('006_UF'),
      objective: `Verify that the PID Provider rejects a key proof signed with a key that the KA does not list in \`attested_keys\` ${where}.`,
      references: ['[ARF] Annex 2, WUA_09a, WUA_12', '[OpenID4VCI] Appendix D and F.1'],
      steps: [faultStep(format, grant, 'proof.key-not-attested', invalidProof)],
    }),
    testCase(format, grant, {
      id: id('007_UF'),
      objective: `Verify that the PID Provider, which offers a nonce endpoint, rejects a KA without \`nonce\` sent as the \`attestation\` proof type ${where}, and record how it treats the \`nonce\` of a KA in the \`key_attestation\` header of a \`jwt\` proof.`,
      references: ['[ARF] Annex 2, WUA_10b', '[OpenID4VCI] Appendix D.1, F.1, F.3 and F.4', '[TS3] section 2.2.2.2'],
      profile: [...pidProfile(format, grant), issuerProfiles['P-DPN']],
      steps: [
        validStep(format, grant, { unit: 'CW-2', why: 'its `c_nonce` is the nonce of another session in the next step' }),
        validStep(format, grant, { why: 'the KA carries the `c_nonce` of this request in its `nonce` claim', action: { keyAttestationNonce: true } }),
        faultStep(format, grant, 'ka.nonce-other-session', jwtNonceInfo, { keyAttestationNonce: true }),
        faultStep(format, grant, 'ka.nonce-missing', jwtNonceInfo, { keyAttestationNonce: true }),
        faultStep(format, grant, 'ka.nonce-missing', rejected(['invalid_nonce', 'invalid_proof']), { proofType: 'attestation' }),
      ],
      comments: [
        'As the `attestation` proof type the KA is the key proof, so OpenID4VCI 1.0 Appendix F.4 ("if the server has a Nonce Endpoint, the nonce in the key proof matches the server-provided `c_nonce` value") and TS3 section 2.2.2.2 require its `c_nonce`: step 5 expects the rejection.',
        'In a `jwt` proof (steps 3 and 4) the nonce that F.4 and TS3 section 2.2.2.2 ("the `jwt` element includes a valid `c_nonce`") require is the proof\'s own, which is valid. Appendix F.1 says the KA\'s `nonce` "MUST be set to a server-provided `c_nonce`", a rule for the wallet that F.4 does not turn into a check of the Credential Issuer; step 4 is the same request as the valid baseline of the area. Both steps are informational since the spec review of 2026-11-20 (issuer catalogue section 8.3).',
      ],
    }),
    testCase(format, grant, {
      id: id('008_UF'),
      objective: `Verify that the PID Provider rejects the KA of a revoked WSCD ${where}.`,
      references: ['[ARF] Annex 2, ISSU_21, ISSU_30, WUA_11a', '[Token Status List]', '[TS3] section 2.5'],
      steps: [revocationStep('ka'), issuanceStep(format, grant, 'all valid; its KA refers to the revoked entry', rejected())],
    }),
    testCase(format, grant, {
      id: id('009_UF'),
      objective: `Verify that the PID Provider issues no PID ${where} when the status of the KA cannot be obtained: the list is unreachable, or it is a Status List Token with a bad signature, expired, malformed or signed under a wrong anchor.`,
      references: ['[ARF] Annex 2, ISSU_21, WUA_11a', '[Token Status List] sections 5.1 and 8.3', '[TS3] section 2.5'],
      steps: [
        ...STATUS_LIST_HTTP.flatMap((status) => statusListSteps(format, grant, 'ka', status)),
        ...STATUS_LIST_FAULTS.flatMap((fault) => statusListSteps(format, grant, 'ka', fault)),
      ],
      comments: [
        'The stimuli of `PP_WS_SM_ClientAttestation_013_UF`, applied to the status reference of the KA.',
        'A PID Provider rejects (decision 2); an Attestation Provider follows its ICS-18 policy (`POLICY`).',
      ],
    }),
    testCase(format, grant, {
      id: id('010_UF'),
      objective: `Verify that the PID Provider rejects a KA whose \`key_storage\` or \`user_authentication\` is below \`iso_18045_high\` or absent ${where}.`,
      references: ['[ARF] Annex 2, WUA_34, ISSU_27d, WIAM_14b', OPENID4VCI],
      steps: (
        [
          'ka.key-storage-moderate',
          'ka.key-storage-basic',
          'ka.key-storage-absent',
          'ka.user-authentication-moderate',
          'ka.user-authentication-basic',
          'ka.user-authentication-absent',
        ] as const
      ).map((fault) => faultStep(format, grant, fault, invalidProof)),
      comments: ['PID only.'],
    }),
    testCase(format, grant, {
      id: id('011'),
      objective: `Verify that the PID Provider issues the PID in ${FORMAT_NAMES[format]} format with an expiry no later than the end of the KA's revocation maintenance period, when that period ends in 31 days.`,
      references: ['[ARF] Annex 2, ISSU_12c, WUA_30', '[TS3] sections 2.4.1, 2.4.2 and 2.4.3'],
      steps: [faultStep(format, grant, 'ka.maintenance-31-days', maintenanceConf(format, 'KA'))],
      comments: [
        'PID only. The WIA keeps its maintenance period of more than a year, so only the KA bounds the expiry.',
        'An EUDI/TS3 requirement (TS3 section 2.4.3, ARF ISSU_12c). The stimulus is 31 days, the remaining period TS3 section 2.4.2 guarantees; it was 30 days before the spec review of 2026-11-20.',
      ],
    }),
    testCase(format, grant, {
      id: id('012_UF'),
      objective: `Verify that the PID Provider rejects a KA whose \`typ\` is \`JWT\`, and a KA signed with \`ES256K\`, ${where}.`,
      references: ['[OpenID4VCI] Appendix D.1', '[ARF] Annex 2, WUA_04', '[ECCG ACM]'],
      steps: [faultStep(format, grant, 'ka.typ-jwt', invalidProof), faultStep(format, grant, 'ka.es256k', invalidProof)],
    }),
    testCase(format, grant, {
      id: id('013_UF'),
      objective: `Verify how the PID Provider treats a KA of another Wallet Unit, valid in itself, sent with this Wallet Unit's WIA ${where}: it rejects the request, or the outcome is recorded.`,
      references: ['[ARF] Annex 2, WUA_10b', '[TS3] section 2.2'],
      relevancy: relevancy.specificOptional,
      steps: [
        faultStep(format, grant, 'ka.other-unit', {
          codes: ['REJ', 'INFO'],
          oneOf: true,
          text: 'The Provider rejects the request with HTTP 4xx and an OAuth or OpenID4VCI error object, or the outcome (a PID bound to a key of `CW-2`) is recorded in the report; never HTTP 5xx.',
        }),
      ],
      comments: ['Nothing in the request links the KA to the WIA, so a Provider cannot tell the two Wallet Units apart; the catalogue records the behaviour.'],
    }),
  ];
}

export const definitions = keyAttestation('SD', 'PA');
