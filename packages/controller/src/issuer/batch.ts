// Issue 26: batch issuance for the test cases that need a batch of one logical PID (`PP_WS_SM_Revocation_004`,
// `PP_WS_SM_Unlinkability_003`, `_004`). The issuance client sends one proof; this binding gives the Wallet Unit a KA over
// `batchSize` fresh keys and adds one `openid4vci-proof+jwt` per further attested key to the credential request
// (OpenID4VCI 1.0 section 8.2, `proofs.jwt` with several entries), each with the same `aud`, `nonce` and KA as the
// first. The credentials of the answer are then matched to their proof keys by the key they are bound to. Issue 25's
// session client implements batch issuance in full; this covers the valid batch only.
import { base64url, decodeCbor, decodeJws, type EcKeyPair } from '@eudi-pcaf/forge';
import { type IssuedCredential, keyProofParts, type MessageHooks, type WalletUnitBinding, walletUnitOf } from '@eudi-pcaf/issuer-wallet';
import { asMap, deviceKeyOfMso, readIssuerSigned, sameEcKey } from '@eudi-pcaf/validator';
import { keySigner, signJwt, type TestWalletProvider, type WalletUnitId } from '@eudi-pcaf/wallet-provider';

export interface BatchBinding {
  unit: WalletUnitBinding;
  hooks: MessageHooks;
  /** The attested keys of every KA the binding built, in order. */
  keys(): EcKeyPair[];
}

/** A Wallet Unit binding whose credential requests carry `batchSize` proofs over the keys of one KA. */
export function batchBinding(twp: TestWalletProvider, id: WalletUnitId, batchSize: number, base: WalletUnitBinding = walletUnitOf(twp, id)): BatchBinding {
  const built: EcKeyPair[][] = [];
  const unit: WalletUnitBinding = {
    ...base,
    keyAttestation: async () => {
      const ka = await twp.keyAttestation(id, { batchSize });
      built.push(ka.keys);
      return ka;
    },
  };
  const hooks: MessageHooks = {
    request: async (step, message) => {
      if (step !== 'credential' || !message.body) return message;
      const body = JSON.parse(message.body) as { proofs?: { jwt?: string[] } };
      const first = body.proofs?.jwt?.[0];
      const keys = built.at(-1);
      if (!first || !keys || body.proofs?.jwt?.length !== 1) return message;
      const { header, payload } = decodeJws(first);
      const more = await Promise.all(
        keys.slice(1).map((key) =>
          signJwt(
            keyProofParts({
              key,
              audience: payload.aud as string,
              ...(typeof payload.nonce === 'string' ? { nonce: payload.nonce } : {}),
              keyAttestation: header.key_attestation as string,
              ...(typeof payload.iss === 'string' ? { clientId: payload.iss } : {}),
            }),
            keySigner(key),
          ),
        ),
      );
      return { ...message, body: JSON.stringify({ ...body, proofs: { jwt: [first, ...more] } }) };
    },
  };
  return { unit, hooks, keys: () => built.flat() };
}

/** The key a credential is bound to: `cnf.jwk` of an SD-JWT VC, `deviceKeyInfo` of an mdoc. */
export function boundKeyOf(credential: Pick<IssuedCredential, 'format' | 'credential'>): JsonWebKey | undefined {
  try {
    if (credential.format === 'mso_mdoc') return deviceKeyOfMso(readIssuerSigned(asMap(decodeCbor(base64url.decode(credential.credential)), 'IssuerSigned')).mso);
    return (decodeJws(credential.credential.split('~')[0] as string).payload.cnf as { jwk?: JsonWebKey } | undefined)?.jwk;
  } catch {
    return undefined;
  }
}

/** Gives every credential of a batch the proof key it is bound to (the client records the first key for each). */
export function bindBatchKeys(credentials: IssuedCredential[], keys: EcKeyPair[]): void {
  for (const credential of credentials) {
    const bound = boundKeyOf(credential);
    const key = keys.find((candidate) => sameEcKey(candidate.publicJwk, bound));
    if (key) credential.proofKey = key;
  }
}
