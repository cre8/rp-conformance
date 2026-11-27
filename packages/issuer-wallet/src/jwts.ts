// The JWTs the issuance client signs itself: the DPoP proof (RFC 9449) and the key proof of the credential request
// (`openid4vci-proof+jwt`, OpenID4VCI 1.0 Appendix F.1) with the KA in its `key_attestation` header. The WIA and its
// PoP come from the Test Wallet Provider. Each JWT is built as header and payload first and signed after, with the
// same `JwtParts` and `signJwt` as the Test Wallet Provider's builders, so the fault layer (issue 18) can change any
// member of a valid message, or sign it with another key, without a library refusing the result.
import { randomUUID } from 'node:crypto';
import { base64url, type EcKeyPair, sha256 } from '@eudi-pcaf/forge';
import { type JwsSigner, type JwtParts, keySigner, type Overrides, signJwt } from '@eudi-pcaf/wallet-provider';

/** JOSE `typ` values of the JWTs the client signs. */
export const CLIENT_TYP = {
  /** RFC 9449 section 4.2. */
  dpop: 'dpop+jwt',
  /** OpenID4VCI 1.0 Appendix F.1. */
  proof: 'openid4vci-proof+jwt',
} as const;

/** The JOSE header member that carries the KA in a `jwt` proof (OpenID4VCI 1.0 Appendix F.1). */
export const KEY_ATTESTATION_HEADER = 'key_attestation';

const seconds = (date: Date) => Math.floor(date.getTime() / 1000);

function applyOverrides(target: Record<string, unknown>, overrides: Overrides | undefined) {
  for (const [name, value] of Object.entries(overrides ?? {})) {
    if (value === undefined) delete target[name];
    else target[name] = value;
  }
  return target;
}

/** The public members of an EC JWK, as a JOSE header carries it. */
export const publicJwkOf = (jwk: JsonWebKey): JsonWebKey => ({ kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y });

/** `htu` of RFC 9449 section 4.2: the target URI without query and fragment. */
export function htuOf(url: string): string {
  const parsed = new URL(url);
  return `${parsed.origin}${parsed.pathname}`;
}

/** `ath` of RFC 9449 section 4.2: base64url SHA-256 of the access token's ASCII value. */
export const accessTokenHash = (accessToken: string) => base64url.encode(sha256(accessToken));

export interface DpopProofOptions {
  /** The DPoP key of the Wallet Unit; its public key goes into the `jwk` header. */
  key: EcKeyPair;
  /** `htm`: the HTTP method of the request. */
  method: string;
  /** The request URL; `htu` is derived with `htuOf`. */
  url: string;
  /** The access token the request presents; sets `ath`. */
  accessToken?: string;
  /** The server-provided `DPoP-Nonce`. */
  nonce?: string;
  /** `jti`; default a fresh UUID. */
  jti?: string;
  /** `iat`; default now. */
  now?: Date;
  /** Header members set or (with `undefined`) removed last. */
  header?: Overrides;
  /** Claims set or (with `undefined`) removed last. */
  claims?: Overrides;
}

/** Header and payload of a DPoP proof (RFC 9449 section 4.2). */
export function dpopProofParts(options: DpopProofOptions): JwtParts {
  const payload: Record<string, unknown> = {
    jti: options.jti ?? randomUUID(),
    htm: options.method.toUpperCase(),
    htu: htuOf(options.url),
    iat: seconds(options.now ?? new Date()),
    ...(options.accessToken !== undefined ? { ath: accessTokenHash(options.accessToken) } : {}),
    ...(options.nonce !== undefined ? { nonce: options.nonce } : {}),
  };
  const header = applyOverrides({ typ: CLIENT_TYP.dpop, jwk: publicJwkOf(options.key.publicJwk) }, options.header);
  return { header, payload: applyOverrides(payload, options.claims) };
}

export const buildDpopProof = (options: DpopProofOptions, signer: JwsSigner = keySigner(options.key)) => signJwt(dpopProofParts(options), signer);

export interface KeyProofOptions {
  /** The attested key that signs the proof; its public key goes into the `jwk` header. */
  key: EcKeyPair;
  /** `aud`: the Credential Issuer Identifier. */
  audience: string;
  /** `nonce`: the `c_nonce` from the nonce endpoint. */
  nonce?: string;
  /** The KA over `key`, carried in the `key_attestation` header. */
  keyAttestation?: string;
  /** `iss`: the `client_id`; OpenID4VCI 1.0 Appendix F.1 has it left out for anonymous pre-authorized access. */
  clientId?: string;
  /** `iat`; default now. */
  now?: Date;
  header?: Overrides;
  claims?: Overrides;
}

/** Header and payload of a key proof of proof type `jwt` (OpenID4VCI 1.0 Appendix F.1). */
export function keyProofParts(options: KeyProofOptions): JwtParts {
  const payload: Record<string, unknown> = {
    ...(options.clientId !== undefined ? { iss: options.clientId } : {}),
    aud: options.audience,
    iat: seconds(options.now ?? new Date()),
    ...(options.nonce !== undefined ? { nonce: options.nonce } : {}),
  };
  const header = applyOverrides(
    {
      typ: CLIENT_TYP.proof,
      jwk: publicJwkOf(options.key.publicJwk),
      ...(options.keyAttestation !== undefined ? { [KEY_ATTESTATION_HEADER]: options.keyAttestation } : {}),
    },
    options.header,
  );
  return { header, payload: applyOverrides(payload, options.claims) };
}

export const buildKeyProof = (options: KeyProofOptions, signer: JwsSigner = keySigner(options.key)) => signJwt(keyProofParts(options), signer);
