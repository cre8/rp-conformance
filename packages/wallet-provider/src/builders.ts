// Builders for the WIA (`OAuth-Client-Attestation`), its proof of possession (`OAuth-Client-Attestation-PoP`) and the
// KA (OpenID4VCI 1.0 Appendix D). Every claim, the validity, the levels, the signer and the algorithm are parameters, so
// the fault layer (issue 18) can build each one-fault variant with the same functions. JWTs are assembled directly, as
// in the forge, so no library stands between a valid artifact and its deliberate fault.
import { randomUUID } from 'node:crypto';
import { base64url, type CertifiedKey, type EcKeyPair, type ForeignSigner, signEs256 } from '@eudi-pcaf/forge';
import type { Certificate } from '@owf/x509';
import {
  ISO_18045,
  type Iso18045Level,
  KA_CLAIMS,
  POP_CLAIMS,
  STATUS_OBJECT,
  type StatusReference,
  statusClaim,
  TYP,
  WIA_CLAIMS,
} from './claims';

const DAY_S = 24 * 60 * 60;

/** Whoever signs a JWS: the algorithm it claims, the chain it carries in `x5c` (if any), and the signature function. */
export interface JwsSigner {
  alg: string;
  /** Base64 DER, leaf first; omitted from the header when absent. */
  x5c?: string[];
  sign(signingInput: string): Promise<Uint8Array> | Uint8Array;
}

const b64 = (certificate: Certificate) => Buffer.from(certificate.der).toString('base64');

/** A signer of the test PKI: ES256 with its chain (without the anchor) in `x5c`. */
export const certifiedSigner = (key: CertifiedKey): JwsSigner => ({
  alg: 'ES256',
  x5c: key.chain.map(b64),
  sign: (input) => signEs256(key.key.privateKey, input),
});

/** A bare key: ES256, no `x5c` (the WIA's `cnf` key for the PoP). */
export const keySigner = (key: EcKeyPair): JwsSigner => ({ alg: 'ES256', sign: (input) => signEs256(key.privateKey, input) });

/** A key the test PKI does not generate with WebCrypto (ES256K, RS256), from the forge's `foreignSigner`. */
export const foreignJwsSigner = (signer: ForeignSigner, chain: Certificate[] = [signer.certificate]): JwsSigner => ({
  alg: signer.jwsAlg,
  x5c: chain.map(b64),
  sign: (input) => signer.sign(input),
});

/** Header and payload of a JWT before signing. */
export interface JwtParts {
  header: Record<string, unknown>;
  payload: Record<string, unknown>;
}

/** Overrides applied last: a member set to `undefined` is removed. */
export type Overrides = Record<string, unknown>;

function applyOverrides(target: Record<string, unknown>, overrides: Overrides | undefined) {
  for (const [name, value] of Object.entries(overrides ?? {})) {
    if (value === undefined) delete target[name];
    else target[name] = value;
  }
  return target;
}

/** Signs header and payload as a compact JWS with the signer; `header.alg` and `header.x5c` default to the signer's. */
export async function signJwt(parts: JwtParts, signer: JwsSigner): Promise<string> {
  const header: Record<string, unknown> = { alg: signer.alg, ...(signer.x5c ? { x5c: signer.x5c } : {}), ...parts.header };
  for (const [name, value] of Object.entries(header)) if (value === undefined) delete header[name];
  const signingInput = `${base64url.encode(JSON.stringify(header))}.${base64url.encode(JSON.stringify(parts.payload))}`;
  return `${signingInput}.${base64url.encode(await signer.sign(signingInput))}`;
}

const seconds = (date: Date) => Math.floor(date.getTime() / 1000);

/** What every attestation builder shares: the signer, the time, and overrides of any header member or claim. */
interface CommonOptions {
  signer: JwsSigner;
  /** Issuance time; default now. */
  now?: Date;
  /** `typ`; default the one of the artifact. */
  typ?: string;
  /** Header members set or (with `undefined`) removed last, `alg` and `x5c` included. */
  header?: Overrides;
  /** Claims set or (with `undefined`) removed last. */
  claims?: Overrides;
}

export interface WiaOptions extends CommonOptions {
  /** `sub`: the `client_id` of the Wallet Instance. */
  clientId: string;
  /** `cnf.jwk`: the public key that signs the PoP. */
  cnf: JsonWebKey;
  /** `client_status.status`. */
  status: StatusReference;
  /** `client_status.exp`: until when the Wallet Provider maintains the status (TS3 section 2.4.1). */
  maintenanceUntil: Date;
  walletName: string;
  walletVersion: string;
  walletLink?: string;
  certificationInformation?: string;
  /** `iss`; TS3 1.5 no longer requires it (the Wallet Provider follows from `x5c`), so it is left out unless given. */
  issuer?: string;
  /** Seconds from `iat` to `exp`; default one hour (TS3 section 2.2.1.1: less than 24 hours). */
  validitySeconds?: number;
  /** `nbf`; left out unless given. */
  notBefore?: Date;
}

/** Header and payload of a WIA (`typ` `oauth-client-attestation+jwt`). */
export function wiaParts(options: WiaOptions): JwtParts {
  const iat = seconds(options.now ?? new Date());
  const payload: Record<string, unknown> = {
    ...(options.issuer ? { [WIA_CLAIMS.issuer]: options.issuer } : {}),
    [WIA_CLAIMS.subject]: options.clientId,
    [WIA_CLAIMS.walletName]: options.walletName,
    [WIA_CLAIMS.walletVersion]: options.walletVersion,
    ...(options.walletLink ? { [WIA_CLAIMS.walletLink]: options.walletLink } : {}),
    ...(options.certificationInformation ? { [WIA_CLAIMS.certificationInformation]: options.certificationInformation } : {}),
    [WIA_CLAIMS.issuedAt]: iat,
    ...(options.notBefore ? { [WIA_CLAIMS.notBefore]: seconds(options.notBefore) } : {}),
    [WIA_CLAIMS.expiresAt]: iat + (options.validitySeconds ?? 60 * 60),
    [WIA_CLAIMS.clientStatus]: {
      [STATUS_OBJECT.status]: statusClaim(options.status),
      [STATUS_OBJECT.maintenanceExpiry]: seconds(options.maintenanceUntil),
    },
    [WIA_CLAIMS.confirmation]: { jwk: options.cnf },
  };
  return { header: { typ: options.typ ?? TYP.wia, ...options.header }, payload: applyOverrides(payload, options.claims) };
}

export const buildWia = async (options: WiaOptions) => signJwt(wiaParts(options), options.signer);

export interface WiaPopOptions extends CommonOptions {
  /** `iss`: the `client_id`, the WIA's `sub`. */
  clientId: string;
  /** `aud`: the issuer identifier of the Authorization Server. */
  audience: string;
  /** `jti`; default a fresh UUID. */
  jti?: string;
  /** `nonce` from the Authorization Server, when it provides one. */
  nonce?: string;
  /** Seconds from `iat` to `exp`; `exp` is left out unless given. */
  validitySeconds?: number;
}

/** Header and payload of the WIA's proof of possession (`typ` `oauth-client-attestation-pop+jwt`), signed with the `cnf` key. */
export function wiaPopParts(options: WiaPopOptions): JwtParts {
  const iat = seconds(options.now ?? new Date());
  const payload: Record<string, unknown> = {
    [POP_CLAIMS.issuer]: options.clientId,
    [POP_CLAIMS.audience]: options.audience,
    [POP_CLAIMS.jwtId]: options.jti ?? randomUUID(),
    [POP_CLAIMS.issuedAt]: iat,
    ...(options.validitySeconds !== undefined ? { [POP_CLAIMS.expiresAt]: iat + options.validitySeconds } : {}),
    ...(options.nonce !== undefined ? { [POP_CLAIMS.nonce]: options.nonce } : {}),
  };
  return { header: { typ: options.typ ?? TYP.wiaPop, ...options.header }, payload: applyOverrides(payload, options.claims) };
}

export const buildWiaPop = async (options: WiaPopOptions) => signJwt(wiaPopParts(options), options.signer);

export interface KeyAttestationOptions extends CommonOptions {
  /** `attested_keys`: public keys in the WSCD; as many as the batch size. */
  attestedKeys: JsonWebKey[];
  /** `key_storage`; default `[iso_18045_high]`. */
  keyStorage?: (Iso18045Level | string)[];
  /** `user_authentication`; default `[iso_18045_high]`. */
  userAuthentication?: (Iso18045Level | string)[];
  /** `certification`: where the WSCD's certification is described (TS3 section 2.3.2). */
  certification?: string;
  /** `key_storage_status.status`. */
  status: StatusReference;
  /** `key_storage_status.exp`: until when the Wallet Provider maintains the status (TS3 section 2.4.1). */
  maintenanceUntil: Date;
  /** The `c_nonce`, for the `attestation` proof type. */
  nonce?: string;
  /** `iss`; left out unless given, as for the WIA. */
  issuer?: string;
  /** Seconds from `iat` to `exp`; default 30 days. */
  validitySeconds?: number;
}

/** Header and payload of a KA (`typ` `key-attestation+jwt`). */
export function keyAttestationParts(options: KeyAttestationOptions): JwtParts {
  const iat = seconds(options.now ?? new Date());
  const payload: Record<string, unknown> = {
    ...(options.issuer ? { [KA_CLAIMS.issuer]: options.issuer } : {}),
    [KA_CLAIMS.issuedAt]: iat,
    [KA_CLAIMS.expiresAt]: iat + (options.validitySeconds ?? 30 * DAY_S),
    [KA_CLAIMS.attestedKeys]: options.attestedKeys,
    [KA_CLAIMS.keyStorage]: options.keyStorage ?? [ISO_18045.high],
    [KA_CLAIMS.userAuthentication]: options.userAuthentication ?? [ISO_18045.high],
    ...(options.certification ? { [KA_CLAIMS.certification]: options.certification } : {}),
    ...(options.nonce !== undefined ? { [KA_CLAIMS.nonce]: options.nonce } : {}),
    [KA_CLAIMS.keyStorageStatus]: {
      [STATUS_OBJECT.status]: statusClaim(options.status),
      [STATUS_OBJECT.maintenanceExpiry]: seconds(options.maintenanceUntil),
    },
  };
  return { header: { typ: options.typ ?? TYP.keyAttestation, ...options.header }, payload: applyOverrides(payload, options.claims) };
}

export const buildKeyAttestation = async (options: KeyAttestationOptions) => signJwt(keyAttestationParts(options), options.signer);
