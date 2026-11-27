// The fault layer of the issuer suite at the points `wia`, `wia-pop`, `ka` and `proof` (issuer harness design section
// 6.2). Every fault of `ISSUER_FAULTS` (@eudi-pcaf/core) is a pure change of a valid message: the Test Wallet
// Provider and the issuance client build the WIA, PoP, KA and proof valid, and the fault decodes one of them, changes it
// and signs it again, with the original signer or the one the fault names. Where a library would refuse the result
// (another key, `alg` `none`, `HS256`, `ES256K`, P-521, a point off the curve), the JWT is assembled directly.
//
// `applyIssuerFault` returns what the issuance client needs to send an issuance with exactly that fault: a
// `WalletUnitBinding` (for faults of the WIA, and the KA of another Wallet Unit) and `MessageHooks` (`jwt` for the PoP,
// the KA in the proof header and the proof's claims; `request` for omitted headers and re-signed proofs). A test
// definition (issue 19) names the fault only.
import { createHmac, createPublicKey, generateKeyPairSync, randomUUID, sign as nodeSign, X509Certificate } from 'node:crypto';
import { type IssuerFaultId, issuerFaultInfo } from '@eudi-pcaf/core';
import { base64url, type EcKeyPair, flipBitInSegment, foreignSigner, generateEcKeyPair, type TestEntity } from '@eudi-pcaf/forge';
import {
  CLIENT_ATTESTATION_HEADER,
  CLIENT_ATTESTATION_POP_HEADER,
  certifiedSigner,
  foreignJwsSigner,
  ISO_18045,
  type JwsSigner,
  type JwtParts,
  keySigner,
  signerFor,
  signJwt,
  type TestWalletProvider,
  type WalletUnitId,
} from '@eudi-pcaf/wallet-provider';
import { type JwtHook, type KeyAttestationWithKeys, type MessageHooks, type WalletUnitBinding, walletUnitOf } from './client';
import type { HttpRequestMessage, RequestHook } from './http';
import { KEY_ATTESTATION_HEADER, publicJwkOf } from './jwts';

const HOUR = 3600;
const DAY = 24 * HOUR;

export interface IssuerFaultContext {
  twp: TestWalletProvider;
  /** The Wallet Unit of the issuance; the faults that name `WP-A`'s CAs need a unit of `WP-A` (`CW-1`, `CW-2`). */
  unit: WalletUnitId;
  /** Default the current time when the message is built. */
  now?: Date;
  /** `T_skew` of the SUT, seconds; default 300 (catalogue section 3.5). */
  skewSeconds?: number;
  /** `T_proof` of the SUT, seconds; default 300. */
  proofWindowSeconds?: number;
  /** Values of an earlier issuance of the same Wallet Unit, for `proof.nonce-replayed` and `wia-pop.jti-replayed`. */
  replay?: { cNonce?: string; popJti?: string };
  /** A `c_nonce` the SUT issued to another session, for `ka.nonce-other-session`. */
  otherSessionCNonce?: string;
  /** The KA carries the `c_nonce` (catalogue `P-DPN` where the SUT requires it); the valid baseline of `ka.nonce-missing`. */
  keyAttestationNonce?: boolean;
}

export interface AppliedIssuerFault {
  unit: WalletUnitBinding;
  hooks: MessageHooks;
}

// ----------------------------------------------------------------------------------------------------- JOSE

/** Header and payload of a compact JWS, as independent copies. */
export function partsOf(compact: string): JwtParts {
  const [h, p] = compact.split('.');
  return { header: base64url.decodeJson(h ?? ''), payload: base64url.decodeJson(p ?? '') };
}

/** Signs changed parts with a signer; the old `alg` and `x5c` give way to the signer's. */
function resign(parts: JwtParts, signer: JwsSigner): Promise<string> {
  const { alg: _alg, x5c: _x5c, ...header } = parts.header;
  return signJwt({ header, payload: parts.payload }, signer);
}

const encode = (value: unknown) => base64url.encode(JSON.stringify(value));

/** An unsecured JWT (`alg` `none`, empty signature). */
const unsecured = (parts: JwtParts) => `${encode({ ...parts.header, alg: 'none' })}.${encode(parts.payload)}.`;

/** `HS256` keyed with the PEM of a public key: the algorithm confusion of RFC 8725 section 2.1. */
function hs256(parts: JwtParts, publicJwk: JsonWebKey): string {
  const input = `${encode({ ...parts.header, alg: 'HS256' })}.${encode(parts.payload)}`;
  const pem = createPublicKey({ key: publicJwk as never, format: 'jwk' }).export({ type: 'spki', format: 'pem' }).toString();
  return `${input}.${base64url.encode(createHmac('sha256', pem).update(input).digest())}`;
}

const leafJwkOf = (parts: JwtParts): JsonWebKey => {
  const [leaf] = parts.header.x5c as string[];
  return new X509Certificate(Buffer.from(leaf, 'base64')).publicKey.export({ format: 'jwk' }) as JsonWebKey;
};

/** A key pair outside WebCrypto's ES256: secp256k1 (`ES256K`) or P-521 (`ES512`), signing in IEEE P1363 form. */
function foreignKey(kind: 'secp256k1' | 'P-521') {
  const { publicKey, privateKey } = generateKeyPairSync('ec', { namedCurve: kind === 'P-521' ? 'secp521r1' : 'secp256k1' });
  const alg = kind === 'P-521' ? 'ES512' : 'ES256K';
  const hash = kind === 'P-521' ? 'sha512' : 'sha256';
  const signer: JwsSigner = { alg, sign: (input) => new Uint8Array(nodeSign(hash, Buffer.from(input), { key: privateKey, dsaEncoding: 'ieee-p1363' })) };
  return { publicJwk: publicJwkOf(publicKey.export({ format: 'jwk' }) as JsonWebKey), signer };
}

/** A copy of a P-256 public JWK whose `y` is no longer on the curve. */
function offCurve(jwk: JsonWebKey): JsonWebKey {
  const y = base64url.decode(jwk.y ?? '');
  y[y.length - 1] ^= 0x01;
  return { ...publicJwkOf(jwk), y: base64url.encode(y) };
}

const headerName = (headers: Record<string, string>, name: string) => Object.keys(headers).find((key) => key.toLowerCase() === name.toLowerCase());

function withoutHeaders(request: HttpRequestMessage, names: string[]): HttpRequestMessage {
  const headers = { ...request.headers };
  for (const name of names) {
    const key = headerName(headers, name);
    if (key) delete headers[key];
  }
  return { ...request, headers };
}

async function replaceHeader(request: HttpRequestMessage, name: string, change: (value: string) => Promise<string>): Promise<HttpRequestMessage> {
  const key = headerName(request.headers, name);
  if (!key) throw new Error(`the request carries no ${name} header`);
  return { ...request, headers: { ...request.headers, [key]: await change(request.headers[key]) } };
}

async function replaceProofs(request: HttpRequestMessage, change: (proof: string) => Promise<string>): Promise<HttpRequestMessage> {
  const body = JSON.parse(request.body ?? '{}') as { proofs?: { jwt?: string[] } };
  const proofs = body.proofs?.jwt;
  if (!proofs?.length) throw new Error('the credential request carries no proofs.jwt');
  body.proofs!.jwt = await Promise.all(proofs.map(change));
  return { ...request, body: JSON.stringify(body) };
}

// --------------------------------------------------------------------------------------- WIA and KA changes

/** What a fault of the WIA or KA does to the valid attestation: change claims, sign with another signer, or post-process. */
interface AttestationFault {
  change?: (parts: JwtParts, values: Values) => void;
  signer?: (values: Values) => Promise<JwsSigner>;
  /** Replaces signing: builds the compact JWT from the changed parts. */
  assemble?: (parts: JwtParts, values: Values) => string;
  /** Changes the signed compact JWT. */
  after?: (compact: string) => string;
}

/** The values a fault computes with. */
interface Values {
  context: IssuerFaultContext;
  now: number;
  skew: number;
  window: number;
  provider: TestEntity;
  entity: (id: string) => TestEntity;
}

const PRIVATE_STATUS_URI = 'http://169.254.169.254/latest/meta-data/status';

const statusList = (payload: Record<string, unknown>, claim: string) =>
  ((payload[claim] as { status: { status_list: { uri: string; idx: number } } }).status.status_list);
const statusObject = (payload: Record<string, unknown>, claim: string) => payload[claim] as { exp: number };

/** A URL of the Test Status Provider (the origin of the unit's status list) that no other step uses. */
const tspUrl = (payload: Record<string, unknown>, claim: string, path: string) => new URL(`/${path}/${randomUUID()}`, statusList(payload, claim).uri).href;

const issuanceSigner = (id: string) => async (v: Values) => certifiedSigner(v.entity(id).signers.issuance);

/** `WP-A`, whose separate WIA and KA CAs the wrong-service-anchor faults use. */
const wpA = (v: Values) => {
  if (v.provider.spec.id !== 'WP-A') throw new Error(`the fault needs a Wallet Unit of WP-A, not of ${v.provider.spec.id}`);
  return v.provider;
};

/** A secp256k1 signer certified under the anchor of a Wallet Provider's WIA (`wia`) or KA (`ka`) service. */
async function es256kUnder(v: Values, purpose: 'wia' | 'ka'): Promise<JwsSigner> {
  const entity = v.provider;
  const anchor = purpose === 'ka' && entity.keyAttestation ? entity.keyAttestation.anchor : entity.anchors.issuance;
  const signer = await foreignSigner('secp256k1', { ...entity, anchors: { ...entity.anchors, issuance: anchor } }, 'dc+sd-jwt', new Date(v.now * 1000));
  return foreignJwsSigner(signer);
}

const WIA_FAULTS: Partial<Record<IssuerFaultId, AttestationFault>> = {
  'wia.signature-bitflip': { after: (jwt) => flipBitInSegment(jwt, 2) },
  'wia.signer-ca-x': { signer: issuanceSigner('CA-X') },
  'wia.signer-pp-a': { signer: issuanceSigner('PP-A') },
  'wia.signer-ac-a': { signer: issuanceSigner('AC-A') },
  'wia.signer-wp-w': { signer: issuanceSigner('WP-W') },
  'wia.signer-ka-ca': { signer: async (v) => certifiedSigner(signerFor(wpA(v), 'ka')) },
  'wia.exp-past': {
    change: (p, v) => {
      p.payload.exp = v.now - v.skew - HOUR;
      p.payload.iat = (p.payload.exp as number) - HOUR;
    },
  },
  'wia.nbf-future': { change: (p, v) => void (p.payload.nbf = v.now + v.skew + HOUR) },
  'wia.typ-jwt': { change: (p) => void (p.header.typ = 'JWT') },
  'wia.es256k': { signer: (v) => es256kUnder(v, 'wia') },
  'wia.hs256': { assemble: (p) => hs256(p, leafJwkOf(p)) },
  'wia.sub-other': { change: (p) => void (p.payload.sub = 'other-wallet-unit') },
  'wia.maintenance-31-days': { change: (p, v) => void (statusObject(p.payload, 'client_status').exp = v.now + 31 * DAY) },
  'wia.maintenance-tomorrow': { change: (p, v) => void (statusObject(p.payload, 'client_status').exp = v.now + DAY) },
  'wia.ca-x-status-uri': {
    change: (p) => void (statusList(p.payload, 'client_status').uri = tspUrl(p.payload, 'client_status', 'ca-x-wia-status')),
    signer: issuanceSigner('CA-X'),
  },
  'wia.status-uri-private': { change: (p) => void (statusList(p.payload, 'client_status').uri = PRIVATE_STATUS_URI) },
  'wia.status-uri-private-top-level': { change: (p) => void (p.payload.status = { status_list: { uri: PRIVATE_STATUS_URI, idx: 0 } }) },
  'wia.jku-header': { change: (p) => void (p.header.jku = tspUrl(p.payload, 'client_status', 'jku')) },
  'wia.x5u-header': { change: (p) => void (p.header.x5u = tspUrl(p.payload, 'client_status', 'x5u')) },
};

const levels = (claim: 'key_storage' | 'user_authentication', value: string | undefined): AttestationFault => ({
  change: (p) => {
    if (value === undefined) delete p.payload[claim];
    else p.payload[claim] = [value];
  },
});

const KA_FAULTS: Partial<Record<IssuerFaultId, AttestationFault>> = {
  'ka.signature-bitflip': { after: (jwt) => flipBitInSegment(jwt, 2) },
  'ka.signer-ca-x': { signer: issuanceSigner('CA-X') },
  'ka.signer-pp-a': { signer: issuanceSigner('PP-A') },
  'ka.signer-wp-w': { signer: issuanceSigner('WP-W') },
  'ka.signer-wia-ca': { signer: async (v) => certifiedSigner(signerFor(wpA(v), 'wia')) },
  'ka.exp-past': {
    change: (p, v) => {
      p.payload.exp = v.now - v.skew - HOUR;
      p.payload.iat = (p.payload.exp as number) - 30 * DAY;
    },
  },
  'ka.nonce-other-session': {
    change: (p, v) => {
      if (!v.context.otherSessionCNonce) throw new Error('ka.nonce-other-session needs otherSessionCNonce, a c_nonce of another session');
      p.payload.nonce = v.context.otherSessionCNonce;
    },
  },
  'ka.nonce-missing': { change: (p) => void delete p.payload.nonce },
  'ka.key-storage-moderate': levels('key_storage', ISO_18045.moderate),
  'ka.key-storage-basic': levels('key_storage', ISO_18045.basic),
  'ka.key-storage-absent': levels('key_storage', undefined),
  'ka.user-authentication-moderate': levels('user_authentication', ISO_18045.moderate),
  'ka.user-authentication-basic': levels('user_authentication', ISO_18045.basic),
  'ka.user-authentication-absent': levels('user_authentication', undefined),
  'ka.maintenance-31-days': { change: (p, v) => void (statusObject(p.payload, 'key_storage_status').exp = v.now + 31 * DAY) },
  'ka.typ-jwt': { change: (p) => void (p.header.typ = 'JWT') },
  'ka.es256k': { signer: (v) => es256kUnder(v, 'ka') },
  'ka.ca-x-status-uri': {
    change: (p) => void (statusList(p.payload, 'key_storage_status').uri = tspUrl(p.payload, 'key_storage_status', 'ca-x-ka-status')),
    signer: issuanceSigner('CA-X'),
  },
  'ka.status-uri-private': { change: (p) => void (statusList(p.payload, 'key_storage_status').uri = PRIVATE_STATUS_URI) },
  'ka.status-uri-private-top-level': { change: (p) => void (p.payload.status = { status_list: { uri: PRIVATE_STATUS_URI, idx: 0 } }) },
  'ka.jku-header': { change: (p) => void (p.header.jku = tspUrl(p.payload, 'key_storage_status', 'jku')) },
  'ka.x5u-header': { change: (p) => void (p.header.x5u = tspUrl(p.payload, 'key_storage_status', 'x5u')) },
};

/** Applies an attestation fault to a valid WIA or KA; `defaultSigner` signs when the fault names no other. */
async function applyAttestationFault(compact: string, fault: AttestationFault | undefined, v: Values, defaultSigner: JwsSigner, change?: (parts: JwtParts) => void) {
  if (!fault && !change) return compact;
  const parts = partsOf(compact);
  change?.(parts);
  fault?.change?.(parts, v);
  if (fault?.assemble) return fault.assemble(parts, v);
  const signed = await resign(parts, fault?.signer ? await fault.signer(v) : defaultSigner);
  return fault?.after ? fault.after(signed) : signed;
}

// ------------------------------------------------------------------------------------------- PoP and proof

/** Changes of the PoP's or proof's header and claims, applied by the client's `jwt` hook before it signs. */
type PartsChange = (parts: JwtParts, v: Values, keys: EcKeyPair[]) => void;

const POP_CHANGES: Partial<Record<IssuerFaultId, PartsChange>> = {
  'wia-pop.aud-other': (p) => void (p.payload.aud = 'https://other-issuer.example'),
  'wia-pop.iat-stale': (p, v) => void (p.payload.iat = v.now - v.window - v.skew - HOUR),
  'wia-pop.jti-replayed': (p, v) => {
    if (!v.context.replay?.popJti) throw new Error('wia-pop.jti-replayed needs replay.popJti, the jti of an earlier PoP');
    p.payload.jti = v.context.replay.popJti;
  },
  'wia-pop.typ-jwt': (p) => void (p.header.typ = 'JWT'),
};

/** The attested key whose public part a proof header carries. */
const proofKeyOf = (parts: JwtParts, keys: EcKeyPair[]) => {
  const jwk = parts.header.jwk as JsonWebKey;
  const key = keys.find((k) => k.publicJwk.x === jwk.x && k.publicJwk.y === jwk.y);
  if (!key) throw new Error('the proof key is not one of the attested keys');
  return key;
};

const PROOF_CHANGES: Partial<Record<IssuerFaultId, PartsChange>> = {
  'proof.typ-jwt': (p) => void (p.header.typ = 'JWT'),
  'proof.typ-missing': (p) => void (p.header.typ = undefined),
  'proof.aud-other': (p) => void (p.payload.aud = 'https://other-issuer.example'),
  'proof.aud-missing': (p) => void delete p.payload.aud,
  'proof.nonce-missing': (p) => void delete p.payload.nonce,
  'proof.nonce-random': (p) => void (p.payload.nonce = base64url.encode(Buffer.from(randomUUID()))),
  'proof.nonce-replayed': (p, v) => {
    if (!v.context.replay?.cNonce) throw new Error('proof.nonce-replayed needs replay.cNonce, the c_nonce of an earlier credential request');
    p.payload.nonce = v.context.replay.cNonce;
  },
  'proof.iat-past': (p, v) => void (p.payload.iat = v.now - v.window - HOUR),
  'proof.iat-future': (p, v) => void (p.payload.iat = v.now + v.skew + HOUR),
  'proof.iss-other': (p) => void (p.payload.iss = 'other-wallet-unit'),
  'proof.jwk-private': (p, _v, keys) => void (p.header.jwk = { ...publicJwkOf(proofKeyOf(p, keys).publicJwk), d: proofKeyOf(p, keys).privateJwk.d }),
  'proof.jwk-and-x5c': (p, v) => void (p.header.x5c = v.entity('CA-X').signers.issuance.chain.map((c) => Buffer.from(c.der).toString('base64'))),
  'proof.off-curve': (p) => void (p.header.jwk = offCurve(p.header.jwk as JsonWebKey)),
  'proof.jku-header': (p) => void (p.header.jku = new URL(`/jku/${randomUUID()}`, statusUriOf(p)).href),
  'proof.kid-url': (p) => void (p.header.kid = new URL(`/kid/${randomUUID()}`, statusUriOf(p)).href),
};

/** The status list URI of the KA in a proof header: its origin is the Test Status Provider. */
const statusUriOf = (parts: JwtParts) => statusList(partsOf(parts.header[KEY_ATTESTATION_HEADER] as string).payload, 'key_storage_status').uri;

/** Faults that replace the signed proof: another key or algorithm, which the client's own signing cannot produce. */
type ProofReplacement = (proof: string, v: Values, kaSigner: JwsSigner) => Promise<string>;

/** The proof signed by a key outside P-256, with its KA re-issued over that key so only the algorithm differs. */
const foreignProof =
  (kind: 'secp256k1' | 'P-521'): ProofReplacement =>
  async (proof, v, kaSigner) => {
    const parts = partsOf(proof);
    const key = foreignKey(kind);
    const ka = partsOf(parts.header[KEY_ATTESTATION_HEADER] as string);
    ka.payload.attested_keys = [key.publicJwk];
    parts.header.jwk = key.publicJwk;
    parts.header[KEY_ATTESTATION_HEADER] = await resign(ka, kaSigner);
    return resign(parts, key.signer);
  };

const PROOF_REPLACEMENTS: Partial<Record<IssuerFaultId, ProofReplacement>> = {
  'proof.signature-bitflip': async (proof) => flipBitInSegment(proof, 2),
  'proof.alg-none': async (proof) => unsecured(partsOf(proof)),
  'proof.hs256': async (proof) => {
    const parts = partsOf(proof);
    return hs256(parts, parts.header.jwk as JsonWebKey);
  },
  'proof.es256k': foreignProof('secp256k1'),
  'proof.p521': foreignProof('P-521'),
  'proof.key-not-attested': async (proof) => {
    const parts = partsOf(proof);
    const key = await generateEcKeyPair();
    parts.header.jwk = publicJwkOf(key.publicJwk);
    return resign(parts, keySigner(key));
  },
};

// --------------------------------------------------------------------------------------------------- apply

/** The other Wallet Unit of the same Wallet Provider, or `CW-2` / `CW-1`. */
const otherUnit = (unit: WalletUnitId): WalletUnitId => (unit === 'CW-2' ? 'CW-1' : 'CW-2');

/**
 * Applies one named fault (or none: the valid issuance, with the `keyAttestationNonce` variant if asked) to an issuance
 * of `context.unit`, through the seams of the issuance client.
 */
export async function applyIssuerFault(fault: IssuerFaultId | undefined, context: IssuerFaultContext): Promise<AppliedIssuerFault> {
  const info = fault && issuerFaultInfo(fault);
  if (info?.requiresKeyAttestationNonce && !context.keyAttestationNonce) throw new Error(`${fault} is a fault of the keyAttestationNonce variant`);
  const { twp } = context;
  const unitInfo = twp.units[context.unit];
  const provider = twp.entityOf(unitInfo.provider);
  const values = (): Values => ({
    context,
    now: Math.floor((context.now ?? new Date()).getTime() / 1000),
    skew: context.skewSeconds ?? 300,
    window: context.proofWindowSeconds ?? 300,
    provider,
    entity: (id) => {
      const entity = twp.pki.entities[id];
      if (!entity) throw new Error(`no entity ${id} in the test PKI`);
      return entity;
    },
  });
  const wiaSigner = certifiedSigner(signerFor(provider, 'wia'));
  const kaSigner = certifiedSigner(signerFor(provider, 'ka'));
  const base = walletUnitOf(twp, context.unit);
  let keys: EcKeyPair[] = [];

  const unit: WalletUnitBinding = {
    ...base,
    wia: async () => applyAttestationFault(await base.wia(), info?.point === 'wia' ? WIA_FAULTS[fault!] : undefined, values(), wiaSigner),
    keyAttestation: async (): Promise<KeyAttestationWithKeys> => {
      const ka = fault === 'ka.other-unit' ? await twp.keyAttestation(otherUnit(context.unit)) : await base.keyAttestation();
      keys = ka.keys;
      return ka;
    },
  };

  const jwt: JwtHook = async (point, parts) => {
    const v = values();
    if (point === 'wia-pop' && fault && POP_CHANGES[fault]) POP_CHANGES[fault]!(parts, v, keys);
    if (point === 'proof') {
      const ka = parts.header[KEY_ATTESTATION_HEADER];
      if (fault === 'ka.missing') delete parts.header[KEY_ATTESTATION_HEADER];
      else if (typeof ka === 'string') {
        const kaFault = info?.point === 'ka' ? KA_FAULTS[fault!] : undefined;
        const nonce = parts.payload.nonce;
        const withNonce = context.keyAttestationNonce ? (kaParts: JwtParts) => void (kaParts.payload.nonce = nonce) : undefined;
        parts.header[KEY_ATTESTATION_HEADER] = await applyAttestationFault(ka, kaFault, v, kaSigner, withNonce);
      }
      if (fault && PROOF_CHANGES[fault]) PROOF_CHANGES[fault]!(parts, v, keys);
    }
    return parts;
  };

  const request: RequestHook = async (step, message) => {
    if (step === 'token' && fault === 'wia.missing') return withoutHeaders(message, [CLIENT_ATTESTATION_HEADER, CLIENT_ATTESTATION_POP_HEADER]);
    if (step === 'token' && fault === 'wia-pop.missing') return withoutHeaders(message, [CLIENT_ATTESTATION_POP_HEADER]);
    if (step === 'token' && fault === 'wia-pop.other-key') {
      return replaceHeader(message, CLIENT_ATTESTATION_POP_HEADER, async (pop) => resign(partsOf(pop), keySigner(await generateEcKeyPair())));
    }
    if (step === 'credential' && fault && PROOF_REPLACEMENTS[fault]) return replaceProofs(message, (proof) => PROOF_REPLACEMENTS[fault]!(proof, values(), kaSigner));
    return message;
  };

  return { unit, hooks: { jwt, request } };
}
