// The issuer request checks of the reference validator (issuer harness design sections 6.2 and 7): one named check per
// property of the WIA and its PoP (token endpoint), and of the key proof and its KA (credential endpoint), as the
// Conformance Wallet sends them to a PID or Attestation Provider. A conforming issuer accepts a request only if every
// check passes, so each issuer request fault can be shown to fail exactly one of them.
//
// The names of claims and `typ` values are written out here from the specifications (OpenID4VCI 1.0 Appendices D, E
// and F.1, Attestation-Based Client Authentication, TS3 v1.5.2) rather than imported from the Test Wallet Provider, so
// a wrong name in the builders is not repeated by the validator, and the validator keeps no dependency on the forge
// of the issuer suite.
import { createPublicKey, verify as nodeVerify } from 'node:crypto';
import { inflateSync } from 'node:zlib';
import { type CheckId, ISSUER_REQUEST_CHECKS } from '@eudi-pcaf/core';
import { base64url } from '@eudi-pcaf/forge';
import { parseCertificate } from '@owf/x509';
import { CheckRecorder, NotApplicable, type ValidationMode, type ValidationResult } from './checks';
import { fail } from './status-list';
import type { LoadedList, TrustedService } from './trust';
import { validatePath } from './x509-path';

/** `typ` values (Attestation-Based Client Authentication; OpenID4VCI 1.0 Appendices D.1 and F.1). */
const TYP = {
  wia: 'oauth-client-attestation+jwt',
  wiaPop: 'oauth-client-attestation-pop+jwt',
  keyAttestation: 'key-attestation+jwt',
  proof: 'openid4vci-proof+jwt',
  statusList: 'statuslist+jwt',
} as const;

/** The algorithms TS3 section 2.6 allows for WIAs, KAs and their proofs of possession, with the curve of each. */
const TS3_ALGORITHMS: Record<string, string> = { ES256: 'P-256', ES384: 'P-384', ES512: 'P-521' };
const ALG_CURVE: Record<string, string> = { ...TS3_ALGORITHMS, ES256K: 'secp256k1' };
const NODE_HASH: Record<string, string> = { ES256: 'sha256', ES384: 'sha384', ES512: 'sha512', ES256K: 'sha256' };

/** `WalletSolution` services of an ETSI TS 119 602 Wallet Providers list. */
export const WALLET_PROVIDER_SERVICE = {
  issuance: 'http://uri.etsi.org/19602/SvcType/WalletSolution/Issuance',
  revocation: 'http://uri.etsi.org/19602/SvcType/WalletSolution/Revocation',
} as const;

const HIGH = 'iso_18045_high';
const PRIVATE_MEMBERS = ['d', 'p', 'q', 'dp', 'dq', 'qi', 'k', 'oth'];
/** Header members that name a key by URL (RFC 8725 section 3.10): a conforming issuer neither follows nor accepts them. */
const URL_KEY_MEMBERS = ['jku', 'x5u'];

/** What the Conformance Wallet sent: the headers of the token request and the key proof of the credential request. */
export interface IssuerRequestInput {
  /** `OAuth-Client-Attestation`. */
  clientAttestation?: string;
  /** `OAuth-Client-Attestation-PoP`. */
  clientAttestationPop?: string;
  /** The `client_id` of the token request. */
  clientId?: string;
  /** The key proof (`proofs.jwt[0]`). */
  proof?: string;
  /** The KA; default the `key_attestation` header of the proof. */
  keyAttestation?: string;
}

export interface IssuerRequestOptions {
  /** `TL-WP` as the issuer loaded it (`checkLote`): the anchors of WIAs, KAs and their status lists. */
  walletProviders: LoadedList;
  /** The issuer identifier of the Authorization Server: the PoP's `aud`. */
  authorizationServer: string;
  /** The Credential Issuer Identifier: the proof's `aud`. */
  credentialIssuer: string;
  /** The `c_nonce` the SUT issued for this credential request. */
  cNonce: string;
  /** `c_nonce` values of earlier, answered credential requests. */
  usedNonces?: string[];
  /** `jti` values of earlier PoPs. */
  usedPopJtis?: string[];
  /** Fetches a status list; default `fetch`. Returns the body, or undefined when it cannot be obtained. */
  fetchStatusList?: (uri: string) => Promise<string | undefined>;
  /** `proof_signing_alg_values_supported` of the credential configuration; default `ES256`. */
  proofSigningAlgorithms?: string[];
  /** The level `key_storage` and `user_authentication` must reach; default `iso_18045_high` (PID). */
  requiredLevel?: string;
  /** The SUT requires the KA to carry the `c_nonce` (catalogue `P-DPN`, `PP_WS_SM_KeyAttestation_007`). */
  requireKeyAttestationNonce?: boolean;
  /** `T_skew`, seconds; default 300. */
  skewSeconds?: number;
  /** `T_proof`, seconds; default 300. */
  proofWindowSeconds?: number;
  /** Accept `http` status URIs on loopback hosts, for runs on one machine. */
  allowLoopbackHttp?: boolean;
  now?: Date;
  mode?: ValidationMode;
}

export interface IssuerRequestValidation extends ValidationResult {}

interface DecodedJwt {
  compact: string;
  header: Record<string, unknown>;
  payload: Record<string, unknown>;
  input: string;
  signature: Uint8Array;
}

function decodeJwt(compact: unknown, what: string): DecodedJwt {
  if (typeof compact !== 'string' || compact.length === 0) return fail(`no ${what}`);
  const parts = compact.split('.');
  if (parts.length !== 3) return fail(`the ${what} is not a compact JWS`);
  const object = (segment: string, part: string) => {
    let value: unknown;
    try {
      value = base64url.decodeJson(segment);
    } catch {
      return fail(`the ${what} ${part} cannot be decoded`);
    }
    if (!value || typeof value !== 'object' || Array.isArray(value)) return fail(`the ${what} ${part} is not a JSON object`);
    return value as Record<string, unknown>;
  };
  return { compact, header: object(parts[0], 'header'), payload: object(parts[1], 'payload'), input: `${parts[0]}.${parts[1]}`, signature: base64url.decode(parts[2]) };
}

/** Decodes without failing a check: for the checks that only read a value of another artifact. */
const tryDecode = (compact: unknown): DecodedJwt | undefined => {
  try {
    return decodeJwt(compact, 'JWT');
  } catch {
    return undefined;
  }
};

const isObject = (value: unknown): value is Record<string, unknown> => Boolean(value) && typeof value === 'object' && !Array.isArray(value);

/** The public key of a JWK, or a failure when it is not one (wrong type, private members, not a point on its curve). */
function publicKeyOf(jwk: unknown, what: string) {
  if (!isObject(jwk)) return fail(`${what} is not a JWK`);
  const priv = PRIVATE_MEMBERS.filter((member) => member in jwk);
  if (priv.length) return fail(`${what} carries the private key member(s) ${priv.join(', ')}`);
  if (jwk.kty !== 'EC') return fail(`${what} has kty ${String(jwk.kty)}, not EC`);
  try {
    return createPublicKey({ key: jwk as never, format: 'jwk' });
  } catch (error) {
    return fail(`${what} is not a valid ${String(jwk.crv)} public key: ${(error as Error).message}`);
  }
}

/** Verifies a JWS signature with one of `algorithms`, whose curve must be that of the key. */
function verifySignature(jwt: DecodedJwt, jwk: JsonWebKey, algorithms: string[], what: string) {
  const alg = jwt.header.alg;
  if (typeof alg !== 'string' || !algorithms.includes(alg)) return fail(`${what} alg ${String(alg)} is not one of ${algorithms.join(', ')}`);
  if (ALG_CURVE[alg] !== jwk.crv) return fail(`${what} alg ${alg} does not match the key on ${String(jwk.crv)}`);
  const key = createPublicKey({ key: jwk as never, format: 'jwk' });
  const valid = nodeVerify(NODE_HASH[alg], Buffer.from(jwt.input), { key, dsaEncoding: 'ieee-p1363' }, jwt.signature);
  if (!valid) fail(`${what} signature does not verify`);
}

const x5cOf = (jwt: DecodedJwt, what: string): string[] => {
  const x5c = jwt.header.x5c;
  if (!Array.isArray(x5c) || x5c.length === 0 || x5c.some((entry) => typeof entry !== 'string')) return fail(`${what} header has no x5c`);
  return x5c as string[];
};

/** Signature of a WIA or KA: no key by URL, an algorithm of TS3, verified with the key of the `x5c` leaf. */
function verifyAttestationSignature(jwt: DecodedJwt, what: string) {
  const byUrl = URL_KEY_MEMBERS.filter((member) => member in jwt.header);
  if (byUrl.length) fail(`${what} header names a key by URL (${byUrl.join(', ')})`);
  const leaf = parseCertificate(x5cOf(jwt, what)[0]);
  const jwk = leaf.publicKey.jwk;
  if (typeof jwt.header.alg === 'string' && !(jwt.header.alg in TS3_ALGORITHMS)) fail(`${what} alg ${jwt.header.alg} is not one of TS3 (${Object.keys(TS3_ALGORITHMS).join(', ')})`);
  if (!jwk) return fail(`${what} x5c leaf key is not supported`);
  verifySignature(jwt, jwk as JsonWebKey, Object.keys(TS3_ALGORITHMS), what);
}

const issuanceServices = (list: LoadedList) =>
  list.entities.map((entity) => ({ entity: entity.name, services: entity.services.filter((s) => s.type === WALLET_PROVIDER_SERVICE.issuance) }));

/** The path of `x5c` to the anchors of the services given, with the name of the service that matched. */
async function trustedUnder(x5c: string[], services: { entity: string; service: TrustedService }[], now: Date, what: string) {
  const reasons: string[] = [];
  for (const { entity, service } of services) {
    const path = await validatePath(x5c, service.anchors, now);
    if (path.ok) return `${entity} ${service.name ?? service.type}`;
    reasons.push(path.reason);
  }
  return fail(`${what} does not chain to an anchor of TL-WP${reasons.length ? ` (${[...new Set(reasons)].join('; ')})` : ''}`);
}

const seconds = (date: Date) => Math.floor(date.getTime() / 1000);

/** Private, loopback, link-local and unique-local addresses (OWASP SSRF), by literal host. */
function isPrivateHost(hostname: string): boolean {
  const host = hostname.replace(/^\[|\]$/g, '').toLowerCase();
  if (host === 'localhost' || host === '::1' || host.startsWith('fe80:') || host.startsWith('fc') || host.startsWith('fd')) return true;
  const octets = host.split('.').map(Number);
  if (octets.length !== 4 || octets.some((o) => !Number.isInteger(o))) return false;
  const [a, b] = octets;
  return a === 10 || a === 127 || a === 0 || (a === 169 && b === 254) || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168);
}

const isLoopback = (hostname: string) => ['127.0.0.1', 'localhost', '[::1]', '::1'].includes(hostname);

/** The status reference of `client_status` / `key_storage_status`: `{ status: { status_list: { idx, uri } }, exp }`. */
function statusObjectOf(payload: Record<string, unknown>, claim: string, what: string) {
  const object = payload[claim];
  if (!isObject(object)) return fail(`${what} has no ${claim} object`);
  const reference = isObject(object.status) && isObject(object.status.status_list) ? object.status.status_list : undefined;
  if (!reference) return fail(`${what} ${claim} has no status.status_list`);
  if (typeof reference.idx !== 'number' || !Number.isInteger(reference.idx) || reference.idx < 0) return fail(`${what} ${claim} idx is not a non-negative integer`);
  if (typeof reference.uri !== 'string') return fail(`${what} ${claim} has no uri`);
  if (typeof object.exp !== 'number') return fail(`${what} ${claim} has no numeric exp (end of the revocation maintenance period)`);
  return { idx: reference.idx, uri: reference.uri, maintenanceUntil: object.exp };
}

/**
 * Status of a WIA or KA (Token Status List; TS3 section 2.4): the URI is fetched only if it is an `https` URL (or `http`
 * on loopback when allowed) that is not a private address; the list must be a `statuslist+jwt` for that URI, signed
 * under a WalletSolution/Revocation anchor of `TL-WP`, not expired, and the entry must be 0 (VALID).
 */
async function checkStatus(reference: { idx: number; uri: string }, options: IssuerRequestOptions, now: Date, what: string): Promise<string> {
  let url: URL;
  try {
    url = new URL(reference.uri);
  } catch {
    return fail(`${what} status uri is not a URL`);
  }
  const loopbackAllowed = options.allowLoopbackHttp && isLoopback(url.hostname);
  if (isPrivateHost(url.hostname) && !loopbackAllowed) fail(`${what} status uri ${reference.uri} is a private address and is not fetched`);
  if (url.protocol !== 'https:' && !(url.protocol === 'http:' && loopbackAllowed)) fail(`${what} status uri ${reference.uri} is not https`);
  const body = await (options.fetchStatusList ?? defaultFetch)(reference.uri);
  if (!body) return fail(`${what} status list ${reference.uri} cannot be obtained`);
  const token = decodeJwt(body.trim(), 'status list token');
  if (token.header.typ !== TYP.statusList) fail(`${what} status list typ is ${String(token.header.typ)}`);
  if (token.payload.sub !== reference.uri) fail(`${what} status list sub ${String(token.payload.sub)} is not ${reference.uri}`);
  if (typeof token.payload.iat !== 'number') fail(`${what} status list has no numeric iat`);
  const anchors = options.walletProviders.entities.flatMap((entity) =>
    entity.services.filter((s) => s.type === WALLET_PROVIDER_SERVICE.revocation).map((service) => ({ entity: entity.name, service })),
  );
  await trustedUnder(x5cOf(token, 'status list'), anchors, now, `${what} status list`);
  const leaf = parseCertificate(x5cOf(token, 'status list')[0]);
  verifySignature(token, leaf.publicKey.jwk as JsonWebKey, Object.keys(TS3_ALGORITHMS), `${what} status list`);
  if (typeof token.payload.exp === 'number' && seconds(now) > token.payload.exp + (options.skewSeconds ?? 300)) fail(`${what} status list has expired`);
  const list = token.payload.status_list as { bits?: number; lst?: string } | undefined;
  if (!list || typeof list.lst !== 'string' || ![1, 2, 4, 8].includes(list.bits ?? 0)) return fail(`${what} status list has no valid status_list`);
  const bits = list.bits as number;
  if (!/^[A-Za-z0-9_-]*$/.test(list.lst)) fail(`${what} status list lst is not base64url`);
  const decoded = inflateSync(Buffer.from(list.lst, 'base64url'), { maxOutputLength: 16 * 1024 * 1024 });
  if (reference.idx >= (decoded.length * 8) / bits) fail(`${what} status index ${reference.idx} is outside the list`);
  const value = (decoded[Math.floor((reference.idx * bits) / 8)] >> ((reference.idx * bits) % 8)) & ((1 << bits) - 1);
  if (value !== 0) fail(`${what} status at index ${reference.idx} is 0x${value.toString(16).padStart(2, '0')}${value === 1 ? ' (INVALID)' : ''}`);
  return `${reference.uri}#${reference.idx} VALID`;
}

const defaultFetch = async (uri: string) => {
  const response = await fetch(uri);
  return response.ok ? response.text() : undefined;
};

/** Whether `iat` lies within [now − window − skew, now + skew]. */
function checkIat(iat: unknown, now: Date, windowSeconds: number, skewSeconds: number, what: string) {
  if (typeof iat !== 'number') return fail(`${what} has no numeric iat`);
  const t = seconds(now);
  if (iat < t - windowSeconds - skewSeconds) fail(`${what} iat ${iat} is older than T_proof (${windowSeconds} s) and T_skew`);
  if (iat > t + skewSeconds) fail(`${what} iat ${iat} is in the future beyond T_skew`);
}

/**
 * Evaluates every issuer request check (`ISSUER_REQUEST_CHECKS`) over the WIA, its PoP, the KA and the key proof of one
 * issuance. Default mode `all`, so the self-validation sees every check a fault fails.
 */
export async function validateIssuerRequest(input: IssuerRequestInput, options: IssuerRequestOptions): Promise<IssuerRequestValidation> {
  const recorder = new CheckRecorder(options.mode ?? 'all');
  const now = options.now ?? new Date();
  const skew = options.skewSeconds ?? 300;
  const window = options.proofWindowSeconds ?? 300;
  const t = seconds(now);
  let wia: DecodedJwt | undefined;
  let ka: DecodedJwt | undefined;
  let proof: DecodedJwt | undefined;
  let proofJwk: JsonWebKey | undefined;
  let wiaStatus: { idx: number; uri: string } | undefined;
  let kaStatus: { idx: number; uri: string } | undefined;

  return recorder.collect(async () => {
    // ----------------------------------------------------------------------------------------------------- WIA
    await recorder.run('wia-format', [], () => {
      wia = decodeJwt(input.clientAttestation, 'WIA (OAuth-Client-Attestation)');
      if (wia.header.typ !== TYP.wia) fail(`WIA typ is ${String(wia.header.typ)}, not ${TYP.wia}`);
      for (const claim of ['iat', 'exp']) if (typeof wia.payload[claim] !== 'number') fail(`WIA has no numeric ${claim}`);
      if (typeof wia.payload.sub !== 'string') fail('WIA has no sub');
      if (typeof wia.payload.wallet_name !== 'string') fail('WIA has no wallet_name');
      const cnf = wia.payload.cnf;
      if (!isObject(cnf) || !isObject(cnf.jwk)) fail('WIA has no cnf.jwk');
      wiaStatus = statusObjectOf(wia.payload, 'client_status', 'WIA');
    });
    await recorder.run('wia-signature', ['wia-format'], () => verifyAttestationSignature(wia!, 'WIA'));
    await recorder.run('wia-trust', ['wia-format'], async () => {
      // TS3 section 2.2.1.2: the signing certificate "can be verified with a trust anchor found on the Trusted List for
      // Wallet Providers". The anchor is bound to the Wallet Provider, not to one of its services: the mapping of
      // `wallet_name` to a ServiceName in TS3 section 3.2 is informative (spec review 2026-11-20).
      const services = issuanceServices(options.walletProviders).flatMap(({ entity, services: list }) => list.map((service) => ({ entity, service })));
      return trustedUnder(x5cOf(wia!, 'WIA'), services, now, 'WIA');
    });
    await recorder.run('wia-validity', ['wia-format'], () => {
      const { exp, nbf, iat } = wia!.payload as { exp: number; nbf?: unknown; iat: number };
      if (t > exp + skew) fail(`WIA expired: exp ${exp}, now ${t}, T_skew ${skew}`);
      if (nbf !== undefined && (typeof nbf !== 'number' || nbf > t + skew)) fail(`WIA not yet valid: nbf ${String(nbf)}, now ${t}, T_skew ${skew}`);
      if (iat > t + skew) fail(`WIA iat ${iat} is in the future`);
    });
    await recorder.run('wia-client-id', ['wia-format'], () => {
      if (input.clientId === undefined) return new NotApplicable('the request names no client_id');
      if (wia!.payload.sub !== input.clientId) fail(`WIA sub ${String(wia!.payload.sub)} is not the client_id ${input.clientId}`);
    });
    // The status of a WIA whose signature or trust failed is not fetched (Token Status List section 6.2).
    await recorder.run('wia-status', ['wia-format', 'wia-signature', 'wia-trust'], () => checkStatus(wiaStatus!, options, now, 'WIA'));

    // --------------------------------------------------------------------------------------------- WIA PoP
    await recorder.run('wia-pop', ['wia-format'], () => {
      const pop = decodeJwt(input.clientAttestationPop, 'PoP (OAuth-Client-Attestation-PoP)');
      if (pop.header.typ !== TYP.wiaPop) fail(`PoP typ is ${String(pop.header.typ)}, not ${TYP.wiaPop}`);
      const cnfJwk = (wia!.payload.cnf as { jwk: JsonWebKey }).jwk;
      publicKeyOf(cnfJwk, "the WIA's cnf.jwk");
      verifySignature(pop, cnfJwk, Object.keys(TS3_ALGORITHMS), 'PoP');
      if (input.clientId !== undefined && pop.payload.iss !== input.clientId) fail(`PoP iss ${String(pop.payload.iss)} is not the client_id ${input.clientId}`);
      if (pop.payload.aud !== options.authorizationServer) fail(`PoP aud ${JSON.stringify(pop.payload.aud)} is not ${options.authorizationServer}`);
      checkIat(pop.payload.iat, now, window, skew, 'PoP');
      if (typeof pop.payload.exp === 'number' && t > pop.payload.exp + skew) fail('PoP expired');
      if (typeof pop.payload.jti !== 'string' || pop.payload.jti.length === 0) fail('PoP has no jti');
      if (options.usedPopJtis?.includes(pop.payload.jti as string)) fail(`PoP jti ${String(pop.payload.jti)} was used before`);
    });

    // ------------------------------------------------------------------------------------------------- KA
    const kaCompact = input.keyAttestation ?? tryDecode(input.proof)?.header.key_attestation;
    await recorder.run('ka-format', [], () => {
      ka = decodeJwt(kaCompact, 'KA (key_attestation)');
      if (ka.header.typ !== TYP.keyAttestation) fail(`KA typ is ${String(ka.header.typ)}, not ${TYP.keyAttestation}`);
      for (const claim of ['iat', 'exp']) if (typeof ka.payload[claim] !== 'number') fail(`KA has no numeric ${claim}`);
      const keys = ka.payload.attested_keys;
      if (!Array.isArray(keys) || keys.length === 0) fail('KA has no attested_keys');
      (keys as unknown[]).forEach((key, i) => publicKeyOf(key, `KA attested_keys[${i}]`));
      kaStatus = statusObjectOf(ka.payload, 'key_storage_status', 'KA');
    });
    await recorder.run('ka-signature', ['ka-format'], () => verifyAttestationSignature(ka!, 'KA'));
    await recorder.run('ka-trust', ['ka-format'], async () => {
      // TS3 section 2.2.2.2: any trust anchor of the Trusted List for Wallet Providers; TS3 section 3.2 is informative and
      // maps no KA field to a service (spec review 2026-11-20).
      const services = issuanceServices(options.walletProviders).flatMap(({ entity, services: list }) => list.map((service) => ({ entity, service })));
      return trustedUnder(x5cOf(ka!, 'KA'), services, now, 'KA');
    });
    await recorder.run('ka-validity', ['ka-format'], () => {
      const { exp, iat } = ka!.payload as { exp: number; iat: number };
      if (t > exp + skew) fail(`KA expired: exp ${exp}, now ${t}, T_skew ${skew}`);
      if (iat > t + skew) fail(`KA iat ${iat} is in the future`);
    });
    await recorder.run('ka-levels', ['ka-format'], () => {
      const required = options.requiredLevel ?? HIGH;
      for (const claim of ['key_storage', 'user_authentication']) {
        const value = ka!.payload[claim];
        if (!Array.isArray(value)) fail(`KA has no ${claim}, required ${required}`);
        if (!(value as unknown[]).includes(required)) fail(`KA ${claim} ${JSON.stringify(value)} does not reach ${required}`);
      }
    });
    await recorder.run('ka-nonce', ['ka-format'], () => {
      const nonce = ka!.payload.nonce;
      if (nonce === undefined) {
        if (options.requireKeyAttestationNonce) fail('KA has no nonce, and the SUT requires its c_nonce');
        return 'no nonce, and the SUT does not require one';
      }
      if (nonce !== options.cNonce) fail(`KA nonce ${String(nonce)} is not the c_nonce of this request`);
    });
    await recorder.run('ka-status', ['ka-format', 'ka-signature', 'ka-trust'], () => checkStatus(kaStatus!, options, now, 'KA'));

    // ---------------------------------------------------------------------------------------------- proof
    await recorder.run('proof-format', [], () => {
      proof = decodeJwt(input.proof, 'key proof');
      if (proof.header.typ !== TYP.proof) fail(`proof typ is ${String(proof.header.typ)}, not ${TYP.proof}`);
    });
    await recorder.run('proof-key', ['proof-format'], () => {
      const header = proof!.header;
      const byUrl = [...URL_KEY_MEMBERS.filter((member) => member in header), ...(typeof header.kid === 'string' && /^[a-z]+:\/\//i.test(header.kid) ? ['kid URL'] : [])];
      if (byUrl.length) fail(`proof header names a key by URL (${byUrl.join(', ')})`);
      const named = ['jwk', 'kid', 'x5c'].filter((member) => member in header);
      if (named.length !== 1) fail(`proof header carries ${named.length ? named.join(' and ') : 'none'} of jwk, kid, x5c; exactly one is allowed`);
      if (!('jwk' in header)) fail('proof header carries no jwk, the key the KA attests');
      publicKeyOf(header.jwk, 'proof jwk');
      proofJwk = header.jwk as JsonWebKey;
    });
    await recorder.run('proof-signature', ['proof-key'], () => {
      verifySignature(proof!, proofJwk!, options.proofSigningAlgorithms ?? ['ES256'], 'proof');
    });
    await recorder.run('proof-claims', ['proof-format'], () => {
      const { aud, iss, iat } = proof!.payload;
      if (aud !== options.credentialIssuer) fail(`proof aud ${JSON.stringify(aud)} is not the Credential Issuer ${options.credentialIssuer}`);
      checkIat(iat, now, window, skew, 'proof');
      if (iss !== undefined && iss !== input.clientId) fail(`proof iss ${String(iss)} is not the client_id ${String(input.clientId)}`);
    });
    await recorder.run('proof-nonce', ['proof-format'], () => {
      const nonce = proof!.payload.nonce;
      if (nonce === undefined) fail('proof has no nonce');
      if (options.usedNonces?.includes(nonce as string)) fail(`proof nonce ${String(nonce)} is a c_nonce already used`);
      if (nonce !== options.cNonce) fail(`proof nonce ${String(nonce)} is not the c_nonce of this request`);
    });
    await recorder.run('proof-key-attested', ['proof-key', 'ka-format'], () => {
      const same = (key: JsonWebKey) => key.crv === proofJwk!.crv && key.x === proofJwk!.x && key.y === proofJwk!.y;
      if (!(ka!.payload.attested_keys as JsonWebKey[]).some(same)) fail('the proof key is not one of the KA attested_keys');
    });
  });
}

/** Every issuer request check, for callers that list them. */
export const ISSUER_REQUEST_CHECK_IDS: CheckId[] = [...ISSUER_REQUEST_CHECKS];
