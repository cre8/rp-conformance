// The session checks of the reference validator (issue 25; issuer harness design sections 6.2 and 7): what the
// Conformance Wallet sends a PID or Attestation Provider once the grant has started, beyond the WIA, PoP, KA and proof of
// issuer-request.ts: the DPoP proof and the binding of the access token or refresh token to its key (RFC 9449), the
// proofs of a batch (OpenID4VCI 1.0 section 8.2), the encoding of the request body, the parameters of credential
// response encryption, and the notification and deferred credential requests (sections 9 and 11). A conforming issuer
// accepts a request only if every check passes, so each session fault can be shown to fail exactly one of them.
import { createPublicKey, verify as nodeVerify } from 'node:crypto';
import { type CheckId, SESSION_CHECKS } from '@eudi-pcaf/core';
import { base64url, sha256 } from '@eudi-pcaf/forge';
import { CheckRecorder, NotApplicable, type ValidationMode, type ValidationResult } from './checks';
import { fail } from './status-list';

/** A request as sent: method, URL, headers (any case), body. */
export interface SessionHttpRequest {
  method: string;
  url: string;
  headers: Record<string, string>;
  body?: string;
}

/**
 * Which request it is: `token` (the grant of the offer), `refresh` (the refresh grant), or a request to a resource of
 * the Credential Issuer that presents the access token: `credential`, `notification`, `deferred`.
 */
export type SessionRequestKind = 'token' | 'refresh' | 'credential' | 'notification' | 'deferred';

export interface SessionRequestOptions {
  kind: SessionRequestKind;
  /** The access token the request must present (`credential`, `notification`, `deferred`). */
  accessToken?: string;
  /** The public key the access token (resource requests) or the refresh token (`refresh`) is bound to. */
  boundKey?: JsonWebKey;
  /** The last `DPoP-Nonce` of the server, which the proof must carry. */
  dpopNonce?: string;
  /** `jti` values of earlier DPoP proofs (RFC 9449 section 11.1). */
  usedDpopJtis?: string[];
  /** `batch_size` the Credential Issuer advertises; default 1. */
  batchSize?: number;
  /** `credential_response_encryption` of the Credential Issuer metadata. */
  responseEncryption?: { alg_values_supported?: string[]; enc_values_supported?: string[] };
  /** `notification_id` values the credential responses issued. */
  notificationIds?: string[];
  /** `transaction_id` values the credential responses issued and not yet redeemed. */
  transactionIds?: string[];
  /** When the access token the request presents expires (`expires_in` after the token response). */
  accessTokenExpiresAt?: Date;
  /** `T_skew` in seconds; default 300. */
  skewSeconds?: number;
  /** `T_proof` in seconds, the age a DPoP proof may have; default 300. */
  proofWindowSeconds?: number;
  /** Upper bound of a request body; default 1 MiB. */
  maxBodyBytes?: number;
  /** Upper bound of the nesting depth of a JSON body; default 32. */
  maxDepth?: number;
  now?: Date;
  mode?: ValidationMode;
}

export interface SessionRequestValidation extends ValidationResult {}

export const SESSION_CHECK_IDS: CheckId[] = [...SESSION_CHECKS];

const NOTIFICATION_EVENTS = ['credential_accepted', 'credential_failure', 'credential_deleted'];
const DPOP_ALGORITHMS: Record<string, string> = { ES256: 'sha256', ES384: 'sha384', ES512: 'sha512' };
const PRIVATE_MEMBERS = ['d', 'p', 'q', 'dp', 'dq', 'qi', 'k', 'oth'];

const isObject = (value: unknown): value is Record<string, unknown> => Boolean(value) && typeof value === 'object' && !Array.isArray(value);
const header = (headers: Record<string, string>, name: string) => Object.entries(headers).find(([key]) => key.toLowerCase() === name.toLowerCase())?.[1];
const seconds = (date: Date) => Math.floor(date.getTime() / 1000);

/** RFC 7638 thumbprint of an EC public key. */
export function jwkThumbprint(jwk: JsonWebKey): string {
  return base64url.encode(sha256(JSON.stringify({ crv: jwk.crv, kty: jwk.kty, x: jwk.x, y: jwk.y })));
}

/** The public key of a JWK, or a failure when it is not one (private members, not a point on its curve). */
function publicKeyOf(jwk: unknown, what: string) {
  if (!isObject(jwk)) return fail(`${what} is not a JWK`);
  const priv = PRIVATE_MEMBERS.filter((member) => member in jwk);
  if (priv.length) return fail(`${what} carries the private key member(s) ${priv.join(', ')}`);
  try {
    return createPublicKey({ key: jwk as never, format: 'jwk' });
  } catch (error) {
    return fail(`${what} is not a valid ${String(jwk.crv ?? jwk.kty)} public key: ${(error as Error).message}`);
  }
}

/** Nesting depth of a JSON value, iteratively (a deep value would overflow a recursive walk). */
function depthOf(value: unknown): number {
  let max = 0;
  const stack: [unknown, number][] = [[value, 1]];
  while (stack.length) {
    const [item, depth] = stack.pop()!;
    if (!item || typeof item !== 'object') continue;
    max = Math.max(max, depth);
    for (const child of Object.values(item as object)) stack.push([child, depth + 1]);
  }
  return max;
}

const presentsAccessToken = (kind: SessionRequestKind) => kind === 'credential' || kind === 'notification' || kind === 'deferred';

/**
 * Validates one request of the session. Checks that do not concern the request (`proof-batch` for a token request)
 * are recorded as `skip`, so the result names every check of `SESSION_CHECKS` in order.
 */
export async function validateSessionRequest(request: SessionHttpRequest, options: SessionRequestOptions): Promise<SessionRequestValidation> {
  const recorder = new CheckRecorder(options.mode ?? 'all');
  const now = seconds(options.now ?? new Date());
  const skew = options.skewSeconds ?? 300;
  const window = options.proofWindowSeconds ?? 300;
  const kind = options.kind;
  let dpopJwk: JsonWebKey | undefined;
  let body: unknown;

  return recorder.collect(async () => {
    // RFC 9449 section 4.3: the checks of a DPoP proof.
    await recorder.run('dpop-proof', [], () => {
      const value = header(request.headers, 'DPoP');
      if (!value) return fail('the request carries no DPoP header');
      const parts = value.split('.');
      if (parts.length !== 3) fail(`the DPoP proof is not a compact JWS (${parts.length} parts)`);
      let h: Record<string, unknown>;
      let p: Record<string, unknown>;
      try {
        h = base64url.decodeJson(parts[0]);
        p = base64url.decodeJson(parts[1]);
      } catch {
        return fail('the DPoP proof header or payload cannot be decoded');
      }
      if (h.typ !== 'dpop+jwt') fail(`DPoP typ is ${String(h.typ)}, not dpop+jwt`);
      const hash = DPOP_ALGORITHMS[String(h.alg)];
      if (!hash) fail(`DPoP alg ${String(h.alg)} is not an asymmetric algorithm the suite accepts`);
      const key = publicKeyOf(h.jwk, 'the DPoP jwk');
      if (!nodeVerify(hash, Buffer.from(`${parts[0]}.${parts[1]}`), { key, dsaEncoding: 'ieee-p1363' }, base64url.decode(parts[2]))) fail('DPoP signature does not verify with its jwk');
      if (p.htm !== request.method.toUpperCase()) fail(`DPoP htm ${String(p.htm)} is not the request method ${request.method}`);
      const url = new URL(request.url);
      if (p.htu !== `${url.origin}${url.pathname}`) fail(`DPoP htu ${String(p.htu)} is not the request URI ${url.origin}${url.pathname}`);
      if (typeof p.iat !== 'number') return fail('DPoP has no numeric iat');
      if (p.iat > now + skew) fail(`DPoP iat ${p.iat} is in the future (now ${now}, T_skew ${skew})`);
      if (p.iat < now - window - skew) fail(`DPoP iat ${p.iat} is older than T_proof ${window} s plus T_skew ${skew} s (now ${now})`);
      if (typeof p.jti !== 'string' || !p.jti) return fail('DPoP has no jti');
      if (options.usedDpopJtis?.includes(p.jti)) fail(`DPoP jti ${p.jti} was used before`);
      if (presentsAccessToken(kind)) {
        if (!options.accessToken) fail('no access token to compare ath with');
        if (p.ath === undefined) fail('DPoP has no ath, while the request presents an access token');
        if (p.ath !== base64url.encode(sha256(options.accessToken ?? ''))) fail('DPoP ath is not the hash of the access token the request presents');
      }
      if (options.dpopNonce !== undefined && p.nonce !== options.dpopNonce) fail(`DPoP nonce ${String(p.nonce)} is not the server's DPoP-Nonce ${options.dpopNonce}`);
      dpopJwk = h.jwk as JsonWebKey;
    });

    // RFC 9449 sections 5, 6 and 7.1: the token is presented as DPoP-bound, and the proof is signed with its key.
    await recorder.run('dpop-binding', ['dpop-proof'], () => {
      if (kind === 'token') return new NotApplicable('the token request binds the token it asks for; no token is bound yet');
      if (presentsAccessToken(kind)) {
        const authorization = header(request.headers, 'Authorization') ?? '';
        const [scheme, token] = authorization.split(' ');
        if (scheme !== 'DPoP') fail(`the access token is presented with the scheme ${scheme || '(none)'}, not DPoP`);
        if (token !== options.accessToken) fail('the Authorization header does not carry the access token');
      }
      if (!options.boundKey) return fail('no key the token is bound to');
      const bound = jwkThumbprint(options.boundKey);
      const used = jwkThumbprint(dpopJwk!);
      if (bound !== used) fail(`the DPoP proof is signed with the key ${used}, not with the key ${bound} the ${kind === 'refresh' ? 'refresh' : 'access'} token is bound to`);
    });

    await recorder.run('request-encoding', [], () => {
      const contentType = (header(request.headers, 'Content-Type') ?? '').split(';')[0].trim().toLowerCase();
      const size = Buffer.byteLength(request.body ?? '');
      const max = options.maxBodyBytes ?? 1 << 20;
      if (size > max) fail(`the body has ${size} bytes, more than ${max}`);
      if (kind === 'token' || kind === 'refresh') {
        if (contentType !== 'application/x-www-form-urlencoded') fail(`Content-Type ${contentType || '(none)'} of a token request, not application/x-www-form-urlencoded`);
        return;
      }
      if (contentType === 'application/jwt') return 'an encrypted request (application/jwt)';
      if (contentType !== 'application/json') fail(`Content-Type ${contentType || '(none)'}, not application/json`);
      try {
        body = JSON.parse(request.body ?? '');
      } catch (error) {
        return fail(`the body is not JSON: ${(error as Error).message}`);
      }
      const depth = depthOf(body);
      const maxDepth = options.maxDepth ?? 32;
      if (depth > maxDepth) fail(`the JSON body nests ${depth} levels deep, more than ${maxDepth}`);
    });

    await recorder.run('proof-batch', ['request-encoding'], () => {
      if (kind !== 'credential') return new NotApplicable(`a ${kind} request carries no proofs`);
      if (!isObject(body)) return new NotApplicable('an encrypted credential request');
      const proofs = isObject(body.proofs) ? body.proofs.jwt : undefined;
      if (!Array.isArray(proofs)) return new NotApplicable('the request carries no proofs.jwt');
      const size = options.batchSize ?? 1;
      if (proofs.length > size) fail(`the request carries ${proofs.length} proofs, more than batch_size ${size}`);
      const keys = proofs.map((proof) => {
        try {
          const jwk = base64url.decodeJson(String(proof).split('.')[0]).jwk as JsonWebKey;
          return jwk ? jwkThumbprint(jwk) : undefined;
        } catch {
          return undefined;
        }
      });
      const seen = keys.filter((k): k is string => k !== undefined);
      const twice = seen.find((k, i) => seen.indexOf(k) !== i);
      if (twice) fail(`two proofs of the batch are signed by the same key ${twice}`);
      return `${proofs.length} proof(s), each with a key of its own`;
    });

    await recorder.run('response-encryption', ['request-encoding'], () => {
      if (kind !== 'credential' || !isObject(body)) return new NotApplicable('no credential_response_encryption');
      const parameters = body.credential_response_encryption;
      if (parameters === undefined) return new NotApplicable('no credential_response_encryption');
      if (!isObject(parameters)) return fail('credential_response_encryption is not an object');
      const advertised = options.responseEncryption;
      if (!advertised) return fail('the Credential Issuer advertises no credential_response_encryption');
      const jwk = parameters.jwk;
      if (!isObject(jwk)) return fail('credential_response_encryption has no jwk');
      if (typeof jwk.alg !== 'string' || !(advertised.alg_values_supported ?? []).includes(jwk.alg)) {
        fail(`the alg ${String(jwk.alg)} of the encryption jwk is not in alg_values_supported ${JSON.stringify(advertised.alg_values_supported ?? [])}`);
      }
      if (typeof parameters.enc !== 'string' || !(advertised.enc_values_supported ?? []).includes(parameters.enc)) {
        fail(`enc ${String(parameters.enc)} is not in enc_values_supported ${JSON.stringify(advertised.enc_values_supported ?? [])}`);
      }
      publicKeyOf(jwk, 'the encryption jwk');
    });

    await recorder.run('notification-request', ['request-encoding'], () => {
      if (kind !== 'notification') return new NotApplicable(`not a notification request`);
      if (!isObject(body)) return fail('the notification request is not a JSON object');
      if (!options.notificationIds?.includes(String(body.notification_id))) fail(`notification_id ${String(body.notification_id)} was not issued by a credential response`);
      if (!NOTIFICATION_EVENTS.includes(String(body.event))) fail(`event ${String(body.event)} is not one of ${NOTIFICATION_EVENTS.join(', ')}`);
    });

    await recorder.run('deferred-request', ['request-encoding'], () => {
      if (kind !== 'deferred') return new NotApplicable(`not a deferred credential request`);
      if (!isObject(body)) return fail('the deferred credential request is not a JSON object');
      if (!options.transactionIds?.includes(String(body.transaction_id))) fail(`transaction_id ${String(body.transaction_id)} was not issued to this access token, or was redeemed`);
    });

    await recorder.run('access-token-validity', [], () => {
      if (!presentsAccessToken(kind)) return new NotApplicable('the request presents no access token');
      if (!options.accessTokenExpiresAt) return new NotApplicable('no expiry of the access token known');
      const exp = seconds(options.accessTokenExpiresAt);
      if (now > exp + skew) fail(`the access token expired at ${exp}, the request was sent at ${now} (T_skew ${skew})`);
    });
  });
}
