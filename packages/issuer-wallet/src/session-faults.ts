// The session faults of issue 25 (`SESSION_FAULTS`, @eudi-pcaf/core): each is a pure change of a valid request of
// the session client (session.ts), applied through its seams after the valid build: the `jwt` hook for the claims of a
// DPoP proof, the `body` hook for the JSON of a credential, notification or deferred request before it is encrypted, the
// `request` hook for headers and the body as sent. Batch faults also set how many proofs the request carries and which
// key signs each. A test definition names the fault only.
import { generateKeyPairSync, randomBytes, randomUUID } from 'node:crypto';
import { type SessionFaultId, sessionFaultInfo } from '@eudi-pcaf/core';
import { base64url, flipBitInSegment, generateEcKeyPair, sha256 } from '@eudi-pcaf/forge';
import { CLIENT_ATTESTATION_HEADER, keySigner, signJwt } from '@eudi-pcaf/wallet-provider';
import type { HttpRequestMessage, IssuanceStep } from './http';
import { publicJwkOf } from './jwts';
import type { CredentialRequestOptions, SessionHooks } from './session';

const HOUR = 3600;

export interface SessionFaultContext {
  /** `batch_size` the Credential Issuer advertises (ICS-08.batch_size). */
  batchSize?: number;
  /** `T_proof` and `T_skew` of the SUT, seconds; default 300 each (catalogue section 3.5). */
  proofWindowSeconds?: number;
  skewSeconds?: number;
  now?: () => Date;
}

export interface AppliedSessionFault {
  hooks: SessionHooks;
  /** Options of the credential request: number of proofs and keys, the key of each proof. */
  credential: Pick<CredentialRequestOptions, 'proofs' | 'keys' | 'keyIndex'>;
  /** Do not answer `use_dpop_nonce` with a retry. */
  noDpopRetry?: boolean;
}

const headerName = (headers: Record<string, string>, name: string) => Object.keys(headers).find((key) => key.toLowerCase() === name.toLowerCase());

function setHeader(request: HttpRequestMessage, name: string, value: string | undefined): HttpRequestMessage {
  const headers = { ...request.headers };
  const key = headerName(headers, name);
  if (key) delete headers[key];
  if (value !== undefined) headers[key ?? name] = value;
  return { ...request, headers };
}

const headerOf = (request: HttpRequestMessage, name: string) => {
  const key = headerName(request.headers, name);
  return key ? request.headers[key] : undefined;
};

/** A JWT without its signature part and the separator before it. */
const twoParts = (jwt: string) => jwt.split('.').slice(0, 2).join('.');

/** The DPoP proof of a request re-signed by a newly generated key, whose public key replaces `jwk`. */
async function resignDpop(request: HttpRequestMessage): Promise<HttpRequestMessage> {
  const proof = headerOf(request, 'DPoP');
  if (!proof) throw new Error('the request carries no DPoP header');
  const [h, p] = proof.split('.');
  const key = await generateEcKeyPair();
  const { alg: _alg, ...header } = base64url.decodeJson(h) as Record<string, unknown>;
  const signed = await signJwt({ header: { ...header, jwk: publicJwkOf(key.publicJwk) }, payload: base64url.decodeJson(p) }, keySigner(key));
  return setHeader(request, 'DPoP', signed);
}

function changeProofs(request: HttpRequestMessage, change: (proofs: string[]) => string[]): HttpRequestMessage {
  const body = JSON.parse(request.body ?? '{}') as { proofs?: { jwt?: string[] } };
  if (!body.proofs?.jwt) throw new Error('the credential request carries no proofs.jwt');
  body.proofs.jwt = change(body.proofs.jwt);
  return { ...request, body: JSON.stringify(body) };
}

/** A P-256 public JWK whose `y` is no longer on the curve. */
function offCurve(jwk: Record<string, unknown>): Record<string, unknown> {
  const y = base64url.decode(String(jwk.y));
  y[y.length - 1] ^= 0x01;
  return { ...jwk, y: base64url.encode(y) };
}

/** 10 MiB: above the 1 MiB the reference validator allows and any body limit a Provider should have. */
const OVERSIZE = 10 << 20;
const NESTING = 10_000;

/** Applies one session fault (or none) to a session: the hooks and the options of its credential request. */
export function applySessionFault(fault: SessionFaultId | undefined, context: SessionFaultContext = {}): AppliedSessionFault {
  const batchSize = context.batchSize ?? 1;
  const applied: AppliedSessionFault = { hooks: {}, credential: {} };
  if (!fault) return applied;
  const info = sessionFaultInfo(fault);
  const target = info.request as IssuanceStep;
  const now = () => Math.floor((context.now?.() ?? new Date()).getTime() / 1000);
  const onTarget = (change: (request: HttpRequestMessage) => HttpRequestMessage | Promise<HttpRequestMessage>) => {
    applied.hooks.request = async (step, request) => (step === target ? change(request) : request);
  };
  const dpopClaims = (change: (payload: Record<string, unknown>) => void) => {
    applied.hooks.jwt = (point, parts, { step }) => {
      if (point === 'dpop' && step === target) change(parts.payload);
      return parts;
    };
  };
  const body = (change: (body: Record<string, unknown>) => Record<string, unknown>) => {
    applied.hooks.body = (step, value) => (step === target ? change({ ...value }) : value);
  };

  switch (fault) {
    case 'dpop.missing':
      onTarget((r) => setHeader(r, 'DPoP', undefined));
      break;
    case 'dpop.bearer':
      onTarget((r) => setHeader(r, 'Authorization', (headerOf(r, 'Authorization') ?? '').replace(/^\S+ /, 'Bearer ')));
      break;
    case 'dpop.other-key':
      onTarget(resignDpop);
      break;
    case 'dpop.htm-wrong':
      dpopClaims((p) => void (p.htm = 'GET'));
      break;
    case 'dpop.htu-wrong':
      dpopClaims((p) => void (p.htu = `${String(p.htu).replace(/\/$/, '')}/other`));
      break;
    case 'dpop.ath-missing':
      dpopClaims((p) => void delete p.ath);
      break;
    case 'dpop.ath-wrong':
      dpopClaims((p) => void (p.ath = base64url.encode(sha256(`other-${randomUUID()}`))));
      break;
    case 'dpop.iat-stale':
      dpopClaims((p) => void (p.iat = now() - (context.proofWindowSeconds ?? 300) - (context.skewSeconds ?? 300) - HOUR));
      break;
    case 'dpop.nonce-omitted':
      dpopClaims((p) => void delete p.nonce);
      applied.noDpopRetry = true;
      break;
    case 'access-token.expired':
    case 'deferred.access-token-foreign':
      // Not a change of a message: the runner waits until the access token has expired, or redeems the
      // `transaction_id` with the session of another Wallet Unit (packages/controller/src/issuer/session.ts).
      break;
    case 'batch.over-size':
      applied.credential = { proofs: batchSize + 1, keys: batchSize + 1 };
      break;
    case 'batch.one-bad-proof':
      applied.credential = { proofs: batchSize, keys: batchSize };
      onTarget((r) => changeProofs(r, (proofs) => proofs.map((proof, i) => (i === 1 ? flipBitInSegment(proof, 2) : proof))));
      break;
    case 'batch.same-key-twice':
      applied.credential = { proofs: batchSize, keys: batchSize, keyIndex: (i) => (i === 1 ? 0 : i) };
      break;
    case 'encoding.truncated-json':
      onTarget((r) => ({ ...r, body: (r.body ?? '').slice(0, Math.floor((r.body ?? '').length / 2)) }));
      break;
    case 'encoding.text-plain':
    case 'encoding.token-text-plain':
      onTarget((r) => setHeader(r, 'Content-Type', 'text/plain'));
      break;
    case 'encoding.two-part-jwt':
      onTarget((r) => setHeader(r, CLIENT_ATTESTATION_HEADER, twoParts(headerOf(r, CLIENT_ATTESTATION_HEADER) ?? '')));
      break;
    case 'encoding.dpop-two-part-jwt':
      onTarget((r) => setHeader(r, 'DPoP', twoParts(headerOf(r, 'DPoP') ?? '')));
      break;
    case 'encoding.oversized':
      onTarget((r) => ({ ...r, body: `${(r.body ?? '{}').slice(0, -1)},"padding":"${'a'.repeat(OVERSIZE)}"}` }));
      break;
    case 'encoding.deep-nesting':
      onTarget((r) => ({ ...r, body: `${(r.body ?? '{}').slice(0, -1)},"nested":${'['.repeat(NESTING)}${']'.repeat(NESTING)}}` }));
      break;
    case 'encryption.alg-unsupported': {
      const rsa = generateKeyPairSync('rsa', { modulusLength: 2048 }).publicKey.export({ format: 'jwk' }) as Record<string, unknown>;
      body((b) => ({ ...b, credential_response_encryption: { ...(b.credential_response_encryption as object), jwk: { ...rsa, alg: 'RSA-OAEP-256', use: 'enc' } } }));
      break;
    }
    case 'encryption.enc-unsupported':
      body((b) => ({ ...b, credential_response_encryption: { ...(b.credential_response_encryption as object), enc: 'A128CBC-HS256' } }));
      break;
    case 'encryption.off-curve-jwk':
      body((b) => {
        const parameters = b.credential_response_encryption as { jwk: Record<string, unknown> };
        return { ...b, credential_response_encryption: { ...parameters, jwk: offCurve(parameters.jwk) } };
      });
      break;
    case 'notification.id-unknown':
      body((b) => ({ ...b, notification_id: base64url.encode(randomBytes(16)) }));
      break;
    case 'notification.event-unknown':
      body((b) => ({ ...b, event: 'foo' }));
      break;
    case 'deferred.transaction-id-unknown':
      body((b) => ({ ...b, transaction_id: base64url.encode(randomBytes(16)) }));
      break;
    default: {
      const unhandled: never = fault;
      throw new Error(`no implementation of the session fault ${String(unhandled)}`);
    }
  }
  return applied;
}
