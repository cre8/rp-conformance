// A Relying Party's request as the reference Relying Party builds it, captured as the Conformance Wallet sees it, valid
// or with one request fault. Only the self-validation of the request-side checks uses it: the harness checks the
// requests the Relying Party under test sends, and never sends one itself.
import { createHash, randomBytes } from 'node:crypto';
import type { CapturedRequest, DcqlQuery, FaultId, Flow } from '@eudi-pcaf/core';
import { faultInfo } from '@eudi-pcaf/core';
import { base64url, signCompactJws } from './crypto';
import { PID_NAMESPACE } from './mdoc';
import type { CertifiedKey, TestPki } from './pki';

export interface RequestBuildOptions {
  pki: TestPki;
  flow: Flow;
  query: DcqlQuery;
  /** The registration certificate in `verifier_info`. */
  registrationCertificate: string;
  /** The Relying Party's base URL and, via the DC API, the Origin of its page. */
  baseUrl: string;
  /** Default: a new random value of 32 bytes. */
  nonce?: string;
  /** The public encryption key in `client_metadata`; default a new key. */
  encryptionJwk?: JsonWebKey & { kid?: string };
  fault?: FaultId;
  /** Via redirects, how the Conformance Wallet retrieved the request object: also a second GET, or a POST with `wallet_nonce`. */
  requestUri?: 'twice' | 'post';
}

export interface BuiltRequest {
  captured: CapturedRequest;
  nonce: string;
  encryptionJwk: JsonWebKey & { kid?: string };
}

/** `x509_hash` Client Identifier of a base64 DER certificate (OpenID4VP 1.0 section 5.9.3). */
export const x509Hash = (certificateDer: Uint8Array) => `x509_hash:${base64url.encode(createHash('sha256').update(certificateDer).digest())}`;

const derOf = (key: CertifiedKey) => Buffer.from(key.certificate.der).toString('base64');

/** Builds a request in the form of the reference Relying Party, with `options.fault` applied. */
export async function buildRequest(options: RequestBuildOptions): Promise<BuiltRequest> {
  const { fault, flow, pki } = options;
  if (fault) {
    const info = faultInfo(fault);
    if (info.point !== 'request') throw new Error(`fault ${fault} does not apply to a request`);
    if (info.flow && info.flow !== flow) throw new Error(`fault ${fault} applies to the ${info.flow} flow`);
  }
  const signer = fault === 'request.access-certificate-plain' ? pki.entities['AC-A'].signers.issuance : pki.relyingPartyAccess;
  const x5c = [derOf(signer), ...(fault === 'request.x5c-anchor' ? [derOf(pki.entities['AC-A'].anchors.issuance)] : [])];
  const clientId = fault === 'request.client-id-other' ? x509Hash(randomBytes(64)) : x509Hash(signer.certificate.der);
  const nonce = fault === 'request.nonce-short' ? 'abc123' : (options.nonce ?? base64url.encode(randomBytes(32)));
  const encryptionJwk = options.encryptionJwk ?? (await newEncryptionKey());
  const query = structuredClone(options.query) as DcqlQuery & { credentials: Record<string, unknown>[] };
  const [first] = query.credentials;
  switch (fault) {
    case 'request.dcql-duplicate-id':
      query.credentials.push(structuredClone(first));
      break;
    case 'request.holder-binding-false':
      first.require_cryptographic_holder_binding = false;
      break;
    case 'request.trusted-authorities-other': {
      const ski = pki.entities['CA-X'].anchors.issuance.certificate.subjectKeyIdentifier as string;
      for (const credential of query.credentials) credential.trusted_authorities = [{ type: 'aki', values: [Buffer.from(ski, 'hex').toString('base64url')] }];
      break;
    }
    case 'request.unregistered-claim': {
      const claims = (first.claims ?? []) as { path: (string | number | null)[] }[];
      claims.push({ path: first.format === 'mso_mdoc' ? [PID_NAMESPACE, 'email_address'] : ['email'] });
      first.claims = claims;
      break;
    }
  }
  const dcApi = flow === 'dc-api';
  const origin = new URL(options.baseUrl).origin;
  const id = base64url.encode(randomBytes(8));
  const payload: Record<string, unknown> = {
    response_type: 'vp_token',
    client_id: clientId,
    ...(dcApi
      ? {
          response_mode: fault === 'request.dc-api-response-mode-unencrypted' ? 'dc_api' : 'dc_api.jwt',
          expected_origins: fault === 'request.expected-origins-other' ? [origin, 'https://other.example'] : [origin],
        }
      : {
          response_mode: fault === 'request.response-mode-direct-post' ? 'direct_post' : 'direct_post.jwt',
          response_uri: `${options.baseUrl}/oid4vp/${id}/response`,
          state: fault === 'request.state-short' ? '1' : base64url.encode(randomBytes(16)),
        }),
    nonce,
    ...(options.requestUri === 'post' && fault !== 'request.wallet-nonce-missing' ? { wallet_nonce: WALLET_NONCE } : {}),
    dcql_query: query,
    client_metadata: {
      jwks: { keys: [fault === 'request.enc-key-private' ? { ...encryptionJwk, d: base64url.encode(randomBytes(32)) } : encryptionJwk] },
      encrypted_response_enc_values_supported: fault === 'request.enc-values-one' ? ['A128GCM'] : ['A128GCM', 'A256GCM'],
      vp_formats_supported: {
        'dc+sd-jwt': {
          'sd-jwt_alg_values': fault === 'request.vp-formats-es256k' ? ['ES256', 'ES256K'] : ['ES256'],
          'kb-jwt_alg_values': ['ES256'],
        },
        mso_mdoc: { issuerauth_alg_values: fault === 'request.vp-formats-es256k' ? [-7, -47] : [-7], deviceauth_alg_values: [-7] },
      },
    },
    ...(fault === 'request.registration-certificate-missing' ? {} : { verifier_info: [{ format: 'registration_cert', data: options.registrationCertificate }] }),
    aud: 'https://self-issued.me/v2',
    iat: Math.floor(Date.now() / 1000),
  };
  const header = { alg: 'ES256', typ: fault === 'request.typ-jwt' ? 'JWT' : 'oauth-authz-req+jwt', x5c };
  const unsigned = fault === 'request.unsigned';
  const jws = unsigned
    ? `${base64url.encode(JSON.stringify({ alg: 'none', typ: 'oauth-authz-req+jwt' }))}.${base64url.encode(JSON.stringify(payload))}.`
    : await signCompactJws(header, payload, signer.key.privateKey);
  if (dcApi) {
    const captured: CapturedRequest = unsigned
      ? { flow, protocol: 'openid4vp-v1-unsigned', data: payload, origin }
      : { flow, protocol: 'openid4vp-v1-signed', data: { request: jws }, origin };
    return { captured, nonce, encryptionJwk };
  }
  const invocation = new URL(fault === 'request.invocation-scheme-other' ? 'mdoc-openid4vp://' : 'openid4vp://');
  invocation.searchParams.set('client_id', clientId);
  invocation.searchParams.set('request_uri', `${options.baseUrl}/oid4vp/${id}/request`);
  // The reference Relying Party offers request_uri_method post (ICS RP.P.8) and answers GET as well.
  invocation.searchParams.set('request_uri_method', 'post');
  if (fault === 'request.unsigned-parameter') invocation.searchParams.set('nonce', nonce);
  const contentType = fault === 'request.request-uri-content-type-jwt' ? 'application/jwt' : 'application/oauth-authz-req+jwt';
  const answer = { status: 200, contentType, body: jws };
  return {
    captured: {
      flow,
      invocationUri: invocation.href,
      requestUri: answer,
      ...(options.requestUri === 'twice' ? { refetch: fault === 'request.refetch-refused' ? { status: 404, contentType: 'application/json', body: '{"error":"not_found"}' } : answer } : {}),
      ...(options.requestUri === 'post' ? { walletNonce: WALLET_NONCE } : {}),
    },
    nonce,
    encryptionJwk,
  };
}

/** The `wallet_nonce` of the self-validation's POST to `request_uri`. */
const WALLET_NONCE = 'wallet-nonce-of-the-self-validation';

async function newEncryptionKey(): Promise<JsonWebKey & { kid: string }> {
  const pair = (await globalThis.crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits'])) as CryptoKeyPair;
  const { kty, crv, x, y } = await globalThis.crypto.subtle.exportKey('jwk', pair.publicKey);
  return { kty, crv, x, y, kid: `enc-${base64url.encode(randomBytes(8))}`, use: 'enc', alg: 'ECDH-ES' };
}

/**
 * The key identifiers (base64url) a `trusted_authorities` entry of type `aki` may name for a PID: those of the
 * PID/Issuance anchors of the entities on `TL-PID`.
 */
export function requestAnchorKeyIds(pki: TestPki): string[] {
  return Object.values(pki.entities)
    .filter((entity) => entity.spec.list === 'TL-PID')
    .map((entity) => entity.anchors.issuance.certificate.subjectKeyIdentifier)
    .filter((ski): ski is string => Boolean(ski))
    .map((ski) => Buffer.from(ski, 'hex').toString('base64url'));
}
