// A minimal Credential Issuer for the unit tests, on 127.0.0.1, whose every check is the libraries' own issuer side:
// `Oauth2AuthorizationServer` verifies the token request (pre-authorized code, `tx_code`, WIA and PoP, DPoP),
// `Oauth2ResourceServer` the DPoP-bound access token at the credential endpoint (`ath`), `Openid4vciIssuer` the key
// proof with its `key_attestation`. The first token request and the first credential request are answered with
// `use_dpop_nonce`, so the client's retry runs on every issuance.
import { createHash, randomBytes, randomUUID } from 'node:crypto';
import { type CallbackContext, type Jwk, type JwtSigner, Oauth2AuthorizationServer, Oauth2ResourceServer } from '@openid4vc/oauth2';
import { Openid4vciIssuer } from '@openid4vc/openid4vci';
import { type RunningServer, sendJson, startServer } from '@eudi-pcaf/core';
import { base64url, type EcKeyPair, generateEcKeyPair, signEs256, verifyEs256 } from '@eudi-pcaf/forge';
import { parseCertificate } from '@owf/x509';

export const CONFIGURATION_ID = 'test_sd_jwt_vc';
export const KEY_ATTESTATIONS_REQUIRED = { key_storage: ['iso_18045_high'], user_authentication: ['iso_18045_high'] };

const hash: CallbackContext['hash'] = (data, alg) => createHash(alg.replace('-', '').toLowerCase()).update(data).digest();

/** Verifies an ES256 JWT with the key its signer names: `jwk`, or the leaf of `x5c` (no path validation here). */
export const verifyJwt: CallbackContext['verifyJwt'] = async (signer: JwtSigner, { compact }) => {
  const jwk =
    signer.method === 'jwk' ? (signer.publicJwk as JsonWebKey) : signer.method === 'x5c' ? (parseCertificate(signer.x5c[0]).publicKey.jwk as JsonWebKey) : undefined;
  if (!jwk) return { verified: false };
  const [h, p, s] = compact.split('.');
  const verified = await verifyEs256(jwk, `${h}.${p}`, base64url.decode(s ?? ''));
  return verified ? { verified: true, signerJwk: jwk as Jwk } : { verified: false };
};

export interface LibraryIssuer {
  url: string;
  /** Requests the issuer refused, with the library's reason. */
  rejections: { path: string; reason: string }[];
  offerByValue(): string;
  stop(): Promise<void>;
}

export async function startLibraryIssuer(options: { preAuthorizedCode: string; txCode: string; clientId: string }): Promise<LibraryIssuer> {
  const tokenKey: EcKeyPair = await generateEcKeyPair();
  const signJwt: CallbackContext['signJwt'] = async (_signer, { header, payload }) => {
    const input = `${base64url.encode(JSON.stringify(header))}.${base64url.encode(JSON.stringify(payload))}`;
    return { jwt: `${input}.${base64url.encode(await signEs256(tokenKey.privateKey, input))}`, signerJwk: tokenKey.publicJwk as Jwk };
  };
  const callbacks = {
    hash,
    verifyJwt,
    signJwt,
    generateRandom: (length: number) => randomBytes(length),
    clientAuthentication: () => undefined,
    decryptJwe: () => ({ decrypted: false as const }),
    encryptJwe: () => {
      throw new Error('not used');
    },
  };
  const as = new Oauth2AuthorizationServer({ callbacks });
  const rs = new Oauth2ResourceServer({ callbacks });
  const issuer = new Openid4vciIssuer({ callbacks });
  const rejections: LibraryIssuer['rejections'] = [];
  const dpopNonce = { token: randomUUID(), credential: randomUUID() };
  const seenWithoutNonce = new Set<string>();
  const cNonces = new Set<string>();
  let base = '';

  const issuerMetadata = () => ({
    credential_issuer: base,
    credential_endpoint: `${base}/credential`,
    nonce_endpoint: `${base}/nonce`,
    credential_configurations_supported: {
      [CONFIGURATION_ID]: {
        format: 'dc+sd-jwt',
        vct: 'urn:test:vct',
        cryptographic_binding_methods_supported: ['jwk'],
        credential_signing_alg_values_supported: ['ES256'],
        proof_types_supported: { jwt: { proof_signing_alg_values_supported: ['ES256'], key_attestations_required: KEY_ATTESTATIONS_REQUIRED } },
      },
    },
  });
  const asMetadata = () => ({
    issuer: base,
    token_endpoint: `${base}/token`,
    jwks_uri: `${base}/jwks`,
    grant_types_supported: ['urn:ietf:params:oauth:grant-type:pre-authorized_code'],
    token_endpoint_auth_methods_supported: ['attest_jwt_client_auth'],
    dpop_signing_alg_values_supported: ['ES256'],
  });

  const server: RunningServer = await startServer({ host: '127.0.0.1' }, async (req, res, body) => {
    const path = new URL(req.url ?? '/', 'http://localhost').pathname;
    const request = { method: (req.method ?? 'GET') as 'GET', url: `${base}${req.url}`, headers: new Headers(req.headers as Record<string, string>) };
    const reject = (status: number, reason: string, error = 'invalid_request', headers: Record<string, string> = {}) => {
      rejections.push({ path, reason });
      sendJson(res, status, { error, error_description: reason }, headers);
    };
    try {
      if (path === '/.well-known/openid-credential-issuer') {
        if (req.headers.accept === 'application/jwt') return sendJson(res, 406, { error: 'not_acceptable' });
        return sendJson(res, 200, issuerMetadata());
      }
      if (path === '/.well-known/oauth-authorization-server') return sendJson(res, 200, asMetadata());
      if (path === '/jwks') return sendJson(res, 200, { keys: [{ ...tokenKey.publicJwk, kid: 'access-token', alg: 'ES256', use: 'sig' }] });
      if (path === '/token') {
        const parsed = as.parseAccessTokenRequest({ request, accessTokenRequest: Object.fromEntries(new URLSearchParams(body.toString())) });
        if (!seenWithoutNonce.has('token')) {
          seenWithoutNonce.add('token');
          return reject(400, 'DPoP nonce required', 'use_dpop_nonce', { 'DPoP-Nonce': dpopNonce.token });
        }
        if (parsed.grant.grantType !== 'urn:ietf:params:oauth:grant-type:pre-authorized_code') return reject(400, 'grant');
        const verified = await as.verifyPreAuthorizedCodeAccessTokenRequest({
          authorizationServerMetadata: asMetadata(),
          grant: parsed.grant,
          accessTokenRequest: parsed.accessTokenRequest,
          request,
          expectedPreAuthorizedCode: options.preAuthorizedCode,
          expectedTxCode: options.txCode,
          dpop: { required: true, jwt: parsed.dpop?.jwt, expectedNonce: dpopNonce.token, allowedSigningAlgs: ['ES256'] },
          clientAttestation: {
            required: true,
            clientAttestationJwt: parsed.clientAttestation?.clientAttestationJwt,
            clientAttestationPopJwt: parsed.clientAttestation?.clientAttestationPopJwt,
            expectedClientId: options.clientId,
          },
        });
        const response = await as.createAccessTokenResponse({
          authorizationServer: base,
          audience: base,
          expiresInSeconds: 300,
          subject: options.clientId,
          signer: { method: 'jwk', alg: 'ES256', publicJwk: { ...tokenKey.publicJwk, kid: 'access-token' } as Jwk },
          dpop: verified.dpop?.jwk ? { jwk: verified.dpop.jwk } : undefined,
          clientId: verified.clientAttestation?.clientAttestation.payload.sub,
        });
        return sendJson(res, 200, response);
      }
      if (path === '/nonce') {
        const cNonce = randomUUID();
        cNonces.add(cNonce);
        return sendJson(res, 200, { c_nonce: cNonce });
      }
      if (path === '/credential') {
        if (!seenWithoutNonce.has('credential')) {
          seenWithoutNonce.add('credential');
          rejections.push({ path, reason: 'DPoP nonce required' });
          res.writeHead(401, { 'WWW-Authenticate': 'DPoP error="use_dpop_nonce"', 'DPoP-Nonce': dpopNonce.credential });
          return res.end();
        }
        const { dpop } = await rs.verifyResourceRequest({
          request,
          resourceServer: base,
          authorizationServers: [asMetadata()],
          allowedAuthenticationSchemes: ['DPoP' as never],
        });
        if (!dpop) return reject(401, 'no DPoP');
        const credentialRequest = JSON.parse(body.toString()) as { credential_configuration_id: string; proofs: { jwt: string[] } };
        const metadata = { credentialIssuer: issuerMetadata(), authorizationServers: [asMetadata()] };
        const [proofJwt] = credentialRequest.proofs.jwt;
        const nonce = JSON.parse(Buffer.from(proofJwt.split('.')[1], 'base64url').toString()).nonce as string;
        if (!cNonces.delete(nonce)) return reject(400, 'unknown c_nonce', 'invalid_nonce');
        const proof = await issuer.verifyCredentialRequestJwtProof({
          issuerMetadata: metadata as never,
          jwt: proofJwt,
          expectedNonce: nonce,
          clientId: options.clientId,
          keyAttestationsRequired: KEY_ATTESTATIONS_REQUIRED,
        });
        return sendJson(res, 200, { credentials: [{ credential: `issued-to~${JSON.stringify(proof.signer)}~` }] });
      }
      return reject(404, `no route ${path}`, 'not_found');
    } catch (error) {
      return reject(400, (error as Error).message);
    }
  });
  base = server.localUrl;
  return {
    url: base,
    rejections,
    offerByValue: () =>
      `openid-credential-offer://?credential_offer=${encodeURIComponent(
        JSON.stringify({
          credential_issuer: base,
          credential_configuration_ids: [CONFIGURATION_ID],
          grants: {
            'urn:ietf:params:oauth:grant-type:pre-authorized_code': {
              'pre-authorized_code': options.preAuthorizedCode,
              tx_code: { input_mode: 'numeric', length: options.txCode.length },
            },
          },
        }),
      )}`,
    stop: () => server.close(),
  };
}
