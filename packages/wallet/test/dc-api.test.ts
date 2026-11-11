import { createHash } from 'node:crypto';
import { pid, presentation } from '@rp-conformance/core';
import { base64url, createTestPki, forgePresentation, PID_QUERY, signCompactJws, type TestPki } from '@rp-conformance/forge';
import { compactDecrypt, exportJWK, generateKeyPair, type JWK } from 'jose';
import { beforeAll, describe, expect, it } from 'vitest';
import { ConformanceWallet, type DcApiCall, type HeldCredential } from '../src/index';

// The Conformance Wallet via the W3C Digital Credentials API (OpenID4VP 1.0 Appendix A): the three request types HAIP 1.0
// section 5.2 requires of a Wallet, the check of `expected_origins`, and a response of mode `dc_api.jwt` whose KB-JWT
// is addressed to `origin:<origin>`.
const ORIGIN = 'https://rp.rp-test';

let pki: TestPki;
let wallet: ConformanceWallet;
let held: HeldCredential;
let encryption: { privateKey: CryptoKey; publicJwk: JWK };
let clientId: string;
let x5c: string[];

beforeAll(async () => {
  pki = await createTestPki();
  wallet = await ConformanceWallet.create({ accessCertificateAnchors: [pki.entities['AC-A'].anchors.issuance.certificate] });
  const forged = await forgePresentation(presentation({ query: 'default_query_pid', credential: pid.sdJwtVc() }), {
    pki,
    holderPublicJwk: wallet.holderKey.publicJwk,
    allocateStatusUri: () => 'https://status.rp-test/wallet/1',
    skewSeconds: 60,
  });
  held = { format: 'dc+sd-jwt', value: forged.credential as string };
  const pair = await generateKeyPair('ECDH-ES', { crv: 'P-256', extractable: true });
  encryption = { privateKey: pair.privateKey as CryptoKey, publicJwk: { ...(await exportJWK(pair.publicKey)), kid: 'enc-1', use: 'enc', alg: 'ECDH-ES' } };
  const access = pki.relyingPartyAccess;
  x5c = access.chain.map((c) => Buffer.from(c.der).toString('base64'));
  clientId = `x509_hash:${base64url.encode(createHash('sha256').update(access.certificate.der).digest())}`;
});

const parameters = (overrides: Record<string, unknown> = {}) => ({
  response_type: 'vp_token',
  response_mode: 'dc_api.jwt',
  nonce: 'n-dc-api',
  dcql_query: PID_QUERY,
  client_metadata: { jwks: { keys: [encryption.publicJwk] }, encrypted_response_enc_values_supported: ['A128GCM'] },
  ...overrides,
});

const header = { alg: 'ES256', typ: 'oauth-authz-req+jwt' };

const signed = async (overrides: Record<string, unknown> = {}): Promise<DcApiCall> => ({
  origin: ORIGIN,
  pageUrl: `${ORIGIN}/page`,
  requests: [
    {
      protocol: 'openid4vp-v1-signed',
      data: {
        request: await signCompactJws({ ...header, x5c }, { client_id: clientId, expected_origins: [ORIGIN], ...parameters(), ...overrides }, pki.relyingPartyAccess.key.privateKey),
      },
    },
  ],
});

/** A multi-signed request: one signature by the access certificate, with `client_id` in its protected header. */
const multiSigned = async (): Promise<DcApiCall> => {
  const compact = await signCompactJws({ ...header, x5c, client_id: clientId }, { expected_origins: [ORIGIN], ...parameters() }, pki.relyingPartyAccess.key.privateKey);
  const [protectedHeader, payload, signature] = compact.split('.');
  return {
    origin: ORIGIN,
    pageUrl: `${ORIGIN}/page`,
    requests: [{ protocol: 'openid4vp-v1-multisigned', data: { request: { payload, signatures: [{ protected: protectedHeader, signature }] } } }],
  };
};

/** The KB-JWT payload of the presentation in a `dc_api.jwt` response. */
async function kbJwtOf(data: Record<string, unknown>) {
  const { plaintext } = await compactDecrypt(data.response as string, encryption.privateKey);
  const payload = JSON.parse(new TextDecoder().decode(plaintext)) as { vp_token: Record<string, string[]>; state?: string };
  expect(payload.state).toBeUndefined();
  const kbJwt = payload.vp_token.pid[0].split('~').at(-1) as string;
  return base64url.decodeJson<{ aud: string; nonce: string }>(kbJwt.split('.')[1]);
}

describe('Conformance Wallet via the DC API', () => {
  it('answers a signed request with dc_api.jwt and the audience origin:<origin>', async () => {
    const { evidence, answer } = await wallet.presentDcApi(await signed(), held);
    expect(evidence.error).toBeUndefined();
    expect(answer?.protocol).toBe('openid4vp-v1-signed');
    expect(await kbJwtOf(answer?.data ?? {})).toMatchObject({ aud: `origin:${ORIGIN}`, nonce: 'n-dc-api' });
  });

  it('answers a multi-signed request, taking client_id from the protected header', async () => {
    const { evidence, answer } = await wallet.presentDcApi(await multiSigned(), held);
    expect(evidence.error).toBeUndefined();
    expect(evidence.request?.header.client_id).toBe(clientId);
    expect(await kbJwtOf(answer?.data ?? {})).toMatchObject({ aud: `origin:${ORIGIN}` });
  });

  it('answers an unsigned request and records that the Relying Party is not authenticated', async () => {
    const call: DcApiCall = { origin: ORIGIN, pageUrl: `${ORIGIN}/page`, requests: [{ protocol: 'openid4vp-v1-unsigned', data: parameters() }] };
    const { evidence, answer } = await wallet.presentDcApi(call, held);
    expect(evidence.error).toBeUndefined();
    expect(evidence.findings.map((f) => f.code)).toContain('unsigned-request');
    expect(await kbJwtOf(answer?.data ?? {})).toMatchObject({ aud: `origin:${ORIGIN}` });
  });

  it('refuses a signed request whose expected_origins does not name the page', async () => {
    const { evidence, answer } = await wallet.presentDcApi(await signed({ expected_origins: ['https://other.rp-test'] }), held);
    expect(answer).toBeUndefined();
    expect(evidence.error).toBeDefined();
  });

  it('refuses a request with response mode dc_api', async () => {
    const { evidence, answer } = await wallet.presentDcApi(await signed({ response_mode: 'dc_api' }), held);
    expect(answer).toBeUndefined();
    expect(evidence.findings.map((f) => f.code)).toContain('response-mode');
  });

  it('records the encryption key of a request it does not answer', async () => {
    const evidence = await wallet.startDcApi(await signed());
    expect(evidence.encryptionKey?.kid).toBe('enc-1');
  });
});
