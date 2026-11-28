// The issuance client's messages are valid by the libraries' own issuer side: the WIA PoP, the DPoP proofs (token
// request; credential request with `ath`) and the key proof with its KA, built without a network and verified with
// `@openid4vc/oauth2` and `@openid4vc/openid4vci`. Then the whole valid path against a local issuer made of those
// verifiers (`library-issuer.ts`), with the `use_dpop_nonce` retry and the hooks of the fault layer.
import { createHash, randomUUID } from 'node:crypto';
import { Oauth2AuthorizationServer } from '@openid4vc/oauth2';
import { Openid4vciIssuer } from '@openid4vc/openid4vci';
import { base64url, createTestPki, decodeJws, type EcKeyPair, generateEcKeyPair, sha256, type TestPki } from '@eudi-pcaf/forge';
import { StatusProvider } from '@eudi-pcaf/status-provider';
import { CLIENT_ATTESTATION_HEADER, CLIENT_ATTESTATION_POP_HEADER, keySigner, signJwt, TestWalletProvider, TYP, wiaPopParts } from '@eudi-pcaf/wallet-provider';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import {
  accessTokenHash,
  buildDpopProof,
  buildKeyProof,
  CLIENT_TYP,
  credentialRequest,
  dpopProofParts,
  htuOf,
  IssuanceClient,
  KEY_ATTESTATION_HEADER,
  keyProofParts,
  tokenRequest,
  walletUnitOf,
} from '../src/index';
import { CONFIGURATION_ID, KEY_ATTESTATIONS_REQUIRED, type LibraryIssuer, startLibraryIssuer, verifyJwt } from './library-issuer';

const AS = 'https://pp-t.rp-test';
const callbacks = {
  hash: (data: Uint8Array, alg: string) => new Uint8Array(createHash(alg.replace('-', '').toLowerCase()).update(data).digest()),
  verifyJwt,
  signJwt: () => {
    throw new Error('not used');
  },
  generateRandom: (n: number) => new Uint8Array(n),
  clientAuthentication: () => undefined,
  decryptJwe: () => ({ decrypted: false as const }),
  encryptJwe: () => {
    throw new Error('not used');
  },
};

let pki: TestPki;
let status: StatusProvider;
let twp: TestWalletProvider;
let dpopKey: EcKeyPair;

beforeAll(async () => {
  pki = await createTestPki();
  status = await new StatusProvider().start({ host: '127.0.0.1' });
  twp = await TestWalletProvider.create({ pki, statusProvider: status, runId: 'issuer-wallet-test' });
  dpopKey = await generateEcKeyPair();
}, 60_000);

afterAll(async () => {
  await status?.stop();
});

const requestLike = (message: { method: string; url: string; headers: Record<string, string> }) => ({
  method: message.method as 'POST',
  url: message.url,
  headers: new Headers(message.headers),
});

describe('message building', () => {
  it('builds a DPoP proof with typ, jwk, htm, htu, iat, jti, and ath and nonce when given', async () => {
    const parts = dpopProofParts({ key: dpopKey, method: 'post', url: `${AS}/credential?x=1#y`, accessToken: 'token-1', nonce: 'n-1' });
    expect(parts.header).toEqual({ typ: CLIENT_TYP.dpop, jwk: dpopKey.publicJwk });
    expect(parts.payload).toMatchObject({ htm: 'POST', htu: `${AS}/credential`, ath: base64url.encode(sha256('token-1')), nonce: 'n-1' });
    expect(typeof parts.payload.jti).toBe('string');
    expect(Math.abs((parts.payload.iat as number) - Date.now() / 1000)).toBeLessThan(5);
    expect(dpopProofParts({ key: dpopKey, method: 'POST', url: AS }).payload.jti).not.toBe(parts.payload.jti);
    expect(htuOf('https://a.example/p/q?r#s')).toBe('https://a.example/p/q');
    expect(accessTokenHash('abc')).toBe(base64url.encode(sha256('abc')));
  });

  it('lets an override set or remove any member, for the fault layer', () => {
    const parts = dpopProofParts({ key: dpopKey, method: 'POST', url: AS, header: { typ: 'JWT' }, claims: { htm: undefined, jti: 'fixed' } });
    expect(parts.header.typ).toBe('JWT');
    expect(parts.payload).not.toHaveProperty('htm');
    expect(parts.payload.jti).toBe('fixed');
  });

  it('builds a token request whose WIA, PoP and DPoP proof the authorization server library accepts', async () => {
    const unit = twp.units['CW-1'];
    const wia = await twp.wia('CW-1');
    const pop = await signJwt(wiaPopParts({ signer: keySigner(unit.instanceKey), clientId: unit.clientId, audience: AS }), keySigner(unit.instanceKey));
    const tokenEndpoint = `${AS}/token`;
    const message = tokenRequest({
      tokenEndpoint,
      preAuthorizedCode: 'code-1',
      txCode: '493536',
      clientId: unit.clientId,
      clientAttestation: wia,
      clientAttestationPop: pop,
      dpop: await buildDpopProof({ key: dpopKey, method: 'POST', url: tokenEndpoint }),
    });
    expect(message.headers[CLIENT_ATTESTATION_HEADER]).toBe(wia);
    expect(message.headers[CLIENT_ATTESTATION_POP_HEADER]).toBe(pop);
    expect(decodeJws(pop).header.typ).toBe(TYP.wiaPop);

    const as = new Oauth2AuthorizationServer({ callbacks });
    const parsed = as.parseAccessTokenRequest({ request: requestLike(message), accessTokenRequest: Object.fromEntries(new URLSearchParams(message.body)) });
    const verified = await as.verifyPreAuthorizedCodeAccessTokenRequest({
      authorizationServerMetadata: { issuer: AS, token_endpoint: tokenEndpoint },
      grant: parsed.grant as never,
      accessTokenRequest: parsed.accessTokenRequest,
      request: requestLike(message),
      expectedPreAuthorizedCode: 'code-1',
      expectedTxCode: '493536',
      dpop: { required: true, jwt: parsed.dpop?.jwt, allowedSigningAlgs: ['ES256'] },
      clientAttestation: { required: true, ...parsed.clientAttestation, expectedClientId: unit.clientId },
    });
    expect(verified.dpop?.jwk).toMatchObject({ x: dpopKey.publicJwk.x, y: dpopKey.publicJwk.y });
    expect(verified.clientAttestation?.clientAttestation.payload.sub).toBe(unit.clientId);
  });

  it('builds a credential request whose key proof, signed by an attested key with the KA in key_attestation, the issuer library accepts', async () => {
    const { jwt: ka, keys } = await twp.keyAttestation('CW-1');
    const proof = await buildKeyProof({ key: keys[0], audience: AS, nonce: 'c-nonce-1', keyAttestation: ka, clientId: twp.units['CW-1'].clientId });
    const { header, payload } = decodeJws(proof);
    expect(header).toMatchObject({ alg: 'ES256', typ: CLIENT_TYP.proof, jwk: keys[0].publicJwk, [KEY_ATTESTATION_HEADER]: ka });
    expect(payload).toMatchObject({ aud: AS, nonce: 'c-nonce-1', iss: twp.units['CW-1'].clientId });

    const issuer = new Openid4vciIssuer({ callbacks: callbacks as never });
    const verified = await issuer.verifyCredentialRequestJwtProof({
      issuerMetadata: { credentialIssuer: { credential_issuer: AS }, authorizationServers: [] } as never,
      jwt: proof,
      expectedNonce: 'c-nonce-1',
      clientId: twp.units['CW-1'].clientId,
      keyAttestationsRequired: KEY_ATTESTATIONS_REQUIRED,
    });
    expect(verified.keyAttestation?.payload.attested_keys).toEqual([keys[0].publicJwk]);

    const message = credentialRequest({
      credentialEndpoint: `${AS}/credential`,
      accessToken: 'at',
      tokenType: 'DPoP',
      dpop: 'dpop-jwt',
      credentialConfigurationId: CONFIGURATION_ID,
      proofs: [proof],
    });
    expect(message.headers).toMatchObject({ authorization: 'DPoP at', DPoP: 'dpop-jwt', 'content-type': 'application/json' });
    expect(JSON.parse(message.body!)).toEqual({ credential_configuration_id: CONFIGURATION_ID, proofs: { jwt: [proof] } });
  });

  it('the issuer library refuses a key proof by a key outside attested_keys', async () => {
    const { jwt: ka } = await twp.keyAttestation('CW-1');
    const other = await generateEcKeyPair();
    const proof = await signJwt(keyProofParts({ key: other, audience: AS, nonce: 'n', keyAttestation: ka }), keySigner(other));
    const issuer = new Openid4vciIssuer({ callbacks: callbacks as never });
    await expect(
      issuer.verifyCredentialRequestJwtProof({
        issuerMetadata: { credentialIssuer: { credential_issuer: AS }, authorizationServers: [] } as never,
        jwt: proof,
        expectedNonce: 'n',
        keyAttestationsRequired: KEY_ATTESTATIONS_REQUIRED,
      }),
    ).rejects.toThrow();
  });
});

describe('valid path against an issuer made of the library verifiers', () => {
  let issuer: LibraryIssuer;
  const preAuthorizedCode = randomUUID();

  beforeAll(async () => {
    issuer = await startLibraryIssuer({ preAuthorizedCode, txCode: '493536', clientId: twp.units['CW-1'].clientId });
  });
  afterAll(async () => {
    await issuer?.stop();
  });

  it('obtains a credential with a single retry on use_dpop_nonce at token and credential endpoint, and records every exchange', async () => {
    const steps: string[] = [];
    const client = await IssuanceClient.create(walletUnitOf(twp, 'CW-1'), {
      allowInsecureUrls: true,
      hooks: {
        request: (step, request) => {
          steps.push(step);
          return request;
        },
        jwt: (point, parts) => (point === 'proof' ? { ...parts, payload: { ...parts.payload, extra: 'kept' } } : parts),
      },
    });
    const evidence = await client.issue({ offer: issuer.offerByValue(), txCode: '493536' });
    expect(evidence.error, JSON.stringify(issuer.rejections)).toBeUndefined();
    expect(evidence.offer?.byReference).toBe(false);
    expect(evidence.credentials).toHaveLength(1);
    const [credential] = evidence.credentials;
    expect(credential.credential).toContain(credential.proofKey.publicJwk.x as string);
    expect(decodeJws(credential.keyAttestation).payload.attested_keys).toEqual([credential.proofKey.publicJwk]);

    expect(evidence.exchanges.map((e) => `${e.step}:${e.attempt}:${e.response?.status}`)).toEqual([
      'metadata:1:200',
      'metadata:1:200',
      'metadata-jwt:1:406',
      'token:1:400',
      'token:2:200',
      'nonce:1:200',
      'credential:1:401',
      'credential:2:200',
    ]);
    expect(steps).toEqual(evidence.exchanges.map((e) => e.step));
    const [token1, token2] = evidence.exchanges.filter((e) => e.step === 'token');
    expect(token1.request.headers.DPoP).not.toBe(token2.request.headers.DPoP);
    expect(token1.request.headers[CLIENT_ATTESTATION_POP_HEADER]).not.toBe(token2.request.headers[CLIENT_ATTESTATION_POP_HEADER]);
    expect(token2.response?.headers['content-type']).toContain('application/json');
    const credentialDpop = decodeJws(evidence.exchanges.at(-1)!.request.headers.DPoP).payload;
    expect(credentialDpop).toMatchObject({ ath: accessTokenHash(evidence.token!.accessToken), htm: 'POST' });
    // One DPoP key per Wallet Unit: the same key at token and credential endpoint.
    expect(decodeJws(token2.request.headers.DPoP).header.jwk).toEqual(decodeJws(evidence.exchanges.at(-1)!.request.headers.DPoP).header.jwk);
    const proof = (JSON.parse(evidence.exchanges.at(-1)!.request.body!) as { proofs: { jwt: string[] } }).proofs.jwt[0];
    expect(decodeJws(proof).payload.extra).toBe('kept');
  });
});
