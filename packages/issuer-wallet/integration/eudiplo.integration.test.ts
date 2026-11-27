// The issuance client obtains SD-JWT VCs from EUDIPLO with wallet attestation and key attestation required, for Wallet
// Units of the Test Wallet Provider, with EUDIPLO trusting `TL-WP` as the harness's Test Trust Infrastructure serves it.
// EUDIPLO signs with an internal key chain of its own (the Test Registrar is issue 14, the issuer adapter issue 16).
// Needs Docker, so it is not part of `pnpm test`:
//
//   EUDIPLO_PORT=3215 docker compose --env-file adapters/issuer-eudiplo/reference.env -p eudi-pcaf-i15 \
//     -f adapters/eudiplo/docker-compose.yml up -d --wait
//   EUDIPLO_PORT=3215 pnpm test:issuer-wallet:eudiplo
//   docker compose -p eudi-pcaf-i15 -f adapters/eudiplo/docker-compose.yml down -v
//
// ISSUER_WALLET_EVIDENCE=<file> writes the evidence of both issuances as JSON.
import { randomUUID } from 'node:crypto';
import { writeFileSync } from 'node:fs';
import { base64url, createTestPki, decodeJws, type TestPki, verifyEs256 } from '@eudi-pcaf/forge';
import { StatusProvider } from '@eudi-pcaf/status-provider';
import { TrustInfrastructure } from '@eudi-pcaf/trust-infrastructure';
import { CLIENT_ATTESTATION_HEADER, CLIENT_ATTESTATION_POP_HEADER, publishTlWp, TestWalletProvider } from '@eudi-pcaf/wallet-provider';
import { parseCertificate } from '@owf/x509';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { type IssuanceEvidence, IssuanceClient, walletUnitOf } from '../src/index';

const BASE = (process.env.EUDIPLO_URL ?? `http://127.0.0.1:${process.env.EUDIPLO_PORT ?? 3215}`).replace(/\/$/, '');
const HARNESS_HOST = process.env.HARNESS_HOST ?? 'host.docker.internal';
const CONFIGURATION_ID = 'pid_sd_jwt_ka';
const TX_CODE = '493536';
const KEY_ATTESTATIONS_REQUIRED = { key_storage: ['iso_18045_high'], user_authentication: ['iso_18045_high'] };

async function call<T>(method: string, path: string, body?: unknown, token?: string): Promise<T> {
  const response = await fetch(`${BASE}${path}`, {
    method,
    headers: { ...(body !== undefined ? { 'content-type': 'application/json' } : {}), ...(token ? { authorization: `Bearer ${token}` } : {}) },
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });
  const text = await response.text();
  if (!response.ok) throw new Error(`EUDIPLO ${method} ${path}: HTTP ${response.status} ${text}`);
  return (text ? JSON.parse(text) : undefined) as T;
}

const tokenOf = async (clientId: string, clientSecret: string) =>
  (await call<{ access_token: string }>('POST', '/api/oauth2/token', { grant_type: 'client_credentials', client_id: clientId, client_secret: clientSecret })).access_token;

let pki: TestPki;
let status: StatusProvider;
let trust: TrustInfrastructure;
let twp: TestWalletProvider;
let token: string;
const evidence: Record<string, IssuanceEvidence> = {};

const createOffer = () =>
  call<{ uri: string; session: string }>(
    'POST',
    '/api/issuer/offer',
    {
      response_type: 'uri',
      flow: 'pre_authorized_code',
      credentialConfigurationIds: [CONFIGURATION_ID],
      credentialClaims: { [CONFIGURATION_ID]: { type: 'inline', claims: { given_name: 'ERIKA', family_name: 'MUSTERMANN' } } },
      tx_code: TX_CODE,
    },
    token,
  );

/** The SD-JWT VC verifies with the leaf of its `x5c` and is bound (`cnf.jwk`) to the proof key, which the KA attests. */
async function expectBoundCredential(result: IssuanceEvidence) {
  expect(result.error, JSON.stringify(result.exchanges.at(-1), null, 2)).toBeUndefined();
  expect(result.credentials).toHaveLength(1);
  const [issued] = result.credentials;
  const [jws] = issued.credential.split('~');
  const { header, payload } = decodeJws(jws);
  expect(header.typ).toBe('dc+sd-jwt');
  const [h, p, s] = jws.split('.');
  const leaf = parseCertificate((header.x5c as string[])[0]);
  expect(await verifyEs256(leaf.publicKey.jwk as JsonWebKey, `${h}.${p}`, base64url.decode(s))).toBe(true);
  const cnf = (payload.cnf as { jwk: JsonWebKey }).jwk;
  expect({ x: cnf.x, y: cnf.y }).toEqual({ x: issued.proofKey.publicJwk.x, y: issued.proofKey.publicJwk.y });
  expect(decodeJws(issued.keyAttestation).payload.attested_keys).toEqual([issued.proofKey.publicJwk]);
}

beforeAll(async () => {
  pki = await createTestPki();
  status = await new StatusProvider().start({ publicHost: HARNESS_HOST });
  trust = await new TrustInfrastructure().start({ publicHost: HARNESS_HOST });
  const namespace = `i15-${randomUUID().slice(0, 8)}`;
  const tlWp = await publishTlWp(trust, namespace, pki);
  twp = await TestWalletProvider.create({ pki, statusProvider: status, runId: namespace });

  const root = await tokenOf(process.env.EUDIPLO_CLIENT_ID ?? 'rp-conformance', process.env.EUDIPLO_CLIENT_SECRET ?? 'rp-conformance-secret');
  const tenant = await call<{ client: { clientId: string; clientSecret: string } }>(
    'POST',
    '/api/tenant',
    { id: namespace, name: `Issuer wallet ${namespace}`, description: 'Issue 15 integration test', roles: ['issuance:manage', 'issuance:offer', 'keys:manage'] },
    root,
  );
  token = await tokenOf(tenant.client.clientId, tenant.client.clientSecret);

  const { id: keyChainId } = await call<{ id: string }>(
    'POST',
    '/api/key-chain',
    { usageType: 'attestation', type: 'internalChain', description: 'Credential signing (EUDIPLO-generated until the Test Registrar)' },
    token,
  );
  // EUDIPLO signs its metadata (Accept: application/jwt) with the tenant's access key chain; without one it answers
  // HTTP 500 there (finding of issue 15).
  await call('POST', '/api/key-chain', { usageType: 'access', type: 'standalone', description: 'Signs the issuer metadata' }, token);
  const verifierX509Der = Buffer.from(pki.schemeOperators['TL-WP'].certificate.der).toString('base64');
  await call(
    'POST',
    '/api/issuer/config',
    {
      authorizationServers: [{ type: 'built-in', id: 'issuer-built-in', walletAttestationRequired: true }],
      walletAttestationRequired: true,
      walletProviderTrustLists: [{ url: tlWp.url, verifierX509Der }],
      dPopRequired: true,
    },
    token,
  );
  await call(
    'POST',
    '/api/issuer/credentials',
    {
      id: CONFIGURATION_ID,
      description: 'PID (SD-JWT VC), key attestation required',
      keyChainId,
      vct: 'urn:eudi:pid:1',
      keyBinding: true,
      statusManagement: false,
      lifeTime: 86_400,
      config: {
        format: 'dc+sd-jwt',
        display: [{ name: 'PID', locale: 'en-US' }],
        proofTypesSupported: ['jwt'],
        keyAttestationsRequired: KEY_ATTESTATIONS_REQUIRED,
      },
      fields: [
        { path: ['given_name'], type: 'string', mandatory: true, disclosable: true },
        { path: ['family_name'], type: 'string', mandatory: true, disclosable: true },
      ],
    },
    token,
  );
}, 120_000);

afterAll(async () => {
  if (process.env.ISSUER_WALLET_EVIDENCE) {
    const fetches = { statusProvider: status?.log, trustInfrastructure: trust?.log };
    writeFileSync(process.env.ISSUER_WALLET_EVIDENCE, JSON.stringify({ issuances: evidence, fetches }, null, 2));
  }
  await status?.stop();
  await trust?.stop();
});

describe(`EUDIPLO at ${BASE}`, () => {
  it('issues an SD-JWT VC to CW-1 for an offer by reference, with WIA, PoP, DPoP, tx_code and a KA-carrying proof', async () => {
    const offer = await createOffer();
    const client = await IssuanceClient.create(walletUnitOf(twp, 'CW-1'), { allowInsecureUrls: true });
    const result = await client.issue({ offer: offer.uri, txCode: TX_CODE });
    evidence['CW-1 by reference'] = result;
    await expectBoundCredential(result);

    expect(result.offer?.byReference).toBe(true);
    expect(result.metadata?.result.authorizationServers[0].token_endpoint_auth_methods_supported).toContain('attest_jwt_client_auth');
    const configuration = result.metadata?.result.credentialIssuer.credential_configurations_supported[CONFIGURATION_ID] as {
      proof_types_supported?: { jwt?: { key_attestations_required?: unknown } };
    };
    expect(configuration.proof_types_supported?.jwt?.key_attestations_required).toEqual(KEY_ATTESTATIONS_REQUIRED);
    const tokenExchange = result.exchanges.filter((e) => e.step === 'token').at(-1)!;
    expect(tokenExchange.request.headers[CLIENT_ATTESTATION_HEADER]).toBeDefined();
    expect(tokenExchange.request.headers[CLIENT_ATTESTATION_POP_HEADER]).toBeDefined();
    expect(result.token?.tokenType).toBe('DPoP');
    expect(result.metadata?.signed?.status).toBe(200);
    expect(result.metadata?.signed?.headers['content-type']).toContain('application/jwt');
    // EUDIPLO fetched TL-WP from the Test Trust Infrastructure.
    expect(trust.log.some((entry) => entry.url.endsWith('/TL-WP') && entry.status === 200)).toBe(true);
  });

  it('issues an SD-JWT VC to CW-2 for an offer by value', async () => {
    const offer = await createOffer();
    // EUDIPLO hands out offers by reference only; the test resolves the reference and passes the offer object by value.
    const offerUri = new URL(offer.uri.replace(/^openid-credential-offer:\/\/\/?/, 'https://x/')).searchParams.get('credential_offer_uri')!;
    const object = await (await fetch(offerUri)).text();
    const client = await IssuanceClient.create(walletUnitOf(twp, 'CW-2'), { allowInsecureUrls: true });
    const result = await client.issue({ offer: `openid-credential-offer://?credential_offer=${encodeURIComponent(object)}`, txCode: TX_CODE });
    evidence['CW-2 by value'] = result;
    await expectBoundCredential(result);
    expect(result.offer?.byReference).toBe(false);
  });

  // Controls that the requirements are in force, so the passes above mean something: the hooks of the fault layer
  // remove one part of a valid message, and EUDIPLO refuses it.
  it('refuses a token request without the WIA and its PoP (wallet attestation required)', async () => {
    const offer = await createOffer();
    const client = await IssuanceClient.create(walletUnitOf(twp, 'CW-1'), {
      allowInsecureUrls: true,
      hooks: {
        request: (step, request) => {
          if (step !== 'token') return request;
          const { [CLIENT_ATTESTATION_HEADER]: _wia, [CLIENT_ATTESTATION_POP_HEADER]: _pop, ...headers } = request.headers;
          return { ...request, headers };
        },
      },
    });
    const result = await client.issue({ offer: offer.uri, txCode: TX_CODE, signedMetadata: false });
    evidence['control: no WIA'] = result;
    expect(result.token).toBeUndefined();
    expect(result.exchanges.at(-1)?.step).toBe('token');
    expect(result.exchanges.at(-1)?.response?.status).toBeGreaterThanOrEqual(400);
  });

  it('refuses a key proof without key_attestation (key attestation required)', async () => {
    const offer = await createOffer();
    const client = await IssuanceClient.create(walletUnitOf(twp, 'CW-1'), {
      allowInsecureUrls: true,
      hooks: { jwt: (point, parts) => (point === 'proof' ? { ...parts, header: { ...parts.header, key_attestation: undefined } } : parts) },
    });
    const result = await client.issue({ offer: offer.uri, txCode: TX_CODE, signedMetadata: false });
    evidence['control: no KA'] = result;
    expect(result.credentials).toHaveLength(0);
    const last = result.exchanges.at(-1)!;
    expect(last.step).toBe('credential');
    expect(JSON.parse(last.response!.body).error).toBe('invalid_proof');
  });
});
