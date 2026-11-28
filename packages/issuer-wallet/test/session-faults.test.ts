// Issuer harness design section 7, level 1, for the session faults of issue 25 (points `dpop`, batch, `encoding`,
// encryption, notification, deferred): every valid request of the session client passes every session check of the
// reference validator, and every fault of `SESSION_FAULTS` fails exactly its target check and no other, counting the
// issuer request checks of each key proof. No issuer is involved: a capture endpoint answers every request with a fixed,
// valid-looking response and judges nothing.
import { randomUUID } from 'node:crypto';
import {
  ISSUER_REQUEST_CHECKS,
  type RunningServer,
  SESSION_CHECKS,
  SESSION_FAULT_IDS,
  SESSION_FAULTS,
  type SessionFaultId,
  sendJson,
  sessionFaultInfo,
  startServer,
} from '@eudi-pcaf/core';
import { createTestPki, LIST_PROFILES } from '@eudi-pcaf/forge';
import { StatusProvider } from '@eudi-pcaf/status-provider';
import { TrustInfrastructure } from '@eudi-pcaf/trust-infrastructure';
import { checkLote, type LoadedList, type SessionRequestKind, validateIssuerRequest, validateSessionRequest } from '@eudi-pcaf/validator';
import { CLIENT_ATTESTATION_HEADER, CLIENT_ATTESTATION_POP_HEADER, publishTlWp, TestWalletProvider } from '@eudi-pcaf/wallet-provider';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import {
  applySessionFault,
  decryptJwe,
  encryptJwe,
  generateEncryptionKey,
  type HttpExchange,
  type IssuanceStep,
  SessionClient,
  type SessionEvidence,
  type SessionState,
  walletUnitOf,
} from '../src/index';

const CONFIGURATION_ID = 'test_sd_jwt_vc';
const DEFERRED_ID = 'test_deferred';
const BATCH_SIZE = 2;
const DPOP_NONCE = 'server-dpop-nonce';
const ENCRYPTION = { alg_values_supported: ['ECDH-ES'], enc_values_supported: ['A128GCM', 'A256GCM'] };

/** Answers every request of the session client; remembers the tokens, notification and transaction IDs it issued. */
async function startCaptureEndpoint() {
  let base = '';
  const requestKey = generateEncryptionKey();
  const issued = { accessTokens: new Map<string, string>(), notificationIds: [] as string[], transactionIds: new Map<string, string>() };
  const configuration = { format: 'dc+sd-jwt', vct: 'urn:test:vct', cryptographic_binding_methods_supported: ['jwk'], proof_types_supported: { jwt: { proof_signing_alg_values_supported: ['ES256'] } } };
  const server: RunningServer = await startServer({ host: '127.0.0.1' }, async (req, res, buffered) => {
    const path = new URL(req.url ?? '/', 'http://localhost').pathname;
    const raw = buffered.toString('utf8');
    const token = String(req.headers.authorization ?? '').split(' ')[1] ?? '';
    if (path === '/.well-known/openid-credential-issuer') {
      return sendJson(res, 200, {
        credential_issuer: base,
        credential_endpoint: `${base}/credential`,
        nonce_endpoint: `${base}/nonce`,
        notification_endpoint: `${base}/notification`,
        deferred_credential_endpoint: `${base}/deferred`,
        batch_credential_issuance: { batch_size: BATCH_SIZE },
        credential_request_encryption: { jwks: { keys: [{ ...requestKey.publicJwk, kid: 'request-key', alg: 'ECDH-ES', use: 'enc' }] }, enc_values_supported: ['A128GCM'], encryption_required: false },
        credential_response_encryption: { ...ENCRYPTION, encryption_required: false },
        credential_configurations_supported: { [CONFIGURATION_ID]: configuration, [DEFERRED_ID]: configuration },
      });
    }
    if (path === '/.well-known/oauth-authorization-server') {
      return sendJson(res, 200, {
        issuer: base,
        token_endpoint: `${base}/token`,
        grant_types_supported: ['urn:ietf:params:oauth:grant-type:pre-authorized_code', 'refresh_token'],
        token_endpoint_auth_methods_supported: ['attest_jwt_client_auth'],
        dpop_signing_alg_values_supported: ['ES256'],
      });
    }
    if (path === '/token') {
      const accessToken = randomUUID();
      issued.accessTokens.set(accessToken, randomUUID());
      return sendJson(res, 200, { access_token: accessToken, token_type: 'DPoP', expires_in: 300, refresh_token: randomUUID() });
    }
    if (path === '/nonce') {
      // A DPoP-Nonce (RFC 9449 section 8) the client must carry in every later DPoP proof to this origin.
      res.setHeader('DPoP-Nonce', DPOP_NONCE);
      return sendJson(res, 200, { c_nonce: randomUUID() });
    }
    if (path === '/credential') {
      let body: { credential_configuration_id?: string; proofs?: { jwt?: unknown[] } } = {};
      try {
        body = JSON.parse(String(req.headers['content-type']).startsWith('application/jwt') ? decryptJwe(raw, requestKey.privateJwk).plaintext : raw);
      } catch {
        // judged by the validator, not here
      }
      if (body.credential_configuration_id === DEFERRED_ID) {
        const transactionId = randomUUID();
        issued.transactionIds.set(transactionId, token);
        return sendJson(res, 202, { transaction_id: transactionId, interval: 0 });
      }
      const notificationId = randomUUID();
      issued.notificationIds.push(notificationId);
      return sendJson(res, 200, { credentials: (body.proofs?.jwt ?? [1]).map(() => ({ credential: 'captured~' })), notification_id: notificationId });
    }
    if (path === '/deferred') return sendJson(res, 200, { credentials: [{ credential: 'captured~' }] });
    if (path === '/notification') {
      res.statusCode = 204;
      return res.end();
    }
    return sendJson(res, 404, { error: 'not_found' });
  });
  base = server.localUrl;
  const offer = (configurationId = CONFIGURATION_ID) =>
    `openid-credential-offer://?credential_offer=${encodeURIComponent(
      JSON.stringify({
        credential_issuer: base,
        credential_configuration_ids: [configurationId],
        grants: { 'urn:ietf:params:oauth:grant-type:pre-authorized_code': { 'pre-authorized_code': randomUUID() } },
      }),
    )}`;
  return { url: base, offer, issued, requestKey, stop: () => server.close() };
}

let status: StatusProvider;
let trust: TrustInfrastructure;
let twp: TestWalletProvider;
let tlWp: LoadedList;
let capture: Awaited<ReturnType<typeof startCaptureEndpoint>>;

interface Run {
  client: SessionClient;
  state: SessionState;
  evidence: SessionEvidence;
}

/** A session of a Wallet Unit with one fault (or none), up to the request the fault targets; `other` is another session. */
async function runSession(fault: SessionFaultId | undefined, request: SessionRequestKind, other?: Run, unit: 'CW-1' | 'CW-2' = 'CW-1'): Promise<Run> {
  const applied = applySessionFault(fault, { batchSize: BATCH_SIZE });
  const client = await SessionClient.create(walletUnitOf(twp, unit), (n) => twp.keyAttestation(unit, { batchSize: n }), {
    allowInsecureUrls: true,
    hooks: applied.hooks,
    ...(applied.noDpopRetry ? { noDpopRetry: true } : {}),
  });
  const evidence = SessionClient.newEvidence(unit);
  const state = await client.start(capture.offer(request === 'deferred' ? DEFERRED_ID : CONFIGURATION_ID), evidence);
  // The nonce endpoint hands out the DPoP-Nonce first, so the token request already carries it.
  await client.nonce(state, evidence);
  state.cNonce = undefined;
  await client.token(state, evidence);
  if (request === 'token') return { client, state, evidence };
  await client.credential(state, evidence, {
    proofs: applied.credential.proofs ?? 1,
    ...(applied.credential.keys ? { keys: applied.credential.keys } : {}),
    ...(applied.credential.keyIndex ? { keyIndex: applied.credential.keyIndex } : {}),
    encryption: fault?.startsWith('encryption.') ?? false,
    followDeferred: !(fault === 'deferred.access-token-foreign'),
  });
  if (fault === 'deferred.access-token-foreign' && other) {
    await other.client.pollDeferred(other.state, evidence, { interval: 0, maxPolls: 1, sleep: async () => {}, encryption: false, transactionId: state.transactionId! });
  }
  if (request === 'refresh') await client.refresh(state, evidence);
  if (request === 'notification') await client.notify(state, evidence, 'credential_accepted');
  return { client, state, evidence };
}

const lastOf = (exchanges: HttpExchange[], step: IssuanceStep) => exchanges.filter((e) => e.step === step).at(-1)!;
const header = (headers: Record<string, string>, name: string) => Object.entries(headers).find(([k]) => k.toLowerCase() === name.toLowerCase())?.[1];

/** Every failed check of the request the fault targets: the session checks, and the issuer request checks of each key proof. */
async function failuresOf(run: Run, kind: SessionRequestKind, options: { foreign?: Run; expired?: boolean } = {}): Promise<string[]> {
  const exchange = lastOf(run.evidence.exchanges, kind as IssuanceStep);
  let request = exchange.request;
  const plaintext = run.evidence.plaintext.filter((p) => p.step === kind).at(-1);
  if (plaintext) request = { ...request, headers: { ...request.headers, 'content-type': 'application/json' }, body: plaintext.body };
  const presented = header(request.headers, 'authorization')?.split(' ')[1];
  // The key the presented token is bound to: that of the session it belongs to.
  const owner = options.foreign ?? run;
  const ownJtis = run.state.dpopJtis.slice(0, -1);
  const session = await validateSessionRequest(request, {
    kind,
    ...(presented ? { accessToken: presented } : {}),
    boundKey: owner.client.dpopKey.publicJwk,
    dpopNonce: DPOP_NONCE,
    usedDpopJtis: ownJtis,
    batchSize: BATCH_SIZE,
    responseEncryption: ENCRYPTION,
    notificationIds: capture.issued.notificationIds,
    transactionIds: [...capture.issued.transactionIds.entries()].filter(([, token]) => token === presented).map(([id]) => id),
    ...(options.expired ? { accessTokenExpiresAt: new Date(Date.now() - 3600_000) } : { accessTokenExpiresAt: new Date(Date.now() + 300_000) }),
  });
  const failed = session.checks.filter((c) => c.status === 'fail').map((c) => `${c.check}: ${c.detail}`);
  if (kind === 'token') {
    // The WIA and its PoP at the token endpoint; the proof checks do not concern a token request.
    const result = await validateIssuerRequest(
      { clientAttestation: header(request.headers, CLIENT_ATTESTATION_HEADER), clientAttestationPop: header(request.headers, CLIENT_ATTESTATION_POP_HEADER), clientId: new URLSearchParams(request.body).get('client_id') ?? undefined },
      { walletProviders: tlWp, authorizationServer: capture.url, credentialIssuer: capture.url, cNonce: 'none', allowLoopbackHttp: true },
    );
    failed.push(...result.checks.filter((c) => c.status === 'fail' && c.check.startsWith('wia')).map((c) => `${c.check}: ${c.detail}`));
  }
  if (kind === 'credential') {
    let proofs: string[] = [];
    try {
      proofs = (JSON.parse(request.body ?? '') as { proofs: { jwt: string[] } }).proofs.jwt;
    } catch {
      proofs = [];
    }
    const token = lastOf(run.evidence.exchanges, 'token').request;
    for (const proof of proofs) {
      const result = await validateIssuerRequest(
        {
          clientAttestation: header(token.headers, CLIENT_ATTESTATION_HEADER),
          clientAttestationPop: header(token.headers, CLIENT_ATTESTATION_POP_HEADER),
          clientId: new URLSearchParams(token.body).get('client_id') ?? undefined,
          proof,
        },
        { walletProviders: tlWp, authorizationServer: capture.url, credentialIssuer: capture.url, cNonce: run.state.cNonce!, allowLoopbackHttp: true },
      );
      failed.push(...result.checks.filter((c) => c.status === 'fail').map((c) => `${c.check}: ${c.detail}`));
    }
  }
  return [...new Set(failed)];
}

beforeAll(async () => {
  const pki = await createTestPki();
  status = await new StatusProvider().start({ host: '127.0.0.1' });
  trust = await new TrustInfrastructure().start({ host: '127.0.0.1' });
  const { url, jws } = await publishTlWp(trust, 'session-faults', pki);
  const loaded = await checkLote(jws, { id: 'TL-WP', url, loteType: LIST_PROFILES['TL-WP'].loteType, schemeOperatorCertificatePem: pki.schemeOperators['TL-WP'].certificate.pem });
  if (!loaded.list) throw new Error(`TL-WP does not load: ${JSON.stringify(loaded.checks)}`);
  tlWp = loaded.list;
  twp = await TestWalletProvider.create({ pki, statusProvider: status, runId: 'session-faults' });
  capture = await startCaptureEndpoint();
}, 120_000);

afterAll(async () => {
  await capture?.stop();
  await status?.stop();
  await trust?.stop();
});

describe('session faults (level 1)', () => {
  it('the JWE of the session client round-trips (ECDH-ES, A128GCM and A256GCM)', () => {
    const key = generateEncryptionKey();
    for (const enc of ['A128GCM', 'A256GCM']) expect(decryptJwe(encryptJwe('{"a":1}', key.publicJwk, enc, { kid: 'k' }), key.privateJwk).plaintext).toBe('{"a":1}');
  });

  it.each(['token', 'credential', 'refresh', 'notification', 'deferred'] as SessionRequestKind[])('the valid %s request passes every session check', async (kind) => {
    const run = await runSession(undefined, kind);
    expect(await failuresOf(run, kind)).toEqual([]);
  });

  it('a valid batch of batch_size proofs and a valid encrypted credential request pass every check', async () => {
    const applied = applySessionFault(undefined);
    expect(applied.credential).toEqual({});
    const client = await SessionClient.create(walletUnitOf(twp, 'CW-1'), (n) => twp.keyAttestation('CW-1', { batchSize: n }), { allowInsecureUrls: true });
    for (const options of [{ proofs: BATCH_SIZE }, { encryption: true }]) {
      const evidence = SessionClient.newEvidence('CW-1');
      const state = await client.start(capture.offer(), evidence);
      await client.token(state, evidence);
      await client.credential(state, evidence, options);
      expect(await failuresOf({ client, state, evidence }, 'credential')).toEqual([]);
    }
    const sent = lastOf((await runSession(undefined, 'credential')).evidence.exchanges, 'credential');
    expect(sent.request.body).toContain('proofs');
  });

  it.each(SESSION_FAULT_IDS)('%s fails exactly its target check', async (fault) => {
    const info = sessionFaultInfo(fault);
    const kind = info.request as SessionRequestKind;
    const other = info.needsOtherSession ? await runSession(undefined, 'deferred', undefined, 'CW-2') : undefined;
    const run = await runSession(fault, kind, other);
    const failed = await failuresOf(run, kind, { ...(other ? { foreign: other } : {}), expired: info.waitsAfterExpiry !== undefined });
    expect(failed.map((f) => f.split(':')[0]), failed.join('\n')).toEqual([info.target]);
  });

  it('every session check is the target of some fault, and every fault traces to a catalogue objective', () => {
    const targets = new Set(Object.values(SESSION_FAULTS).map((f) => f.target));
    for (const check of SESSION_CHECKS) expect(targets.has(check), check).toBe(true);
    for (const info of Object.values(SESSION_FAULTS)) {
      expect(info.testCases.length).toBeGreaterThan(0);
      if (!(SESSION_CHECKS as readonly string[]).includes(info.target)) expect(ISSUER_REQUEST_CHECKS as readonly string[]).toContain(info.target);
    }
  });
});
