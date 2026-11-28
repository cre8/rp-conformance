// Issuer harness design section 7, level 1, for the points `wia`, `wia-pop`, `ka` and `proof`: every valid WIA, PoP, KA
// and proof of every Wallet Unit passes every issuer request check of the reference validator, and every fault of
// `ISSUER_FAULTS`, applied through the seams of the issuance client, fails exactly its target check and no other. No
// issuer is involved: a capture endpoint answers every request of the client with a fixed, valid-looking response,
// judges nothing, and the reference validator alone decides.
import { randomUUID } from 'node:crypto';
import { readFileSync } from 'node:fs';
import {
  ISSUER_FAULT_IDS,
  ISSUER_FAULTS,
  ISSUER_REQUEST_CHECKS,
  ISSUER_REQUEST_STIMULI,
  type IssuerFaultId,
  issuerFaultInfo,
  type RunningServer,
  sendJson,
  startServer,
} from '@eudi-pcaf/core';
import { createTestPki, decodeJws, LIST_PROFILES, type TestPki } from '@eudi-pcaf/forge';
import { StatusProvider } from '@eudi-pcaf/status-provider';
import { TrustInfrastructure } from '@eudi-pcaf/trust-infrastructure';
import { checkLote, type LoadedList, validateIssuerRequest } from '@eudi-pcaf/validator';
import { CLIENT_ATTESTATION_HEADER, CLIENT_ATTESTATION_POP_HEADER, publishTlWp, TestWalletProvider, WALLET_UNITS, type WalletUnitId } from '@eudi-pcaf/wallet-provider';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { applyIssuerFault, type IssuanceEvidence, IssuanceClient, type IssuerFaultContext, KEY_ATTESTATION_HEADER } from '../src/index';

const CONFIGURATION_ID = 'test_sd_jwt_vc';
const TX_CODE = '493536';
const UNITS = Object.keys(WALLET_UNITS) as WalletUnitId[];

/** Answers every request of the issuance client; records nothing but the `c_nonce` values it issued. */
async function startCaptureEndpoint() {
  let base = '';
  const server: RunningServer = await startServer({ host: '127.0.0.1' }, (req, res) => {
    const path = new URL(req.url ?? '/', 'http://localhost').pathname;
    if (path === '/.well-known/openid-credential-issuer') {
      return sendJson(res, 200, {
        credential_issuer: base,
        credential_endpoint: `${base}/credential`,
        nonce_endpoint: `${base}/nonce`,
        credential_configurations_supported: {
          [CONFIGURATION_ID]: {
            format: 'dc+sd-jwt',
            vct: 'urn:test:vct',
            cryptographic_binding_methods_supported: ['jwk'],
            credential_signing_alg_values_supported: ['ES256'],
            proof_types_supported: { jwt: { proof_signing_alg_values_supported: ['ES256'] } },
          },
        },
      });
    }
    if (path === '/.well-known/oauth-authorization-server') {
      return sendJson(res, 200, {
        issuer: base,
        token_endpoint: `${base}/token`,
        grant_types_supported: ['urn:ietf:params:oauth:grant-type:pre-authorized_code'],
        token_endpoint_auth_methods_supported: ['attest_jwt_client_auth'],
      });
    }
    if (path === '/token') return sendJson(res, 200, { access_token: randomUUID(), token_type: 'DPoP', expires_in: 300 });
    if (path === '/nonce') return sendJson(res, 200, { c_nonce: randomUUID() });
    if (path === '/credential') return sendJson(res, 200, { credentials: [{ credential: 'captured~' }] });
    return sendJson(res, 404, { error: 'not_found' });
  });
  base = server.localUrl;
  const offer = () =>
    `openid-credential-offer://?credential_offer=${encodeURIComponent(
      JSON.stringify({
        credential_issuer: base,
        credential_configuration_ids: [CONFIGURATION_ID],
        grants: { 'urn:ietf:params:oauth:grant-type:pre-authorized_code': { 'pre-authorized_code': randomUUID(), tx_code: { input_mode: 'numeric', length: 6 } } },
      }),
    )}`;
  return { url: base, offer, stop: () => server.close() };
}

/**
 * The reason the reference validator gives for each fault: several faults fail the same check, so the reason shows that
 * each fails it for its own defect and not, say, for a signature the fault layer broke on the way.
 */
const NO_ANCHOR = /does not chain to an anchor of TL-WP/;
const REASONS: Partial<Record<IssuerFaultId, RegExp>> = {
  'wia.missing': /no WIA/,
  'wia.signature-bitflip': /WIA signature does not verify/,
  'wia.signer-ca-x': NO_ANCHOR,
  'wia.signer-pp-a': NO_ANCHOR,
  'wia.signer-ac-a': NO_ANCHOR,
  'wia.signer-wp-w': NO_ANCHOR,
  'wia.exp-past': /WIA expired/,
  'wia.nbf-future': /WIA not yet valid/,
  'wia.typ-jwt': /WIA typ is JWT/,
  'wia.es256k': /WIA alg ES256K/,
  'wia.hs256': /WIA alg HS256/,
  'wia.sub-other': /WIA sub other-wallet-unit/,
  'wia.ca-x-status-uri': /CA-CA-X/,
  'wia.status-uri-private': /private address/,
  'wia.jku-header': /by URL \(jku\)/,
  'wia.x5u-header': /by URL \(x5u\)/,
  'wia-pop.missing': /no PoP/,
  'wia-pop.other-key': /PoP signature does not verify/,
  'wia-pop.aud-other': /PoP aud "https:\/\/other-issuer\.example"/,
  'wia-pop.iat-stale': /PoP iat \d+ is older/,
  'wia-pop.jti-replayed': /PoP jti .* was used before/,
  'wia-pop.typ-jwt': /PoP typ is JWT/,
  'ka.missing': /no KA/,
  'ka.signature-bitflip': /KA signature does not verify/,
  'ka.signer-ca-x': /CA-CA-X/,
  'ka.signer-pp-a': /CA-PP-A/,
  'ka.signer-wp-w': /CA-WP-W/,
  'ka.exp-past': /KA expired/,
  'ka.nonce-other-session': /KA nonce .* is not the c_nonce/,
  'ka.nonce-missing': /KA has no nonce/,
  'ka.key-storage-moderate': /key_storage \["iso_18045_moderate"\]/,
  'ka.key-storage-basic': /key_storage \["iso_18045_basic"\]/,
  'ka.key-storage-absent': /no key_storage/,
  'ka.user-authentication-moderate': /user_authentication \["iso_18045_moderate"\]/,
  'ka.user-authentication-basic': /user_authentication \["iso_18045_basic"\]/,
  'ka.user-authentication-absent': /no user_authentication/,
  'ka.typ-jwt': /KA typ is JWT/,
  'ka.es256k': /KA alg ES256K/,
  'ka.ca-x-status-uri': /CA-CA-X/,
  'ka.status-uri-private': /private address/,
  'ka.jku-header': /by URL \(jku\)/,
  'ka.x5u-header': /by URL \(x5u\)/,
  'proof.signature-bitflip': /proof signature does not verify/,
  'proof.alg-none': /proof alg none/,
  'proof.hs256': /proof alg HS256/,
  'proof.es256k': /proof alg ES256K/,
  'proof.typ-jwt': /proof typ is JWT/,
  'proof.typ-missing': /proof typ is undefined/,
  'proof.aud-other': /proof aud "https:\/\/other-issuer\.example"/,
  'proof.aud-missing': /proof aud undefined/,
  'proof.nonce-missing': /proof has no nonce/,
  'proof.nonce-random': /is not the c_nonce of this request/,
  'proof.nonce-replayed': /a c_nonce already used/,
  'proof.iat-past': /proof iat \d+ is older/,
  'proof.iat-future': /proof iat \d+ is in the future/,
  'proof.iss-other': /proof iss other-wallet-unit/,
  'proof.jwk-private': /private key member\(s\) d/,
  'proof.jwk-and-x5c': /jwk and x5c/,
  'proof.off-curve': /not a valid P-256 public key/,
  'proof.p521': /proof alg ES512/,
  'proof.key-not-attested': /not one of the KA attested_keys/,
  'proof.jku-header': /by URL \(jku\)/,
  'proof.kid-url': /by URL \(kid URL\)/,
};

let pki: TestPki;
let status: StatusProvider;
let trust: TrustInfrastructure;
let twp: TestWalletProvider;
let capture: Awaited<ReturnType<typeof startCaptureEndpoint>>;
let tlWp: LoadedList;
/** A valid issuance of `CW-1` before the faults: the source of `replay`. */
let earlier: Sent;
/** A `c_nonce` issued to the session of another Wallet Unit. */
let otherSessionCNonce: string;

/** What the client sent in one issuance: the token request's attestation headers and `client_id`, the key proof. */
interface Sent {
  evidence: IssuanceEvidence;
  clientAttestation?: string;
  clientAttestationPop?: string;
  clientId?: string;
  proof?: string;
  cNonce: string;
}

const header = (headers: Record<string, string>, name: string) => Object.entries(headers).find(([key]) => key.toLowerCase() === name.toLowerCase())?.[1];

async function issue(unit: WalletUnitId, fault?: IssuerFaultId, extra: Partial<IssuerFaultContext> = {}): Promise<Sent> {
  const context: IssuerFaultContext = {
    twp,
    unit,
    ...(earlier ? { replay: { cNonce: earlier.cNonce, popJti: decodeJws(earlier.clientAttestationPop!).payload.jti as string } } : {}),
    ...(otherSessionCNonce ? { otherSessionCNonce } : {}),
    ...extra,
  };
  const applied = await applyIssuerFault(fault, context);
  const client = await IssuanceClient.create(applied.unit, { allowInsecureUrls: true, hooks: applied.hooks });
  const evidence = await client.issue({ offer: capture.offer(), txCode: TX_CODE, signedMetadata: false });
  expect(evidence.error, evidence.error).toBeUndefined();
  const token = evidence.exchanges.filter((e) => e.step === 'token').at(-1)!.request;
  const credential = evidence.exchanges.filter((e) => e.step === 'credential').at(-1)!.request;
  return {
    evidence,
    clientAttestation: header(token.headers, CLIENT_ATTESTATION_HEADER),
    clientAttestationPop: header(token.headers, CLIENT_ATTESTATION_POP_HEADER),
    clientId: new URLSearchParams(token.body).get('client_id') ?? undefined,
    proof: (JSON.parse(credential.body ?? '{}') as { proofs: { jwt: string[] } }).proofs.jwt[0],
    cNonce: evidence.cNonce!,
  };
}

function validate(sent: Sent, options: { requireKeyAttestationNonce?: boolean } = {}) {
  return validateIssuerRequest(sent, {
    walletProviders: tlWp,
    authorizationServer: capture.url,
    credentialIssuer: capture.url,
    cNonce: sent.cNonce,
    usedNonces: [earlier.cNonce],
    usedPopJtis: [decodeJws(earlier.clientAttestationPop!).payload.jti as string],
    allowLoopbackHttp: true,
    ...options,
  });
}

const failuresOf = (result: Awaited<ReturnType<typeof validate>>) => result.checks.filter((c) => c.status === 'fail').map((c) => `${c.check}: ${c.detail}`);

beforeAll(async () => {
  pki = await createTestPki();
  status = await new StatusProvider().start({ host: '127.0.0.1' });
  trust = await new TrustInfrastructure().start({ host: '127.0.0.1' });
  const { url, jws } = await publishTlWp(trust, 'issuer-faults', pki);
  const loaded = await checkLote(jws, { id: 'TL-WP', url, loteType: LIST_PROFILES['TL-WP'].loteType, schemeOperatorCertificatePem: pki.schemeOperators['TL-WP'].certificate.pem });
  if (!loaded.list) throw new Error(`TL-WP does not load: ${JSON.stringify(loaded.checks)}`);
  tlWp = loaded.list;
  twp = await TestWalletProvider.create({ pki, statusProvider: status, runId: 'issuer-faults' });
  capture = await startCaptureEndpoint();
  earlier = await issue('CW-1');
  otherSessionCNonce = (await issue('CW-2')).cNonce;
}, 120_000);

afterAll(async () => {
  await capture?.stop();
  await status?.stop();
  await trust?.stop();
});

describe('issuer request faults (level 1)', () => {
  it.each(UNITS)('the valid WIA, PoP, KA and proof of %s pass every issuer request check', async (unit) => {
    const result = await validate(await issue(unit));
    expect(failuresOf(result)).toEqual([]);
    expect(result.checks.map((c) => [c.check, c.status])).toEqual(ISSUER_REQUEST_CHECKS.map((check) => [check, 'pass']));
  });

  it.each(UNITS)('the valid issuance of %s with the c_nonce in its KA passes every check where the SUT requires it', async (unit) => {
    const sent = await issue(unit, undefined, { keyAttestationNonce: true });
    const ka = decodeJws(decodeJws(sent.proof!).header[KEY_ATTESTATION_HEADER] as string);
    expect(ka.payload.nonce).toBe(sent.cNonce);
    const result = await validate(sent, { requireKeyAttestationNonce: true });
    expect(failuresOf(result)).toEqual([]);
    expect(result.checks.every((c) => c.status === 'pass')).toBe(true);
  });

  it.each(ISSUER_FAULT_IDS)('%s fails exactly its target check', async (fault) => {
    const info = issuerFaultInfo(fault);
    const variant = info.requiresKeyAttestationNonce ? { keyAttestationNonce: true } : {};
    const result = await validate(await issue('CW-1', fault, variant), { requireKeyAttestationNonce: Boolean(info.requiresKeyAttestationNonce) });
    const failed = result.checks.filter((c) => c.status === 'fail').map((c) => c.check);
    expect(failed, failuresOf(result).join('\n')).toEqual(info.target ? [info.target] : []);
    if (info.target) expect(result.checks.find((c) => c.check === info.target)?.detail, fault).toMatch(REASONS[fault]!);
  });

  it('the faults that must pass every check change what they name', async () => {
    const days = (exp: unknown) => Math.round(((exp as number) * 1000 - Date.now()) / 86_400_000);
    const wiaOf = (sent: Sent) => decodeJws(sent.clientAttestation!).payload as { client_status: { exp: number } };
    const kaOf = (sent: Sent) => decodeJws(decodeJws(sent.proof!).header[KEY_ATTESTATION_HEADER] as string).payload as Record<string, any>;
    expect(days(wiaOf(await issue('CW-1', 'wia.maintenance-31-days')).client_status.exp)).toBe(31);
    expect(days(wiaOf(await issue('CW-1', 'wia.maintenance-tomorrow')).client_status.exp)).toBe(1);
    expect(days(kaOf(await issue('CW-1', 'ka.maintenance-31-days')).key_storage_status.exp)).toBe(31);
    const other = await issue('CW-1', 'ka.other-unit');
    expect(kaOf(other).key_storage_status.status.status_list.idx).toBe(twp.units['CW-2'].kaStatus.idx);
    expect(decodeJws(other.clientAttestation!).payload.sub).toBe(twp.units['CW-1'].clientId);
  });

  it('a WIA of a revoked Wallet Instance fails exactly wia-status, a KA of a revoked WSCD exactly ka-status', async () => {
    const unit = twp.units['CW-2'];
    try {
      await twp.revokeInstance('CW-2');
      expect((await validate(await issue('CW-2'))).failures).toEqual(['wia-status']);
      await twp.setStatus(unit.provider, unit.wiaStatus, 0);
      await twp.revokeWscd('CW-2');
      expect((await validate(await issue('CW-2'))).failures).toEqual(['ka-status']);
    } finally {
      await twp.setStatus(unit.provider, unit.wiaStatus, 0);
      await twp.setStatus(unit.provider, unit.kaStatus, 0);
    }
  });

  it('the status of a WIA or KA under CA-X is not fetched, nor a status at a private address', async () => {
    const since = new Date();
    for (const fault of ['wia.ca-x-status-uri', 'ka.ca-x-status-uri', 'wia.status-uri-private', 'ka.status-uri-private'] as IssuerFaultId[]) {
      await validate(await issue('CW-1', fault));
    }
    expect(status.log.filter((entry) => new Date(entry.at) >= since && /ca-x-(wia|ka)-status/.test(entry.url))).toEqual([]);
  });
});

describe('catalogue coverage of the issuer request faults', () => {
  /** The IDs of a table of the catalogue, by its heading. */
  const catalogueIds = (table: string) => {
    const text = readFileSync(new URL('../../../issuer-test-catalogue.md', import.meta.url), 'utf8');
    const section = text.split(/^##### /m).find((s) => s.startsWith(table)) ?? '';
    return [...section.matchAll(/^\| `([A-Za-z_0-9]+)` \|/gm)].map((m) => m[1]);
  };

  it.each(['PP_WS_SM_ClientAttestation', 'PP_WS_SM_KeyAttestation', 'PP_WS_SM_ProofOfPossession'])('every objective of %s has its stimuli mapped', (table) => {
    const ids = catalogueIds(table);
    expect(ids.length).toBeGreaterThan(9);
    const mapped = new Set(ISSUER_REQUEST_STIMULI.map((s) => s.testCase));
    expect(ids.filter((id) => !mapped.has(id))).toEqual([]);
  });

  it('every stimulus has a fault or a reason it is left to another layer', () => {
    for (const stimulus of ISSUER_REQUEST_STIMULI) {
      expect(stimulus.faults.length > 0 || Boolean(stimulus.leftOut), `${stimulus.testCase}: ${stimulus.stimulus}`).toBe(true);
      for (const fault of stimulus.faults) expect(issuerFaultInfo(fault).testCases, fault).toContain(stimulus.testCase);
    }
  });

  it('every fault is the stimulus of a catalogue objective', () => {
    const listed = new Set(ISSUER_REQUEST_STIMULI.flatMap((s) => s.faults));
    expect(ISSUER_FAULT_IDS.filter((fault) => !listed.has(fault))).toEqual([]);
    for (const [id, info] of Object.entries(ISSUER_FAULTS)) expect(info.testCases.length, id).toBeGreaterThan(0);
  });

  it('the stimuli left to later issues are named', () => {
    const left = ISSUER_REQUEST_STIMULI.filter((s) => s.leftOut).map((s) => `${s.testCase}: ${s.stimulus}`);
    expect(left).toEqual([
      'PP_WS_SM_ClientAttestation_001: SCN-I',
      'PP_WS_SM_ClientAttestation_012_UF: Status set in `SL-WP-A`',
      "PP_WS_SM_ClientAttestation_013_UF: Each TSP mutation of the RP catalogue's `RP_PP_SM_Revocation`",
      "PP_WS_SM_KeyAttestation_001: SCN-I; KA in the proof's `key_attestation` header",
      'PP_WS_SM_KeyAttestation_001: KA as `attestation` proof type where supported',
      'PP_WS_SM_KeyAttestation_008_UF: Status set in `SL-WP-A`',
      'PP_WS_SM_KeyAttestation_009_UF: As `ClientAttestation_013_UF`',
      'PP_WS_SM_ProofOfPossession_010: SCN-I',
      'PP_WS_IA_Batch: one bad proof; one key twice; `batch_size` + 1 proofs',
    ]);
  });

  it('every fault with a target has its own expected reason', () => {
    expect(ISSUER_FAULT_IDS.filter((fault) => issuerFaultInfo(fault).target && !REASONS[fault])).toEqual([]);
  });

  it('every check of the four points is the target of a fault', () => {
    const targets = new Set(ISSUER_FAULT_IDS.map((fault) => issuerFaultInfo(fault).target));
    expect(ISSUER_REQUEST_CHECKS.filter((check) => !targets.has(check))).toEqual([]);
  });
});
