// The Test Wallet Provider builds valid artifacts: every WIA, PoP and KA of `CW-1`, `CW-2` and `CW-B` verifies, and
// chains to the anchor `TL-WP` publishes for its purpose, read from the sealed list as the Test Trust Infrastructure
// serves it; a revocation shows in the status list the Test Status Provider serves.
import { getListFromStatusListJWT } from '@owf/token-status-list';
import { base64url, createTestPki, decodeJws, LIST_PROFILES, type TestPki, verifyEs256 } from '@eudi-pcaf/forge';
import { StatusProvider } from '@eudi-pcaf/status-provider';
import { TrustInfrastructure } from '@eudi-pcaf/trust-infrastructure';
import { type ListSource, validatePath, verifyLote } from '@eudi-pcaf/validator';
import { parseCertificate } from '@owf/x509';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import {
  anchorsInList,
  certifiedSigner,
  ISO_18045,
  publishTlWp,
  REVOKED,
  serviceFor,
  TestWalletProvider,
  TL_WP_VERSION_WITH_WP_C,
  TYP,
  WALLET_UNITS,
  type WalletProviderPurpose,
  type WalletUnitId,
} from '../src/index';

const NAMESPACE = 'wallet-provider';
const UNITS = Object.keys(WALLET_UNITS) as WalletUnitId[];
const AS = 'https://pp-t.rp-test';

let pki: TestPki;
let status: StatusProvider;
let trust: TrustInfrastructure;
let twp: TestWalletProvider;
let source: ListSource;
/** The payload of `TL-WP` version 1 as served, after its seal verified. */
let tlWp: unknown;

const fetchText = async (url: string) => {
  const response = await fetch(url);
  expect(response.status).toBe(200);
  return response.text();
};

/** The served `TL-WP`, verified as an issuer must (seal, type, strict profile), and its payload. */
async function servedTlWp() {
  const jws = await fetchText(source.url);
  const list = await verifyLote(jws, source);
  return { list, payload: base64url.decodeJson(jws.split('.')[1]) };
}

/** Verifies a JWS's signature with the key of its `x5c` leaf and validates the chain to the anchors given. */
async function verifyUnder(jws: string, anchorsB64: string[]) {
  const { header } = decodeJws(jws);
  const x5c = header.x5c as string[];
  const leaf = parseCertificate(x5c[0]);
  const [h, p, s] = jws.split('.');
  const signatureValid = await verifyEs256(leaf.publicKey.jwk as JsonWebKey, `${h}.${p}`, base64url.decode(s));
  const path = await validatePath(x5c, anchorsB64.map((a) => parseCertificate(a)));
  return { signatureValid, path };
}

/** The anchors `TL-WP` publishes for a Wallet Provider and purpose, found by service type and ServiceName. */
const listedAnchors = (provider: string, purpose: WalletProviderPurpose) => {
  const { type, name } = serviceFor(pki.entities[provider], purpose);
  return anchorsInList(tlWp, { entity: provider, type, name });
};

beforeAll(async () => {
  pki = await createTestPki();
  status = await new StatusProvider().start({ host: '127.0.0.1' });
  trust = await new TrustInfrastructure().start({ host: '127.0.0.1' });
  const { url } = await publishTlWp(trust, NAMESPACE, pki);
  source = { id: 'TL-WP', url, loteType: LIST_PROFILES['TL-WP'].loteType, schemeOperatorCertificatePem: pki.schemeOperators['TL-WP'].certificate.pem };
  tlWp = (await servedTlWp()).payload;
  twp = await TestWalletProvider.create({ pki, statusProvider: status, runId: 'unit-test', batchSize: 3 });
}, 60_000);

afterAll(async () => {
  await status.stop();
  await trust.stop();
});

describe('TL-WP', () => {
  it('is sealed, served, and lists WP-A, WP-B and WP-W, not WP-C', async () => {
    const { list } = await servedTlWp();
    expect(list.sequenceNumber).toBe(1);
    expect(list.entities.map((e) => e.name)).toEqual(['WP-A', 'WP-B', 'WP-W']);
  });

  it('gives WP-A separate anchors for WIAs, KAs and status lists', () => {
    const [wia, ka, sl] = (['wia', 'ka', 'status'] as const).map((purpose) => listedAnchors('WP-A', purpose));
    for (const anchors of [wia, ka, sl]) expect(anchors).toHaveLength(1);
    expect(new Set([wia[0], ka[0], sl[0]]).size).toBe(3);
  });

  it('lists WP-W without an issuance service (withdrawn), as TL-PID does for PP-W', async () => {
    const { list } = await servedTlWp();
    const wpW = list.entities.find((e) => e.name === 'WP-W');
    expect(wpW?.services.map((s) => s.type)).toEqual([LIST_PROFILES['TL-WP'].revocationServiceType]);
    expect(listedAnchors('WP-W', 'wia')).toEqual([]);
  });

  it(`adds WP-C in version ${TL_WP_VERSION_WITH_WP_C}, served under the same URL`, async () => {
    const other = new TrustInfrastructure();
    await other.start({ host: '127.0.0.1' });
    try {
      await publishTlWp(other, NAMESPACE, pki);
      const { url, version } = await publishTlWp(other, NAMESPACE, pki, { sequenceNumber: TL_WP_VERSION_WITH_WP_C });
      expect(version).toBe(2);
      const list = await verifyLote(await fetchText(url), { ...source, url });
      expect(list.sequenceNumber).toBe(TL_WP_VERSION_WITH_WP_C);
      expect(list.entities.map((e) => e.name)).toEqual(['WP-A', 'WP-B', 'WP-W', 'WP-C']);
    } finally {
      await other.stop();
    }
  });
});

describe.each(UNITS)('%s', (unitId) => {
  const provider = () => twp.units[unitId].provider;

  it('has a WIA that verifies under the WIA anchor of its Wallet Provider in TL-WP', async () => {
    const unit = twp.units[unitId];
    const wia = await twp.wia(unitId);
    const { header, payload } = decodeJws(wia);
    expect(header).toMatchObject({ typ: TYP.wia, alg: 'ES256' });
    expect(payload).toMatchObject({
      sub: unit.clientId,
      wallet_name: pki.entities[provider()].spec.walletSolution?.name,
      wallet_version: '1.0.0',
      cnf: { jwk: unit.instanceKey.publicJwk },
      client_status: { status: { status_list: unit.wiaStatus }, exp: Math.floor(unit.maintenanceUntil.getTime() / 1000) },
    });
    expect(payload.iss).toBeUndefined();
    expect((payload.exp as number) - (payload.iat as number)).toBeLessThan(24 * 60 * 60);
    const { signatureValid, path } = await verifyUnder(wia, listedAnchors(provider(), 'wia'));
    expect(signatureValid).toBe(true);
    expect(path.ok).toBe(true);
    // WP-A separates its anchors by purpose; WP-B has one anchor for all of them.
    if (provider() === 'WP-A') {
      expect((await verifyUnder(wia, listedAnchors('WP-A', 'ka'))).path.ok).toBe(false);
      expect((await verifyUnder(wia, listedAnchors('WP-A', 'status'))).path.ok).toBe(false);
    }
  });

  it('has a revocation maintenance period of more than one year', () => {
    const remaining = twp.units[unitId].maintenanceUntil.getTime() - Date.now();
    expect(remaining).toBeGreaterThan(365 * 24 * 60 * 60 * 1000);
  });

  it("has a PoP signed with the WIA's cnf key", async () => {
    const unit = twp.units[unitId];
    const pop = await twp.pop(unitId, { audience: AS, nonce: 'n-1' });
    const { header, payload } = decodeJws(pop);
    expect(header).toEqual({ alg: 'ES256', typ: TYP.wiaPop });
    expect(payload).toMatchObject({ iss: unit.clientId, aud: AS, nonce: 'n-1' });
    expect(typeof payload.jti).toBe('string');
    expect(decodeJws(await twp.pop(unitId, { audience: AS })).payload.jti).not.toBe(payload.jti);
    const cnf = decodeJws(await twp.wia(unitId)).payload.cnf as { jwk: JsonWebKey };
    const [h, p, s] = pop.split('.');
    expect(await verifyEs256(cnf.jwk, `${h}.${p}`, base64url.decode(s))).toBe(true);
  });

  it('has a KA at iso_18045_high over batch-size fresh keys, under the KA anchor of its Wallet Provider', async () => {
    const unit = twp.units[unitId];
    const { jwt, keys } = await twp.keyAttestation(unitId);
    const { header, payload } = decodeJws(jwt);
    expect(header).toMatchObject({ typ: TYP.keyAttestation, alg: 'ES256' });
    expect(keys).toHaveLength(3);
    expect(payload).toMatchObject({
      attested_keys: keys.map((k) => k.publicJwk),
      key_storage: [ISO_18045.high],
      user_authentication: [ISO_18045.high],
      key_storage_status: { status: { status_list: unit.kaStatus }, exp: Math.floor(unit.maintenanceUntil.getTime() / 1000) },
    });
    const again = await twp.keyAttestation(unitId, { batchSize: 1 });
    expect(again.keys).toHaveLength(1);
    expect(keys.map((k) => k.publicJwk.x)).not.toContain(again.keys[0].publicJwk.x);
    const { signatureValid, path } = await verifyUnder(jwt, listedAnchors(provider(), 'ka'));
    expect(signatureValid).toBe(true);
    expect(path.ok).toBe(true);
    if (provider() === 'WP-A') expect((await verifyUnder(jwt, listedAnchors('WP-A', 'wia'))).path.ok).toBe(false);
  });
});

describe('builders', () => {
  it('take every claim, the levels, the validity, the signer and the algorithm as parameters', async () => {
    const wpB = pki.entities['WP-B'];
    const now = new Date('2026-01-01T00:00:00Z');
    const { jwt } = await twp.keyAttestation('CW-1', {
      keyStorage: [ISO_18045.moderate],
      userAuthentication: [],
      validitySeconds: 60,
      now,
      nonce: 'c-nonce',
      typ: 'JWT',
      header: { alg: 'ES384', x5c: undefined },
      claims: { certification: undefined, extra: true },
    });
    const { header, payload } = decodeJws(jwt);
    expect(header).toEqual({ typ: 'JWT', alg: 'ES384' });
    expect(payload).toMatchObject({ key_storage: [ISO_18045.moderate], user_authentication: [], nonce: 'c-nonce', extra: true, iat: 1767225600, exp: 1767225660 });
    expect(payload.certification).toBeUndefined();
    const wia = await twp.wia('CW-1', { signer: certifiedSigner(wpB.signers.issuance) });
    expect((await verifyUnder(wia, listedAnchors('WP-B', 'wia'))).path.ok).toBe(true);
    expect((await verifyUnder(wia, listedAnchors('WP-A', 'wia'))).path.ok).toBe(false);
  });
});

describe('revocation', () => {
  /** The served status list, verified under the status anchor of the provider in TL-WP. */
  async function servedStatusOf(unitId: WalletUnitId, which: 'wiaStatus' | 'kaStatus') {
    const reference = twp.units[unitId][which];
    const token = await fetchText(reference.uri);
    const { header, payload } = decodeJws(token);
    expect(header.typ).toBe('statuslist+jwt');
    expect(payload.sub).toBe(reference.uri);
    const { signatureValid, path } = await verifyUnder(token, listedAnchors(twp.units[unitId].provider, 'status'));
    expect(signatureValid && path.ok).toBe(true);
    return getListFromStatusListJWT(token).getStatus(reference.idx);
  }

  it('starts with every entry valid', async () => {
    for (const unit of UNITS) {
      expect(await servedStatusOf(unit, 'wiaStatus')).toBe(0);
      expect(await servedStatusOf(unit, 'kaStatus')).toBe(0);
    }
  });

  it('revokeInstance publishes a new SL-WP-A with the WIA entry set, and nothing else', async () => {
    const before = twp.statusLists['WP-A'].version;
    const list = await twp.revokeInstance('CW-1');
    expect(list.id).toBe('SL-WP-A');
    expect(list.version).toBe(before + 1);
    expect(await servedStatusOf('CW-1', 'wiaStatus')).toBe(REVOKED);
    expect(await servedStatusOf('CW-1', 'kaStatus')).toBe(0);
    expect(await servedStatusOf('CW-2', 'wiaStatus')).toBe(0);
    expect(await servedStatusOf('CW-B', 'wiaStatus')).toBe(0);
  });

  it('revokeWscd publishes a new SL-WP-A with the KA entry set', async () => {
    await twp.revokeWscd('CW-2');
    expect(await servedStatusOf('CW-2', 'kaStatus')).toBe(REVOKED);
    expect(await servedStatusOf('CW-2', 'wiaStatus')).toBe(0);
  });

  it('logs the fetches of the status list', () => {
    expect(status.requestsFor(twp.statusLists['WP-A'].uri).length).toBeGreaterThan(0);
  });
});
