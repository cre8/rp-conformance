// Issue 26: self-validation of the checks of `PP_WS_SM_IssuerIntegrity`, `PP_WS_SM_Unlinkability` and
// `PP_Inf_SM_TrustMechanisms_008`: a credential the forge issues as the catalogue requires passes each check, and a
// credential or set of credentials with one defect fails exactly the check of that rule.
import { ISSUER_INTEGRITY_CHECKS } from '@eudi-pcaf/core';
import { base64url, createTestPki, type EcKeyPair, generateEcKeyPair, issueMdoc, issuePidSdJwtVc, type TestPki } from '@eudi-pcaf/forge';
import { beforeAll, describe, expect, it } from 'vitest';
import {
  checkIssuerIntegrity,
  checkNoWalletIdentifier,
  checkOutboundPrivacy,
  checkSelectiveDisclosure,
  checkStatusIndexOrder,
  checkUnlinkability,
  type InspectedCredential,
  inspectIssued,
} from '../src/index';

const DOCTYPE = 'eu.europa.ec.eudi.pid.1';
const STATUS = 'https://pp-t.rp-test/status/1';
/** Every claim, member and array element on its own (PID_21). */
const FULL_FRAME = { _sd: ['family_name', 'given_name', 'birthdate', 'place_of_birth', 'nationalities'], place_of_birth: { _sd: ['locality', 'country'] }, nationalities: { _sd: [0] } };

let pki: TestPki;
let holder: EcKeyPair;

beforeAll(async () => {
  pki = await createTestPki();
  holder = await generateEcKeyPair();
});

const der = (c: { der: Uint8Array }) => Buffer.from(c.der).toString('base64');

const sdJwt = async (options: { frame?: Record<string, unknown>; idx?: number; bind?: EcKeyPair; typ?: string } = {}) =>
  (
    await issuePidSdJwtVc({
      signer: pki.entities['PP-T'].signers.issuance,
      issuer: 'https://pp-t.rp-test',
      holderPublicJwk: (options.bind ?? holder).publicJwk,
      status: { uri: STATUS, idx: options.idx ?? 7 },
      disclosureFrame: options.frame ?? FULL_FRAME,
      ...(options.typ ? { typ: options.typ } : {}),
    })
  ).compact;

const mdoc = async () =>
  base64url.encode(
    (
      await issueMdoc({
        signer: pki.entities['PP-T'].signers.mdoc,
        holderPublicJwk: holder.publicJwk,
        docType: DOCTYPE,
        namespace: DOCTYPE,
        claims: { family_name: 'Mustermann', given_name: 'Erika' },
        fullDates: new Set(),
        status: { statusList: { uri: STATUS, idx: 3 } },
      })
    ).issuerSigned,
  );

const ctx = () => ({
  enrolledSigners: [der(pki.entities['PP-T'].signers.issuance.certificate), der(pki.entities['PP-T'].signers.mdoc.certificate)],
  accessCertificate: der(pki.relyingPartyAccess.certificate),
  advertisedAlgorithms: ['ES256', -7],
});

const statuses = (credential: InspectedCredential, checks = [...ISSUER_INTEGRITY_CHECKS]) => Object.fromEntries(checkIssuerIntegrity(credential, checks, ctx()).map((r) => [r.check, r.status]));

describe('PP_WS_SM_IssuerIntegrity checks', () => {
  it('a valid SD-JWT VC PID passes every check that applies to it', async () => {
    const result = statuses(inspectIssued('dc+sd-jwt', await sdJwt(), 'sd', 1));
    expect(result).toMatchObject({ 'sd-jwt-typ': 'pass', 'signer-algorithm': 'pass', 'signer-chain': 'pass', 'mdoc-digest-algorithm': 'skip', 'selective-disclosure': 'pass', 'salt-entropy': 'pass', 'algorithm-advertised': 'pass', 'signer-not-access': 'pass' });
  });

  it('a valid mdoc PID passes every check that applies to it', async () => {
    const result = statuses(inspectIssued('mso_mdoc', await mdoc(), 'md', 1));
    expect(result).toMatchObject({ 'sd-jwt-typ': 'skip', 'signer-algorithm': 'pass', 'signer-chain': 'pass', 'mdoc-digest-algorithm': 'pass', 'selective-disclosure': 'skip', 'salt-entropy': 'pass', 'algorithm-advertised': 'pass', 'signer-not-access': 'pass', 'signer-profile': 'pass' });
  });

  it('fails sd-jwt-typ for typ vc+sd-jwt only', async () => {
    const result = statuses(inspectIssued('dc+sd-jwt', await sdJwt({ typ: 'vc+sd-jwt' }), 'sd', 1));
    expect(Object.entries(result).filter(([, s]) => s === 'fail').map(([c]) => c)).toEqual(['sd-jwt-typ']);
  });

  it('fails signer-chain when the chain carries the trust anchor', async () => {
    const credential = inspectIssued('dc+sd-jwt', await sdJwt(), 'sd', 1);
    const anchored = { ...credential, chain: [...credential.chain, der(pki.entities['PP-T'].anchors.issuance.certificate)] };
    expect(checkIssuerIntegrity(anchored, ['signer-chain'])[0]?.status).toBe('fail');
  });

  it('fails signer-not-access when the credential is signed with the access certificate', async () => {
    const credential = inspectIssued('dc+sd-jwt', await sdJwt(), 'sd', 1);
    const result = checkIssuerIntegrity({ ...credential, chain: [der(pki.relyingPartyAccess.certificate)] }, ['signer-not-access'], ctx());
    expect(result[0]?.status).toBe('fail');
  });

  it('fails signer-profile for a certificate the Registrar did not enrol', async () => {
    const credential = inspectIssued('dc+sd-jwt', await sdJwt(), 'sd', 1);
    expect(checkIssuerIntegrity(credential, ['signer-profile'], { enrolledSigners: [der(pki.entities['PP-B'].signers.issuance.certificate)] })[0]?.status).toBe('fail');
  });

  it('fails selective-disclosure for an array disclosed as a whole, and for a claim in the clear', async () => {
    const whole = inspectIssued('dc+sd-jwt', await sdJwt({ frame: { ...FULL_FRAME, nationalities: undefined } }), 'sd', 1);
    expect(checkSelectiveDisclosure(whole)).toMatchObject({ status: 'fail', detail: expect.stringContaining('nationalities[0]') });
    const clear = inspectIssued('dc+sd-jwt', await sdJwt({ frame: { _sd: ['given_name'] } }), 'sd', 1);
    expect(checkSelectiveDisclosure(clear)).toMatchObject({ status: 'fail', detail: expect.stringContaining('in the clear') });
  });

  it('records 64-bit SD-JWT VC salts (128 bits is RECOMMENDED) and fails a repeated salt', async () => {
    const credential = inspectIssued('dc+sd-jwt', await sdJwt(), 'sd', 1);
    const short = checkIssuerIntegrity({ ...credential, salts: credential.salts.map((_, i) => ({ value: `bfd93fb4ac923e${String(i).padStart(2, '0')}`, bytes: 8 })) }, ['salt-entropy'])[0];
    expect(short).toMatchObject({ status: 'pass', detail: expect.stringContaining('below the RECOMMENDED minimum') });
    expect(checkIssuerIntegrity({ ...credential, salts: [credential.salts[0]!, credential.salts[0]!] }, ['salt-entropy'])[0]?.status).toBe('fail');
    // A hex salt counts 4 bits per character.
    expect(inspectIssued('dc+sd-jwt', await sdJwt(), 'sd', 1).salts.every((s) => s.bytes >= 16)).toBe(true);
  });

  it('fails algorithm-advertised when the algorithm is not advertised', async () => {
    const credential = inspectIssued('mso_mdoc', await mdoc(), 'md', 1);
    expect(checkIssuerIntegrity(credential, ['algorithm-advertised'], { advertisedAlgorithms: [-35] })[0]?.status).toBe('fail');
  });
});

describe('PP_WS_SM_Unlinkability checks', () => {
  it('distinct credentials pass every comparison; a repeated value fails exactly its check', async () => {
    const a = inspectIssued('dc+sd-jwt', await sdJwt({ idx: 11 }), 'a', 1);
    const b = inspectIssued('dc+sd-jwt', await sdJwt({ idx: 4711, bind: await generateEcKeyPair() }), 'b', 2);
    const all = ['unique-salts', 'unique-digests', 'unique-status-index', 'unique-device-key', 'unique-signature'] as const;
    expect(checkUnlinkability([a, b], [...all]).map((r) => r.status)).toEqual(['pass', 'pass', 'pass', 'pass', 'pass']);
    const failing = (other: InspectedCredential) => checkUnlinkability([a, other], [...all]).filter((r) => r.status === 'fail').map((r) => r.check);
    expect(failing({ ...b, status: a.status! })).toEqual(['unique-status-index']);
    expect(failing({ ...b, deviceKey: a.deviceKey! })).toEqual(['unique-device-key']);
    expect(failing({ ...b, signature: a.signature })).toEqual(['unique-signature']);
    expect(failing({ ...b, salts: [a.salts[0]!] })).toEqual(['unique-salts']);
    expect(failing({ ...b, digests: [a.digests[0]!] })).toEqual(['unique-digests']);
  });

  const withIndices = (indices: number[]) => indices.map((idx, i) => ({ label: `#${i}`, status: { uri: STATUS, idx } }) as InspectedCredential);

  it('status-index-order passes random indices and fails sequential or arithmetic ones', () => {
    expect(checkStatusIndexOrder(withIndices([8812, 17, 4410, 9921, 301, 6640, 2210])).status).toBe('pass');
    expect(checkStatusIndexOrder(withIndices([100, 101, 102, 103, 104])).status).toBe('fail');
    expect(checkStatusIndexOrder(withIndices([9000, 50, 70, 90, 110, 3])).status).toBe('fail');
    expect(checkStatusIndexOrder(withIndices([900, 800, 700, 600, 500])).status).toBe('fail');
  });

  it('batch-timestamps and batch-spread', () => {
    const at = new Date('2026-11-20T10:10:00Z');
    const one = (step: number, idx: number, iat: number) => ({ label: `s${step}`, step, receivedAt: at, status: { uri: STATUS, idx }, times: { iat, exp: iat + 30 * 86400 } }) as unknown as InspectedCredential;
    const hour = 1_795_600_800;
    expect(checkUnlinkability([one(1, 5, hour), one(1, 900, hour), one(2, 70, hour), one(2, 4000, hour)], ['batch-timestamps', 'batch-spread'], { precisionSeconds: 3600 }).map((r) => r.status)).toEqual(['pass', 'pass']);
    expect(checkUnlinkability([one(1, 5, hour), one(2, 70, hour + 3600)], ['batch-timestamps'], { precisionSeconds: 3600 })[0]?.status).toBe('fail');
    expect(checkUnlinkability([one(1, 5, hour), one(1, 6, hour)], ['batch-spread'])[0]?.status).toBe('fail');
  });

  it('no-wallet-identifier fails when the credential carries the WIA client_id', async () => {
    const credential = inspectIssued('dc+sd-jwt', await sdJwt(), 'sd', 1);
    const jwt = (payload: Record<string, unknown>) => `e30.${base64url.encode(JSON.stringify(payload))}.c2ln`;
    const wia = jwt({ sub: 'wallet-unit-cw-1', jti: 'a1b2c3d4e5f6', cnf: { jwk: { x: 'xxxxxxxxxxxxxxxxxxxx', y: 'yyyyyyyyyyyyyyyyyy' } } });
    expect(checkNoWalletIdentifier(credential, { wia }).status).toBe('pass');
    expect(checkNoWalletIdentifier({ ...credential, text: `${credential.text} wallet-unit-cw-1` }, { wia }).status).toBe('fail');
  });
});

describe('outbound-privacy', () => {
  const url = 'http://harness:1234/ns/TL-WP';
  it('passes anonymous GETs of the published URL and fails a query, a cookie or another method', () => {
    const get = { at: 'now', method: 'GET', url, headers: { host: 'harness:1234' } };
    expect(checkOutboundPrivacy([get], [url]).status).toBe('pass');
    expect(checkOutboundPrivacy([{ ...get, url: `${url}?pid=1` }], [url]).status).toBe('fail');
    expect(checkOutboundPrivacy([{ ...get, headers: { cookie: 'session=1' } }], [url]).status).toBe('fail');
    expect(checkOutboundPrivacy([{ ...get, method: 'POST', headers: { 'content-length': '12' } }], [url]).status).toBe('fail');
    expect(checkOutboundPrivacy([], [url]).status).toBe('skip');
  });
});
