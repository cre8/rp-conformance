import {
  buildSealedLote,
  buildStatusListTokenJwt,
  createTestPki,
  DEFAULT_PID_CLAIMS,
  generateEcKeyPair,
  issuePidSdJwtVc,
  type LoteListId,
  PID_VCT,
  presentSdJwtVc,
  type TestPki,
  LIST_PROFILES,
} from '@rp-conformance/forge';
import { StatusProvider } from '@rp-conformance/status-provider';
import { TrustInfrastructure } from '@rp-conformance/trust-infrastructure';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { type ListSource, SD_JWT_VC_CHECKS, TrustStore, validateSdJwtVcPresentation, verifyLote } from '../src/index';

// Harness design section 7, step 1: every artifact a Phase 0 builder produces passes the reference validator.

const LISTS: LoteListId[] = ['TL-PID', 'TL-PUB', 'TL-WP', 'TL-AC', 'TL-RC'];
const AUDIENCE = 'x509_hash:test-client';
const NONCE = 'n-0S6_WzA2Mj';

let pki: TestPki;
let status: StatusProvider;
let trustInfra: TrustInfrastructure;
let sources: ListSource[];
let trust: TrustStore;
let holder: Awaited<ReturnType<typeof generateEcKeyPair>>;

beforeAll(async () => {
  pki = await createTestPki();
  status = await new StatusProvider().start({ host: '127.0.0.1' });
  trustInfra = await new TrustInfrastructure().start({ host: '127.0.0.1' });
  sources = [];
  for (const list of LISTS) {
    const { jws } = await buildSealedLote({ list, pki });
    const { url } = trustInfra.publish('self-validation', list, jws);
    sources.push({ id: list, url, loteType: LIST_PROFILES[list].loteType, schemeOperatorCertificatePem: pki.schemeOperators[list].certificate.pem });
  }
  trust = new TrustStore(sources);
  holder = await generateEcKeyPair();
});

afterAll(async () => {
  await status.stop();
  await trustInfra.stop();
});

async function issueValidPid(options: { issuer?: string; statusValue?: number } = {}) {
  const issuer = pki.entities[options.issuer ?? 'PP-A'];
  const uri = status.allocate('self-validation');
  const statusList = await buildStatusListTokenJwt({
    signer: issuer.signers.revocation,
    issuer: issuer.issuerUri,
    uri,
    statuses: Array.from({ length: 128 }, (_, i) => (i === 7 ? (options.statusValue ?? 0) : 0)),
  });
  status.register(uri, statusList);
  const credential = await issuePidSdJwtVc({
    signer: issuer.signers.issuance,
    issuer: issuer.issuerUri,
    holderPublicJwk: holder.publicJwk,
    status: { uri, idx: 7 },
  });
  const presentation = await presentSdJwtVc(credential.compact, {
    holderPrivateKey: holder.privateKey,
    disclose: ['family_name', 'given_name', 'birthdate'],
    audience: AUDIENCE,
    nonce: NONCE,
  });
  return { uri, presentation };
}

const validate = (presentation: string, overrides: Partial<Parameters<typeof validateSdJwtVcPresentation>[1]> = {}) =>
  validateSdJwtVcPresentation(presentation, {
    trust,
    issuerList: 'TL-PID',
    expectedVct: [PID_VCT],
    nonce: NONCE,
    audience: AUDIENCE,
    skewSeconds: 60,
    kbMaxAgeSeconds: 300,
    requireStatus: true,
    fetchStatusList: async (uri) => {
      const response = await fetch(uri);
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      return response.text();
    },
    ...overrides,
  });

describe('LoTE builder', () => {
  it.each(LISTS)('%s is sealed by its scheme operator and passes the strict ETSI TS 119 602 profile', async (list) => {
    const source = sources.find((s) => s.id === list)!;
    const jws = await (await fetch(source.url)).text();
    const loaded = await verifyLote(jws, source);
    expect(loaded.loteType).toBe(LIST_PROFILES[list].loteType);
    expect(loaded.entities.length).toBeGreaterThan(0);
  });

  it('every list loads into the trust store and its retrieval is logged', async () => {
    const results = await trust.refresh();
    expect(results.filter((r) => r.error)).toEqual([]);
    expect(trustInfra.retrievalsOf('self-validation', 'TL-PID').length).toBeGreaterThan(0);
  });

  it('TL-PID lists PP-A with separate issuance and revocation anchors', () => {
    const ppA = trust.lists.get('TL-PID')!.entities.find((e) => e.name === 'PP-A')!;
    const anchorOf = (suffix: string) => ppA.services.find((s) => s.type.endsWith(suffix))!.anchors[0].subject.commonName;
    expect(anchorOf('/Issuance')).toBe('CA-PP-A');
    expect(anchorOf('/Revocation')).toBe('CA-PP-A-REV');
  });

  it('a list sealed by another key is refused', async () => {
    const source = sources.find((s) => s.id === 'TL-PID')!;
    const { jws } = await buildSealedLote({ list: 'TL-PID', pki });
    const foreign = { ...source, schemeOperatorCertificatePem: pki.schemeOperators['TL-PUB'].certificate.pem };
    await expect(verifyLote(jws, foreign)).rejects.toThrow(/other than the scheme operator/);
  });
});

describe('PID SD-JWT VC and Status List Token builders', () => {
  it('a valid presentation of default_credential_pid passes every check of the reference validator', async () => {
    await trust.refresh();
    const { uri, presentation } = await issueValidPid();
    const since = new Date(Date.now() - 1000);
    const result = await validate(presentation);
    expect(result.failed).toBeUndefined();
    expect(result.valid).toBe(true);
    expect(result.checks.map((c) => c.check)).toEqual([...SD_JWT_VC_CHECKS]);
    expect(result.issuer).toBe('PP-A');
    expect(result.claims).toMatchObject({
      family_name: DEFAULT_PID_CLAIMS.family_name,
      given_name: DEFAULT_PID_CLAIMS.given_name,
      birthdate: DEFAULT_PID_CLAIMS.birthdate,
      vct: PID_VCT,
    });
    expect(result.claims).not.toHaveProperty('nationalities');
    expect(status.requestsFor(uri, since)).toHaveLength(1);
  });

  it.each(['PP-B', 'PP-D'])('a PID issued by %s, which shares one anchor for both services, passes', async (issuer) => {
    const { presentation } = await issueValidPid({ issuer });
    expect((await validate(presentation)).valid).toBe(true);
  });
});

// Not the systematic fault self-validation of Phase 1, but evidence that the reference validator discriminates.
describe('reference validator discriminates', () => {
  it.each([
    ['a revoked status', { statusValue: 1 }, {}, 'status'],
    ['an issuer that is on no list (PP-C)', { issuer: 'PP-C' }, {}, 'issuer-trust'],
    ['an issuer whose anchor has expired (PP-E)', { issuer: 'PP-E' }, {}, 'issuer-trust'],
    ['a KB-JWT for another nonce', {}, { nonce: 'other' }, 'key-binding'],
    ['a KB-JWT for another audience', {}, { audience: 'x509_hash:other' }, 'key-binding'],
  ] as const)('%s fails exactly the check %s', async (_name, issue, overrides, expected) => {
    const { presentation } = await issueValidPid(issue);
    const result = await validate(presentation, overrides);
    expect(result.failed).toBe(expected);
    expect(result.checks.filter((c) => !c.ok)).toHaveLength(1);
  });
});
