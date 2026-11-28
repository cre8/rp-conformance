// Issue 27: output-side self-validation of the Attestation Provider checks (issuer harness design section 7): FCAF
// `default_credential_A` as the forge issues it, signed by `QP-T` under its granted qualified EAA service on `TL-QEAA`,
// passes every credential check and the attestation checks; a forge-built attestation with one defect fails exactly
// the check of that rule. And `holder-binding` of a configuration that is not device-bound.
import { ATTESTATION_TEST_SUBJECTS } from '@eudi-pcaf/core';
import {
  buildTrustedLists,
  CREDENTIAL_A_DOCTYPE,
  CREDENTIAL_A_NAMESPACE,
  CREDENTIAL_A_VCT,
  createTestPki,
  DEFAULT_CREDENTIAL_A_CLAIMS,
  type EcKeyPair,
  generateEcKeyPair,
  issueMdoc,
  issueSdJwtVc,
  type TestPki,
} from '@eudi-pcaf/forge';
import { beforeAll, describe, expect, it } from 'vitest';
import { checkQualifiedService, type IssuedOutputOptions, TRUST_RULES, TrustStore, validateIssuedMdoc, validateIssuedSdJwtVc } from '../src/index';

const LOCATIONS = { LOTL: 'https://trust.rp-test/issued-attestation/LOTL.xml', 'TL-QEAA': 'https://trust.rp-test/issued-attestation/TL-QEAA.xml' };
const SUBJECT = ATTESTATION_TEST_SUBJECTS['SUBJ-1'];
const DAY = 24 * 60 * 60;

const keyAttestation = (keys: JsonWebKey[]) =>
  [{ alg: 'ES256', typ: 'key-attestation+jwt' }, { attested_keys: keys }].map((part) => Buffer.from(JSON.stringify(part)).toString('base64url')).join('.') + '.c2ln';

let pki: TestPki;
let trust: TrustStore;
let holder: EcKeyPair;

beforeAll(async () => {
  pki = await createTestPki();
  holder = await generateEcKeyPair();
  const lists = await buildTrustedLists({ pki, locations: LOCATIONS, sequenceNumber: 1 });
  const bodies: Record<string, string> = { [LOCATIONS.LOTL]: lists.LOTL, [LOCATIONS['TL-QEAA']]: lists['TL-QEAA'] };
  trust = new TrustStore(
    { lotes: [], listOfTrustedLists: { url: LOCATIONS.LOTL, signingCertificatesPem: [pki.trustedListOperators.LOTL.certificate.pem] } },
    (async (url: string) => new Response(bodies[url] ?? '', { status: bodies[url] ? 200 : 404 })) as unknown as typeof fetch,
  );
  const refused = (await trust.refresh()).filter((r) => r.error);
  expect(refused).toEqual([]);
});

const SD_CHECKS = ['attestation-type', 'attestation-attributes', 'attestation-values', 'attestation-disclosure', 'revocation-method', 'qualified-service'] as const;
const MD_CHECKS = ['attestation-type', 'attestation-attributes', 'attestation-values', 'revocation-method', 'qualified-service'] as const;

const output = (checks: readonly string[]): IssuedOutputOptions => ({ checks: [...checks] as IssuedOutputOptions['checks'], attestationSubject: SUBJECT });

/** `default_credential_A` in SD-JWT VC, valid for 12 hours (short-lived, no status), each attribute disclosable. */
const issueSd = async (options: { claims?: Record<string, unknown>; vct?: string; validitySeconds?: number; frame?: Record<string, unknown>; bound?: boolean } = {}) => {
  const issued = await issueSdJwtVc({
    signer: pki.entities['QP-T'].signers.issuance,
    issuer: 'https://qp-t.rp-test',
    holderPublicJwk: holder.publicJwk,
    vct: options.vct ?? CREDENTIAL_A_VCT,
    claims: options.claims ?? { ...DEFAULT_CREDENTIAL_A_CLAIMS },
    validitySeconds: options.validitySeconds ?? DAY / 2,
    ...(options.frame ? { disclosureFrame: options.frame } : {}),
  });
  return issued.compact;
};

const validateSd = (credential: string, checks: readonly string[] = SD_CHECKS, extra: { vct?: string; deviceBound?: boolean } = {}) =>
  validateIssuedSdJwtVc(credential, {
    trust,
    trustRule: TRUST_RULES.qeaa,
    issuerEntity: 'QP-T',
    expectedVct: [extra.vct ?? CREDENTIAL_A_VCT],
    proofKeys: [holder.publicJwk],
    keyAttestations: [keyAttestation([holder.publicJwk])],
    skewSeconds: 60,
    requireStatus: false,
    maxStatusListBytes: 1 << 20,
    fetchStatusList: async () => ({ status: 404, body: '' }),
    ...(extra.deviceBound === false ? { deviceBound: false } : {}),
    output: output(checks),
  });

describe('issued default_credential_A in SD-JWT VC (QEAA of QP-T)', () => {
  it('passes every credential check and every attestation check', async () => {
    const result = await validateSd(await issueSd());
    expect(result.failures).toEqual([]);
    for (const check of SD_CHECKS) expect(result.checks.find((c) => c.check === check)?.status, check).toBe('pass');
    expect(result.issuer).toBe('QP-T');
  });

  it.each([
    ['attestation-type', { vct: 'urn:rp-conformance:credential_b:1' }],
    ['attestation-attributes', { claims: { ...DEFAULT_CREDENTIAL_A_CLAIMS, attribute_A: -1, attribute_B: SUBJECT.attribute_B } }],
    ['attestation-attributes', { claims: { ...DEFAULT_CREDENTIAL_A_CLAIMS, attribute_C: '2999-01-01' } }],
    ['attestation-attributes', { claims: { ...DEFAULT_CREDENTIAL_A_CLAIMS, attribute_B: 'Ω'.repeat(3) } }],
    ['attestation-values', { claims: { ...DEFAULT_CREDENTIAL_A_CLAIMS, attribute_B: ATTESTATION_TEST_SUBJECTS['SUBJ-2'].attribute_B } }],
    ['attestation-disclosure', { frame: { _sd: ['attribute_A', 'attribute_B'] } }],
    ['revocation-method', { validitySeconds: 30 * DAY }],
  ] as const)('fails exactly %s', async (check, options) => {
    const credential = await issueSd(options as Parameters<typeof issueSd>[0]);
    // A `vct` other than the requested one also fails `format`; the attestation check is the one under test.
    // An attribute that breaks the rulebook also differs from the subject's value: `attestation-values` is left out there.
    const checks = check === 'attestation-attributes' ? SD_CHECKS.filter((c) => c !== 'attestation-values') : SD_CHECKS;
    const result = await validateSd(credential, checks, 'vct' in options ? { vct: options.vct } : {});
    expect(result.failures).toEqual([check]);
  });

  it('attestation-values passes for the data of SUBJ-2 when compared with SUBJ-2', async () => {
    const credential = await issueSd({ claims: { ...ATTESTATION_TEST_SUBJECTS['SUBJ-2'] } });
    const result = await validateIssuedSdJwtVc(credential, {
      trust,
      trustRule: TRUST_RULES.qeaa,
      expectedVct: [CREDENTIAL_A_VCT],
      proofKeys: [holder.publicJwk],
      keyAttestations: [keyAttestation([holder.publicJwk])],
      skewSeconds: 60,
      requireStatus: false,
      maxStatusListBytes: 1 << 20,
      fetchStatusList: async () => ({ status: 404, body: '' }),
      output: { checks: ['attestation-values'], attestationSubject: ATTESTATION_TEST_SUBJECTS['SUBJ-2'] },
    });
    expect(result.failures).toEqual([]);
  });
});

describe('holder-binding of a configuration that is not device-bound (ICS-04, P-NDB)', () => {
  it('fails exactly holder-binding for a credential bound to a key (cnf)', async () => {
    const compact = await issueSd();
    const result = await validateSd(compact, [], { deviceBound: false });
    expect(result.failures).toEqual(['holder-binding']);
    expect(result.checks.find((c) => c.check === 'holder-binding')?.detail).toMatch(/carries cnf/);
  });
});

describe('issued default_credential_A in mdoc (QEAA of QP-T)', () => {
  const issueMd = async (fullDates = true, claims: Record<string, unknown> = { ...DEFAULT_CREDENTIAL_A_CLAIMS }) =>
    (
      await issueMdoc({
        signer: pki.entities['QP-T'].signers.mdoc,
        holderPublicJwk: holder.publicJwk,
        short: true,
        docType: CREDENTIAL_A_DOCTYPE,
        namespace: CREDENTIAL_A_NAMESPACE,
        claims,
        fullDates: new Set(fullDates ? ['attribute_C'] : []),
      })
    ).issuerSigned;
  const encode = (bytes: Uint8Array) => Buffer.from(bytes).toString('base64url');

  const validateMd = (credential: Uint8Array) =>
    validateIssuedMdoc(encode(credential), {
      trust,
      trustRule: TRUST_RULES.qeaa,
      issuerEntity: 'QP-T',
      expectedDocType: CREDENTIAL_A_DOCTYPE,
      proofKeys: [holder.publicJwk],
      keyAttestations: [keyAttestation([holder.publicJwk])],
      skewSeconds: 60,
      requireStatus: false,
      maxStatusListBytes: 1 << 20,
      fetchStatusList: async () => ({ status: 404, body: new Uint8Array() }),
      output: output(MD_CHECKS),
    });

  it('passes every credential check and every attestation check', async () => {
    const result = await validateMd(await issueMd());
    expect(result.failures).toEqual([]);
    for (const check of MD_CHECKS) expect(result.checks.find((c) => c.check === check)?.status, check).toBe('pass');
  });

  it('attribute_C as a text string, not full-date, fails exactly attestation-attributes', async () => {
    const result = await validateMd(await issueMd(false));
    expect(result.failures).toEqual(['attestation-attributes']);
  });

  it('another attribute_A than SUBJ-1 fails exactly attestation-values', async () => {
    const result = await validateMd(await issueMd(true, { ...DEFAULT_CREDENTIAL_A_CLAIMS, attribute_A: 7 }));
    expect(result.failures).toEqual(['attestation-values']);
  });
});

describe('qualified-service', () => {
  it('passes for a granted EAA/Q service and fails for a non-qualified or withdrawn one', () => {
    const granted = 'http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted';
    expect(checkQualifiedService({ type: 'http://uri.etsi.org/TrstSvc/Svctype/EAA/Q', status: granted }, 'TL DE')).toMatch(/granted EAA\/Q/);
    expect(() => checkQualifiedService({ type: 'http://uri.etsi.org/TrstSvc/Svctype/EAA', status: granted }, 'TL DE')).toThrow(/not a qualified EAA service/);
    expect(() => checkQualifiedService({ type: 'http://uri.etsi.org/TrstSvc/Svctype/EAA/Q', status: 'http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/withdrawn' }, 'TL DE')).toThrow(/not granted/);
  });
});
