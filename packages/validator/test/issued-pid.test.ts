// Output-side self-validation of the issuer suite (issuer harness design section 7): a PID the forge issues valid per the
// PID Rulebook, in SD-JWT VC and in mdoc, passes every credential check and every output check (`SM_Validity`,
// `DM_*`); a forge-built PID with one defect fails exactly the check of that rule.
import { ATTESTATION_OUTPUT_CHECKS, ISSUER_OUTPUT_CHECKS, PID_TEST_SUBJECTS, pidClaimsOf } from '@eudi-pcaf/core';
import {
  base64url,
  buildSealedLote,
  type CborMap,
  createTestPki,
  decodeCbor,
  type EcKeyPair,
  encodeCbor,
  generateEcKeyPair,
  issueMdoc,
  issuePidSdJwtVc,
  issueSdJwtVc,
  LIST_PROFILES,
  mdocValidity,
  PID_VCT,
  type TestPki,
  tdate,
} from '@eudi-pcaf/forge';
import { beforeAll, describe, expect, it } from 'vitest';
import {
  checkMdocValidityPeriod,
  checkTypeMetadata,
  comparePidFormats,
  type IssuedOutputOptions,
  ISSUED_MDOC_CHECKS,
  TRUST_RULES,
  TrustStore,
  typeMetadataUrl,
  validateIssuedMdoc,
  validateIssuedSdJwtVc,
} from '../src/index';

const URL_TL_PID = 'https://trust.rp-test/issued-pid/TL-PID';
const DOCTYPE = 'eu.europa.ec.eudi.pid.1';
const DAY = 24 * 60 * 60;
const SUBJECT = PID_TEST_SUBJECTS['SUBJ-1'];

const keyAttestation = (keys: JsonWebKey[]) =>
  [{ alg: 'ES256', typ: 'key-attestation+jwt' }, { attested_keys: keys }].map((part) => Buffer.from(JSON.stringify(part)).toString('base64url')).join('.') + '.c2ln';

let pki: TestPki;
let trust: TrustStore;
let holder: EcKeyPair;
let otherKey: EcKeyPair;

beforeAll(async () => {
  pki = await createTestPki();
  holder = await generateEcKeyPair();
  otherKey = await generateEcKeyPair();
  const { jws } = await buildSealedLote({ list: 'TL-PID', pki, distributionPoint: URL_TL_PID });
  trust = new TrustStore(
    [{ id: 'TL-PID', url: URL_TL_PID, loteType: LIST_PROFILES['TL-PID'].loteType, schemeOperatorCertificatePem: pki.schemeOperators['TL-PID'].certificate.pem }],
    (async () => new Response(jws, { status: 200 })) as unknown as typeof fetch,
  );
  await trust.refresh();
});

/** A copy of `claims` without `name`. */
const without = (claims: Record<string, unknown>, name: string) => Object.fromEntries(Object.entries(claims).filter(([k]) => k !== name));

const day = (date: Date) => date.toISOString().slice(0, 10);
const age = (now: Date) => now.getUTCFullYear() - 1964 - (now.getUTCMonth() < 7 || (now.getUTCMonth() === 7 && now.getUTCDate() < 12) ? 1 : 0);

/** Every output check except `pid-portrait`, which applies after a portrait opt-out only, and `pid-formats`, a step check. */
// Issue 27: the checks of an attestation (`default_credential_A`) have their own tests (issued-attestation.test.ts).
const OUTPUT_CHECKS = ISSUER_OUTPUT_CHECKS.filter((c) => c !== 'pid-portrait' && c !== 'pid-formats' && !ATTESTATION_OUTPUT_CHECKS.includes(c));
const SD_OUTPUT = OUTPUT_CHECKS.filter((c) => c !== 'pid-unique');
const MD_OUTPUT = OUTPUT_CHECKS.filter((c) => c !== 'type-metadata' && c !== 'pid-extension');

const output = (checks: readonly string[], overrides: Partial<IssuedOutputOptions> = {}): IssuedOutputOptions => ({
  checks: [...checks] as IssuedOutputOptions['checks'],
  subject: SUBJECT,
  declaredValiditySeconds: 30 * DAY,
  precisionSeconds: 3600,
  ...overrides,
});

// ---------------------------------------------------------------------------------------------------------------------
// SD-JWT VC

/** `SUBJ-1`'s PID in SD-JWT VC per the PID Rulebook, with age claims and the issuance and expiry dates, valid 30 days. */
const sdClaims = (now = new Date()) => ({
  ...pidClaimsOf(SUBJECT, 'SD'),
  age_equal_or_over: { '18': true, '65': age(now) >= 65 },
  age_in_years: age(now),
  age_birth_year: 1964,
  date_of_issuance: day(now),
  date_of_expiry: day(new Date(now.getTime() + 30 * DAY * 1000)),
});

const issueSd = async (options: { claims?: Record<string, unknown>; vct?: string; validitySeconds?: number; bind?: EcKeyPair } = {}) =>
  (
    await issueSdJwtVc({
      signer: pki.entities['PP-T'].signers.issuance,
      issuer: 'https://pp-t.rp-test',
      holderPublicJwk: (options.bind ?? holder).publicJwk,
      vct: options.vct ?? PID_VCT,
      claims: options.claims ?? sdClaims(),
      ...(options.validitySeconds ? { validitySeconds: options.validitySeconds } : {}),
    })
  ).compact;

const validateSd = (credential: string, out: IssuedOutputOptions = output(SD_OUTPUT), vct = PID_VCT) =>
  validateIssuedSdJwtVc(credential, {
    trust,
    trustRule: TRUST_RULES.pid,
    issuerEntity: 'PP-T',
    expectedVct: [vct],
    proofKeys: [holder.publicJwk],
    keyAttestations: [keyAttestation([holder.publicJwk])],
    skewSeconds: 60,
    requireStatus: false,
    maxStatusListBytes: 1 << 20,
    fetchStatusList: async () => ({ status: 404, body: '' }),
    output: out,
  });

describe('issued PID in SD-JWT VC: output checks', () => {
  it('a PID per the Rulebook passes every credential and output check', async () => {
    const result = await validateSd(await issueSd());
    expect(result.failures).toEqual([]);
    for (const check of SD_OUTPUT) expect(result.checks.find((c) => c.check === check)?.status, check).toBe('pass');
  });

  it("the forge's default PID with the Rulebook's issuing metadata passes the data model checks", async () => {
    const credential = (
      await issuePidSdJwtVc({
        signer: pki.entities['PP-T'].signers.issuance,
        issuer: 'https://pp-t.rp-test',
        holderPublicJwk: holder.publicJwk,
        claims: { issuing_authority: 'DE', issuing_country: 'DE' },
      })
    ).compact;
    expect((await validateSd(credential)).failures).toEqual([]);
  });

  const faults: [string, () => Promise<{ credential: string; out?: IssuedOutputOptions; vct?: string }>, string][] = [
    ['a vct outside the urn:eudi:pid: namespace', async () => ({ credential: await issueSd({ vct: 'urn:example:id:1' }), vct: 'urn:example:id:1' }), 'pid-type'],
    ['no issuing_country', async () => ({ credential: await issueSd({ claims: without(sdClaims(), 'issuing_country') }) }), 'pid-attributes'],
    ['sex as a string', async () => ({ credential: await issueSd({ claims: { ...sdClaims(), sex: 'female' } }) }), 'pid-attributes'],
    ['another given_name than SUBJ-1', async () => ({ credential: await issueSd({ claims: { ...sdClaims(), given_name: 'Erica' } }) }), 'pid-values'],
    ['age_equal_or_over.18 false for a subject over 18', async () => ({ credential: await issueSd({ claims: { ...sdClaims(), age_equal_or_over: { '18': false } } }) }), 'pid-values'],
    [
      'date_of_expiry before exp',
      async () => ({ credential: await issueSd({ claims: { ...sdClaims(), date_of_expiry: day(new Date(Date.now() + 2 * DAY * 1000)) } }) }),
      'pid-dates',
    ],
    ['a claim outside the Rulebook under urn:eudi:pid:1', async () => ({ credential: await issueSd({ claims: { ...sdClaims(), shoe_size: 42 } }) }), 'pid-extension'],
    ['a validity period of 10 days where 30 are declared', async () => ({ credential: await issueSd({ validitySeconds: 10 * DAY, claims: sdClaims() }) }), 'validity-declared'],
    ['iat only as a disclosure, not in the payload', async () => ({ credential: await issueSd({ claims: { ...sdClaims(), iat: Math.floor(Date.now() / 1000) } }) }), 'validity-period'],
    ['bound to a key the Conformance Wallet did not prove', async () => ({ credential: await issueSd({ bind: otherKey }) }), 'holder-binding'],
  ];
  for (const [name, build, check] of faults) {
    it(`${name} fails exactly ${check}`, async () => {
      const { credential, out, vct } = await build();
      expect((await validateSd(credential, out, vct)).failures).toEqual([check]);
    });
  }

  it('pid-portrait: an empty picture passes, a missing one fails', async () => {
    const out = output(['pid-portrait']);
    expect((await validateSd(await issueSd({ claims: { ...sdClaims(), picture: '' } }), out)).failures).toEqual([]);
    expect((await validateSd(await issueSd(), out)).failures).toEqual(['pid-portrait']);
  });
});

describe('type-metadata', () => {
  it('records a URN vct, which has no retrieval', async () => {
    expect(await checkTypeMetadata({ vct: PID_VCT })).toMatch(/not an https URL/);
  });

  it('retrieves the Type Metadata of an https vct and matches vct#integrity', async () => {
    const vct = 'https://issuer.rp-test/pid/1';
    const body = new TextEncoder().encode(JSON.stringify({ vct }));
    const integrity = `sha256-${Buffer.from(await crypto.subtle.digest('SHA-256', body)).toString('base64')}`;
    const fetchTypeMetadata = async (url: string) => (url === typeMetadataUrl(vct) ? { status: 200, body } : { status: 404, body: new Uint8Array() });
    expect(typeMetadataUrl(vct)).toBe('https://issuer.rp-test/.well-known/vct/pid/1');
    expect(await checkTypeMetadata({ vct, 'vct#integrity': integrity }, fetchTypeMetadata)).toMatch(/vct#integrity matches/);
    await expect(checkTypeMetadata({ vct, 'vct#integrity': 'sha256-AAAA' }, fetchTypeMetadata)).rejects.toThrow(/does not match/);
    await expect(checkTypeMetadata({ vct: 'https://issuer.rp-test/other' }, fetchTypeMetadata)).rejects.toThrow(/HTTP 404/);
  });
});

// ---------------------------------------------------------------------------------------------------------------------
// mdoc

const FULL_DATES = new Set(['birth_date', 'expiry_date', 'issuance_date']);

/** `SUBJ-1`'s PID in mdoc per the PID Rulebook, as `issueMdoc` signs it (validity of `mdocValidity`). */
const mdClaims = (now = new Date()) => {
  const { validFrom, validUntil } = mdocValidity(now);
  return {
    ...pidClaimsOf(SUBJECT, 'MD'),
    age_over_18: true,
    age_over_65: age(validFrom) >= 65,
    age_in_years: age(validFrom),
    age_birth_year: 1964,
    issuance_date: day(validFrom),
    expiry_date: day(validUntil),
  } as Record<string, unknown>;
};

const issueMd = async (options: { claims?: Record<string, unknown>; docType?: string; fullDates?: Set<string>; bind?: EcKeyPair } = {}) =>
  base64url.encode(
    (
      await issueMdoc({
        signer: pki.entities['PP-T'].signers.mdoc,
        holderPublicJwk: (options.bind ?? holder).publicJwk,
        docType: options.docType ?? DOCTYPE,
        namespace: DOCTYPE,
        claims: options.claims ?? mdClaims(),
        fullDates: options.fullDates ?? FULL_DATES,
      })
    ).issuerSigned,
  );

const validateMd = (credential: string, out: IssuedOutputOptions = output(MD_OUTPUT), docType = DOCTYPE) =>
  validateIssuedMdoc(credential, {
    trust,
    trustRule: TRUST_RULES.pid,
    issuerEntity: 'PP-T',
    expectedDocType: docType,
    proofKeys: [holder.publicJwk],
    keyAttestations: [keyAttestation([holder.publicJwk])],
    skewSeconds: 60,
    requireStatus: false,
    maxStatusListBytes: 1 << 20,
    fetchStatusList: async () => ({ status: 404, body: new Uint8Array() }),
    output: out,
  });

/** The IssuerSigned of a base64url mdoc with the first element of the PID namespace appended once more. */
const withDuplicate = (credential: string) => {
  const issuerSigned = decodeCbor<CborMap>(base64url.decode(credential));
  const items = (issuerSigned.get('nameSpaces') as CborMap).get(DOCTYPE) as unknown[];
  items.push(items[0]);
  return base64url.encode(encodeCbor(issuerSigned));
};

describe('issued PID in mdoc: credential and output checks', () => {
  it('a PID per the Rulebook passes every credential and output check, holder-binding on deviceKeyInfo', async () => {
    const result = await validateMd(await issueMd());
    expect(result.failures).toEqual([]);
    expect(result.checks.slice(0, ISSUED_MDOC_CHECKS.length).map((c) => c.check)).toEqual(ISSUED_MDOC_CHECKS);
    for (const check of MD_OUTPUT) expect(result.checks.find((c) => c.check === check)?.status, check).toBe('pass');
    expect(result.checks.find((c) => c.check === 'holder-binding')?.detail).toMatch(/deviceKeyInfo is the key of proof 1/);
    expect(result.issuer).toBe('PP-T');
  });

  const faults: [string, () => Promise<{ credential: string; out?: IssuedOutputOptions; docType?: string }>, string][] = [
    ['a docType other than eu.europa.ec.eudi.pid.1', async () => ({ credential: await issueMd({ docType: 'eu.europa.ec.eudi.pid.de.1' }), docType: 'eu.europa.ec.eudi.pid.de.1' }), 'pid-type'],
    ['a non-Rulebook element in the EU namespace', async () => ({ credential: await issueMd({ claims: { ...mdClaims(), shoe_size: 42 } }) }), 'pid-type'],
    ['birth_date as a text string, not full-date', async () => ({ credential: await issueMd({ fullDates: new Set(['expiry_date', 'issuance_date']) }) }), 'pid-attributes'],
    ['no expiry_date', async () => ({ credential: await issueMd({ claims: without(mdClaims(), 'expiry_date') }) }), 'pid-attributes'],
    ['an element twice', async () => ({ credential: withDuplicate(await issueMd()) }), 'pid-unique'],
    ['another family_name than SUBJ-1', async () => ({ credential: await issueMd({ claims: { ...mdClaims(), family_name: 'Gabler' } }) }), 'pid-values'],
    ['age_over_65 true for a subject under 65', async () => ({ credential: await issueMd({ claims: { ...mdClaims(), age_over_65: true } }) }), 'pid-values'],
    ['expiry_date before validUntil', async () => ({ credential: await issueMd({ claims: { ...mdClaims(), expiry_date: day(new Date()) } }) }), 'pid-dates'],
    ['a declared validity period of 7 days', async () => ({ credential: await issueMd(), out: output(MD_OUTPUT, { declaredValiditySeconds: 7 * DAY }) }), 'validity-declared'],
    ['bound to a key the Conformance Wallet did not prove', async () => ({ credential: await issueMd({ bind: otherKey }) }), 'holder-binding'],
  ];
  for (const [name, build, check] of faults) {
    it(`${name} fails exactly ${check}`, async () => {
      const { credential, out, docType } = await build();
      expect((await validateMd(credential, out, docType)).failures).toEqual([check]);
    });
  }

  it('validity-period fails for a validUntil not after validFrom, and for an mdoc not yet valid', () => {
    const now = new Date();
    const mso = (validFrom: Date, validUntil: Date) =>
      new Map<unknown, unknown>([['validityInfo', new Map<unknown, unknown>([['signed', tdate(validFrom)], ['validFrom', tdate(validFrom)], ['validUntil', tdate(validUntil)]])]]);
    const seconds = Math.floor(now.getTime() / 1000);
    expect(() => checkMdocValidityPeriod(mso(now, now), seconds, 60)).toThrow(/not after validFrom/);
    expect(() => checkMdocValidityPeriod(mso(new Date(now.getTime() + DAY * 1000), new Date(now.getTime() + 2 * DAY * 1000)), seconds, 60)).toThrow(/in the future|not valid at issuance/);
    expect(checkMdocValidityPeriod(mso(now, new Date(now.getTime() + DAY * 1000)), seconds, 60)).toMatch(/valid at issuance/);
  });

  it('pid-portrait: an empty portrait byte string passes, a missing one fails', async () => {
    const out = output(['pid-portrait']);
    expect((await validateMd(await issueMd({ claims: { ...mdClaims(), portrait: new Uint8Array() } }), out)).failures).toEqual([]);
    expect((await validateMd(await issueMd(), out)).failures).toEqual(['pid-portrait']);
  });
});

describe('pid-formats', () => {
  it('passes for the SD-JWT VC and the mdoc of the same subject, and fails when one value differs', async () => {
    const sd = await validateSd(await issueSd());
    const md = await validateMd(await issueMd());
    // Both formats carry the same dates when issued at the same time; the forge signs the mdoc two days earlier.
    const mdoc = { ...(md.pidClaims as Record<string, unknown>) };
    const sdClaimsDisclosed: Record<string, unknown> = {
      ...(sd.claims as Record<string, unknown>),
      date_of_issuance: mdoc.issuance_date,
      date_of_expiry: mdoc.expiry_date,
      age_equal_or_over: { '18': mdoc.age_over_18, '65': mdoc.age_over_65 },
    };
    expect(comparePidFormats(sdClaimsDisclosed, mdoc)).toMatchObject({ status: 'pass' });
    expect(comparePidFormats({ ...sdClaimsDisclosed, given_name: 'Erica' }, mdoc)).toMatchObject({ status: 'fail', detail: expect.stringMatching(/given_name/) });
    expect(comparePidFormats(sdClaimsDisclosed, undefined)).toMatchObject({ status: 'skip' });
  });
});
