// `holder-binding` and the issued-credential validation of the issuer side (`OBS-CRED`): a credential the forge issues
// valid passes every check; bound to another key, or to a key the KA does not attest, it fails `holder-binding` only.
import { buildSealedLote, createTestPki, type EcKeyPair, generateEcKeyPair, issuePidSdJwtVc, LIST_PROFILES, PID_VCT, type TestPki } from '@eudi-pcaf/forge';
import { beforeAll, describe, expect, it } from 'vitest';
import { checkHolderBinding, ISSUED_SD_JWT_VC_CHECKS, TRUST_RULES, TrustStore, validateIssuedSdJwtVc } from '../src/index';

const URL_TL_PID = 'https://trust.rp-test/holder-binding/TL-PID';

/** A KA as the issuance client sends it; `holder-binding` only reads its `attested_keys`. */
const keyAttestation = (keys: JsonWebKey[]) =>
  [{ alg: 'ES256', typ: 'key-attestation+jwt' }, { attested_keys: keys }].map((part) => Buffer.from(JSON.stringify(part)).toString('base64url')).join('.') + '.c2ln';

let pki: TestPki;
let trust: TrustStore;
let proofKey: EcKeyPair;
let otherKey: EcKeyPair;

beforeAll(async () => {
  pki = await createTestPki();
  proofKey = await generateEcKeyPair();
  otherKey = await generateEcKeyPair();
  const { jws } = await buildSealedLote({ list: 'TL-PID', pki, distributionPoint: URL_TL_PID });
  const fetchList = (async () => new Response(jws, { status: 200 })) as unknown as typeof fetch;
  trust = new TrustStore(
    [{ id: 'TL-PID', url: URL_TL_PID, loteType: LIST_PROFILES['TL-PID'].loteType, schemeOperatorCertificatePem: pki.schemeOperators['TL-PID'].certificate.pem }],
    fetchList,
  );
  await trust.refresh();
});

/** A PID issued by `PP-T` (the harness's own signer under `PP-T`) to `holder`, without status reference. */
const issue = async (holder: EcKeyPair) =>
  (await issuePidSdJwtVc({ signer: pki.entities['PP-T'].signers.issuance, issuer: 'https://pp-t.rp-test', holderPublicJwk: holder.publicJwk })).compact;

const validate = (credential: string, keyAttestations: string[]) =>
  validateIssuedSdJwtVc(credential, {
    trust,
    trustRule: TRUST_RULES.pid,
    issuerEntity: 'PP-T',
    expectedVct: [PID_VCT],
    proofKeys: [proofKey.publicJwk],
    keyAttestations,
    skewSeconds: 60,
    requireStatus: false,
    maxStatusListBytes: 1 << 20,
    fetchStatusList: async () => ({ status: 404, body: '' }),
  });

describe('holder-binding', () => {
  it('passes when cnf.jwk is the proof key and an attested key', () => {
    expect(checkHolderBinding({ cnf: { jwk: proofKey.publicJwk } }, [proofKey.publicJwk], [keyAttestation([otherKey.publicJwk, proofKey.publicJwk])])).toMatch(
      /proof 1 and attested_keys entry of key attestation 1/,
    );
  });

  it('fails when cnf.jwk is not a proof key', () => {
    expect(() => checkHolderBinding({ cnf: { jwk: otherKey.publicJwk } }, [proofKey.publicJwk], [keyAttestation([otherKey.publicJwk])])).toThrow(/none of the 1 proof key/);
  });

  it('fails when the proof key is not attested by the KA', () => {
    expect(() => checkHolderBinding({ cnf: { jwk: proofKey.publicJwk } }, [proofKey.publicJwk], [keyAttestation([otherKey.publicJwk])])).toThrow(/no key attestation/);
  });

  it('fails without cnf.jwk', () => {
    expect(() => checkHolderBinding({}, [proofKey.publicJwk], [keyAttestation([proofKey.publicJwk])])).toThrow(/no cnf.jwk/);
  });
});

describe('validateIssuedSdJwtVc', () => {
  it('passes every check of a valid issued PID, with holder-binding instead of key-binding', async () => {
    const result = await validate(await issue(proofKey), [keyAttestation([proofKey.publicJwk])]);
    expect(result.failures).toEqual([]);
    expect(result.issuer).toBe('PP-T');
    expect(result.checks.map((c) => c.check)).toEqual(ISSUED_SD_JWT_VC_CHECKS);
    expect(result.checks.some((c) => c.check === 'key-binding' || c.check === 'kb-freshness')).toBe(false);
  });

  it('fails exactly holder-binding for a credential bound to another key', async () => {
    expect((await validate(await issue(otherKey), [keyAttestation([proofKey.publicJwk])])).failures).toEqual(['holder-binding']);
  });

  it('fails exactly holder-binding when the proof key is not attested', async () => {
    expect((await validate(await issue(proofKey), [keyAttestation([otherKey.publicJwk])])).failures).toEqual(['holder-binding']);
  });

  it('fails issuer-trust for a PID of another Provider on TL-PID (PP-A, not the enrolled PP-T)', async () => {
    const credential = (await issuePidSdJwtVc({ signer: pki.entities['PP-A'].signers.issuance, issuer: 'https://pp-a.rp-test', holderPublicJwk: proofKey.publicJwk })).compact;
    const result = await validate(credential, [keyAttestation([proofKey.publicJwk])]);
    expect(result.failures).toEqual(['issuer-trust']);
    expect(result.checks.find((c) => c.check === 'issuer-trust')?.detail).toMatch(/PP-A .*not of the enrolled PP-T/);
  });
});
