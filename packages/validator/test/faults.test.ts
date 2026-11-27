import {
  attestation,
  FAULT_IDS,
  type FaultId,
  faultInfo,
  identifierListToken,
  pid,
  pidQueryOf,
  presentation,
  RESPONSE_CHECKS,
  statusListToken,
  type TrustListAction,
} from '@rp-conformance/core';
import { createPublicKey, verify, X509Certificate } from 'node:crypto';
import { defaultEntitiesOf, faultySigner, isSignerFault, mdocValidity, trustedListEntitiesOf } from '@rp-conformance/forge';
import {
  base64url,
  type CborMap,
  COSE,
  decodeCbor,
  decodeEmbedded,
  embedded,
  encodeCbor,
  jwkThumbprint as jwkThumbprintOf,
  readCose,
  sha256,
  sigStructure,
  Tagged,
  x5chainOf,
} from '@rp-conformance/forge';
import { beforeAll, describe, expect, it } from 'vitest';
import { MDOC_IDENTIFIER_LIST_CHECKS, MDOC_STATUS_LIST_CHECKS, openid4vpSessionTranscript, SD_JWT_VC_CHECKS, TRUST_RULES } from '../src/index';
import { AUDIENCE, Fixture, RESPONSE_URI } from './fixture';

// Harness design section 7, steps 1 and 2: the valid artifacts pass every check of the reference validator, and every
// fault of the catalogue fails exactly its target check and no other.

let fixture: Fixture;

beforeAll(async () => {
  fixture = await Fixture.create();
});

/**
 * A presentation with `fault`, in the credential format the fault applies to (`format` for a response fault or a
 * presentation fault of either format).
 */
const actionWith = (fault?: FaultId, format: 'dc+sd-jwt' | 'mso_mdoc' = 'dc+sd-jwt') => {
  const info = fault && faultInfo(fault);
  const credentialFormat = info?.format === 'mso_mdoc' || info?.format === 'cwt' ? 'mso_mdoc' : format;
  const only = (point: string) => (info?.point === point ? [fault as FaultId] : []);
  return presentation({
    // An attribute variant of the PID is presented for the query that requests the changed attributes.
    query: info?.query ?? pidQueryOf(credentialFormat),
    credential: pid.of(credentialFormat, { faults: only('credential'), ...(info?.issuer ? { issuer: info.issuer } : {}) }),
    ...(info?.point === 'identifier-list'
      ? { identifierList: identifierListToken.cwt({ contains: false, faults: only('identifier-list') }) }
      : { statusList: statusListToken.of(credentialFormat === 'mso_mdoc' ? 'cwt' : 'jwt', { faults: only('status-list') }) }),
    response: { faults: [...only('response'), ...only('presentation')], ...(fault === 'presentation.replay' ? { presentationOfStep: 1 } : {}) },
  });
};

/** Another transaction, for the faults that use one. */
const otherFor = (fault: FaultId) =>
  fault === 'response.other-transaction-key' || fault === 'presentation.replay' ? fixture.transaction() : Promise.resolve(undefined);

/**
 * The reason the reference validator gives for each fault of the device binding and session binding test cases: several
 * of them fail the same check, so the reason shows that each fails it for its own defect and not, say, for a signature
 * broken by the fault layer.
 */
const BINDING_REASONS: Partial<Record<FaultId, RegExp>> = {
  'credential.no-cnf': /no cnf\.jwk/,
  'mdoc.no-device-key': /no deviceKeyInfo/,
  'presentation.kb-nonce-other': /KB-JWT nonce/,
  'presentation.kb-aud-other-client': /KB-JWT aud x509_hash:/,
  'presentation.kb-aud-no-prefix': /KB-JWT aud (?!x509_hash:)/,
  'presentation.kb-aud-client-id': /KB-JWT aud x509_hash:/,
  'presentation.kb-aud-other-origin': /KB-JWT aud origin:https:\/\/other\.example/,
  'presentation.kb-aud-missing': /KB-JWT aud undefined/,
  // A string and the array that holds it read the same in the reason: the aud the validator names is the one it expects.
  'presentation.kb-aud-array': /KB-JWT aud (\S+) is not \1$/,
  'presentation.kb-nonce-missing': /KB-JWT nonce does not match/,
  'presentation.kb-iat-past': /older than T_kb/,
  'presentation.kb-iat-future': /in the future/,
  'presentation.kb-signature-bitflip': /KB-JWT signature does not verify/,
  'presentation.kb-other-key': /KB-JWT signature does not verify/,
  'presentation.no-kb-jwt': /no KB-JWT/,
  'presentation.kb-typ-missing': /KB-JWT typ is undefined/,
  'presentation.kb-typ-jwt': /KB-JWT typ is JWT/,
  'presentation.kb-sd-hash-other': /sd_hash/,
  'presentation.kb-alg-none': /KB-JWT alg none/,
  'presentation.kb-hs256-public-key': /KB-JWT alg HS256/,
  'presentation.kb-es256k': /KB-JWT alg ES256K/,
  'presentation.replay': /KB-JWT nonce/,
  'presentation.transcript-nonce': /SessionTranscript of this request/,
  'presentation.transcript-client-id': /SessionTranscript of this request/,
  'presentation.transcript-response-uri': /SessionTranscript of this request/,
  'presentation.transcript-client-id-no-prefix': /SessionTranscript of this request/,
  'presentation.transcript-jwk-thumbprint': /SessionTranscript of this request/,
  'presentation.transcript-jwk-thumbprint-null': /SessionTranscript of this request/,
  'presentation.transcript-origin-prefixed': /SessionTranscript of this request/,
  'presentation.device-signature-doctype-other': /SessionTranscript of this request/,
  'presentation.device-signature-missing': /no deviceSignature/,
  'presentation.device-signature-not-detached': /not detached/,
  'presentation.transcript-origin': /SessionTranscript of this request/,
  'presentation.device-signature-bitflip': /SessionTranscript of this request/,
  'presentation.device-signature-other-key': /SessionTranscript of this request/,
  'presentation.no-device-auth': /no deviceAuth/,
  'presentation.device-signed-element': /DeviceNameSpaces is not empty/,
  'presentation.device-signature-es256k': /alg -47/,
  'presentation.kb-duplicate-alg': /KB-JWT header carries the member alg twice/,
  'presentation.kb-duplicate-nonce': /KB-JWT payload carries the member nonce twice/,
  // Issue 10.
  'presentation.kb-crit-unknown': /KB-JWT header marks \["rp_conformance_ext"\] critical/,
  'presentation.kb-exp-string': /KB-JWT exp "\d+" is not a NumericDate/,
  'presentation.transcript-dcapi-handover': /covers an OpenID4VPDCAPIHandover instead of the OpenID4VPHandover/,
  'presentation.transcript-redirect-handover': /covers an OpenID4VPHandover instead of the OpenID4VPDCAPIHandover/,
  'mdoc.device-key-okp-p256': /key type 1 with the curve 1, which do not belong together/,
};

/** The reason for each fault of IssuerIntegrity: many fail the same check, so the reason shows each fails it for its own defect. */
const ISSUER_REASONS: Partial<Record<FaultId, RegExp>> = {
  'credential.alg-none': /alg none/,
  'credential.alg-hs256': /alg HS256/,
  'credential.es256k': /key secp256k1/,
  'credential.no-x5c': /x5c is missing/,
  'credential.embedded-root': /no trust anchor named .*CA-X/,
  'credential.self-signed': /no trust anchor named .*self-signed/,
  'credential.typ-missing': /typ is undefined/,
  'credential.typ-jwt': /typ is JWT/,
  'credential.typ-vc-sd-jwt': /typ is vc\+sd-jwt/,
  'credential.disclosure-foreign': /not referenced/,
  'credential.disclosure-modified': /not referenced/,
  'credential.disclosure-duplicate': /presented twice/,
  'credential.digest-duplicate': /occurs more than once/,
  'credential.disclosure-name-sd': /reserved claim name _sd/,
  'credential.disclosure-name-ellipsis': /reserved claim name \.\.\./,
  'credential.disclosure-name-present': /family_name is already present/,
  'credential.disclosure-two-elements': /object property has two elements/,
  'credential.disclosure-four-elements': /two or three elements/,
  'credential.signature-der': /issuer signature does not verify/,
  'credential.disclosure-array-three-elements': /array element has three elements/,
  'credential.sd-alg-md5': /_sd_alg md5/,
  'credential.sd-alg-sha1': /_sd_alg sha-1/,
  'credential.vct-other': /vct urn:eudi:other:1/,
  'credential.signer-expired': /has expired/,
  'credential.signer-not-yet-valid': /not yet valid/,
  'credential.intermediate-expired': /INT expired.* has expired/,
  'credential.intermediate-missing': /no trust anchor named .*CA-PP-I-INT/,
  'credential.issuer-not-ca': /without cA.* is not a CA certificate/,
  'credential.key-p192': /key P-192/,
  'credential.key-rsa1024': /key RSA 1024 bit/,
  'credential.critical-extension': /unknown critical extension 1\.3\.6\.1\.4\.1\.55555\.1\.1/,
  'mdoc.element-value-changed': /digest of family_name does not match/,
  'mdoc.digest-id-unknown': /no digest with ID/,
  'mdoc.mso-doctype-other': /MSO docType differs/,
  'mdoc.digest-sha1': /digestAlgorithm SHA-1/,
  'mdoc.digest-reencoded-item': /digest of family_name does not match/,
  'mdoc.digest-truncated': /digest of family_name does not match/,
  'mdoc.signature-der': /IssuerAuth signature does not verify/,
  'mdoc.doctype-other': /docType org\.iso\.18013\.5\.1\.mDL was not requested/,
  'mdoc.embedded-root': /no trust anchor named .*CA-X/,
  'mdoc.ds-no-eku': /not a document signer/,
  'mdoc.signed-after-ds-expiry': /signed .* outside the validity period/,
  'mdoc.signer-expired': /has expired/,
  'mdoc.signer-not-yet-valid': /not yet valid/,
  'mdoc.intermediate-expired': /INT expired.* has expired/,
  'mdoc.intermediate-missing': /no trust anchor named .*CA-PP-I-INT/,
  'mdoc.issuer-not-ca': /without cA.* is not a CA certificate/,
  'mdoc.key-p192': /key P-192/,
  'mdoc.key-rsa1024': /key RSA 1024 bit/,
  'mdoc.critical-extension': /unknown critical extension/,
  'credential.x5c-50': /carries 50 certificates/,
  'mdoc.x5chain-50': /carries 50 certificates/,
  'credential.disclosure-invalid-json': /not base64url-encoded JSON/,
  // Issue 10.
  'credential.crit-unknown': /issuer-signed JWT header marks \["rp_conformance_ext"\] critical/,
  'credential.exp-disclosed': /disclosure carries the claim exp/,
  'credential.iss-disclosed': /disclosure carries the claim iss/,
  'credential.signer-names-other-issuer': /names the URI https:\/\/other-issuer\.rp-test, not iss/,
  'credential.signer-names-other-host': /names neither iss .* nor its host \(DNS names: other-issuer\.rp-test\)/,
  'credential.signer-uri-beats-host': /names the URI https:\/\/other-issuer\.rp-test, not iss/,
  'mdoc.issuer-auth-es384-p256': /IssuerAuth alg -35 pairs with P-384, and the document signer holds a key on P-256/,
  'mdoc.issuer-auth-esp384-p256': /IssuerAuth alg -51 is ECDSA on P-384, and the document signer holds a key on P-256/,
  'mdoc.issuer-auth-crit-unknown': /IssuerAuth crit lists the label -65537/,
};

/** The reason for the faults of encoding (Encoding_003), which fail the check that reads the artifact. */
const OTHER_REASONS: Partial<Record<FaultId, RegExp>> = {
  'mdoc.issuer-auth-duplicate-label': /protected header.*repeat map key/,
  'mdoc.mso-not-tag24': /not MobileSecurityObjectBytes/,
};

const reasonOf = (result: Awaited<ReturnType<Fixture['validate']>>, check: string) => result.credential?.checks.find((c) => c.check === check)?.detail;

const statuses = (checks: { check: string; status: string }[] | undefined) => checks?.map((c) => [c.check, c.status]);

describe('fault self-validation', () => {
  it('the valid SD-JWT VC presentation passes every check, the response checks included', async () => {
    const result = await fixture.validate(actionWith());
    expect(result.failures).toEqual([]);
    expect(statuses(result.response)).toEqual(RESPONSE_CHECKS.map((c) => [c, 'pass']));
    expect(statuses(result.credential?.checks)).toEqual(SD_JWT_VC_CHECKS.map((c) => [c, 'pass']));
  });

  it('the valid mdoc presentation with a Status List Token in CWT format passes every check', async () => {
    const result = await fixture.validate(actionWith(undefined, 'mso_mdoc'));
    expect(result.failures).toEqual([]);
    expect(statuses(result.response)).toEqual(RESPONSE_CHECKS.map((c) => [c, 'pass']));
    expect(statuses(result.credential?.checks)).toEqual(MDOC_STATUS_LIST_CHECKS.map((c) => [c, 'pass']));
  });

  it.each(['dc+sd-jwt', 'mso_mdoc'] as const)('the valid %s presentation via the DC API (dc_api.jwt, origin audience) passes every check', async (format) => {
    const result = await fixture.validate(actionWith(undefined, format), { flow: 'dc-api' });
    expect(result.failures).toEqual([]);
    expect(statuses(result.response)).toEqual(RESPONSE_CHECKS.map((c) => [c, 'pass']));
    expect(statuses(result.credential?.checks)).toEqual((format === 'mso_mdoc' ? MDOC_STATUS_LIST_CHECKS : SD_JWT_VC_CHECKS).map((c) => [c, 'pass']));
  });

  it('the valid mdoc presentation with an identifier list passes every check', async () => {
    const action = presentation({
      query: 'default_query_pid_mdoc',
      credential: pid.mdoc(),
      identifierList: identifierListToken.cwt({ contains: false }),
    });
    const result = await fixture.validate(action);
    expect(result.failures).toEqual([]);
    expect(statuses(result.credential?.checks)).toEqual(MDOC_IDENTIFIER_LIST_CHECKS.map((c) => [c, 'pass']));
  });

  it('an mdoc whose identifier is on its identifier list fails exactly identifier-status', async () => {
    const action = presentation({
      query: 'default_query_pid_mdoc',
      credential: pid.mdoc(),
      identifierList: identifierListToken.cwt({ contains: true }),
    });
    expect((await fixture.validate(action)).failures).toEqual(['identifier-status']);
  });

  it.each(FAULT_IDS.filter((fault) => ['response', 'presentation'].includes(faultInfo(fault).point) && !faultInfo(fault).flow))(
    '%s fails exactly its target check via the DC API too',
    async (fault) => {
      const result = await fixture.validate(actionWith(fault), { other: await otherFor(fault), flow: 'dc-api' });
      const target = faultInfo(fault).target;
      expect(result.failures).toEqual(target ? [target] : []);
      if (BINDING_REASONS[fault] && target) expect(reasonOf(result, target)).toMatch(BINDING_REASONS[fault]);
    },
  );

  it.each(FAULT_IDS.filter((fault) => !['trust-list', 'request', 'vp-token'].includes(faultInfo(fault).point)))('%s fails exactly its target check', async (fault) => {
    const result = await fixture.validate(actionWith(fault), { other: await otherFor(fault) });
    const target = faultInfo(fault).target;
    expect(result.failures).toEqual(target ? [target] : []);
    if (BINDING_REASONS[fault] && target) expect(reasonOf(result, target)).toMatch(BINDING_REASONS[fault]);
    if (ISSUER_REASONS[fault] && target) expect(reasonOf(result, target)).toMatch(ISSUER_REASONS[fault]);
    if (OTHER_REASONS[fault] && target) expect(reasonOf(result, target)).toMatch(OTHER_REASONS[fault]);
  });

  // A new version of TL-PID or TL-QEAA that adds an entity (PP-C, or a granted service of QP-N), with the fault: the
  // reference validator refuses it for exactly the fault's target check, and keeps the version in use, so the added
  // entity stays untrusted. A version within its grace period is used and reported stale.
  it.each(FAULT_IDS.filter((fault) => faultInfo(fault).point === 'trust-list'))('%s fails exactly its target check', async (fault) => {
    const qeaa = faultInfo(fault).format === 'trusted-list';
    const list = qeaa ? 'TL-QEAA' : 'TL-PID';
    // A rollback undercuts a version the store has loaded before.
    if (fault === 'trust-list.rollback') await fixture.publishVersion({ kind: 'trust-list', list }, defaultEntitiesOf(fixture.pki, 'TL-PID'));
    const entities = qeaa ? trustedListEntitiesOf(fixture.pki) : [...defaultEntitiesOf(fixture.pki, 'TL-PID'), 'PP-C'];
    const action: TrustListAction = {
      kind: 'trust-list',
      list,
      faults: [fault],
      ...(qeaa ? { grantQualified: ['QP-N'] } : fault === 'trust-list.rollback' ? { restoreIssuance: ['PP-W'] } : {}),
    };
    try {
      const refused = await fixture.publishVersion(action, entities);
      const target = faultInfo(fault).target;
      expect(refused.map((r) => r.failed ?? r.error)).toEqual(target ? [target] : []);
      const added = qeaa ? 'QP-N' : fault === 'trust-list.rollback' ? 'PP-W' : 'PP-C';
      const chain = [Buffer.from(fixture.pki.entities[added].signers.issuance.certificate.der).toString('base64')];
      const match = await fixture.trust.match(qeaa ? TRUST_RULES.qeaa : TRUST_RULES.pid, chain);
      expect(match.ok, `${added} trusted`).toBe(!target);
      if (match.ok) expect(match.stale).toBe(fault === 'trust-list.stale-within-grace');
      // The version in use stays: PP-A and QP-A remain trusted.
      const kept = qeaa ? 'QP-A' : 'PP-A';
      const keptChain = [Buffer.from(fixture.pki.entities[kept].signers.issuance.certificate.der).toString('base64')];
      expect((await fixture.trust.match(qeaa ? TRUST_RULES.qeaa : TRUST_RULES.pid, keptChain)).ok, `${kept} trusted`).toBe(true);
    } finally {
      await fixture.restore();
    }
  });

  // The request-side checks: a valid request of the reference Relying Party's form passes every check that applies in
  // its flow, and each request fault fails exactly its target check, in each flow it applies to.
  it.each(['redirect', 'dc-api'] as const)('valid requests via %s pass every request check that applies', async (flow) => {
    for (const query of ['default_query_pid', 'default_query_pid_mdoc', 'default_query_pid_trusted_authorities'] as const) {
      const result = await fixture.validateRequests(flow, query, { count: 3 });
      expect(result.failures, query).toEqual([]);
      const skipped = result.checks.filter((c) => c.status === 'skip').map((c) => c.check);
      const otherFlow = flow === 'redirect' ? ['dc-api-request', 'expected-origins'] : ['request-by-reference', 'request-object', 'state', 'invocation-scheme', 'request-uri-content-type'];
      // A single GET of request_uri: the checks of a second retrieval and of a POST with wallet_nonce do not apply.
      const retrieval = ['request-uri-refetch', 'wallet-nonce'];
      expect(skipped.sort(), query).toEqual([...otherFlow, ...retrieval, ...(query.endsWith('_trusted_authorities') ? [] : ['trusted-authorities'])].sort());
      if (flow === 'redirect') {
        for (const requestUri of ['twice', 'post'] as const) {
          const retrieved = await fixture.validateRequests(flow, query, { requestUri });
          expect(retrieved.failures, `${query} ${requestUri}`).toEqual([]);
          expect(retrieved.checks.find((c) => c.check === (requestUri === 'twice' ? 'request-uri-refetch' : 'wallet-nonce'))?.status).toBe('pass');
        }
      }
    }
  });

  it.each(
    FAULT_IDS.filter((fault) => faultInfo(fault).point === 'request').flatMap((fault) =>
      (faultInfo(fault).flow ? [faultInfo(fault).flow] : ['redirect', 'dc-api']).map((flow) => [fault, flow] as const),
    ),
  )('%s fails exactly its target check via %s', async (fault, flow) => {
    const query = fault === 'request.trusted-authorities-other' ? 'default_query_pid_trusted_authorities' : 'default_query_pid';
    const result = await fixture.validateRequests(flow as 'redirect' | 'dc-api', query, { fault });
    expect(result.failures).toEqual([faultInfo(fault).target]);
  });

  // The disclosure variants of the data model test cases apply to both formats.
  it.each(['presentation.family-name-withheld', 'presentation.unrequested-disclosed'] as const)('%s fails exactly its target check in mdoc format too', async (fault) => {
    const result = await fixture.validate(actionWith(fault, 'mso_mdoc'));
    const target = faultInfo(fault).target;
    expect(result.failures).toEqual(target ? [target] : []);
    if (target) expect(reasonOf(result, target)).toMatch(/family_name is not disclosed/);
  });

  it('every fault that fails key-binding or kb-freshness has its own expected reason', () => {
    const binding = FAULT_IDS.filter((fault) => ['key-binding', 'kb-freshness'].includes(faultInfo(fault).target ?? ''));
    expect(binding.filter((fault) => !BINDING_REASONS[fault])).toEqual([]);
  });

  // A signer fault that is not about the validity of the signing certificate keeps the MSO `signed` time within that
  // validity: the reference validator checks the signed date only once the path is valid, so a faulted path hides it,
  // while an RP that checks the date first rejects the credential for it and passes the test case for the wrong reason.
  const VALIDITY_FAULTS = new Set<FaultId>(['mdoc.signer-expired', 'mdoc.signer-not-yet-valid', 'mdoc.signed-after-ds-expiry']);
  it.each(FAULT_IDS.filter((fault) => faultInfo(fault).format === 'mso_mdoc' && isSignerFault(fault) && !VALIDITY_FAULTS.has(fault)))(
    '%s signs within the validity of its document signer certificate',
    async (fault) => {
      const now = new Date();
      const signer = await faultySigner(fault, fixture.pki.entities[faultInfo(fault).issuer ?? 'PP-A'], 'mso_mdoc', fixture.pki, now);
      const leaf = signer.certificate;
      for (const short of [false, true]) {
        const { signed } = mdocValidity(now, short);
        expect(leaf.notBefore.getTime()).toBeLessThanOrEqual(signed.getTime());
        expect(leaf.notAfter.getTime()).toBeGreaterThanOrEqual(signed.getTime());
      }
    },
  );

  // The ES256K faults are genuine device authentication with another algorithm: the credential is bound to the
  // secp256k1 key, and the signature verifies with it.
  const verifiesWithSecp256k1 = (jwk: JsonWebKey, data: Uint8Array | string, signature: Uint8Array) =>
    verify('sha256', typeof data === 'string' ? Buffer.from(data) : data, { key: createPublicKey({ key: jwk as never, format: 'jwk' }), dsaEncoding: 'ieee-p1363' }, signature);

  it('presentation.kb-es256k is an ES256K KB-JWT by the secp256k1 key in cnf.jwk', async () => {
    const result = await fixture.validate(actionWith('presentation.kb-es256k'));
    const parts = result.presentation.split('~');
    const cnf = base64url.decodeJson<{ cnf: { jwk: JsonWebKey } }>(parts[0].split('.')[1]).cnf.jwk;
    expect(cnf).toEqual(fixture.secp256k1.publicJwk);
    const [h, p, sig] = (parts.at(-1) ?? '').split('.');
    expect(base64url.decodeJson(h).alg).toBe('ES256K');
    expect(verifiesWithSecp256k1(cnf, `${h}.${p}`, base64url.decode(sig))).toBe(true);
  });

  it('presentation.device-signature-es256k is an ES256K device signature by the secp256k1 device key of the MSO', async () => {
    const result = await fixture.validate(actionWith('presentation.device-signature-es256k'));
    const document = (decodeCbor<CborMap>(base64url.decode(result.presentation)).get('documents') as CborMap[])[0];
    const issuerAuth = readCose((document.get('issuerSigned') as CborMap).get('issuerAuth'));
    const deviceKey = ((decodeEmbedded<CborMap>(decodeCbor(issuerAuth.payload as Uint8Array)).get('deviceKeyInfo') as CborMap).get('deviceKey')) as CborMap;
    expect(deviceKey.get(-1)).toBe(8);
    const jwk = { kty: 'EC', crv: 'secp256k1', x: base64url.encode(deviceKey.get(-2) as Uint8Array), y: base64url.encode(deviceKey.get(-3) as Uint8Array) };
    expect(jwk).toEqual(fixture.secp256k1.publicJwk);
    const deviceSigned = document.get('deviceSigned') as CborMap;
    const signature = readCose((deviceSigned.get('deviceAuth') as CborMap).get('deviceSignature'));
    const transcript = openid4vpSessionTranscript({
      handover: { flow: 'redirect', clientId: AUDIENCE, responseUri: RESPONSE_URI },
      nonce: result.transaction.nonce,
      jwkThumbprint: await jwkThumbprintOf(result.transaction.key.publicJwk as JsonWebKey),
    });
    const deviceAuthentication = encodeCbor(embedded(['DeviceAuthentication', transcript, document.get('docType'), deviceSigned.get('nameSpaces')]));
    expect(verifiesWithSecp256k1(jwk, sigStructure(signature.protectedBytes, deviceAuthentication), signature.signature)).toBe(true);
  });

  // The partial-match faults change one property of an artifact that is otherwise valid: the signature that is in
  // another form, the structure that is malformed in one place. These tests show the rest of it is not what fails.
  const sdJwtParts = async (fault: FaultId) => {
    const result = await fixture.validate(actionWith(fault));
    const parts = result.presentation.split('~');
    return { parts, issuerJwt: parts[0].split('.'), kbJwt: (parts.at(-1) ?? '').split('.') };
  };
  const mdocParts = async (fault: FaultId) => {
    const result = await fixture.validate(actionWith(fault, 'mso_mdoc'));
    const document = (decodeCbor<CborMap>(base64url.decode(result.presentation)).get('documents') as CborMap[])[0];
    const issuerSigned = document.get('issuerSigned') as CborMap;
    const issuerAuth = readCose(issuerSigned.get('issuerAuth'));
    const signerKey = new X509Certificate(Buffer.from((x5chainOf(issuerAuth.unprotectedHeader.get(COSE.x5chain)) as Uint8Array[])[0])).publicKey;
    return { result, document, issuerSigned, issuerAuth, signerKey };
  };
  const p1363 = (key: ReturnType<typeof createPublicKey>, data: Uint8Array | string, signature: Uint8Array, dsaEncoding: 'der' | 'ieee-p1363' = 'ieee-p1363') =>
    verify('sha256', typeof data === 'string' ? Buffer.from(data) : data, { key, dsaEncoding }, signature);

  it('credential.signature-der is the valid issuer signature, in DER form', async () => {
    const { issuerJwt } = await sdJwtParts('credential.signature-der');
    const signature = base64url.decode(issuerJwt[2]);
    expect(signature.length).not.toBe(64);
    const key = new X509Certificate(Buffer.from(base64url.decodeJson<{ x5c: string[] }>(issuerJwt[0]).x5c[0], 'base64')).publicKey;
    expect(p1363(key, `${issuerJwt[0]}.${issuerJwt[1]}`, signature, 'der')).toBe(true);
  });

  it('mdoc.signature-der is the valid IssuerAuth signature, in DER form', async () => {
    const { issuerAuth, signerKey } = await mdocParts('mdoc.signature-der');
    expect(issuerAuth.signature.length).not.toBe(64);
    expect(p1363(signerKey, sigStructure(issuerAuth.protectedBytes, issuerAuth.payload as Uint8Array), issuerAuth.signature, 'der')).toBe(true);
  });

  it('mdoc.issuer-auth-duplicate-label signs a protected header that repeats alg, and nothing else is wrong with the signature', async () => {
    const { issuerAuth, signerKey } = await mdocParts('mdoc.issuer-auth-duplicate-label');
    expect(Buffer.from(issuerAuth.protectedBytes).toString('hex')).toBe('a201260126');
    expect(p1363(signerKey, sigStructure(issuerAuth.protectedBytes, issuerAuth.payload as Uint8Array), issuerAuth.signature)).toBe(true);
  });

  it('mdoc.mso-not-tag24 signs the bare MSO, which is otherwise the valid MSO', async () => {
    const { issuerAuth, signerKey, issuerSigned } = await mdocParts('mdoc.mso-not-tag24');
    const payload = decodeCbor<unknown>(issuerAuth.payload as Uint8Array);
    expect(payload).toBeInstanceOf(Map);
    expect((payload as CborMap).get('docType')).toBe('eu.europa.ec.eudi.pid.1');
    expect(p1363(signerKey, sigStructure(issuerAuth.protectedBytes, issuerAuth.payload as Uint8Array), issuerAuth.signature)).toBe(true);
    expect(issuerSigned.get('nameSpaces')).toBeInstanceOf(Map);
  });

  it('mdoc.digest-reencoded-item is an item with the content the MSO digests, written in other bytes', async () => {
    const { issuerSigned, issuerAuth } = await mdocParts('mdoc.digest-reencoded-item');
    const mso = decodeEmbedded<CborMap>(decodeCbor(issuerAuth.payload as Uint8Array));
    const [namespace, items] = [...(issuerSigned.get('nameSpaces') as Map<string, Tagged[]>)][0];
    const item = items.find((i) => decodeEmbedded<CborMap>(i).get('elementIdentifier') === 'family_name') as Tagged;
    const digestId = decodeEmbedded<CborMap>(item).get('digestID');
    const digest = ((mso.get('valueDigests') as CborMap).get(namespace) as CborMap).get(digestId) as Uint8Array;
    // The MSO has a digest for this item, so the digest of the item as presented is the only thing that differs.
    expect(digest).toBeInstanceOf(Uint8Array);
    expect(Buffer.from(sha256(encodeCbor(item))).equals(Buffer.from(digest))).toBe(false);
    // The digestID is in a wider form than the shortest one: its first byte is 0x18 to 0x1b, not the value itself.
    const bytes = item.value as Uint8Array;
    const at = Buffer.from(bytes).indexOf(Buffer.from(encodeCbor('digestID')));
    expect(bytes[at + encodeCbor('digestID').length]).toBeGreaterThanOrEqual(0x18);
  });

  it('mdoc.digest-truncated is the first 20 bytes of the valid digest', async () => {
    const { issuerSigned, issuerAuth } = await mdocParts('mdoc.digest-truncated');
    const mso = decodeEmbedded<CborMap>(decodeCbor(issuerAuth.payload as Uint8Array));
    const [namespace, items] = [...(issuerSigned.get('nameSpaces') as Map<string, Tagged[]>)][0];
    const item = items.find((i) => decodeEmbedded<CborMap>(i).get('elementIdentifier') === 'family_name') as Tagged;
    const digest = ((mso.get('valueDigests') as CborMap).get(namespace) as CborMap).get(decodeEmbedded<CborMap>(item).get('digestID')) as Uint8Array;
    expect(digest).toHaveLength(20);
    expect(Buffer.from(sha256(encodeCbor(item))).subarray(0, 20).equals(Buffer.from(digest))).toBe(true);
  });

  /** The device key of the MSO and what the device signature of the presented document covers. */
  const deviceSignatureOf = async (fault: FaultId) => {
    const { result, document, issuerAuth } = await mdocParts(fault);
    const deviceKey = (decodeEmbedded<CborMap>(decodeCbor(issuerAuth.payload as Uint8Array)).get('deviceKeyInfo') as CborMap).get('deviceKey') as CborMap;
    const key = createPublicKey({
      key: { kty: 'EC', crv: 'P-256', x: base64url.encode(deviceKey.get(-2) as Uint8Array), y: base64url.encode(deviceKey.get(-3) as Uint8Array) },
      format: 'jwk',
    });
    const deviceSigned = document.get('deviceSigned') as CborMap;
    const signature = readCose((deviceSigned.get('deviceAuth') as CborMap).get('deviceSignature'));
    const transcript = openid4vpSessionTranscript({
      handover: { flow: 'redirect', clientId: AUDIENCE, responseUri: RESPONSE_URI },
      nonce: result.transaction.nonce,
      jwkThumbprint: await jwkThumbprintOf(result.transaction.key.publicJwk as JsonWebKey),
    });
    const authentication = (docType: unknown) => encodeCbor(embedded(['DeviceAuthentication', transcript, docType, deviceSigned.get('nameSpaces')]));
    return { document, key, signature, authentication };
  };

  it('presentation.device-signature-doctype-other is a valid device signature over a DeviceAuthentication of the mDL docType', async () => {
    const { document, key, signature, authentication } = await deviceSignatureOf('presentation.device-signature-doctype-other');
    expect(document.get('docType')).toBe('eu.europa.ec.eudi.pid.1');
    expect(p1363(key, sigStructure(signature.protectedBytes, authentication('org.iso.18013.5.1.mDL')), signature.signature)).toBe(true);
    expect(p1363(key, sigStructure(signature.protectedBytes, authentication(document.get('docType'))), signature.signature)).toBe(false);
  });

  it('presentation.device-signature-not-detached is a valid device signature that carries the DeviceAuthenticationBytes it covers', async () => {
    const { document, key, signature, authentication } = await deviceSignatureOf('presentation.device-signature-not-detached');
    expect(Buffer.from(signature.payload as Uint8Array).equals(Buffer.from(authentication(document.get('docType'))))).toBe(true);
    expect(p1363(key, sigStructure(signature.protectedBytes, signature.payload as Uint8Array), signature.signature)).toBe(true);
  });

  it.each(['redirect', 'dc-api'] as const)('an mdoc presentation replayed from another transaction fails exactly key-binding (%s)', async (flow) => {
    const result = await fixture.validate(actionWith('presentation.replay', 'mso_mdoc'), { other: await fixture.transaction(), flow });
    expect(result.failures).toEqual(['key-binding']);
    expect(reasonOf(result, 'key-binding')).toMatch(/SessionTranscript of this request/);
  });

  it('in first-failure mode an invalid credential stops before its status list is fetched', async () => {
    for (const fault of ['credential.exp-past', 'credential.signature-bitflip', 'mdoc.valid-until-past', 'mdoc.signature-bitflip'] as const) {
      const result = await fixture.validate(actionWith(fault), { mode: 'first-failure' });
      expect(result.credential?.failed).toBe(faultInfo(fault).target);
      expect(result.credential && 'statusListFetched' in result.credential && result.credential.statusListFetched).toBe(false);
    }
  });
});

// The vp_token faults of the combined presentations (UC_Presentation): a valid PID and a valid non-qualified EAA for
// `default_query_pid_eaa`, of which the vp_token fails exactly `vp-token`, in each format the fault applies to and in
// both flows; the presentations in it are valid, and are not validated once the vp_token as a whole failed.
describe('vp_token faults', () => {
  const combined = (fault: FaultId | undefined, format: 'dc+sd-jwt' | 'mso_mdoc') =>
    presentation({
      query: format === 'mso_mdoc' ? 'default_query_pid_eaa_mdoc' : 'default_query_pid_eaa',
      credential: pid.of(format),
      answers: 'pid',
      alongside: [{ answers: 'eaa', credential: attestation.of('eaa', format) }],
      ...(fault ? { response: { faults: [fault] } } : {}),
    });
  const cases = (['dc+sd-jwt', 'mso_mdoc'] as const).flatMap((format) =>
    (['redirect', 'dc-api'] as const).flatMap((flow) => [
      [undefined, format, flow] as const,
      ...FAULT_IDS.filter((fault) => faultInfo(fault).point === 'vp-token' && (!faultInfo(fault).format || faultInfo(fault).format === format)).map(
        (fault) => [fault, format, flow] as const,
      ),
    ]),
  );

  it.each(cases)('%s (%s via %s) fails exactly its target check', async (fault, format, flow) => {
    const result = await fixture.validate(combined(fault, format), { flow });
    expect(result.failures).toEqual(fault ? [faultInfo(fault).target] : []);
  });

  it.each(['dc+sd-jwt', 'mso_mdoc'] as const)('an EAA of another person fails exactly combined-binding (%s)', async (format) => {
    const action = presentation({
      query: format === 'mso_mdoc' ? 'default_query_pid_eaa_identifying_mdoc' : 'default_query_pid_eaa_identifying',
      credential: pid.of(format),
      answers: 'pid',
      alongside: [{ answers: 'eaa', credential: attestation.of('eaa', format, { identifying: 'other-person' }) }],
    });
    expect((await fixture.validate(action)).failures).toEqual(['combined-binding']);
  });
});
