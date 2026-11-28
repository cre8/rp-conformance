// The Test Registrar (issuer harness design section 5.3): the certificates it issues for the SUT's keys, from CSRs or
// generated, are accepted by the reference validator with the same TRUST_RULES as any other entity. `PP-T` is on
// `TL-PID` of the self-validation fixture; credentials and Status List Tokens are built by the forge and signed with
// the enrolled keys, as the SUT would sign them.
import { randomUUID } from 'node:crypto';
import { parseAccessCertificate, validateAccessCertificate } from '@owf/eudi-access-certificate';
import { parseWRPRC, validateWRPRCPayload, WRP_ENTITLEMENTS } from '@owf/eudi-registration-certificate';
import type { Certificate } from '@owf/x509';
import {
  buildPresentation,
  buildStatusListTokenCwt,
  buildStatusListTokenJwt,
  type CertifiedKey,
  createCsr,
  CsrError,
  type EcKeyPair,
  type EnrolledKey,
  type Enrolment,
  enrolSut,
  generateEcKeyPair,
  issuePidMdoc,
  issuePidSdJwtVc,
  jwkThumbprint,
  MDOC_DS_EXTENDED_KEY_USAGE,
  PID_DOCTYPE,
  PID_VCT,
  type RegistrarRequest,
  STATUS_LIST_CWT_TYPE,
  toEnrolledCertificate,
  verifyCsr,
} from '@eudi-pcaf/forge';
import { beforeAll, describe, expect, it } from 'vitest';
import { type FetchedStatusList, TRUST_RULES, validateMdocPresentation, validatePath, validateSdJwtVcPresentation } from '../src/index';
import { AUDIENCE, Fixture, KB_MAX_AGE, MAX_STATUS_LIST_BYTES, RESPONSE_URI, SKEW } from './fixture';

const ENTITY_IDENTIFIER = 'VATDE-987654321';
const REQUEST: Omit<RegistrarRequest, 'csrs'> = {
  access: { entityIdentifier: ENTITY_IDENTIFIER, serviceIdentifier: 'S1', tradeName: 'PID Provider under test' },
  registration: {
    providesAttestations: [
      { format: 'dc+sd-jwt', meta: { vct_values: [PID_VCT] } },
      { format: 'mso_mdoc', meta: { doctype_value: PID_DOCTYPE } },
    ],
  },
};

const x5c = (chain: Certificate[]) => chain.map((certificate) => Buffer.from(certificate.der).toString('base64'));
/** What the SUT signs with: the enrolled certificate and the SUT's own key. */
const signerOf = (enrolled: EnrolledKey, key: EcKeyPair): CertifiedKey => ({ certificate: enrolled.certificate, chain: enrolled.chain, key });

/** Issues a PID in `format` signed by `signer`, its Status List Token signed by `statusSigner`, and validates a presentation of it. */
async function validatePid(fixture: Fixture, format: 'dc+sd-jwt' | 'mso_mdoc', signer: CertifiedKey, statusSigner: CertifiedKey) {
  const issuer = fixture.pki.entities['PP-T'].issuerUri;
  const uri = `https://status.rp-test/registrar/${randomUUID()}`;
  const served = new Map<string, FetchedStatusList>();
  const statusOptions = { signer: statusSigner, issuer, uri, statuses: [0, 0, 0, 0] };
  const nonce = randomUUID();
  const handover = { flow: 'redirect', clientId: AUDIENCE, responseUri: RESPONSE_URI } as const;
  const encryptionKey = await generateEcKeyPair();
  const thumbprint = await jwkThumbprint(encryptionKey.publicJwk);
  const fetchStatusList = async (url: string): Promise<FetchedStatusList> => served.get(url) ?? { status: 404, body: '' };
  const common = {
    trust: fixture.trust,
    trustRule: TRUST_RULES.pid,
    nonce,
    skewSeconds: SKEW,
    requireStatus: true,
    maxStatusListBytes: MAX_STATUS_LIST_BYTES,
    mode: 'all' as const,
    fetchStatusList,
  };
  const binding = { audience: AUDIENCE, clientId: AUDIENCE, nonce, handover, jwkThumbprint: thumbprint };
  const keys = { holder: fixture.holder };
  const presentationOptions = { skewSeconds: SKEW, kbMaxAgeSeconds: KB_MAX_AGE };
  if (format === 'mso_mdoc') {
    served.set(uri, { status: 200, body: await buildStatusListTokenCwt(statusOptions), contentType: STATUS_LIST_CWT_TYPE });
    const mdoc = await issuePidMdoc({ signer, holderPublicJwk: fixture.holder.publicJwk, status: { statusList: { uri, idx: 1 } } });
    const elements = { [PID_DOCTYPE]: ['family_name', 'given_name'] };
    const presentation = await buildPresentation({ format, value: mdoc.issuerSigned } as never, { disclose: [], elements }, binding, keys, presentationOptions);
    return validateMdocPresentation(presentation, { ...common, expectedDocType: PID_DOCTYPE, handover, jwkThumbprint: thumbprint, fetchIdentifierList: fetchStatusList });
  }
  served.set(uri, { status: 200, body: await buildStatusListTokenJwt(statusOptions), contentType: 'application/statuslist+jwt' });
  const pid = await issuePidSdJwtVc({ signer, issuer, holderPublicJwk: fixture.holder.publicJwk, status: { uri, idx: 1 } });
  const presentation = await buildPresentation({ format, value: pid.compact } as never, { disclose: ['family_name'], elements: {} }, binding, keys, presentationOptions);
  return validateSdJwtVcPresentation(presentation, { ...common, expectedVct: [PID_VCT], audience: AUDIENCE, kbMaxAgeSeconds: KB_MAX_AGE });
}

describe('Test Registrar: enrolment from CSRs', () => {
  let fixture: Fixture;
  const keys = {} as Record<'sdJwt' | 'mdoc' | 'status' | 'access', EcKeyPair>;
  let enrolment: Enrolment;

  beforeAll(async () => {
    fixture = await Fixture.create();
    for (const name of ['sdJwt', 'mdoc', 'status', 'access'] as const) keys[name] = await generateEcKeyPair();
    enrolment = await enrolSut(fixture.pki, {
      ...REQUEST,
      csrs: {
        credentialSigning: [await createCsr(keys.sdJwt, 'SUT SD-JWT VC signer', 'SUT'), await createCsr(keys.mdoc, 'SUT mdoc signer', 'SUT')],
        statusListSigning: await createCsr(keys.status, 'SUT status list signer', 'SUT'),
        access: await createCsr(keys.access, 'SUT access', 'SUT'),
      },
      credentialSigningProfiles: ['sd-jwt-vc', 'mdoc'],
    });
  });

  it('publishes PP-T in TL-PID with its issuance and revocation anchors', () => {
    const entity = fixture.trust.lists.get('TL-PID')?.entities.find((e) => e.name === 'PP-T');
    const anchors = fixture.pki.entities['PP-T'].anchors;
    expect(anchors.issuance).not.toBe(anchors.revocation);
    expect(entity?.services.map((s) => s.anchors[0].pem)).toEqual([anchors.issuance.certificate.pem, anchors.revocation.certificate.pem]);
  });

  it('turns each CSR into a certificate chain for the CSR key under the right anchor of PP-T, and returns no key', async () => {
    expect(enrolment).toMatchObject({ entity: 'PP-T', method: 'csr', statusListWithIssuanceKey: false });
    const { anchors } = fixture.pki.entities['PP-T'];
    const [sdJwt, mdoc] = enrolment.credentialSigners;
    const status = enrolment.statusListSigner as EnrolledKey;
    for (const [enrolled, key] of [[sdJwt, keys.sdJwt], [mdoc, keys.mdoc], [status, keys.status], [enrolment.access, keys.access]] as const) {
      expect(enrolled.key).toBeUndefined();
      expect(enrolled.certificate.publicKey.jwk).toMatchObject({ x: key.publicJwk.x, y: key.publicJwk.y });
      expect(toEnrolledCertificate(enrolled).privateKeyPem).toBeUndefined();
    }
    expect((await validatePath(x5c(sdJwt.chain), [anchors.issuance.certificate])).ok).toBe(true);
    expect((await validatePath(x5c(mdoc.chain), [anchors.issuance.certificate])).ok).toBe(true);
    expect((await validatePath(x5c(status.chain), [anchors.revocation.certificate])).ok).toBe(true);
    expect((await validatePath(x5c(status.chain), [anchors.issuance.certificate])).ok).toBe(false);
    expect(sdJwt.certificate.extendedKeyUsage ?? []).not.toContain(MDOC_DS_EXTENDED_KEY_USAGE);
    expect(mdoc.certificate.extendedKeyUsage).toEqual([MDOC_DS_EXTENDED_KEY_USAGE]);
  });

  it('accepts a PID in SD-JWT VC format signed with the enrolled key, and its Status List Token, under TL-PID', async () => {
    const result = await validatePid(fixture, 'dc+sd-jwt', signerOf(enrolment.credentialSigners[0], keys.sdJwt), signerOf(enrolment.statusListSigner as EnrolledKey, keys.status));
    expect(result.failures).toEqual([]);
    expect(result).toMatchObject({ issuer: 'PP-T', statusListFetched: true });
  });

  it('accepts a PID in mdoc format signed with the enrolled document signer, and its Status List Token, under TL-PID', async () => {
    const result = await validatePid(fixture, 'mso_mdoc', signerOf(enrolment.credentialSigners[1], keys.mdoc), signerOf(enrolment.statusListSigner as EnrolledKey, keys.status));
    expect(result.failures).toEqual([]);
    expect(result).toMatchObject({ issuer: 'PP-T', statusListFetched: true });
  });

  it('refuses a Status List Token signed with the credential signing key, which is not under the revocation anchor', async () => {
    const credential = signerOf(enrolment.credentialSigners[0], keys.sdJwt);
    const result = await validatePid(fixture, 'dc+sd-jwt', credential, credential);
    expect(result.failures).toEqual(['status-list-trust']);
  });

  it('issues the access certificate from AC-A, which validates under TL-AC and names the entity, service and trade name', async () => {
    const acAnchors = fixture.trust.lists.get('TL-AC')?.entities.flatMap((e) => e.services.flatMap((s) => s.anchors)) ?? [];
    expect((await validatePath(x5c(enrolment.access.chain), acAnchors)).ok).toBe(true);
    const parsed = parseAccessCertificate(enrolment.access.certificate.der);
    expect(validateAccessCertificate(parsed).issues.filter((i: { severity: string }) => i.severity === 'error')).toEqual([]);
    expect(parsed.subjectIdentifier?.value).toBe(ENTITY_IDENTIFIER);
    expect(enrolment.access.certificate.subject.rfc4514).toContain('CN=PID Provider under test');
    expect(enrolment.access.certificate.subject.rfc4514).toContain('OU=S1');
  });

  it('issues the registration certificate from RC-A with the entitlement and provides_attestations, bound to the access certificate', async () => {
    const { header, payload } = parseWRPRC(enrolment.registrationCertificate) as { header: { x5c?: string[] }; payload: Record<string, unknown> };
    const rcAnchors = fixture.trust.lists.get('TL-RC')?.entities.flatMap((e) => e.services.flatMap((s) => s.anchors)) ?? [];
    expect((await validatePath(header.x5c ?? [], rcAnchors)).ok).toBe(true);
    expect(validateWRPRCPayload(payload, ENTITY_IDENTIFIER).issues.filter((i: { severity: string }) => i.severity === 'error')).toEqual([]);
    expect(JSON.stringify(payload)).toContain(WRP_ENTITLEMENTS.PID_PROVIDER);
    expect(payload.provides_attestations).toEqual(REQUEST.registration.providesAttestations);
  });

  it('refuses a CSR whose signature does not verify, and issues nothing for the enrolment', async () => {
    const key = await generateEcKeyPair();
    const pem = await createCsr(key, 'SUT tampered signer', 'SUT');
    const der = Buffer.from(pem.replace(/-----[A-Z ]+-----|\s/g, ''), 'base64');
    const at = der.indexOf('tampered');
    der[at] ^= 0x01;
    expect(verifyCsr(await createCsr(key, 'SUT signer', 'SUT')).publicJwk).toMatchObject({ x: key.publicJwk.x });
    expect(() => verifyCsr(new Uint8Array(der))).toThrow(CsrError);
    const other = await generateEcKeyPair();
    await expect(
      enrolSut(fixture.pki, { ...REQUEST, csrs: { credentialSigning: [new Uint8Array(der) as never], statusListSigning: await createCsr(other, 'status'), access: await createCsr(other, 'access') } }),
    ).rejects.toThrow(/proof of possession/);
    await expect(enrolSut(fixture.pki, { ...REQUEST, csrs: { credentialSigning: ['not a CSR'], access: await createCsr(other, 'access') } })).rejects.toThrow(CsrError);
  });
});

describe('Test Registrar: key generation fallback', () => {
  it('generates the keys, returns them with the certificates, and records the way it was used', async () => {
    const fixture = await Fixture.create();
    const enrolment = await enrolSut(fixture.pki, REQUEST);
    expect(enrolment).toMatchObject({ entity: 'PP-T', method: 'generated', statusListWithIssuanceKey: false });
    expect(enrolment.credentialSigners.map((s) => s.profile)).toEqual(['sd-jwt-vc', 'mdoc']);
    const [sdJwt, mdoc] = enrolment.credentialSigners;
    const status = enrolment.statusListSigner as EnrolledKey;
    for (const enrolled of [sdJwt, mdoc, status, enrolment.access]) {
      expect(enrolled.key).toBeDefined();
      expect(toEnrolledCertificate(enrolled)).toMatchObject({ privateKeyPem: enrolled.key?.privateKeyPem, privateJwk: enrolled.key?.privateJwk });
    }
    const asSigner = (enrolled: EnrolledKey) => signerOf(enrolled, enrolled.key as EcKeyPair);
    expect((await validatePid(fixture, 'dc+sd-jwt', asSigner(sdJwt), asSigner(status))).failures).toEqual([]);
    expect((await validatePid(fixture, 'mso_mdoc', asSigner(mdoc), asSigner(status))).failures).toEqual([]);
  });
});

describe('Test Registrar: status lists signed with the issuance key', () => {
  it('issues no status list signer and lists the issuance anchor of PP-T under both services', async () => {
    const fixture = await Fixture.create();
    const key = await generateEcKeyPair();
    const enrolment = await enrolSut(fixture.pki, {
      ...REQUEST,
      csrs: { credentialSigning: [await createCsr(key, 'SUT signer', 'SUT')], access: await createCsr(await generateEcKeyPair(), 'SUT access', 'SUT') },
    });
    expect(enrolment).toMatchObject({ method: 'csr', statusListWithIssuanceKey: true });
    expect(enrolment.statusListSigner).toBeUndefined();
    const { anchors } = fixture.pki.entities['PP-T'];
    expect(anchors.revocation).toBe(anchors.issuance);
    await fixture.publish('TL-PID');
    const services = fixture.trust.lists.get('TL-PID')?.entities.find((e) => e.name === 'PP-T')?.services ?? [];
    expect(services.map((s) => s.anchors[0].pem)).toEqual([anchors.issuance.certificate.pem, anchors.issuance.certificate.pem]);
    const signer = signerOf(enrolment.credentialSigners[0], key);
    const result = await validatePid(fixture, 'dc+sd-jwt', signer, signer);
    expect(result.failures).toEqual([]);
  });
});
