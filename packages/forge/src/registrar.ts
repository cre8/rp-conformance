// The Test Registrar (issuer harness design section 5.3, issuer test catalogue section 3.3): enrols the Provider under
// test in the test PKI before the first test case. From the SUT's CSRs, or from keys it generates itself where the SUT
// can only import keys, it issues the credential signing certificate(s) under the issuance anchor of the SUT's entity
// (`PP-T`, `QP-T`, `PB-T`, `EP-T`), the status list signing certificate under its revocation anchor, the access
// certificate from `AC-A` and the registration certificate from `RC-A`.
import { createAccessCertificate } from '@owf/eudi-access-certificate';
import { signWRPRC, WRP_ENTITLEMENTS, wrprc } from '@owf/eudi-registration-certificate';
import { type Certificate, createCertificate, type NameAttributeInput } from '@owf/x509';
import type { EnrolledCertificate, EnrolmentRequest } from '@eudi-pcaf/core';
import { base64url, type EcKeyPair, generateEcKeyPair, randomSerial, sha256, signEs256 } from './crypto';
import { verifyCsr } from './csr';
import { annexBExtensions, type CertifiedKey, documentSignerValidity, type TestEntity, type TestPki } from './pki';

const DAY = 24 * 60 * 60 * 1000;
const YEAR = 365 * DAY;

/** The entity of the Provider under test, per category (`SUT_ENTITIES`). */
export type SutEntityId = 'PP-T' | 'QP-T' | 'PB-T' | 'EP-T';

/**
 * The profile of a credential signing certificate: `sd-jwt-vc` the ETSI TS 119 412-6 signer profile of the issuing
 * entities of the test PKI (`signers.issuance`), `mdoc` the document signer profile of ISO/IEC 18013-5 Annex B
 * (Table B.3, `signers.mdoc`).
 */
export type CredentialSignerProfile = 'sd-jwt-vc' | 'mdoc';

/** The ETSI TS 119 475 entitlement of each SUT entity's category, the default of `RegistrationRequest.entitlement`. */
export const SUT_ENTITLEMENTS: Record<SutEntityId, string> = {
  'PP-T': WRP_ENTITLEMENTS.PID_PROVIDER,
  'QP-T': WRP_ENTITLEMENTS.QEAA_PROVIDER,
  'PB-T': WRP_ENTITLEMENTS.PUB_EAA_PROVIDER,
  'EP-T': WRP_ENTITLEMENTS.NON_Q_EAA_PROVIDER,
};

/** A certificate the Registrar issued, with its chain; with the key only when the Registrar generated it. */
export interface EnrolledKey {
  certificate: Certificate;
  /** Chain without the trust anchor, leaf first, as carried in `x5c`. */
  chain: Certificate[];
  publicJwk: JsonWebKey;
  /** The key pair, only when the Registrar generated it (`method` `generated`). */
  key?: EcKeyPair;
}

/** What the access certificate from `AC-A` names (`default_configuration_PP_1`). */
export interface AccessRequest {
  /** Semantic identifier of the Provider (ETSI EN 319 412-1), `organizationIdentifier`, e.g. `VATDE-987654321`. */
  entityIdentifier: string;
  /** The registered service, e.g. `S1`; carried as `organizationalUnitName` (ETSI TS 119 411-8 GEN-6.6.1-08). */
  serviceIdentifier: string;
  /** The trade name the user recognises, `commonName` and `organizationName`. */
  tradeName: string;
  /** Host of the Provider's service, in the subject alternative names and contact; default the entity's host. */
  host?: string;
}

/** What the registration certificate from `RC-A` grants (ETSI TS 119 475). */
export interface RegistrationRequest {
  /** Default: the entitlement of the entity's category (`SUT_ENTITLEMENTS`). */
  entitlement?: string;
  /** Every credential type the SUT offers (`provides_attestations`). */
  providesAttestations: { format: string; meta: Record<string, unknown> }[];
}

export interface RegistrarRequest {
  /** The SUT's entity; default `PP-T`. */
  entity?: SutEntityId;
  /**
   * The CSRs of the adapter's `enrol()`. Left out when the SUT can only import keys: the Registrar then generates the
   * key pairs and returns them with the certificates (`method` `generated`).
   */
  csrs?: EnrolmentRequest;
  /**
   * The profile of each credential signing certificate, in the order of `csrs.credentialSigning`. `EnrolmentRequest`
   * does not say which key signs which format, so the caller does. Default with CSRs: `sd-jwt-vc` for every key;
   * without: `['sd-jwt-vc', 'mdoc']`, one generated key per profile.
   */
  credentialSigningProfiles?: CredentialSignerProfile[];
  /**
   * The SUT signs its status lists with its issuance key (catalogue section 3.3, RP catalogue decision 3): no status
   * list signer is issued and the entity's list carries its issuance anchor under both services. Default with CSRs:
   * true when `csrs.statusListSigning` is left out; without CSRs: false.
   */
  statusListWithIssuanceKey?: boolean;
  access: AccessRequest;
  registration: RegistrationRequest;
  now?: Date;
}

export interface Enrolment {
  entity: SutEntityId;
  /** Which way the SUT was enrolled, for the report: from its CSRs, or with keys the Registrar generated. */
  method: 'csr' | 'generated';
  credentialSigners: (EnrolledKey & { profile: CredentialSignerProfile })[];
  /** Under the revocation anchor; left out when the SUT signs status lists with its issuance key. */
  statusListSigner?: EnrolledKey;
  statusListWithIssuanceKey: boolean;
  /** Access certificate from `AC-A` (ETSI TS 119 411-8). */
  access: EnrolledKey;
  /** Registration certificate from `RC-A` (JWT, ETSI TS 119 475), bound to `access.entityIdentifier`. */
  registrationCertificate: string;
}

const subjectFor = (organization: string, commonName: string): NameAttributeInput[] => [
  ['countryName', 'DE'],
  ['organizationName', organization],
  ['commonName', commonName],
];

const keyIdHasher = (data: ArrayBuffer) => sha256(new Uint8Array(data));

/** A key to certify: the public key of a verified CSR, or a key pair the Registrar generated. */
interface Subject {
  publicJwk: JsonWebKey;
  key?: EcKeyPair;
}

async function issueLeaf(
  issuer: CertifiedKey,
  entity: TestEntity,
  subject: Subject,
  commonName: string,
  profile: CredentialSignerProfile | 'status-list',
  now: Date,
): Promise<EnrolledKey> {
  const id = entity.spec.id;
  // As createEntity issues the signers of every other entity: an mdoc document signer per ISO/IEC 18013-5 Annex B,
  // or an end-entity signer with `digitalSignature` and the entity's host and URI in the subject alternative names.
  const mdoc = profile === 'mdoc';
  const validity = mdoc
    ? documentSignerValidity(now, issuer.certificate.notAfter)
    : { notBefore: new Date(now.getTime() - DAY), notAfter: new Date(now.getTime() + 2 * YEAR) };
  const certificate = await createCertificate({
    subject: subjectFor(id, commonName),
    subjectPublicKey: subject.publicJwk,
    issuerCertificate: issuer.certificate.der,
    serialNumber: randomSerial(),
    ...validity,
    signatureAlgorithm: 'ES256',
    keyUsage: ['digitalSignature'],
    ...(mdoc
      ? { crlDistributionPoints: [`${entity.issuerUri}/crl`], extensions: annexBExtensions(entity.issuerUri, true) }
      : { subjectAlternativeNames: { dnsNames: [entity.spec.host], uris: [entity.issuerUri] } }),
    hasher: keyIdHasher,
    signer: (tbs) => signEs256(issuer.key.privateKey, tbs),
  });
  return { certificate, chain: [certificate, ...issuer.chain], publicJwk: subject.publicJwk, ...(subject.key ? { key: subject.key } : {}) };
}

async function issueAccessCertificate(pki: TestPki, entity: TestEntity, subject: Subject, request: AccessRequest, now: Date): Promise<EnrolledKey> {
  const acA = pki.entities['AC-A'];
  const host = request.host ?? entity.spec.host;
  const { certificate } = await createAccessCertificate({
    policy: 'NCP-l-eudiwrp',
    cpsUri: `https://${acA.spec.host}/cps`,
    subject: {
      commonName: request.tradeName,
      organizationName: request.tradeName,
      organizationIdentifier: request.entityIdentifier,
      countryName: 'DE',
      organizationalUnitNames: [request.serviceIdentifier],
    },
    contact: { uris: [`https://${host}`], emails: [`support@${host}`] },
    dnsNames: [host],
    subjectPublicKey: subject.publicJwk,
    issuerCertificate: acA.anchors.issuance.certificate.der,
    serialNumber: randomSerial(),
    notBefore: new Date(now.getTime() - DAY),
    notAfter: new Date(now.getTime() + YEAR),
    signatureAlgorithm: 'ES256',
    hasher: keyIdHasher,
    signer: (tbs: Uint8Array) => signEs256(acA.anchors.issuance.key.privateKey, tbs),
  });
  return { certificate, chain: [certificate], publicJwk: subject.publicJwk, ...(subject.key ? { key: subject.key } : {}) };
}

async function issueRegistration(pki: TestPki, id: SutEntityId, request: RegistrarRequest, now: Date): Promise<string> {
  const { access, registration } = request;
  const host = access.host ?? pki.entities[id].spec.host;
  const builder = wrprc()
    .name(access.tradeName)
    .legalName(access.tradeName)
    .identifier(access.entityIdentifier)
    .country('DE')
    .registryUri('https://registry.rp-test/api')
    .serviceDescription(`Service ${access.serviceIdentifier} of the Provider under conformance test`, 'en')
    .addEntitlement(registration.entitlement ?? SUT_ENTITLEMENTS[id])
    .privacyPolicy(`https://${host}/privacy`)
    .supportUri(`https://${host}/support`)
    .issuedAt(now);
  for (const attestation of registration.providesAttestations) builder.addProvidedAttestation(attestation);
  const signer = pki.entities['RC-A'].signers.issuance;
  const signed = await signWRPRC({
    payload: builder.build(),
    accessCertificateSub: access.entityIdentifier,
    certificates: signer.chain.map((certificate) => certificate.pem),
    signingTime: now,
    signer: async (data: string) => base64url.encode(await signEs256(signer.key.privateKey, data)),
  });
  return signed.jws;
}

const fromCsr = (csr: string): Subject => ({ publicJwk: verifyCsr(csr).publicJwk });
const generated = async (): Promise<Subject> => {
  const key = await generateEcKeyPair();
  return { publicJwk: key.publicJwk, key };
};

/**
 * Enrols the Provider under test (issuer harness design section 5.3), once per run before the first test case. Every
 * CSR is verified (proof of possession) before anything is issued; a CSR that does not verify throws a `CsrError`.
 *
 * When the SUT signs its status lists with its issuance key, the entity in `pki` is replaced by one whose revocation
 * anchor is its issuance anchor, so the lists built from `pki` afterwards carry the issuance anchor under both services.
 */
export async function enrolSut(pki: TestPki, request: RegistrarRequest): Promise<Enrolment> {
  const id = request.entity ?? 'PP-T';
  const entity = pki.entities[id];
  if (!entity) throw new Error(`the test PKI has no entity ${id}`);
  const now = request.now ?? new Date();
  const csrs = request.csrs;
  const method = csrs ? 'csr' : 'generated';
  const profiles = request.credentialSigningProfiles ?? (csrs ? csrs.credentialSigning.map(() => 'sd-jwt-vc' as const) : (['sd-jwt-vc', 'mdoc'] as const));
  if (csrs && profiles.length !== csrs.credentialSigning.length) {
    throw new Error(`${csrs.credentialSigning.length} credential signing CSRs but ${profiles.length} profiles`);
  }
  if (profiles.length === 0) throw new Error('no credential signing key to enrol');
  const withIssuanceKey = request.statusListWithIssuanceKey ?? (csrs ? !csrs.statusListSigning : false);
  if (csrs && withIssuanceKey && csrs.statusListSigning) throw new Error('a status list CSR, but the SUT declares it signs status lists with its issuance key');
  if (csrs && !withIssuanceKey && !csrs.statusListSigning) throw new Error('no status list CSR');

  // Proof of possession first: nothing is issued for a request with one bad CSR.
  const credentialSubjects = csrs ? csrs.credentialSigning.map(fromCsr) : await Promise.all(profiles.map(generated));
  const statusSubject = withIssuanceKey ? undefined : csrs ? fromCsr(csrs.statusListSigning as string) : await generated();
  const accessSubject = csrs ? fromCsr(csrs.access) : await generated();

  const credentialSigners = [];
  for (const [index, subject] of credentialSubjects.entries()) {
    const profile = profiles[index];
    const name = `${id} ${profile === 'mdoc' ? 'document signer' : 'issuance signer'}${credentialSubjects.length > 1 ? ` ${index + 1}` : ''}`;
    credentialSigners.push({ ...(await issueLeaf(entity.anchors.issuance, entity, subject, name, profile, now)), profile });
  }
  const statusListSigner = statusSubject
    ? await issueLeaf(entity.anchors.revocation, entity, statusSubject, `${id} status list signer`, 'status-list', now)
    : undefined;
  if (withIssuanceKey) pki.entities[id] = { ...entity, anchors: { ...entity.anchors, revocation: entity.anchors.issuance } };
  return {
    entity: id,
    method,
    credentialSigners,
    ...(statusListSigner ? { statusListSigner } : {}),
    statusListWithIssuanceKey: withIssuanceKey,
    access: await issueAccessCertificate(pki, entity, accessSubject, request.access, now),
    registrationCertificate: await issueRegistration(pki, id, request, now),
  };
}

/** An enrolled certificate as `IssuerTestEnvironment` hands it to the SUT; with its private key only when generated. */
export function toEnrolledCertificate(enrolled: EnrolledKey): EnrolledCertificate {
  return {
    certificatePem: enrolled.certificate.pem,
    certificate: Buffer.from(enrolled.certificate.der).toString('base64'),
    chainPem: enrolled.chain.map((certificate) => certificate.pem),
    ...(enrolled.key ? { privateJwk: enrolled.key.privateJwk, privateKeyPem: enrolled.key.privateKeyPem } : {}),
  };
}
