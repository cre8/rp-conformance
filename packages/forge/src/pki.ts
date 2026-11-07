import { createAccessCertificate } from '@owf/eudi-access-certificate';
import { type Certificate, createCertificate, type KeyUsageType,
  type NameAttributeInput, parseCertificate } from '@owf/x509';
import { type EcKeyPair, generateEcKeyPair, randomSerial, sha256, signEs256 } from './crypto';

const DAY = 24 * 60 * 60 * 1000;
const YEAR = 365 * DAY;

/** A certificate with its key pair. */
export interface CertifiedKey {
  certificate: Certificate;
  key: EcKeyPair;
  /** Chain without the trust anchor, leaf first, as carried in `x5c`. */
  chain: Certificate[];
}

/** The lists of `default_trust_configuration_rp` published as LoTE (`TL-QEAA` is a Trusted List, Phase 4). */
export type LoteListId = 'TL-PID' | 'TL-PUB' | 'TL-WP' | 'TL-AC' | 'TL-RC';

export interface EntitySpec {
  id: string;
  /** The list the entity is on, if any. */
  list?: LoteListId;
  /** `PP-A` has a revocation anchor separate from its issuance anchor. */
  separateRevocationAnchor?: boolean;
  /** `PP-E`: the anchor certificate has expired. */
  expiredAnchor?: boolean;
  /** `PP-W`: all services withdrawn. */
  withdrawn?: boolean;
  /** Short host-like name used in subject alternative names and `iss`. */
  host: string;
}

/**
 * The entities of `default_trust_configuration_rp` (FCAF defaults, "Relying Party testing").
 * `QP-A`, `QP-N` and `QP-W` (on the Trusted List `TL-QEAA`) follow in Phase 4.
 */
export const ENTITIES: EntitySpec[] = [
  { id: 'PP-A', list: 'TL-PID', separateRevocationAnchor: true, host: 'pp-a.rp-test' },
  { id: 'PP-B', list: 'TL-PID', host: 'pp-b.rp-test' },
  { id: 'PP-C', host: 'pp-c.rp-test' },
  { id: 'PP-D', list: 'TL-PID', host: 'pp-d.rp-test' },
  { id: 'PP-E', list: 'TL-PID', expiredAnchor: true, host: 'pp-e.rp-test' },
  { id: 'PP-W', list: 'TL-PID', withdrawn: true, host: 'pp-w.rp-test' },
  { id: 'PB-A', list: 'TL-PUB', host: 'pb-a.rp-test' },
  { id: 'EP-A', host: 'ep-a.rp-test' },
  { id: 'WP-A', list: 'TL-WP', host: 'wp-a.rp-test' },
  { id: 'AC-A', list: 'TL-AC', host: 'ac-a.rp-test' },
  { id: 'RC-A', list: 'TL-RC', host: 'rc-a.rp-test' },
  { id: 'CA-X', host: 'ca-x.rp-test' },
];

export interface TestEntity {
  spec: EntitySpec;
  /** `iss` of credentials and status lists the entity signs. */
  issuerUri: string;
  anchors: { issuance: CertifiedKey; revocation: CertifiedKey };
  /** End-entity signing certificates under the anchors. */
  signers: { issuance: CertifiedKey; revocation: CertifiedKey };
}

export interface TestPki {
  createdAt: Date;
  entities: Record<string, TestEntity>;
  /** The scheme operator certificate of each list, which the Relying Party is configured with. */
  schemeOperators: Record<LoteListId, CertifiedKey>;
  /** The Relying Party's access certificate, issued by `AC-A`. */
  relyingPartyAccess: CertifiedKey;
}

const subjectFor = (organization: string, commonName: string): NameAttributeInput[] => [
  ['countryName', 'DE'],
  ['organizationName', organization],
  ['commonName', commonName],
];

const keyIdHasher = (data: ArrayBuffer) => sha256(new Uint8Array(data));

export async function createSelfSignedCa(
  organization: string,
  commonName: string,
  validity: { notBefore: Date; notAfter: Date },
): Promise<CertifiedKey> {
  const key = await generateEcKeyPair();
  const certificate = await createCertificate({
    subject: subjectFor(organization, commonName),
    subjectPublicKey: key.publicJwk,
    serialNumber: randomSerial(),
    notBefore: validity.notBefore,
    notAfter: validity.notAfter,
    signatureAlgorithm: 'ES256',
    basicConstraints: { cA: true, pathLenConstraint: 0 },
    hasher: keyIdHasher,
    signer: (tbs) => signEs256(key.privateKey, tbs),
  });
  return { certificate, key, chain: [] };
}

export async function createEndEntity(
  issuer: CertifiedKey,
  organization: string,
  commonName: string,
  options: {
    notBefore: Date;
    notAfter: Date;
    dnsNames?: string[];
    uris?: string[];
    keyUsage?: KeyUsageType[];
  },
): Promise<CertifiedKey> {
  const key = await generateEcKeyPair();
  const certificate = await createCertificate({
    subject: subjectFor(organization, commonName),
    subjectPublicKey: key.publicJwk,
    issuerCertificate: issuer.certificate.der,
    serialNumber: randomSerial(),
    notBefore: options.notBefore,
    notAfter: options.notAfter,
    signatureAlgorithm: 'ES256',
    keyUsage: options.keyUsage ?? ['digitalSignature'],
    subjectAlternativeNames:
      options.dnsNames || options.uris ? { dnsNames: options.dnsNames, uris: options.uris } : undefined,
    hasher: keyIdHasher,
    signer: (tbs) => signEs256(issuer.key.privateKey, tbs),
  });
  return { certificate, key, chain: [certificate, ...issuer.chain] };
}

/** A self-signed end-entity certificate, as used for the scheme operator certificates of the test lists. */
export async function createSelfSignedSigner(organization: string, commonName: string, now: Date): Promise<CertifiedKey> {
  const key = await generateEcKeyPair();
  const certificate = await createCertificate({
    subject: subjectFor(organization, commonName),
    subjectPublicKey: key.publicJwk,
    serialNumber: randomSerial(),
    notBefore: new Date(now.getTime() - DAY),
    notAfter: new Date(now.getTime() + 5 * YEAR),
    signatureAlgorithm: 'ES256',
    keyUsage: ['digitalSignature'],
    hasher: keyIdHasher,
    signer: (tbs) => signEs256(key.privateKey, tbs),
  });
  return { certificate, key, chain: [certificate] };
}

async function createEntity(spec: EntitySpec, now: Date): Promise<TestEntity> {
  const anchorValidity = spec.expiredAnchor
    ? { notBefore: new Date(now.getTime() - 2 * YEAR), notAfter: new Date(now.getTime() - DAY) }
    : { notBefore: new Date(now.getTime() - DAY), notAfter: new Date(now.getTime() + 10 * YEAR) };
  const issuanceAnchor = await createSelfSignedCa(spec.id, `CA-${spec.id}`, anchorValidity);
  const revocationAnchor = spec.separateRevocationAnchor
    ? await createSelfSignedCa(spec.id, `CA-${spec.id}-REV`, anchorValidity)
    : issuanceAnchor;
  const issuerUri = `https://${spec.host}`;
  const leafValidity = {
    notBefore: new Date(Math.min(now.getTime() - DAY, anchorValidity.notAfter.getTime() - YEAR)),
    notAfter: new Date(now.getTime() + 2 * YEAR),
    dnsNames: [spec.host],
    uris: [issuerUri],
  };
  const issuanceSigner = await createEndEntity(issuanceAnchor, spec.id, `${spec.id} issuance signer`, leafValidity);
  const revocationSigner = await createEndEntity(revocationAnchor, spec.id, `${spec.id} status list signer`, leafValidity);
  return {
    spec,
    issuerUri,
    anchors: { issuance: issuanceAnchor, revocation: revocationAnchor },
    signers: { issuance: issuanceSigner, revocation: revocationSigner },
  };
}

/**
 * Creates the test PKI of `default_trust_configuration_rp`: per entity its anchors and signing certificates,
 * the scheme operator certificates of the lists, and the Relying Party's access certificate under `AC-A`.
 * Material is generated per run.
 */
export async function createTestPki(options: { now?: Date; relyingPartyHost?: string } = {}): Promise<TestPki> {
  const now = options.now ?? new Date();
  const entities: Record<string, TestEntity> = {};
  for (const spec of ENTITIES) {
    entities[spec.id] = await createEntity(spec, now);
  }
  const schemeOperators = {} as Record<LoteListId, CertifiedKey>;
  for (const list of ['TL-PID', 'TL-PUB', 'TL-WP', 'TL-AC', 'TL-RC'] as LoteListId[]) {
    schemeOperators[list] = await createSelfSignedSigner('RP conformance test scheme operator', `${list} scheme operator`, now);
  }
  const relyingPartyAccess = await createRelyingPartyAccessCertificate(entities['AC-A'], now, options.relyingPartyHost ?? 'rp.rp-test');
  return { createdAt: now, entities, schemeOperators, relyingPartyAccess };
}

/** The Relying Party's access certificate per ETSI TS 119 411-8, issued under the anchor of `AC-A`. */
async function createRelyingPartyAccessCertificate(acA: TestEntity, now: Date, host: string): Promise<CertifiedKey> {
  const key = await generateEcKeyPair();
  const accessCertificate = await createAccessCertificate({
    policy: 'NCP-l-eudiwrp',
    cpsUri: `https://${acA.spec.host}/cps`,
    subject: {
      commonName: 'RP conformance test Relying Party',
      organizationName: 'RP conformance test Relying Party',
      organizationIdentifier: 'VATDE-123456789',
      countryName: 'DE',
    },
    contact: { uris: [`https://${host}`], emails: [`support@${host}`] },
    dnsNames: [host],
    subjectPublicKey: key.publicJwk,
    issuerCertificate: acA.anchors.issuance.certificate.der,
    serialNumber: randomSerial(),
    notBefore: new Date(now.getTime() - DAY),
    notAfter: new Date(now.getTime() + YEAR),
    signatureAlgorithm: 'ES256',
    signer: (tbs: Uint8Array) => signEs256(acA.anchors.issuance.key.privateKey, tbs),
  });
  const certificate = accessCertificate.certificate;
  return { certificate, key, chain: [certificate] };
}

/** TLS material for the harness services: a harness CA and a server certificate for the given host names. */
export async function createTlsMaterial(hosts: string[], now = new Date()) {
  const ca = await createSelfSignedCa('RP conformance harness', 'RP conformance harness TLS CA', {
    notBefore: new Date(now.getTime() - DAY),
    notAfter: new Date(now.getTime() + 5 * YEAR),
  });
  const server = await createEndEntity(ca, 'RP conformance harness', hosts[0], {
    notBefore: new Date(now.getTime() - DAY),
    notAfter: new Date(now.getTime() + 2 * YEAR),
    dnsNames: hosts,
  });
  return { ca, server };
}

export { parseCertificate };
