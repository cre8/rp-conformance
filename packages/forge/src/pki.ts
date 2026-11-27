import { createAccessCertificate } from '@owf/eudi-access-certificate';
import { type Certificate, createCertificate, type KeyUsageType,
  type NameAttributeInput, parseCertificate, type X509Extension } from '@owf/x509';
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

/** The lists of `default_trust_configuration_rp` published as LoTE (`TL-QEAA` is a Trusted List, see `TrustedListId`). */
export type LoteListId = 'TL-PID' | 'TL-PUB' | 'TL-WP' | 'TL-AC' | 'TL-RC';

export interface EntitySpec {
  id: string;
  /** The list the entity is on, if any. */
  list?: LoteListId;
  /** `PP-A` has a revocation anchor separate from its issuance anchor. */
  separateRevocationAnchor?: boolean;
  /** `PP-E`: the anchor certificate has expired. */
  expiredAnchor?: boolean;
  /**
   * `PP-W`: its PID/Issuance service is withdrawn. ETSI TS 119 602 Annex D gives PID Providers lists no service status,
   * so the list carries only its PID/Revocation service (TrustMechanisms_006).
   */
  issuanceWithdrawn?: boolean;
  /** A list that is not a LoTE: the QTSPs `QP-A`, `QP-N` and `QP-W` are on the Trusted List `TL-QEAA` (ETSI TS 119 612). */
  trustedList?: 'TL-QEAA';
  /**
   * The service for the issuance of attestations the entity has in `TL-QEAA`: a granted qualified service (`QP-A`), a
   * service that is not qualified (`QP-N`), or a qualified service that is withdrawn (`QP-W`).
   */
  qeaaService?: 'granted' | 'not-qualified' | 'withdrawn';
  /**
   * `PP-I`: its signers are issued by an intermediate CA `CA-PP-I-INT` under its anchor, which allows one intermediate
   * (the certificate path test cases of IssuerIntegrity).
   */
  intermediate?: boolean;
  /** `EP-A`: on no list; the rulebook of the credential defines its anchor `CA-EP-A`. */
  rulebook?: 'default_credential_eaa';
  /**
   * A Wallet Provider of `TL-WP` (issuer catalogue section 3.2). `name` is the Wallet Solution's `wallet_name` and the
   * ServiceName of the WalletSolution/Issuance service whose anchor signs WIAs (TS3 section 3.2.1). With
   * `keyAttestationService`, a separate CA signs KAs, listed as a second WalletSolution/Issuance service of that
   * ServiceName (the WSCD type, TS3 section 3.2); without it, the issuance anchor signs both.
   */
  walletSolution?: { name: string; keyAttestationService?: string };
  /** Short host-like name used in subject alternative names and `iss`. */
  host: string;
}

/** The entities of `default_trust_configuration_rp` (FCAF defaults, "Relying Party testing"). */
export const ENTITIES: EntitySpec[] = [
  { id: 'PP-A', list: 'TL-PID', separateRevocationAnchor: true, host: 'pp-a.rp-test' },
  { id: 'PP-B', list: 'TL-PID', host: 'pp-b.rp-test' },
  { id: 'PP-C', host: 'pp-c.rp-test' },
  { id: 'PP-D', list: 'TL-PID', host: 'pp-d.rp-test' },
  { id: 'PP-E', list: 'TL-PID', expiredAnchor: true, host: 'pp-e.rp-test' },
  { id: 'PP-W', list: 'TL-PID', issuanceWithdrawn: true, host: 'pp-w.rp-test' },
  { id: 'PP-I', list: 'TL-PID', intermediate: true, host: 'pp-i.rp-test' },
  { id: 'QP-A', trustedList: 'TL-QEAA', qeaaService: 'granted', host: 'qp-a.rp-test' },
  { id: 'QP-N', trustedList: 'TL-QEAA', qeaaService: 'not-qualified', host: 'qp-n.rp-test' },
  { id: 'QP-W', trustedList: 'TL-QEAA', qeaaService: 'withdrawn', host: 'qp-w.rp-test' },
  { id: 'PB-A', list: 'TL-PUB', host: 'pb-a.rp-test' },
  { id: 'EP-A', rulebook: 'default_credential_eaa', host: 'ep-a.rp-test' },
  { id: 'WP-A', list: 'TL-WP', separateRevocationAnchor: true, walletSolution: { name: 'WP-A Wallet', keyAttestationService: 'WP-A WSCD' }, host: 'wp-a.rp-test' },
  { id: 'WP-B', list: 'TL-WP', walletSolution: { name: 'WP-B Wallet' }, host: 'wp-b.rp-test' },
  { id: 'WP-W', list: 'TL-WP', issuanceWithdrawn: true, walletSolution: { name: 'WP-W Wallet' }, host: 'wp-w.rp-test' },
  // On `TL-WP` only from its second version (PP_Inf_003), which the Test Wallet Provider publishes.
  { id: 'WP-C', walletSolution: { name: 'WP-C Wallet' }, host: 'wp-c.rp-test' },
  { id: 'AC-A', list: 'TL-AC', host: 'ac-a.rp-test' },
  { id: 'RC-A', list: 'TL-RC', host: 'rc-a.rp-test' },
  { id: 'CA-X', host: 'ca-x.rp-test' },
];

export interface TestEntity {
  spec: EntitySpec;
  /** `iss` of credentials and status lists the entity signs. */
  issuerUri: string;
  /** Self-signed anchors in the IACA root profile of ISO/IEC 18013-5 Annex B, which also serve SD-JWT VC. */
  anchors: { issuance: CertifiedKey; revocation: CertifiedKey };
  /**
   * End-entity signing certificates: `issuance` signs SD-JWT VCs, `mdoc` is the document signer (DS) of mdocs in the
   * profile of ISO/IEC 18013-5 Annex B, both under the issuance anchor; `revocation` signs status and identifier lists
   * under the revocation anchor.
   */
  signers: { issuance: CertifiedKey; mdoc: CertifiedKey; revocation: CertifiedKey };
  /** `PP-I`: the intermediate CA under the issuance anchor that issued its signers. */
  intermediate?: CertifiedKey;
  /** `WP-A`: the separate anchor for key attestations (`walletSolution.keyAttestationService`) and its KA signer. */
  keyAttestation?: { anchor: CertifiedKey; signer: CertifiedKey };
}

/** The lists in ETSI TS 119 612 format: the test list of trusted lists and the Trusted List it points to. */
export type TrustedListId = 'LOTL' | 'TL-QEAA';

export interface TestPki {
  createdAt: Date;
  entities: Record<string, TestEntity>;
  /** The scheme operator certificate of each list, which the Relying Party is configured with. */
  schemeOperators: Record<LoteListId, CertifiedKey>;
  /**
   * The certificates that sign the lists in ETSI TS 119 612 format: the LOTL's, which the Relying Party is configured
   * with, and that of `TL-QEAA`, which the LOTL publishes in its pointer.
   */
  trustedListOperators: Record<TrustedListId, CertifiedKey>;
  /** The Relying Party's access certificate, issued by `AC-A`. */
  relyingPartyAccess: CertifiedKey;
}

const subjectFor = (organization: string, commonName: string): NameAttributeInput[] => [
  ['countryName', 'DE'],
  ['organizationName', organization],
  ['commonName', commonName],
];

const keyIdHasher = (data: ArrayBuffer) => sha256(new Uint8Array(data));

/** `id-mdl-kp-mdlDS` (ISO/IEC 18013-5 Annex B, Table B.3): the extended key usage of an mdoc document signer. */
export const MDOC_DS_EXTENDED_KEY_USAGE = '1.0.18013.5.1.2';

/** DER of a length. */
const derLength = (length: number) =>
  length < 0x80 ? [length] : length < 0x100 ? [0x81, length] : [0x82, length >> 8, length & 0xff];
const der = (tag: number, content: number[] | Uint8Array) => new Uint8Array([tag, ...derLength(content.length), ...content]);

/** DER of an object identifier in dotted form. */
function derOid(oid: string): Uint8Array {
  const [first, second, ...rest] = oid.split('.').map(Number);
  const bytes = [40 * first + second];
  for (const arc of rest) {
    const groups = [arc & 0x7f];
    for (let value = arc >> 7; value > 0; value >>= 7) groups.unshift((value & 0x7f) | 0x80);
    bytes.push(...groups);
  }
  return der(0x06, bytes);
}

/** The extensions of the ISO/IEC 18013-5 Annex B profiles that `@owf/x509` has no template field for. */
export const annexBExtensions = (uri: string, documentSigner: boolean): X509Extension[] => [
  // IssuerAltName (2.5.29.18): GeneralNames with one uniformResourceIdentifier [6].
  { oid: '2.5.29.18', critical: false, value: der(0x30, der(0x86, new TextEncoder().encode(uri))) },
  // ExtendedKeyUsage (2.5.29.37), critical for a document signer.
  ...(documentSigner ? [{ oid: '2.5.29.37', critical: true, value: der(0x30, derOid(MDOC_DS_EXTENDED_KEY_USAGE)) }] : []),
];

/**
 * A self-signed CA in the IACA root profile of ISO/IEC 18013-5 Annex B (Table B.1): `basicConstraints` CA with path
 * length 0 and `keyUsage` keyCertSign and cRLSign, both critical, a subject key identifier, an issuer alternative name
 * and a CRL distribution point. The same profile serves as the anchor of SD-JWT VC issuers.
 */
export async function createSelfSignedCa(
  organization: string,
  commonName: string,
  validity: { notBefore: Date; notAfter: Date },
  options: { uri?: string; pathLenConstraint?: number } = {},
): Promise<CertifiedKey> {
  const key = await generateEcKeyPair();
  const uri = options.uri ?? `https://${commonName.toLowerCase().replace(/[^a-z0-9]+/g, '-')}.rp-test`;
  const certificate = await createCertificate({
    subject: subjectFor(organization, commonName),
    subjectPublicKey: key.publicJwk,
    serialNumber: randomSerial(),
    notBefore: validity.notBefore,
    notAfter: validity.notAfter,
    signatureAlgorithm: 'ES256',
    basicConstraints: { cA: true, pathLenConstraint: options.pathLenConstraint ?? 0 },
    keyUsage: ['keyCertSign', 'crlSign'],
    crlDistributionPoints: [`${uri}/crl`],
    extensions: annexBExtensions(uri, false),
    hasher: keyIdHasher,
    signer: (tbs) => signEs256(key.privateKey, tbs),
  });
  return { certificate, key, chain: [] };
}

/**
 * An mdoc document signer certificate in the profile of ISO/IEC 18013-5 Annex B (Table B.3): `keyUsage`
 * digitalSignature and the extended key usage `1.0.18013.5.1.2`, both critical, authority and subject key identifiers,
 * an issuer alternative name, a CRL distribution point, and the issuer's country in the subject.
 */
export async function createDocumentSigner(
  issuer: CertifiedKey,
  organization: string,
  commonName: string,
  validity: { notBefore: Date; notAfter: Date },
  uri = `https://${organization.toLowerCase().replace(/[^a-z0-9]+/g, '-')}.rp-test`,
  options: { extensions?: X509Extension[]; extendedKeyUsage?: boolean } = {},
): Promise<CertifiedKey> {
  const key = await generateEcKeyPair();
  const certificate = await createCertificate({
    subject: subjectFor(organization, commonName),
    subjectPublicKey: key.publicJwk,
    issuerCertificate: issuer.certificate.der,
    serialNumber: randomSerial(),
    notBefore: validity.notBefore,
    notAfter: validity.notAfter,
    signatureAlgorithm: 'ES256',
    keyUsage: ['digitalSignature'],
    crlDistributionPoints: [`${uri}/crl`],
    extensions: [...annexBExtensions(uri, options.extendedKeyUsage ?? true), ...(options.extensions ?? [])],
    hasher: keyIdHasher,
    signer: (tbs) => signEs256(issuer.key.privateKey, tbs),
  });
  return { certificate, key, chain: [certificate, ...issuer.chain] };
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
    extensions?: X509Extension[];
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
    ...(options.extensions ? { extensions: options.extensions } : {}),
    hasher: keyIdHasher,
    signer: (tbs) => signEs256(issuer.key.privateKey, tbs),
  });
  return { certificate, key, chain: [certificate, ...issuer.chain] };
}

/**
 * A CA certificate issued by `issuer`: an intermediate CA (`cA` true, path length 0, `keyUsage` keyCertSign and
 * cRLSign), or, with `cA` false, a certificate that only claims to issue certificates (IssuerIntegrity_034).
 */
export async function createIntermediateCa(
  issuer: CertifiedKey,
  organization: string,
  commonName: string,
  validity: { notBefore: Date; notAfter: Date },
  options: { cA?: boolean } = {},
): Promise<CertifiedKey> {
  const key = await generateEcKeyPair();
  const cA = options.cA ?? true;
  const certificate = await createCertificate({
    subject: subjectFor(organization, commonName),
    subjectPublicKey: key.publicJwk,
    issuerCertificate: issuer.certificate.der,
    serialNumber: randomSerial(),
    notBefore: validity.notBefore,
    notAfter: validity.notAfter,
    signatureAlgorithm: 'ES256',
    basicConstraints: cA ? { cA: true, pathLenConstraint: 0 } : { cA: false },
    keyUsage: ['keyCertSign', 'crlSign'],
    hasher: keyIdHasher,
    signer: (tbs) => signEs256(issuer.key.privateKey, tbs),
  });
  return { certificate, key, chain: [certificate, ...issuer.chain] };
}

/**
 * A certificate for a public key the test PKI does not generate itself (secp256k1, P-192, RSA), issued by `issuer` as an
 * end-entity signer, or as an mdoc document signer with the extended key usage of ISO/IEC 18013-5 Annex B.
 */
export async function createCertificateForKey(
  issuer: CertifiedKey,
  organization: string,
  commonName: string,
  subjectPublicKeyDer: Uint8Array,
  validity: { notBefore: Date; notAfter: Date },
  options: { documentSigner?: boolean; dnsNames?: string[]; uris?: string[] } = {},
): Promise<Certificate> {
  const uri = `https://${organization.toLowerCase().replace(/[^a-z0-9]+/g, '-')}.rp-test`;
  return createCertificate({
    subject: subjectFor(organization, commonName),
    subjectPublicKey: subjectPublicKeyDer,
    issuerCertificate: issuer.certificate.der,
    serialNumber: randomSerial(),
    notBefore: validity.notBefore,
    notAfter: validity.notAfter,
    signatureAlgorithm: 'ES256',
    keyUsage: ['digitalSignature'],
    ...(options.dnsNames || options.uris ? { subjectAlternativeNames: { dnsNames: options.dnsNames, uris: options.uris } } : {}),
    ...(options.documentSigner ? { crlDistributionPoints: [`${uri}/crl`], extensions: annexBExtensions(uri, true) } : {}),
    hasher: keyIdHasher,
    signer: (tbs) => signEs256(issuer.key.privateKey, tbs),
  });
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

/** `id-tsl-kp-tslSigning` (ETSI TS 119 612 clause 5.7.1): the extended key usage of a Trusted List signer. */
export const TSL_SIGNING_EXTENDED_KEY_USAGE = '0.4.0.2231.3.0';

/** The scheme territory and scheme operator name of the lists in ETSI TS 119 612 format. */
export const TRUSTED_LIST_OPERATORS: Record<TrustedListId, { territory: string; name: string }> = {
  LOTL: { territory: 'EU', name: 'RP conformance test LOTL scheme operator' },
  'TL-QEAA': { territory: 'DE', name: 'RP conformance test TL-QEAA scheme operator' },
};

/**
 * The signing certificate of a list in ETSI TS 119 612 format (clause 5.7.1): self-signed, country and organization
 * equal to the scheme territory and the scheme operator name, `keyUsage` digitalSignature only, the extended key usage
 * `id-tsl-kp-tslSigning`, a subject key identifier, and `cA` false.
 */
export async function createTrustedListSigner(list: TrustedListId, now: Date): Promise<CertifiedKey> {
  const { territory, name } = TRUSTED_LIST_OPERATORS[list];
  const key = await generateEcKeyPair();
  const certificate = await createCertificate({
    subject: [
      ['countryName', territory],
      ['organizationName', name],
      ['commonName', `${list} signer`],
    ],
    subjectPublicKey: key.publicJwk,
    serialNumber: randomSerial(),
    notBefore: new Date(now.getTime() - DAY),
    notAfter: new Date(now.getTime() + 5 * YEAR),
    signatureAlgorithm: 'ES256',
    basicConstraints: { cA: false },
    keyUsage: ['digitalSignature'],
    extendedKeyUsage: [TSL_SIGNING_EXTENDED_KEY_USAGE],
    hasher: keyIdHasher,
    signer: (tbs) => signEs256(key.privateKey, tbs),
  });
  return { certificate, key, chain: [certificate] };
}

/** Validity of a document signer certificate: at most 457 days (ISO/IEC 18013-5 Annex B, Table B.3). */
export const documentSignerValidity = (now: Date, anchorNotAfter = new Date(now.getTime() + YEAR)) => ({
  // Starts before the `signed` time of the MSOs the harness issues (two days in the past).
  notBefore: new Date(Math.min(now.getTime() - 10 * DAY, anchorNotAfter.getTime() - YEAR)),
  notAfter: new Date(now.getTime() + YEAR),
});

async function createEntity(spec: EntitySpec, now: Date): Promise<TestEntity> {
  const anchorValidity = spec.expiredAnchor
    ? { notBefore: new Date(now.getTime() - 2 * YEAR), notAfter: new Date(now.getTime() - DAY) }
    : { notBefore: new Date(now.getTime() - 30 * DAY), notAfter: new Date(now.getTime() + 10 * YEAR) };
  const issuerUri = `https://${spec.host}`;
  const issuanceAnchor = await createSelfSignedCa(spec.id, `CA-${spec.id}`, anchorValidity, {
    uri: issuerUri,
    ...(spec.intermediate ? { pathLenConstraint: 1 } : {}),
  });
  const revocationAnchor = spec.separateRevocationAnchor
    ? await createSelfSignedCa(spec.id, `CA-${spec.id}-REV`, anchorValidity, { uri: issuerUri })
    : issuanceAnchor;
  const intermediate = spec.intermediate
    ? await createIntermediateCa(issuanceAnchor, spec.id, `CA-${spec.id}-INT`, {
        notBefore: new Date(now.getTime() - 30 * DAY),
        notAfter: new Date(now.getTime() + 5 * YEAR),
      })
    : undefined;
  // The signers of PP-I are under its intermediate CA; those of every other entity directly under the anchors.
  const issuingCa = intermediate ?? issuanceAnchor;
  const revocationCa = intermediate ?? revocationAnchor;
  const leafValidity = {
    notBefore: new Date(Math.min(now.getTime() - DAY, anchorValidity.notAfter.getTime() - YEAR)),
    notAfter: new Date(now.getTime() + 2 * YEAR),
    dnsNames: [spec.host],
    uris: [issuerUri],
  };
  const issuanceSigner = await createEndEntity(issuingCa, spec.id, `${spec.id} issuance signer`, leafValidity);
  const documentSigner = await createDocumentSigner(
    issuingCa,
    spec.id,
    `${spec.id} document signer`,
    documentSignerValidity(now, anchorValidity.notAfter),
    issuerUri,
  );
  const revocationSigner = await createEndEntity(revocationCa, spec.id, `${spec.id} status list signer`, leafValidity);
  const keyAttestationAnchor = spec.walletSolution?.keyAttestationService
    ? await createSelfSignedCa(spec.id, `CA-${spec.id}-KA`, anchorValidity, { uri: issuerUri })
    : undefined;
  const keyAttestation = keyAttestationAnchor && {
    anchor: keyAttestationAnchor,
    signer: await createEndEntity(keyAttestationAnchor, spec.id, `${spec.id} key attestation signer`, leafValidity),
  };
  return {
    spec,
    issuerUri,
    anchors: { issuance: issuanceAnchor, revocation: revocationAnchor },
    signers: { issuance: issuanceSigner, mdoc: documentSigner, revocation: revocationSigner },
    ...(intermediate ? { intermediate } : {}),
    ...(keyAttestation ? { keyAttestation } : {}),
  };
}

/**
 * The entities that stand for the Provider under test (issuer test catalogue section 3.2): `PP-T` on `TL-PID`, `QP-T`
 * on `TL-QEAA`, `PB-T` on `TL-PUB`, and `EP-T` on no list (its anchor is configured as a rulebook anchor, `TA-EAA`).
 * Their anchors are generated per run like those of every other entity; the leaf certificates the SUT signs with are
 * issued by the Test Registrar (`enrolSut`) for the SUT's own keys. The `signers` the PKI generates for them are the
 * harness's own and never the SUT's.
 */
export const SUT_ENTITIES: EntitySpec[] = [
  { id: 'PP-T', list: 'TL-PID', separateRevocationAnchor: true, host: 'pp-t.rp-test' },
  { id: 'QP-T', trustedList: 'TL-QEAA', qeaaService: 'granted', host: 'qp-t.rp-test' },
  { id: 'PB-T', list: 'TL-PUB', separateRevocationAnchor: true, host: 'pb-t.rp-test' },
  { id: 'EP-T', host: 'ep-t.rp-test' },
];

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
  for (const spec of SUT_ENTITIES) {
    entities[spec.id] = await createEntity(spec, now);
  }
  const schemeOperators = {} as Record<LoteListId, CertifiedKey>;
  for (const list of ['TL-PID', 'TL-PUB', 'TL-WP', 'TL-AC', 'TL-RC'] as LoteListId[]) {
    schemeOperators[list] = await createSelfSignedSigner('RP conformance test scheme operator', `${list} scheme operator`, now);
  }
  const trustedListOperators = {
    LOTL: await createTrustedListSigner('LOTL', now),
    'TL-QEAA': await createTrustedListSigner('TL-QEAA', now),
  };
  const relyingPartyAccess = await createRelyingPartyAccessCertificate(entities['AC-A'], now, options.relyingPartyHost ?? 'rp.rp-test');
  return { createdAt: now, entities, schemeOperators, trustedListOperators, relyingPartyAccess };
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
