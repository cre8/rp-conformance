// Signing certificates with one deliberate defect, for the certificate path faults of IssuerIntegrity: the credential
// is issued with such a signer instead of the entity's own, so the chain it carries is the only difference.
import { generateKeyPairSync, type KeyObject, sign as nodeSign } from 'node:crypto';
import type { CredentialFormat, FaultId } from '@rp-conformance/core';
import type { X509Extension } from '@owf/x509';
import {
  type CertifiedKey,
  createCertificateForKey,
  createDocumentSigner,
  createEndEntity,
  createIntermediateCa,
  createSelfSignedSigner,
  documentSignerValidity,
  type TestEntity,
  type TestPki,
} from './pki';
import type { Certificate } from '@owf/x509';

const HOUR_MS = 60 * 60 * 1000;
const DAY_MS = 24 * HOUR_MS;
const YEAR_MS = 365 * DAY_MS;

/** The private extension the critical-extension faults add, with an empty value (DER NULL). */
export const PRIVATE_CRITICAL_EXTENSION: X509Extension = { oid: '1.3.6.1.4.1.55555.1.1', critical: true, value: new Uint8Array([0x05, 0x00]) };

/** The fault name without its format prefix: `signer-expired` for `credential.signer-expired` and `mdoc.signer-expired`. */
const nameOf = (fault: FaultId) => fault.replace(/^(credential|mdoc)\./, '');

/** The faults whose credential is issued with another signing certificate. */
export const SIGNER_FAULTS = new Set([
  'embedded-root',
  'self-signed',
  'signer-expired',
  'signer-not-yet-valid',
  'intermediate-expired',
  'intermediate-missing',
  'issuer-not-ca',
  'critical-extension',
  'ds-no-eku',
  'signed-after-ds-expiry',
  'signer-names-other-issuer',
  'signer-names-other-host',
  'signer-uri-beats-host',
]);

/** The issuer another issuer's signing certificate names in the faults of SD-JWT VC section 2.5 (issue 10). */
export const OTHER_ISSUER_URI = 'https://other-issuer.rp-test';

export const isSignerFault = (fault: FaultId | undefined) => Boolean(fault && SIGNER_FAULTS.has(nameOf(fault)));

/**
 * The signing certificate of a signer fault: an SD-JWT VC signer, or an mdoc document signer in the profile of
 * ISO/IEC 18013-5 Annex B, that differs from the issuer's own in the one property the fault names.
 */
export async function faultySigner(fault: FaultId, issuer: TestEntity, format: CredentialFormat, pki: TestPki, now: Date): Promise<CertifiedKey> {
  const mdoc = format === 'mso_mdoc';
  const id = issuer.spec.id;
  // The default validity starts before the `signed` time of the MSOs the harness issues (two days in the past, see
  // `mdocValidity`), so a faulted document signer is rejected for its own defect and not for the MSO signed date.
  const leafUnder = (ca: CertifiedKey, name: string, validity = { notBefore: new Date(now.getTime() - 10 * DAY_MS), notAfter: new Date(now.getTime() + YEAR_MS) }, extensions?: X509Extension[]) =>
    mdoc
      ? createDocumentSigner(ca, id, `${id} ${name} document signer`, validity, issuer.issuerUri, { extensions })
      : createEndEntity(ca, id, `${id} ${name} signer`, { ...validity, extensions });
  const intermediateOf = () => {
    if (!issuer.intermediate) throw new Error(`fault ${fault} needs an issuer with an intermediate CA (PP-I), not ${id}`);
    return issuer.intermediate;
  };
  switch (nameOf(fault)) {
    case 'embedded-root': {
      const caX = pki.entities['CA-X'];
      const signer = mdoc ? caX.signers.mdoc : caX.signers.issuance;
      return { ...signer, chain: [signer.certificate, caX.anchors.issuance.certificate] };
    }
    case 'self-signed':
      return createSelfSignedSigner(id, `${id} self-signed signer`, now);
    case 'signer-expired':
      return leafUnder(issuer.anchors.issuance, 'expired', { notBefore: new Date(now.getTime() - YEAR_MS), notAfter: new Date(now.getTime() - HOUR_MS) });
    case 'signer-not-yet-valid':
      return leafUnder(issuer.anchors.issuance, 'future', { notBefore: new Date(now.getTime() + DAY_MS), notAfter: new Date(now.getTime() + YEAR_MS) });
    case 'intermediate-expired': {
      intermediateOf();
      const expired = await createIntermediateCa(issuer.anchors.issuance, id, `CA-${id}-INT expired`, {
        notBefore: new Date(now.getTime() - 2 * YEAR_MS),
        notAfter: new Date(now.getTime() - DAY_MS),
      });
      return leafUnder(expired, 'under an expired intermediate', { notBefore: new Date(now.getTime() - 400 * DAY_MS), notAfter: new Date(now.getTime() + YEAR_MS) });
    }
    case 'intermediate-missing': {
      intermediateOf();
      const signer = mdoc ? issuer.signers.mdoc : issuer.signers.issuance;
      return { ...signer, chain: [signer.certificate] };
    }
    case 'issuer-not-ca': {
      intermediateOf();
      const notCa = await createIntermediateCa(
        issuer.anchors.issuance,
        id,
        `${id} certificate without cA`,
        { notBefore: new Date(now.getTime() - 30 * DAY_MS), notAfter: new Date(now.getTime() + YEAR_MS) },
        { cA: false },
      );
      return leafUnder(notCa, 'under a certificate without cA');
    }
    case 'signer-names-other-issuer':
    case 'signer-names-other-host':
    case 'signer-uri-beats-host': {
      // Another issuer's certificate under the same anchor (SD-JWT VC section 2.5: the issuer is the subject of the
      // end-entity certificate). It names another URI, only another host, or another URI and the host of `iss`.
      if (mdoc) throw new Error(`fault ${fault} applies to SD-JWT VC`);
      const otherHost = new URL(OTHER_ISSUER_URI).host;
      const names = {
        'signer-names-other-issuer': { uris: [OTHER_ISSUER_URI] },
        'signer-names-other-host': { dnsNames: [otherHost] },
        'signer-uri-beats-host': { uris: [OTHER_ISSUER_URI], dnsNames: [new URL(issuer.issuerUri).host] },
      }[nameOf(fault) as 'signer-names-other-issuer' | 'signer-names-other-host' | 'signer-uri-beats-host'];
      return createEndEntity(issuer.anchors.issuance, id, `${id} signer of another issuer`, {
        notBefore: new Date(now.getTime() - 10 * DAY_MS),
        notAfter: new Date(now.getTime() + YEAR_MS),
        ...names,
      });
    }
    case 'critical-extension':
      return leafUnder(issuer.anchors.issuance, 'critical extension', undefined, [PRIVATE_CRITICAL_EXTENSION]);
    case 'ds-no-eku':
      return createEndEntity(issuer.anchors.issuance, id, `${id} signer without document signer EKU`, documentSignerValidity(now));
    case 'signed-after-ds-expiry':
      return createDocumentSigner(
        issuer.anchors.issuance,
        id,
        `${id} short-lived document signer`,
        { notBefore: new Date(now.getTime() - 10 * DAY_MS), notAfter: new Date(now.getTime() + DAY_MS) },
        issuer.issuerUri,
      );
    default:
      throw new Error(`fault ${fault} does not change the signer`);
  }
}

/** A key the test PKI does not generate with WebCrypto, with the certificate and the JOSE / COSE algorithm it signs with. */
export interface ForeignSigner {
  certificate: Certificate;
  privateKey: KeyObject;
  /** JOSE `alg` claimed in the header. */
  jwsAlg: string;
  /** COSE algorithm claimed in the protected header. */
  coseAlg: number;
  sign: (data: Uint8Array | string) => Uint8Array;
}

/**
 * The signer of a key fault, certified under the issuer's issuance anchor: secp256k1 with `ES256K`, P-192 with the
 * claimed `ES256`, or RSA with 1024 bits and `RS256` (RSASSA-PKCS1-v1_5).
 */
export async function foreignSigner(kind: 'secp256k1' | 'p192' | 'rsa1024', issuer: TestEntity, format: CredentialFormat, now: Date): Promise<ForeignSigner> {
  const { publicKey, privateKey } =
    kind === 'rsa1024'
      ? generateKeyPairSync('rsa', { modulusLength: 1024 })
      : generateKeyPairSync('ec', { namedCurve: kind === 'p192' ? 'prime192v1' : 'secp256k1' });
  const id = issuer.spec.id;
  const certificate = await createCertificateForKey(
    issuer.anchors.issuance,
    id,
    `${id} ${kind} signer`,
    new Uint8Array(publicKey.export({ type: 'spki', format: 'der' })),
    // Valid from before the `signed` time of the MSOs the harness issues (two days in the past).
    { notBefore: new Date(now.getTime() - 10 * DAY_MS), notAfter: new Date(now.getTime() + YEAR_MS) },
    // An SD-JWT VC signer names the issuer, as the issuer's own does, so the key is the only difference.
    format === 'mso_mdoc' ? { documentSigner: true } : { dnsNames: [issuer.spec.host], uris: [issuer.issuerUri] },
  );
  const rsa = kind === 'rsa1024';
  return {
    certificate,
    privateKey,
    jwsAlg: rsa ? 'RS256' : kind === 'secp256k1' ? 'ES256K' : 'ES256',
    coseAlg: rsa ? -257 : kind === 'secp256k1' ? -47 : -7,
    sign: (data) =>
      new Uint8Array(nodeSign('sha256', typeof data === 'string' ? Buffer.from(data) : data, rsa ? privateKey : { key: privateKey, dsaEncoding: 'ieee-p1363' })),
  };
}
