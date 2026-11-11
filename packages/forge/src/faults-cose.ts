// The fault layer for mdoc (harness design section 4.3): the faults of the issued mdoc, of the Status List Token in CWT
// format and of the identifier list. Each one decodes the valid artifact as raw CBOR, changes it and assembles and
// signs the COSE structure again, so no library stands between a valid artifact and its deliberate fault.
import { createPublicKey, generateKeyPairSync, randomUUID, sign as nodeSign, createHmac } from 'node:crypto';
import { type FaultId, faultInfo, type FaultPoint } from '@rp-conformance/core';
import { createCertificate } from '@owf/x509';
import {
  type CborMap,
  COSE,
  COSE_ALG,
  type CoseStructure,
  coseValue,
  decodeCbor,
  decodeEmbedded,
  embedded,
  encodeCbor,
  macStructure,
  readCose,
  sigStructure,
  tdate,
  x5chainValue,
} from './cbor';
import { randomSerial, sha256, signEs256 } from './crypto';
import { decompressionBomb, otherSigner, type ServedStatusList, type StatusListFaultContext } from './faults';
import type { CertifiedKey } from './pki';

const HOUR = 3600;
const DAY_MS = 24 * 60 * 60 * 1000;
const seconds = (date: Date) => Math.floor(date.getTime() / 1000);

function ensure(fault: FaultId, point: FaultPoint, format: string) {
  const info = faultInfo(fault);
  if (info.point !== point || info.format !== format) throw new Error(`fault ${fault} does not apply to the ${point} in ${format} format`);
}

/** Flips one bit in the middle of a byte string. */
export function flipBitInBytes(bytes: Uint8Array): Uint8Array {
  if (bytes.length === 0) throw new Error('nothing to flip');
  const copy = new Uint8Array(bytes);
  copy[Math.floor(copy.length / 2)] ^= 0x01;
  return copy;
}

/** Signs a changed COSE_Sign1 again with ES256, keeping its tag and headers. */
async function resign(structure: CoseStructure, payload: Uint8Array, privateKey: CryptoKey, protectedHeader = structure.protectedHeader) {
  const protectedBytes = encodeCbor(protectedHeader);
  const signature = await signEs256(privateKey, sigStructure(protectedBytes, payload));
  return coseValue({ tag: structure.tag, protectedBytes, unprotectedHeader: structure.unprotectedHeader, payload, signature });
}

// --------------------------------------------------------------------------- mdoc

export interface MdocFaultContext {
  /** The document signer that signed the MSO; the changed MSO is signed with it again. */
  signer: CertifiedKey;
  now: Date;
  /** `T_skew`, seconds. */
  skewSeconds: number;
  /** Number of entries in the referenced status list (for `mdoc.status-idx-out-of-range`). */
  statusListEntries?: number;
}

const statusListEntryOf = (mso: CborMap): CborMap => {
  const entry = (mso.get('status') as CborMap | undefined)?.get('status_list');
  if (!(entry instanceof Map)) throw new Error('the MSO has no status_list entry to change');
  return entry;
};
const validityInfoOf = (mso: CborMap) => mso.get('validityInfo') as CborMap;

const MDOC_CHANGES: Partial<Record<FaultId, (mso: CborMap, ctx: MdocFaultContext) => void>> = {
  'mdoc.valid-until-past': (m, c) => void validityInfoOf(m).set('validUntil', tdate(new Date(c.now.getTime() - (c.skewSeconds + HOUR) * 1000))),
  'mdoc.valid-from-future': (m, c) => void validityInfoOf(m).set('validFrom', tdate(new Date(c.now.getTime() + (c.skewSeconds + HOUR) * 1000))),
  'mdoc.expected-update-past': (m, c) => void validityInfoOf(m).set('expectedUpdate', tdate(new Date(c.now.getTime() - DAY_MS))),
  'mdoc.status-no-idx': (m) => void statusListEntryOf(m).delete('idx'),
  'mdoc.status-no-uri': (m) => void statusListEntryOf(m).delete('uri'),
  'mdoc.status-idx-negative': (m) => void statusListEntryOf(m).set('idx', -1),
  'mdoc.status-idx-text': (m) => void statusListEntryOf(m).set('idx', '7'),
  'mdoc.status-uri-invalid': (m) => void statusListEntryOf(m).set('uri', 'not a uri'),
  'mdoc.status-idx-out-of-range': (m, c) => {
    if (c.statusListEntries === undefined) throw new Error('mdoc.status-idx-out-of-range needs the size of the status list');
    statusListEntryOf(m).set('idx', c.statusListEntries);
  },
  'mdoc.no-status': (m) => void m.delete('status'),
};

/** Applies a credential fault to an issued mdoc (`IssuerSigned`, CBOR) and returns the changed `IssuerSigned`. */
export async function applyMdocFault(fault: FaultId, issuerSignedBytes: Uint8Array, ctx: MdocFaultContext): Promise<Uint8Array> {
  ensure(fault, 'credential', 'mso_mdoc');
  const issuerSigned = decodeCbor<CborMap>(issuerSignedBytes);
  const issuerAuth = readCose(issuerSigned.get('issuerAuth'));
  if (fault === 'mdoc.signature-bitflip') {
    issuerSigned.set('issuerAuth', coseValue({ ...issuerAuth, signature: flipBitInBytes(issuerAuth.signature) }));
    return encodeCbor(issuerSigned);
  }
  const change = MDOC_CHANGES[fault];
  if (!change) throw new Error(`fault ${fault} is not implemented`);
  const mso = decodeEmbedded<CborMap>(decodeCbor(issuerAuth.payload ?? new Uint8Array()));
  change(mso, ctx);
  issuerSigned.set('issuerAuth', await resign(issuerAuth, encodeCbor(embedded(mso)), ctx.signer.key.privateKey));
  return encodeCbor(issuerSigned);
}

// --------------------------------------------------------------------------- Status List Token (CWT)

const STATUS_LIST_CWT = 'application/statuslist+cwt';
const CLAIM = { iss: 1, sub: 2, exp: 4, iat: 6, statusList: 65533, identifierList: 65530 } as const;

/** A certificate under the issuer's revocation anchor whose key is on secp256k1, and that key. */
async function secp256k1Signer(ctx: StatusListFaultContext) {
  const anchor = ctx.pki.entities[ctx.issuer].anchors.revocation;
  const { publicKey, privateKey } = generateKeyPairSync('ec', { namedCurve: 'secp256k1' });
  const certificate = await createCertificate({
    subject: [
      ['countryName', 'DE'],
      ['organizationName', ctx.issuer],
      ['commonName', `${ctx.issuer} ES256K status list signer`],
    ],
    subjectPublicKey: new Uint8Array(publicKey.export({ type: 'spki', format: 'der' })),
    issuerCertificate: anchor.certificate.der,
    serialNumber: randomSerial(),
    notBefore: new Date(ctx.now.getTime() - DAY_MS),
    notAfter: new Date(ctx.now.getTime() + 365 * DAY_MS),
    signatureAlgorithm: 'ES256',
    keyUsage: ['digitalSignature'],
    hasher: (data: ArrayBuffer) => sha256(new Uint8Array(data)),
    signer: (tbs: Uint8Array) => signEs256(anchor.key.privateKey, tbs),
  });
  return { certificate, privateKey };
}

/** The DER SubjectPublicKeyInfo of a signer certificate: the "encoded public key" of the COSE_Mac0 confusion. */
export function macKeyOf(signer: CertifiedKey): Uint8Array {
  return new Uint8Array(createPublicKey({ key: signer.certificate.pem, format: 'pem' }).export({ type: 'spki', format: 'der' }));
}

const cwt = (value: unknown): ServedStatusList => ({ body: encodeCbor(value), contentType: STATUS_LIST_CWT });

/** Applies a Status List Token fault to a valid token in CWT format and returns what the Test Status Provider serves. */
export async function applyStatusListCwtFault(fault: FaultId, token: Uint8Array, ctx: StatusListFaultContext): Promise<ServedStatusList> {
  ensure(fault, 'status-list', 'cwt');
  const structure = readCose(decodeCbor(token));
  const claims = decodeCbor<CborMap>(structure.payload ?? new Uint8Array());
  const list = () => claims.get(CLAIM.statusList) as CborMap;
  const withClaims = async (change: () => void) => {
    change();
    return cwt(await resign(structure, encodeCbor(claims), ctx.signer.key.privateKey));
  };
  const withHeader = async (change: (header: CborMap) => void) => {
    const header = new Map(structure.protectedHeader);
    change(header);
    return cwt(await resign(structure, structure.payload as Uint8Array, ctx.signer.key.privateKey, header));
  };
  const now = seconds(ctx.now);
  switch (fault) {
    case 'status-list-cwt.signature-bitflip':
      return cwt(coseValue({ ...structure, signature: flipBitInBytes(structure.signature) }));
    case 'status-list-cwt.bare-list':
      return { body: encodeCbor(list()), contentType: 'application/cbor' };
    case 'status-list-cwt.exp-past':
      return withClaims(() => claims.set(CLAIM.exp, now - ctx.skewSeconds - HOUR));
    case 'status-list-cwt.sub-other':
      return withClaims(() => claims.set(CLAIM.sub, ctx.uri.replace(/[^/]+$/, randomUUID())));
    case 'status-list-cwt.typ-cwt':
      return withHeader((header) => header.set(COSE.typ, 'application/cwt'));
    case 'status-list-cwt.no-sub':
      return withClaims(() => claims.delete(CLAIM.sub));
    case 'status-list-cwt.no-iat':
      return withClaims(() => claims.delete(CLAIM.iat));
    case 'status-list-cwt.no-status-list':
      return withClaims(() => claims.delete(CLAIM.statusList));
    case 'status-list-cwt.no-bits':
      return withClaims(() => list().delete('bits'));
    case 'status-list-cwt.no-lst':
      return withClaims(() => list().delete('lst'));
    case 'status-list-cwt.no-x5chain':
      return withHeader((header) => header.delete(COSE.x5chain));
    case 'status-list-cwt.lst-not-zlib':
      return withClaims(() => list().set('lst', new TextEncoder().encode('not zlib data')));
    case 'status-list-cwt.decompression-bomb': {
      // Every entry of the inflated list is 0x00, so a Relying Party without a size limit would accept.
      const lst = await decompressionBomb();
      return withClaims(() => claims.set(CLAIM.statusList, new Map<string, unknown>([['bits', 1], ['lst', lst]])));
    }
    case 'status-list-cwt.bits-3':
      return withClaims(() => list().set('bits', 3));
    case 'status-list-cwt.es256k': {
      const k1 = await secp256k1Signer(ctx);
      const header = new Map(structure.protectedHeader);
      header.set(COSE.alg, COSE_ALG.ES256K);
      header.set(COSE.x5chain, x5chainValue([k1.certificate.der, ...ctx.signer.chain.slice(1).map((c) => c.der)]));
      const protectedBytes = encodeCbor(header);
      const payload = structure.payload as Uint8Array;
      const signature = nodeSign('sha256', sigStructure(protectedBytes, payload), { key: k1.privateKey, dsaEncoding: 'ieee-p1363' });
      return cwt(coseValue({ ...structure, protectedBytes, payload, signature: new Uint8Array(signature) }));
    }
    case 'status-list-cwt.mac0-public-key': {
      const header = new Map(structure.protectedHeader);
      header.set(COSE.alg, COSE_ALG.HMAC256);
      const protectedBytes = encodeCbor(header);
      const payload = structure.payload as Uint8Array;
      const tag = new Uint8Array(createHmac('sha256', macKeyOf(ctx.signer)).update(macStructure(protectedBytes, payload)).digest());
      return cwt(coseValue({ tag: 17, protectedBytes, unprotectedHeader: structure.unprotectedHeader, payload, signature: tag }));
    }
    default: {
      const signer = await otherSigner(fault, ctx);
      const header = new Map(structure.protectedHeader);
      header.set(COSE.x5chain, x5chainValue(signer.chain.map((c) => c.der)));
      return cwt(await resign(structure, structure.payload as Uint8Array, signer.key.privateKey, header));
    }
  }
}

// --------------------------------------------------------------------------- identifier list (CWT)

const IDENTIFIER_LIST_CWT = 'application/identifierlist+cwt';

/** Applies an identifier list fault to a valid identifier list and returns what the Test Status Provider serves. */
export async function applyIdentifierListFault(fault: FaultId, token: Uint8Array, ctx: StatusListFaultContext): Promise<ServedStatusList> {
  ensure(fault, 'identifier-list', 'cwt');
  const structure = readCose(decodeCbor(token));
  const served = (value: unknown): ServedStatusList => ({ body: encodeCbor(value), contentType: IDENTIFIER_LIST_CWT });
  switch (fault) {
    case 'identifier-list.signature-bitflip':
      return served(coseValue({ ...structure, signature: flipBitInBytes(structure.signature) }));
    case 'identifier-list.exp-past': {
      const claims = decodeCbor<CborMap>(structure.payload ?? new Uint8Array());
      claims.set(CLAIM.exp, seconds(ctx.now) - ctx.skewSeconds - HOUR);
      return served(await resign(structure, encodeCbor(claims), ctx.signer.key.privateKey));
    }
    case 'identifier-list.signer-ca-x': {
      const signer = ctx.pki.entities['CA-X'].signers.revocation;
      const header = new Map(structure.protectedHeader);
      header.set(COSE.x5chain, x5chainValue(signer.chain.map((c) => c.der)));
      return served(await resign(structure, structure.payload as Uint8Array, signer.key.privateKey, header));
    }
    default:
      throw new Error(`fault ${fault} is not implemented`);
  }
}
