// The fault layer (harness design section 4.3): pure, named functions that turn a valid artifact into one with exactly
// one deliberate fault. The catalogue (point, target check, FCAF wording) is FAULTS in @rp-conformance/core; this
// module implements every entry, at three points: the issued credential, the Status List Token, the Authorization
// Response.
import { createHash, createHmac, createPublicKey, generateKeyPairSync, randomUUID, sign as nodeSign } from 'node:crypto';
import { createDeflate } from 'node:zlib';
import { type FaultId, faultInfo, type FaultPoint } from '@rp-conformance/core';
import { CompactEncrypt, CompactSign, exportJWK, generateKeyPair, importJWK, type JWK } from 'jose';
import { createCertificate } from '@owf/x509';
import { base64url, type EcKeyPair, randomSerial, sha256, signEs256 } from './crypto';
import { decodeJws, flipBitInSegment, resignJws } from './jose';
import { type CertifiedKey, createEndEntity, createSelfSignedCa, createSelfSignedSigner, type TestPki } from './pki';

const HOUR = 3600;
const DAY_MS = 24 * 60 * 60 * 1000;
const x5cOf = (key: CertifiedKey) => key.chain.map((certificate) => Buffer.from(certificate.der).toString('base64'));
const seconds = (date: Date) => Math.floor(date.getTime() / 1000);

function ensurePoint(fault: FaultId, point: FaultPoint, format?: string) {
  const info = faultInfo(fault);
  if (info.point !== point) throw new Error(`fault ${fault} does not apply to the ${point}`);
  if (format && info.format !== format) throw new Error(`fault ${fault} applies to ${info.format}, not ${format}`);
}

// --------------------------------------------------------------------------- credential

export interface CredentialFaultContext {
  /** The key that signed the credential; the changed issuer-signed JWT is signed with it again. */
  signer: CertifiedKey;
  now: Date;
  /** `T_skew`, seconds. */
  skewSeconds: number;
  /** Number of entries in the referenced status list (for `credential.status-idx-out-of-range`). */
  statusListEntries?: number;
}

type Payload = Record<string, unknown> & { status?: { status_list?: Record<string, unknown> } };

const CREDENTIAL_CHANGES: Partial<Record<FaultId, (payload: Payload, ctx: CredentialFaultContext) => void>> = {
  'credential.exp-past': (p, c) => void (p.exp = seconds(c.now) - c.skewSeconds - HOUR),
  'credential.exp-within-skew': (p, c) => void (p.exp = seconds(c.now) - Math.floor(c.skewSeconds / 2)),
  'credential.nbf-future': (p, c) => void (p.nbf = seconds(c.now) + c.skewSeconds + HOUR),
  'credential.status-no-idx': (p) => void delete statusListOf(p).idx,
  'credential.status-no-uri': (p) => void delete statusListOf(p).uri,
  'credential.status-idx-negative': (p) => void (statusListOf(p).idx = -1),
  'credential.status-idx-string': (p) => void (statusListOf(p).idx = '7'),
  'credential.status-uri-invalid': (p) => void (statusListOf(p).uri = 'not a uri'),
  'credential.status-idx-out-of-range': (p, c) => {
    if (c.statusListEntries === undefined) throw new Error('credential.status-idx-out-of-range needs the size of the status list');
    statusListOf(p).idx = c.statusListEntries;
  },
  'credential.no-status': (p) => void delete p.status,
};

function statusListOf(payload: Payload): Record<string, unknown> {
  const reference = payload.status?.status_list;
  if (!reference) throw new Error('the credential has no status reference to change');
  return reference;
}

/** Applies a credential fault to an issued SD-JWT VC (issuer-signed JWT `~` disclosures `~`, without KB-JWT). */
export async function applyCredentialFault(fault: FaultId, sdJwt: string, ctx: CredentialFaultContext): Promise<string> {
  ensurePoint(fault, 'credential', 'dc+sd-jwt');
  const [issuerJwt, ...rest] = sdJwt.split('~');
  if (fault === 'credential.signature-bitflip') return [flipBitInSegment(issuerJwt, 2), ...rest].join('~');
  const change = CREDENTIAL_CHANGES[fault];
  if (!change) throw new Error(`fault ${fault} is not implemented`);
  const changed = await resignJws(issuerJwt, ({ payload }) => change(payload as Payload, ctx), ctx.signer.key.privateKey);
  return [changed, ...rest].join('~');
}

// --------------------------------------------------------------------------- Status List Token

export interface StatusListFaultContext {
  pki: TestPki;
  /** The entity that issued the credential. */
  issuer: string;
  /** The key that signed the valid token. */
  signer: CertifiedKey;
  /** The key that signed the credential. */
  credentialSigner: CertifiedKey;
  /** The credential's status URI. */
  uri: string;
  now: Date;
  skewSeconds: number;
}

/** What the Test Status Provider serves for a status list or identifier list URI: text (JWT, JSON) or CBOR. */
export interface ServedStatusList {
  body: string | Uint8Array;
  contentType: string;
}

const STATUS_LIST_JWT = 'application/statuslist+jwt';

let bomb: Promise<Uint8Array> | undefined;

/** A ZLIB stream that inflates to 1 GiB of zero bytes (about 1 MB), built once per process. */
export function decompressionBomb(): Promise<Uint8Array> {
  bomb ??= new Promise<Uint8Array>((resolve, reject) => {
    const deflate = createDeflate({ level: 9 });
    const chunks: Buffer[] = [];
    deflate.on('data', (chunk: Buffer) => chunks.push(chunk));
    deflate.on('error', reject);
    deflate.on('end', () => resolve(new Uint8Array(Buffer.concat(chunks))));
    const zeros = Buffer.alloc(1 << 20);
    let written = 0;
    const write = () => {
      while (written < 1024) {
        written++;
        if (!deflate.write(zeros)) return void deflate.once('drain', write);
      }
      deflate.end();
    };
    write();
  });
  return bomb;
}

const validity = (now: Date, notBefore: number, notAfter: number) => ({
  notBefore: new Date(now.getTime() + notBefore),
  notAfter: new Date(now.getTime() + notAfter),
});

/**
 * Status list signers that differ from the valid one only in the property the fault names; the same signers serve the
 * faults of both formats (`status-list.signer-ca-x`, `status-list-cwt.signer-ca-x`, …).
 */
export async function otherSigner(fault: FaultId, ctx: StatusListFaultContext): Promise<CertifiedKey> {
  const { pki, now } = ctx;
  const revocationAnchor = pki.entities[ctx.issuer].anchors.revocation;
  switch (fault.replace(/^status-list(-cwt)?\./, '')) {
    case 'signer-ca-x':
      return pki.entities['CA-X'].signers.revocation;
    case 'signer-pp-b-revocation':
      return pki.entities['PP-B'].signers.revocation;
    case 'signer-wp-a-revocation':
      return pki.entities['WP-A'].signers.revocation;
    case 'signer-ac-a':
      return pki.entities['AC-A'].signers.issuance;
    case 'signer-credential-certificate':
      return ctx.credentialSigner;
    case 'signer-self-signed':
      return createSelfSignedSigner('RP conformance untrusted signer', 'Self-signed status list signer', now);
    case 'signer-other-issuance-certificate':
      return createEndEntity(pki.entities[ctx.issuer].anchors.issuance, ctx.issuer, `${ctx.issuer} other issuance certificate`, validity(now, -DAY_MS, 365 * DAY_MS));
    case 'embedded-root': {
      const root = await createSelfSignedCa('RP conformance untrusted root', 'Untrusted root', validity(now, -DAY_MS, 365 * DAY_MS));
      const leaf = await createEndEntity(root, 'RP conformance untrusted root', 'Status list signer under an untrusted root', validity(now, -DAY_MS, 365 * DAY_MS));
      return { ...leaf, chain: [leaf.certificate, root.certificate] };
    }
    case 'signer-expired':
      return createEndEntity(revocationAnchor, ctx.issuer, `${ctx.issuer} expired status list signer`, validity(now, -365 * DAY_MS, -DAY_MS));
    case 'signer-not-yet-valid':
      return createEndEntity(revocationAnchor, ctx.issuer, `${ctx.issuer} future status list signer`, validity(now, DAY_MS, 365 * DAY_MS));
    default:
      throw new Error(`fault ${fault} does not change the signer`);
  }
}

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
    ...validity(ctx.now, -DAY_MS, 365 * DAY_MS),
    signatureAlgorithm: 'ES256',
    keyUsage: ['digitalSignature'],
    hasher: (data: ArrayBuffer) => sha256(new Uint8Array(data)),
    signer: (tbs: Uint8Array) => signEs256(anchor.key.privateKey, tbs),
  });
  return { certificate, privateKey };
}

/** Applies a Status List Token fault to a valid token and returns what the Test Status Provider serves. */
export async function applyStatusListFault(fault: FaultId, token: string, ctx: StatusListFaultContext): Promise<ServedStatusList> {
  ensurePoint(fault, 'status-list', 'jwt');
  const jwt = (body: string) => ({ body, contentType: STATUS_LIST_JWT });
  const resign = async (change: Parameters<typeof resignJws>[1], key = ctx.signer.key.privateKey) => jwt(await resignJws(token, change, key));
  const removeFromList = (member: string) => resign(({ payload }) => void delete (payload.status_list as Record<string, unknown>)[member]);
  const setLst = (lst: string) => resign(({ payload }) => void ((payload.status_list as Record<string, unknown>).lst = lst));
  const now = seconds(ctx.now);
  switch (fault) {
    case 'status-list.signature-bitflip':
      return jwt(flipBitInSegment(token, 2));
    case 'status-list.alg-none': {
      const { header, payload } = decodeJws(token);
      return jwt(`${base64url.encode(JSON.stringify({ ...header, alg: 'none' }))}.${base64url.encode(JSON.stringify(payload))}.`);
    }
    case 'status-list.bare-list':
      return { body: JSON.stringify(decodeJws(token).payload.status_list), contentType: 'application/json' };
    case 'status-list.exp-past':
      return resign(({ payload }) => void (payload.exp = now - ctx.skewSeconds - HOUR));
    case 'status-list.sub-other':
      return resign(({ payload }) => void (payload.sub = ctx.uri.replace(/[^/]+$/, randomUUID())));
    case 'status-list.typ-jwt':
      return resign(({ header }) => void (header.typ = 'JWT'));
    case 'status-list.no-sub':
      return resign(({ payload }) => void delete payload.sub);
    case 'status-list.no-iat':
      return resign(({ payload }) => void delete payload.iat);
    case 'status-list.no-status-list':
      return resign(({ payload }) => void delete payload.status_list);
    case 'status-list.no-bits':
      return removeFromList('bits');
    case 'status-list.no-lst':
      return removeFromList('lst');
    case 'status-list.no-x5c':
      return resign(({ header }) => void delete header.x5c);
    case 'status-list.lst-not-base64url': {
      const lst = String((decodeJws(token).payload.status_list as { lst: string }).lst);
      return setLst(`${lst.slice(0, 4)}***${lst.slice(4)}`);
    }
    case 'status-list.lst-not-zlib':
      return setLst(base64url.encode('not zlib data'));
    case 'status-list.decompression-bomb': {
      // Every entry of the inflated list is 0x00, so a Relying Party without a size limit would accept.
      const lst = base64url.encode(await decompressionBomb());
      return resign(({ payload }) => void (payload.status_list = { bits: 1, lst }));
    }
    case 'status-list.bits-3':
      return resign(({ payload }) => void ((payload.status_list as Record<string, unknown>).bits = 3));
    case 'status-list.es256k': {
      const k1 = await secp256k1Signer(ctx);
      const { header, payload } = decodeJws(token);
      const x5c = [Buffer.from(k1.certificate.der).toString('base64'), ...x5cOf(ctx.signer).slice(1)];
      const input = `${base64url.encode(JSON.stringify({ ...header, alg: 'ES256K', x5c }))}.${base64url.encode(JSON.stringify(payload))}`;
      const signature = nodeSign('sha256', Buffer.from(input), { key: k1.privateKey, dsaEncoding: 'ieee-p1363' });
      return jwt(`${input}.${base64url.encode(signature)}`);
    }
    case 'status-list.hs256-public-key': {
      const { header, payload } = decodeJws(token);
      const input = `${base64url.encode(JSON.stringify({ ...header, alg: 'HS256' }))}.${base64url.encode(JSON.stringify(payload))}`;
      return jwt(`${input}.${base64url.encode(createHmac('sha256', hmacKeyOf(ctx.signer)).update(input).digest())}`);
    }
    default: {
      const signer = await otherSigner(fault, ctx);
      return resign(({ header }) => void (header.x5c = x5cOf(signer)), signer.key.privateKey);
    }
  }
}

/** The "encoded public key" of the HS256 confusion: the PEM of the signer certificate's SubjectPublicKeyInfo. */
export function hmacKeyOf(signer: CertifiedKey): string {
  return createPublicKey({ key: signer.certificate.pem, format: 'pem' }).export({ type: 'spki', format: 'pem' }).toString();
}

// --------------------------------------------------------------------------- Authorization Response

export interface ResponseInput {
  /** The decrypted payload of a valid response: `vp_token` and `state`. */
  payload: Record<string, unknown>;
  /** The Relying Party's encryption key from the request's `client_metadata`. */
  recipient: JWK;
  /** Content encryption of the valid response. */
  enc: string;
  /** The Conformance Wallet's key, for `response.jws`. */
  walletKey: EcKeyPair;
  /** For `response.other-transaction-key`: the encryption key recorded for another transaction. */
  otherTransactionKey?: JWK;
}

/** Encrypts a response payload as `direct_post.jwt` (ECDH-ES unless `alg` says otherwise). */
export async function encryptResponse(payload: Record<string, unknown>, recipient: JWK, options: { alg?: string; enc: string; kid?: string }) {
  const alg = options.alg ?? 'ECDH-ES';
  const kid = options.kid ?? recipient.kid;
  return new CompactEncrypt(new TextEncoder().encode(JSON.stringify(payload)))
    .setProtectedHeader({ alg, enc: options.enc, ...(kid ? { kid } : {}) })
    .encrypt(await importJWK({ ...recipient, alg: undefined, use: undefined }, alg));
}

const replaceEpk = (jwe: string, epk: JWK) => {
  const [header, ...rest] = jwe.split('.');
  const decoded = base64url.decodeJson<Record<string, unknown>>(header ?? '');
  return [base64url.encode(JSON.stringify({ ...decoded, epk })), ...rest].join('.');
};

/** A P-256 public key whose coordinates are not a point on the curve. */
function offCurvePoint(): JWK {
  const x = createHash('sha256').update('rp-conformance off-curve x').digest();
  const y = createHash('sha256').update('rp-conformance off-curve y').digest();
  return { kty: 'EC', crv: 'P-256', x: base64url.encode(x), y: base64url.encode(y) };
}

/** The form parameters the Conformance Wallet posts to `response_uri`: the valid response, or one with a fault. */
export async function buildAuthorizationResponse(input: ResponseInput, fault?: FaultId): Promise<Record<string, string>> {
  if (fault) ensurePoint(fault, 'response');
  const encrypted = (jwe: string) => ({ response: jwe });
  const valid = () => encryptResponse(input.payload, input.recipient, { enc: input.enc });
  switch (fault) {
    case undefined:
      return encrypted(await valid());
    case 'response.unencrypted':
      return {
        vp_token: JSON.stringify(input.payload.vp_token),
        ...(input.payload.state !== undefined ? { state: String(input.payload.state) } : {}),
      };
    case 'response.foreign-key': {
      const { publicKey } = await generateKeyPair('ECDH-ES', { crv: 'P-256', extractable: true });
      return encrypted(await encryptResponse(input.payload, await exportJWK(publicKey), { enc: input.enc, kid: input.recipient.kid }));
    }
    case 'response.other-transaction-key':
      if (!input.otherTransactionKey) throw new Error('response.other-transaction-key needs the key of another transaction');
      return encrypted(await encryptResponse(input.payload, input.otherTransactionKey, { enc: input.enc }));
    case 'response.alg-ecdh-es-a128kw':
      return encrypted(await encryptResponse(input.payload, input.recipient, { alg: 'ECDH-ES+A128KW', enc: input.enc }));
    case 'response.alg-ecdh-es-a256kw':
      return encrypted(await encryptResponse(input.payload, input.recipient, { alg: 'ECDH-ES+A256KW', enc: input.enc }));
    case 'response.enc-a128cbc-hs256':
      return encrypted(await encryptResponse(input.payload, input.recipient, { enc: 'A128CBC-HS256' }));
    case 'response.ciphertext-bitflip':
      return encrypted(flipBitInSegment(await valid(), 3));
    case 'response.tag-bitflip':
      return encrypted(flipBitInSegment(await valid(), 4));
    case 'response.epk-off-curve':
      return encrypted(replaceEpk(await valid(), offCurvePoint()));
    case 'response.epk-p384': {
      const { publicKey } = await generateKeyPair('ECDH-ES', { crv: 'P-384', extractable: true });
      return encrypted(replaceEpk(await valid(), await exportJWK(publicKey)));
    }
    case 'response.jws':
      return {
        response: await new CompactSign(new TextEncoder().encode(JSON.stringify(input.payload)))
          .setProtectedHeader({ alg: 'ES256', jwk: input.walletKey.publicJwk as JWK })
          .sign(input.walletKey.privateKey),
      };
    case 'response.alg-none':
      return {
        response: `${base64url.encode(JSON.stringify({ alg: 'none' }))}.${base64url.encode(JSON.stringify(input.payload))}.`,
      };
    case 'response.extra-member':
      return encrypted(await encryptResponse({ ...input.payload, foo: 'bar' }, input.recipient, { enc: input.enc }));
    default:
      throw new Error(`fault ${fault} is not implemented`);
  }
}
