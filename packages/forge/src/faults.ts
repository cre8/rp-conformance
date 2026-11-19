// The fault layer (harness design section 4.3): pure, named functions that turn a valid artifact into one with exactly
// one deliberate fault. The catalogue (point, target check, FCAF wording) is FAULTS in @rp-conformance/core; this
// module implements every entry, at three points: the issued credential, the Status List Token, the Authorization
// Response.
import { createHash, createHmac, createPublicKey, generateKeyPairSync, randomBytes, randomUUID, sign as nodeSign } from 'node:crypto';
import { createDeflate } from 'node:zlib';
import { type FaultId, faultInfo, type FaultPoint, type Flow } from '@rp-conformance/core';
import { CompactEncrypt, CompactSign, exportJWK, generateKeyPair, importJWK, type JWK } from 'jose';
import { createCertificate } from '@owf/x509';
import { base64url, derEcdsaSignature, type EcKeyPair, randomSerial, sha256, signEs256 } from './crypto';
import { decodeJws, flipBitInSegment, resignJws } from './jose';
import { type CertifiedKey, createEndEntity, createSelfSignedCa, createSelfSignedSigner, type TestEntity, type TestPki } from './pki';
import { foreignSigner, isSignerFault } from './signers';

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
  /** The issuing entity, for the faults that certify another key under its anchor. */
  issuer?: TestEntity;
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
  'credential.no-cnf': (p) => void delete p.cnf,
  'credential.minimal-cnf-jwk': (p) => {
    const jwk = (p.cnf as { jwk?: JsonWebKey } | undefined)?.jwk;
    if (!jwk) throw new Error('the credential has no cnf.jwk');
    p.cnf = { jwk: { kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y } };
  },
};

function statusListOf(payload: Payload): Record<string, unknown> {
  const reference = payload.status?.status_list;
  if (!reference) throw new Error('the credential has no status reference to change');
  return reference;
}

/** A disclosure (RFC 9901 section 4.2): base64url of the JSON array, and its digest with `alg` (default SHA-256). */
export const encodeDisclosure = (elements: unknown[]) => base64url.encode(JSON.stringify(elements));
const NODE_HASH: Record<string, string> = { 'sha-256': 'sha256', md5: 'md5', 'sha-1': 'sha1' };
export const disclosureDigest = (disclosure: string, alg = 'sha-256') => base64url.encode(createHash(NODE_HASH[alg] ?? alg).update(disclosure).digest());
const decodeDisclosure = (disclosure: string) => base64url.decodeJson<unknown[]>(disclosure);
const salt = () => base64url.encode(randomBytes(16));

/** An issued SD-JWT VC taken apart: the issuer-signed JWT and its disclosures. */
interface SdJwtParts {
  jwt: string;
  disclosures: string[];
}

const indexOfClaim = (parts: SdJwtParts, name: string) => {
  const index = parts.disclosures.findIndex((d) => decodeDisclosure(d)[1] === name);
  if (index < 0) throw new Error(`the credential has no disclosure of ${name}`);
  return index;
};

/** Replaces a digest in the payload's top-level `_sd`. */
const replaceDigest = (payload: Payload, from: string, to: string[]) => {
  const sd = (payload._sd as string[] | undefined) ?? [];
  const at = sd.indexOf(from);
  if (at < 0) throw new Error('the digest is not in _sd');
  sd.splice(at, 1, ...to);
  payload._sd = sd;
};

/**
 * The faults of the disclosures (IssuerIntegrity_008 to _012, _014, _015): change the disclosures, and the issuer-signed
 * payload where the fault names it, which the issuer's key then signs again.
 */
async function applyDisclosureFault(fault: FaultId, parts: SdJwtParts, ctx: CredentialFaultContext): Promise<SdJwtParts | undefined> {
  const resign = (change: (payload: Payload) => void) => resignJws(parts.jwt, ({ payload }) => change(payload as Payload), ctx.signer.key.privateKey);
  const disclosures = [...parts.disclosures];
  switch (fault) {
    case 'credential.disclosure-foreign':
      return { jwt: parts.jwt, disclosures: [...disclosures, encodeDisclosure([salt(), 'family_name', 'Musterfrau'])] };
    case 'credential.disclosure-modified': {
      const at = indexOfClaim(parts, 'family_name');
      const [s, name] = decodeDisclosure(disclosures[at]);
      disclosures[at] = encodeDisclosure([s, name, 'Musterfrau']);
      return { jwt: parts.jwt, disclosures };
    }
    case 'credential.disclosure-duplicate': {
      const at = indexOfClaim(parts, 'family_name');
      disclosures.splice(at + 1, 0, disclosures[at]);
      return { jwt: parts.jwt, disclosures };
    }
    case 'credential.digest-duplicate': {
      const digest = disclosureDigest(disclosures[indexOfClaim(parts, 'family_name')]);
      return { jwt: await resign((p) => void (p._sd as string[]).push(digest)), disclosures };
    }
    case 'credential.disclosure-name-sd':
    case 'credential.disclosure-name-ellipsis': {
      const extra = encodeDisclosure([salt(), fault === 'credential.disclosure-name-sd' ? '_sd' : '...', 'x']);
      return { jwt: await resign((p) => void (p._sd as string[]).push(disclosureDigest(extra))), disclosures: [...disclosures, extra] };
    }
    case 'credential.disclosure-name-present': {
      const value = decodeDisclosure(disclosures[indexOfClaim(parts, 'family_name')])[2];
      return { jwt: await resign((p) => void (p.family_name = value)), disclosures };
    }
    case 'credential.disclosure-two-elements': {
      const at = indexOfClaim(parts, 'family_name');
      const [s, , value] = decodeDisclosure(disclosures[at]);
      const old = disclosures[at];
      disclosures[at] = encodeDisclosure([s, value]);
      return { jwt: await resign((p) => replaceDigest(p, disclosureDigest(old), [disclosureDigest(disclosures[at])])), disclosures };
    }
    case 'credential.disclosure-four-elements': {
      const at = indexOfClaim(parts, 'family_name');
      const [s, name, value] = decodeDisclosure(disclosures[at]);
      const old = disclosures[at];
      disclosures[at] = encodeDisclosure([s, name, value, 'extra']);
      return { jwt: await resign((p) => replaceDigest(p, disclosureDigest(old), [disclosureDigest(disclosures[at])])), disclosures };
    }
    case 'credential.disclosure-array-three-elements': {
      const at = indexOfClaim(parts, 'nationalities');
      const old = disclosures[at];
      const [first] = decodeDisclosure(old)[2] as unknown[];
      const element = encodeDisclosure([salt(), 'nationality', first]);
      disclosures.splice(at, 1, element);
      const jwt = await resign((p) => {
        replaceDigest(p, disclosureDigest(old), []);
        p.nationalities = [{ '...': disclosureDigest(element) }];
      });
      return { jwt, disclosures };
    }
    case 'credential.sd-alg-md5':
    case 'credential.sd-alg-sha1': {
      const alg = fault === 'credential.sd-alg-md5' ? 'md5' : 'sha-1';
      const jwt = await resign((p) => {
        p._sd = (p._sd as string[]).map((digest) => {
          const disclosure = disclosures.find((d) => disclosureDigest(d) === digest);
          return disclosure ? disclosureDigest(disclosure, alg) : digest;
        });
        p._sd_alg = alg;
      });
      return { jwt, disclosures };
    }
    case 'credential.decoys': {
      const decoys = [0, 1, 2].map(() => base64url.encode(sha256(randomBytes(32))));
      return { jwt: await resign((p) => void (p._sd as string[]).push(...decoys)), disclosures };
    }
    case 'credential.recursive-disclosures': {
      const at = indexOfClaim(parts, 'place_of_birth');
      const old = disclosures[at];
      const value = decodeDisclosure(old)[2] as Record<string, unknown>;
      const members = Object.entries(value).map(([name, v]) => encodeDisclosure([salt(), name, v]));
      disclosures[at] = encodeDisclosure([salt(), 'place_of_birth', { _sd: members.map((d) => disclosureDigest(d)).sort() }]);
      disclosures.push(...members);
      return { jwt: await resign((p) => replaceDigest(p, disclosureDigest(old), [disclosureDigest(disclosures[at])])), disclosures };
    }
    default:
      return undefined;
  }
}

const join = (parts: SdJwtParts) => `${[parts.jwt, ...parts.disclosures].join('~')}~`;

/** Applies a credential fault to an issued SD-JWT VC (issuer-signed JWT `~` disclosures `~`, without KB-JWT). */
export async function applyCredentialFault(fault: FaultId, sdJwt: string, ctx: CredentialFaultContext): Promise<string> {
  ensurePoint(fault, 'credential', 'dc+sd-jwt');
  const [issuerJwt, ...rest] = sdJwt.split('~');
  const parts: SdJwtParts = { jwt: issuerJwt, disclosures: rest.filter(Boolean) };
  // A signer fault is applied when the credential is issued (forgePresentation).
  if (isSignerFault(fault)) return sdJwt;
  const unsigned = (header: Record<string, unknown>) => {
    const decoded = decodeJws(issuerJwt);
    return `${base64url.encode(JSON.stringify({ ...decoded.header, ...header }))}.${base64url.encode(JSON.stringify(decoded.payload))}`;
  };
  const withJwt = (jwt: string) => join({ ...parts, jwt });
  switch (fault) {
    case 'credential.signature-bitflip':
      return withJwt(flipBitInSegment(issuerJwt, 2));
    case 'credential.signature-der': {
      const [header, payload, signature] = issuerJwt.split('.');
      return withJwt(`${header}.${payload}.${base64url.encode(derEcdsaSignature(base64url.decode(signature ?? '')))}`);
    }
    case 'credential.alg-none':
      return withJwt(`${unsigned({ alg: 'none' })}.`);
    case 'credential.alg-hs256': {
      const input = unsigned({ alg: 'HS256' });
      return withJwt(`${input}.${base64url.encode(createHmac('sha256', hmacKeyOf(ctx.signer)).update(input).digest())}`);
    }
    case 'credential.es256k':
    case 'credential.key-p192':
    case 'credential.key-rsa1024': {
      if (!ctx.issuer) throw new Error(`fault ${fault} needs the issuing entity`);
      const kind = fault === 'credential.es256k' ? 'secp256k1' : fault === 'credential.key-p192' ? 'p192' : 'rsa1024';
      const signer = await foreignSigner(kind, ctx.issuer, 'dc+sd-jwt', ctx.now);
      const input = unsigned({ alg: signer.jwsAlg, x5c: [Buffer.from(signer.certificate.der).toString('base64')] });
      return withJwt(`${input}.${base64url.encode(signer.sign(input))}`);
    }
    case 'credential.no-x5c':
      return withJwt(await resignJws(issuerJwt, ({ header }) => void delete header.x5c, ctx.signer.key.privateKey));
    case 'credential.typ-missing':
      return withJwt(await resignJws(issuerJwt, ({ header }) => void delete header.typ, ctx.signer.key.privateKey));
    case 'credential.typ-jwt':
      return withJwt(await resignJws(issuerJwt, ({ header }) => void (header.typ = 'JWT'), ctx.signer.key.privateKey));
    case 'credential.typ-vc-sd-jwt':
      return withJwt(await resignJws(issuerJwt, ({ header }) => void (header.typ = 'vc+sd-jwt'), ctx.signer.key.privateKey));
    case 'credential.vct-other':
      return withJwt(await resignJws(issuerJwt, ({ payload }) => void (payload.vct = 'urn:eudi:other:1'), ctx.signer.key.privateKey));
  }
  const disclosed = await applyDisclosureFault(fault, parts, ctx);
  if (disclosed) return join(disclosed);
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
  /** The HTTP status the Test Status Provider answers with; 200 when left out. */
  status?: number;
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
    case 'status-list.html-error-page':
      return {
        body: '<!doctype html><html><head><title>503 Service Unavailable</title></head><body><h1>Service Unavailable</h1></body></html>',
        contentType: 'text/html',
        status: 503,
      };
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

/** Encrypts a response payload as `direct_post.jwt` or `dc_api.jwt` (ECDH-ES unless `alg` says otherwise). */
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

function ensureFlow(fault: FaultId, flow: Flow) {
  ensurePoint(fault, 'response');
  const faultFlow = faultInfo(fault).flow;
  if (faultFlow && faultFlow !== flow) throw new Error(`fault ${fault} applies to the ${faultFlow} flow, not ${flow}`);
}

/**
 * The form parameters the Conformance Wallet posts to `response_uri` (response mode `direct_post.jwt`): the valid
 * response, or one with a fault.
 */
export async function buildAuthorizationResponse(input: ResponseInput, fault?: FaultId): Promise<Record<string, string>> {
  if (fault) ensureFlow(fault, 'redirect');
  return buildEncryptedResponse(input, fault);
}

/**
 * The `data` object the Conformance Wallet returns through the W3C Digital Credentials API (OpenID4VP 1.0 Appendix
 * A.4, response mode `dc_api.jwt`): `response` with the JWE, or the response with a fault. The payload carries no
 * `state`, which the DC API does not use.
 */
export async function buildDcApiResponse(input: ResponseInput, fault?: FaultId): Promise<Record<string, unknown>> {
  if (fault) ensureFlow(fault, 'dc-api');
  if (fault === 'response.dc-api-unencrypted') return { vp_token: input.payload.vp_token };
  return buildEncryptedResponse(input, fault);
}

/** The `response` parameter of both flows: the JWE, or the response fault that both flows share. */
async function buildEncryptedResponse(input: ResponseInput, fault?: FaultId): Promise<Record<string, string>> {
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
