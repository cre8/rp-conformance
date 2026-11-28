// The faults of RP_WS_SH_Encoding (catalogue section 5.1.6): malformed encodings built from a valid artifact. The
// Authorization Response, the presented SD-JWT VC or DeviceResponse, or the issued credential is built valid first and
// then broken in exactly one way; every signature that still covers the changed bytes is computed again, so the
// encoding is the only defect. The fault layer (faults.ts, faults-cose.ts, presentation.ts) calls these first.
import { createHash, randomBytes } from 'node:crypto';
import type { FaultId } from '@eudi-pcaf/core';
import { type CborMap, COSE, coseValue, decodeCbor, encodeCbor, readCose } from './cbor';
import { base64url, signEs256 } from './crypto';
import { decodeJws, resignJws } from './jose';
import { type CertifiedKey, createSelfSignedCa } from './pki';

/** The faults this module implements, by the point they apply to. */
export const ROBUSTNESS_FAULTS = {
  response: ['response.jwe-four-segments', 'response.jwe-not-base64url', 'response.oversized'],
  sdJwtPresentation: [
    'presentation.sd-jwt-no-separator',
    'presentation.sd-jwt-empty-disclosure',
    'presentation.kb-payload-nan',
    'presentation.kb-duplicate-alg',
    'presentation.kb-duplicate-nonce',
  ],
  mdocPresentation: [
    'presentation.device-response-truncated',
    'presentation.device-response-documents-map',
    'presentation.device-response-deep-nesting',
    'presentation.device-response-unterminated',
  ],
  sdJwtCredential: ['credential.disclosure-invalid-json', 'credential.x5c-50'],
  mdocCredential: ['mdoc.x5chain-50'],
} as const satisfies Record<string, FaultId[]>;

const isOneOf = (list: readonly FaultId[], fault: FaultId | undefined): boolean => fault !== undefined && list.includes(fault);

/** Number of certificates in the excessive `x5c` and `x5chain` (RP_WS_SH_Encoding_006). */
export const EXCESSIVE_CHAIN_LENGTH = 50;
/** Nesting depth of the deeply nested DeviceResponse (RP_WS_SH_Encoding_003). */
export const DEEP_NESTING = 10_000;
const MIB = 1024 * 1024;

// --------------------------------------------------------------------------- Authorization Response

/**
 * The `response` parameter with a robustness fault, or undefined for another fault. `valid` encrypts a payload as the
 * valid response does; `maxResponseBytes` is the maximum response size the Relying Party declares (ICS RP.P.11).
 */
export async function robustResponse(
  fault: FaultId | undefined,
  payload: Record<string, unknown>,
  valid: (payload: Record<string, unknown>) => Promise<string>,
  maxResponseBytes: number | undefined,
): Promise<Record<string, string> | undefined> {
  if (!isOneOf(ROBUSTNESS_FAULTS.response, fault)) return undefined;
  switch (fault) {
    case 'response.jwe-four-segments':
      return { response: (await valid(payload)).split('.').slice(0, 4).join('.') };
    case 'response.jwe-not-base64url': {
      const [header, ...rest] = (await valid(payload)).split('.');
      const at = Math.floor((header ?? '').length / 2);
      return { response: [`${header?.slice(0, at)}*!${header?.slice(at)}`, ...rest].join('.') };
    }
    case 'response.oversized': {
      if (!maxResponseBytes) throw new Error('response.oversized needs the maximum response size the Relying Party declares');
      // The ciphertext is as long as the payload and base64url adds a third, so this padding makes the JWE exceed the
      // maximum by at least one MiB.
      const padding = 'a'.repeat(Math.ceil(((maxResponseBytes + MIB) * 3) / 4));
      return { response: await valid({ ...payload, padding }) };
    }
    default:
      return undefined;
  }
}

// --------------------------------------------------------------------------- presentation

/** Whether `fault` is a robustness fault of an SD-JWT VC presentation. */
export const isRobustSdJwtPresentationFault = (fault: FaultId | undefined) => isOneOf(ROBUSTNESS_FAULTS.sdJwtPresentation, fault);
/** Whether `fault` is a robustness fault of an mdoc DeviceResponse. */
export const isRobustDeviceResponseFault = (fault: FaultId | undefined) => isOneOf(ROBUSTNESS_FAULTS.mdocPresentation, fault);

/** A KB-JWT signed with ES256 over a header and payload given as JSON text, which may be invalid or hold duplicates. */
const signRaw = async (header: string, payload: string, key: CryptoKey) => {
  const input = `${base64url.encode(header)}.${base64url.encode(payload)}`;
  return `${input}.${base64url.encode(await signEs256(key, input))}`;
};

/** JSON text of an object with one more member, appended after the existing ones. */
const withMember = (value: Record<string, unknown>, name: string, member: unknown) =>
  `${JSON.stringify(value).slice(0, -1)},${JSON.stringify(name)}:${JSON.stringify(member)}}`;

/** Breaks the encoding of a valid SD-JWT VC presentation (`<SD-JWT>~<KB-JWT>`); the KB-JWT is signed with `holderKey`. */
export async function robustSdJwtPresentation(valid: string, fault: FaultId, holderKey: CryptoKey): Promise<string> {
  const cut = valid.lastIndexOf('~') + 1;
  const sdJwt = valid.slice(0, cut);
  const kbJwt = valid.slice(cut);
  const { header, payload } = decodeJws(kbJwt);
  switch (fault) {
    case 'presentation.sd-jwt-no-separator':
      return `${sdJwt.slice(0, -1)}${kbJwt}`;
    case 'presentation.sd-jwt-empty-disclosure': {
      const [jwt, first, ...others] = sdJwt.split('~');
      if (!first || others.filter(Boolean).length === 0) throw new Error('the presentation needs two disclosures for an empty segment between them');
      const changed = [jwt, first, '', ...others].join('~');
      const sdHash = base64url.encode(createHash('sha256').update(changed).digest());
      return changed + (await resignJws(kbJwt, ({ payload: p }) => void (p.sd_hash = sdHash), holderKey));
    }
    case 'presentation.kb-payload-nan':
      return sdJwt + (await signRaw(JSON.stringify(header), JSON.stringify(payload).replace(/"iat":-?\d+/, '"iat":NaN'), holderKey));
    case 'presentation.kb-duplicate-alg':
      return sdJwt + (await signRaw(withMember({ ...header, alg: 'ES256' }, 'alg', 'none'), JSON.stringify(payload), holderKey));
    case 'presentation.kb-duplicate-nonce':
      return sdJwt + (await signRaw(JSON.stringify(header), withMember(payload, 'nonce', base64url.encode(randomBytes(16))), holderKey));
    default:
      throw new Error(`fault ${fault} is not a robustness fault of an SD-JWT VC presentation`);
  }
}

/** A CBOR map encoded member by member, so its length can be indefinite and its values raw bytes. */
function rawMap(entries: [string, Uint8Array][], indefinite: boolean): Uint8Array {
  const parts = entries.flatMap(([key, value]) => [encodeCbor(key), value]);
  // A definite map of up to 23 entries has the initial byte 0xa0 + n; an indefinite one 0xbf (and a final 0xff).
  return Buffer.concat([Uint8Array.of(indefinite ? 0xbf : 0xa0 + entries.length), ...parts]);
}

/** Breaks the encoding of a valid DeviceResponse (CBOR bytes). */
export function robustDeviceResponse(valid: Uint8Array, fault: FaultId): Uint8Array {
  const response = decodeCbor<CborMap>(valid);
  const entries = (replace?: Uint8Array) =>
    [...response.entries()].map(([key, value]) => [String(key), key === 'documents' && replace ? replace : encodeCbor(value)] as [string, Uint8Array]);
  switch (fault) {
    case 'presentation.device-response-truncated':
      return valid.slice(0, Math.floor(valid.length / 2));
    case 'presentation.device-response-documents-map': {
      const documents = response.get('documents') as unknown[];
      response.set('documents', new Map([[0, documents[0]]]));
      return encodeCbor(response);
    }
    case 'presentation.device-response-deep-nesting': {
      // 0x81: an array of one element, DEEP_NESTING - 1 times, around 0x80, an empty array.
      const nested = new Uint8Array(DEEP_NESTING).fill(0x81);
      nested[DEEP_NESTING - 1] = 0x80;
      return rawMap(entries(nested), false);
    }
    case 'presentation.device-response-unterminated':
      return rawMap(entries(), true);
    default:
      throw new Error(`fault ${fault} is not a robustness fault of a DeviceResponse`);
  }
}

// --------------------------------------------------------------------------- credential

/** Whether `fault` is a robustness fault of an issued SD-JWT VC. */
export const isRobustSdJwtCredentialFault = (fault: FaultId | undefined) => isOneOf(ROBUSTNESS_FAULTS.sdJwtCredential, fault);
/** Whether `fault` is a robustness fault of an issued mdoc. */
export const isRobustMdocCredentialFault = (fault: FaultId | undefined) => isOneOf(ROBUSTNESS_FAULTS.mdocCredential, fault);

let excessiveChain: Promise<Uint8Array[]> | undefined;

/** 49 self-signed CA certificates on no list, created once per process: the tail of the excessive chain. */
function excessiveChainTail(): Promise<Uint8Array[]> {
  excessiveChain ??= (async () => {
    const now = Date.now();
    const validity = { notBefore: new Date(now - 24 * 3600_000), notAfter: new Date(now + 365 * 24 * 3600_000) };
    const cas: CertifiedKey[] = [];
    for (let i = 1; i < EXCESSIVE_CHAIN_LENGTH; i++) cas.push(await createSelfSignedCa('rp-conformance robustness', `Excessive chain CA ${i}`, validity));
    return cas.map((ca) => ca.certificate.der);
  })();
  return excessiveChain;
}

const SALT = () => base64url.encode(randomBytes(16));

/** Breaks the encoding of an issued SD-JWT VC (`<Issuer-signed JWT>~<disclosures>~`), signing it again with `signer`. */
export async function robustSdJwtCredential(sdJwt: string, fault: FaultId, signer: CertifiedKey): Promise<string> {
  const [jwt, ...rest] = sdJwt.split('~');
  const disclosures = rest.filter(Boolean);
  const digest = (disclosure: string) => base64url.encode(createHash('sha256').update(disclosure).digest());
  switch (fault) {
    case 'credential.disclosure-invalid-json': {
      const index = disclosures.findIndex((d) => {
        try {
          return base64url.decodeJson<unknown[]>(d)[1] === 'family_name';
        } catch {
          return false;
        }
      });
      if (index < 0) throw new Error('the credential has no disclosure of family_name');
      const value = base64url.decodeJson<unknown[]>(disclosures[index] as string)[2];
      // The JSON array without its closing bracket.
      const broken = base64url.encode(`[${JSON.stringify(SALT())}, "family_name", ${JSON.stringify(value)}`);
      const old = digest(disclosures[index] as string);
      const resigned = await resignJws(
        jwt,
        ({ payload }) => {
          const sd = payload._sd as string[];
          const at = sd.indexOf(old);
          if (at < 0) throw new Error('the digest of family_name is not in the top-level _sd array');
          sd[at] = digest(broken);
        },
        signer.key.privateKey,
      );
      disclosures[index] = broken;
      return `${[resigned, ...disclosures].join('~')}~`;
    }
    case 'credential.x5c-50': {
      const tail = (await excessiveChainTail()).map((der) => Buffer.from(der).toString('base64'));
      const resigned = await resignJws(
        jwt,
        ({ header }) => void (header.x5c = [(header.x5c as string[])[0], ...tail]),
        signer.key.privateKey,
      );
      return `${[resigned, ...disclosures].join('~')}~`;
    }
    default:
      throw new Error(`fault ${fault} is not a robustness fault of an SD-JWT VC`);
  }
}

/** Breaks the encoding of an issued mdoc (`IssuerSigned`, CBOR). */
export async function robustMdocCredential(issuerSignedBytes: Uint8Array, fault: FaultId): Promise<Uint8Array> {
  const issuerSigned = decodeCbor<CborMap>(issuerSignedBytes);
  const issuerAuth = readCose(issuerSigned.get('issuerAuth'));
  switch (fault) {
    case 'mdoc.x5chain-50': {
      // The x5chain is in the unprotected header, which the signature does not cover.
      const unprotected = new Map(issuerAuth.unprotectedHeader);
      const current = unprotected.get(COSE.x5chain);
      const leaf = current instanceof Uint8Array ? current : (current as Uint8Array[])[0];
      unprotected.set(COSE.x5chain, [leaf, ...(await excessiveChainTail())]);
      issuerSigned.set('issuerAuth', coseValue({ ...issuerAuth, unprotectedHeader: unprotected }));
      return encodeCbor(issuerSigned);
    }
    default:
      throw new Error(`fault ${fault} is not a robustness fault of an mdoc`);
  }
}
