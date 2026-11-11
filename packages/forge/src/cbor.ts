// Raw CBOR and COSE for the fault layer, the Conformance Wallet and the reference validator. `cborg` keeps every tag
// as a `Tagged` value and every map as a `Map`, without the global extensions of cbor-x (which `@owf/cose` registers,
// and which turn a tag 18 into a validated `Sign1`), so a deliberately broken structure decodes as what it is.
import { decode, encode, Tagged } from 'cborg';
import { signEs256 } from './crypto';

export { Tagged };

/** The tags of mdoc, COSE and CWT: tdate (0), epoch date (1), COSE_Mac0 (17), COSE_Sign1 (18), embedded CBOR (24), full-date (1004). */
const TAGS = [0, 1, 17, 18, 24, 1004];

export type CborMap = Map<unknown, unknown>;

/** Decodes CBOR with maps as `Map` and the mdoc and COSE tags as `Tagged`; other tags fail. */
export function decodeCbor<T = unknown>(bytes: Uint8Array): T {
  return decode(bytes, { useMaps: true, tags: Tagged.preserve(...TAGS) }) as T;
}

/** Encodes CBOR (maps in the deterministic order of RFC 8949 section 4.2.1, as `cborg` sorts them). */
export function encodeCbor(value: unknown): Uint8Array {
  return encode(value);
}

/** `#6.24(bstr .cbor value)`: an embedded CBOR data item. */
export const embedded = (value: unknown) => new Tagged(24, encodeCbor(value));

/** The content of a tag 24 data item, decoded. */
export function decodeEmbedded<T = unknown>(value: unknown): T {
  if (!(value instanceof Tagged) || value.tag !== 24 || !(value.value instanceof Uint8Array)) throw new Error('not an embedded CBOR data item (tag 24)');
  return decodeCbor<T>(value.value);
}

/** A tdate (`#6.0(tstr)`) without fractional seconds, as ISO/IEC 18013-5 section 7.2.1 encodes it. */
export const tdate = (date: Date) => new Tagged(0, `${date.toISOString().split('.')[0]}Z`);

/** Reads a tdate or epoch date. */
export function dateOf(value: unknown): Date | undefined {
  if (!(value instanceof Tagged)) return undefined;
  if (value.tag === 0 && typeof value.value === 'string') {
    const date = new Date(value.value);
    return Number.isNaN(date.getTime()) ? undefined : date;
  }
  if (value.tag === 1 && typeof value.value === 'number') return new Date(value.value * 1000);
  return undefined;
}

/** COSE header labels (RFC 9052, RFC 9360, RFC 9596). */
export const COSE = { alg: 1, kid: 4, typ: 16, x5chain: 33 } as const;
/** COSE algorithms: ES256, ES256K (RFC 8812), HMAC 256/256. */
export const COSE_ALG = { ES256: -7, ES256K: -47, HMAC256: 5 } as const;

/** A COSE_Sign1 or COSE_Mac0 with its protected header decoded. */
export interface CoseStructure {
  /** 18 (COSE_Sign1), 17 (COSE_Mac0), or undefined when untagged. */
  tag?: number;
  protectedBytes: Uint8Array;
  protectedHeader: CborMap;
  unprotectedHeader: CborMap;
  payload: Uint8Array | null;
  /** The signature (COSE_Sign1) or the authentication tag (COSE_Mac0). */
  signature: Uint8Array;
}

/** Reads a COSE_Sign1 or COSE_Mac0 array (tagged or not); throws when it is not one. */
export function readCose(value: unknown): CoseStructure {
  const tag = value instanceof Tagged ? value.tag : undefined;
  const array = value instanceof Tagged ? value.value : value;
  if (!Array.isArray(array) || array.length !== 4) throw new Error('not a COSE structure: expected an array of four');
  const [protectedBytes, unprotectedHeader, payload, signature] = array;
  if (!(protectedBytes instanceof Uint8Array)) throw new Error('the protected header is not a byte string');
  if (!(unprotectedHeader instanceof Map)) throw new Error('the unprotected header is not a map');
  if (payload !== null && !(payload instanceof Uint8Array)) throw new Error('the payload is neither a byte string nor nil');
  if (!(signature instanceof Uint8Array)) throw new Error('the signature is not a byte string');
  const protectedHeader = protectedBytes.length === 0 ? new Map() : decodeCbor<unknown>(protectedBytes);
  if (!(protectedHeader instanceof Map)) throw new Error('the protected header is not a map');
  return { tag, protectedBytes, protectedHeader, unprotectedHeader, payload, signature };
}

/** The COSE structure as an array, tagged when `tag` is set. */
export function coseValue(structure: Omit<CoseStructure, 'protectedHeader'>): unknown {
  const array = [structure.protectedBytes, structure.unprotectedHeader, structure.payload, structure.signature];
  return structure.tag === undefined ? array : new Tagged(structure.tag, array);
}

/** `Sig_structure` of a COSE_Sign1 (RFC 9052 section 4.4), with an empty external AAD. */
export const sigStructure = (protectedBytes: Uint8Array, payload: Uint8Array) =>
  encodeCbor(['Signature1', protectedBytes, new Uint8Array(0), payload]);

/** `MAC_structure` of a COSE_Mac0 (RFC 9052 section 6.3), with an empty external AAD. */
export const macStructure = (protectedBytes: Uint8Array, payload: Uint8Array) =>
  encodeCbor(['MAC0', protectedBytes, new Uint8Array(0), payload]);

/** Signs a COSE_Sign1 with ES256 over `payload` (or over `detached` when the payload is nil). */
export async function signCoseSign1(options: {
  protectedHeader: CborMap;
  unprotectedHeader?: CborMap;
  payload: Uint8Array | null;
  detached?: Uint8Array;
  privateKey: CryptoKey;
  tag?: number;
}): Promise<unknown> {
  const protectedBytes = encodeCbor(options.protectedHeader);
  const signed = options.payload ?? options.detached;
  if (!signed) throw new Error('nothing to sign');
  const signature = await signEs256(options.privateKey, sigStructure(protectedBytes, signed));
  return coseValue({ tag: options.tag, protectedBytes, unprotectedHeader: options.unprotectedHeader ?? new Map(), payload: options.payload, signature });
}

/** The `x5chain` header value (RFC 9360): one certificate as a byte string, several as an array. */
export const x5chainValue = (certificates: Uint8Array[]) => (certificates.length === 1 ? certificates[0] : certificates);

/** The certificates of an `x5chain` header value, or undefined when it is not one. */
export function x5chainOf(value: unknown): Uint8Array[] | undefined {
  if (value instanceof Uint8Array) return [value];
  if (Array.isArray(value) && value.length > 0 && value.every((c) => c instanceof Uint8Array)) return value as Uint8Array[];
  return undefined;
}
