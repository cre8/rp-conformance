// The status list procedures of the reference validator (Token Status List sections 4, 5 and 8; ISO/IEC 18013-5 second
// edition section 12.3.6): one named check per property, for a Status List Token in JWT or CWT format.
import { inflateSync } from 'node:zlib';
import { type CborMap, COSE, COSE_ALG, base64url, decodeCbor, readCose, sigStructure, verifyEs256, x5chainOf } from '@rp-conformance/forge';
import { parseCertificate } from '@owf/x509';
import { CheckFailure, type CheckRecorder, NotApplicable } from './checks';
import type { MatchedIssuer } from './trust';
import { validatePath } from './x509-path';

export interface FetchedStatusList {
  status: number;
  /** The body as received: text for a JWT, bytes for a CWT. */
  body: string | Uint8Array;
  contentType?: string | null;
}

export const fail = (message: string): never => {
  throw new CheckFailure(message);
};

export const isUri = (value: unknown) => {
  if (typeof value !== 'string') return false;
  try {
    const url = new URL(value);
    return url.protocol === 'https:' || url.protocol === 'http:';
  } catch {
    return false;
  }
};

export const decodeSegment = (segment: string | undefined, what: string): Record<string, unknown> => {
  let value: unknown;
  try {
    value = base64url.decodeJson(segment ?? '');
  } catch {
    throw new CheckFailure(`${what} cannot be decoded`);
  }
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new CheckFailure(`${what} is not a JSON object`);
  return value as Record<string, unknown>;
};

export const leafJwk = (x5c: unknown): JsonWebKey | undefined => {
  if (!Array.isArray(x5c) || (typeof x5c[0] !== 'string' && !(x5c[0] instanceof Uint8Array))) return undefined;
  return parseCertificate(x5c[0]).publicKey.jwk;
};

/** Base64 DER of certificates, as `validatePath` takes them. */
export const base64Of = (certificates: Uint8Array[]) => certificates.map((c) => Buffer.from(c).toString('base64'));

const asText = (body: string | Uint8Array) => (typeof body === 'string' ? body : new TextDecoder().decode(body));
const asBytes = (body: string | Uint8Array) => (typeof body === 'string' ? new TextEncoder().encode(body) : body);

/** CWT claim keys (RFC 8392) and the claims of Token Status List section 5.2 and ISO/IEC 18013-5 section 12.3.6.4. */
export const CWT = { iss: 1, sub: 2, exp: 4, iat: 6, identifierList: 65530, statusList: 65533, ttl: 65534 } as const;

export interface StatusListInput {
  format: 'jwt' | 'cwt';
  /** The credential's reference. */
  reference: { uri: string; idx: number } | undefined;
  /** The trusted issuer the credential matched, with the anchors its status lists must be signed under. */
  issuer: MatchedIssuer | undefined;
  fetchStatusList: (uri: string) => Promise<FetchedStatusList>;
  maxStatusListBytes: number;
  validStatuses?: number[];
  skewSeconds: number;
  now: Date;
  /** Called right before the status list is requested. */
  onFetched?: () => void;
}

/** A Status List Token decoded in either format: its header, its claims and what was signed. */
interface DecodedToken {
  typ: unknown;
  alg: unknown;
  /** The signer chain, leaf first, as base64 DER, or undefined when the token carries none. */
  chain?: string[];
  sub: unknown;
  iat: unknown;
  exp: unknown;
  list: unknown;
  verify: (jwk: JsonWebKey) => Promise<boolean>;
}

/**
 * Runs the status list checks for a credential's status reference, in the order of Token Status List section 8.
 * Without a reference they are skipped. The check IDs are the same for both formats.
 */
export async function evaluateStatusList(recorder: CheckRecorder, input: StatusListInput): Promise<void> {
  const { reference, now } = input;
  const nowSeconds = Math.floor(now.getTime() / 1000);
  const skew = input.skewSeconds;
  const noReference = () => (reference ? undefined : new NotApplicable('the credential has no status reference'));
  let body: string | Uint8Array = '';
  let token: DecodedToken | undefined;
  let decoded: Uint8Array | undefined;
  let bits = 0;

  await recorder.run('status-list-fetch', ['status-reference'], async () => {
    if (!reference) return noReference();
    input.onFetched?.();
    const response = await input.fetchStatusList(reference.uri);
    if (response.status !== 200) fail(`HTTP ${response.status}`);
    body = response.body;
  });

  await recorder.run('status-list-format', ['status-list-fetch'], () => {
    token = input.format === 'jwt' ? decodeJwt(asText(body).trim()) : decodeCwt(asBytes(body));
  });

  const expectedTyp = input.format === 'jwt' ? 'statuslist+jwt' : 'application/statuslist+cwt';
  await recorder.run('status-list-type', ['status-list-format'], () => {
    if (token?.typ !== expectedTyp) fail(`typ is ${String(token?.typ)}, expected ${expectedTyp}`);
  });

  await recorder.run('status-list-trust', ['status-list-format', 'issuer-trust'], async () => {
    if (!token?.chain?.length) fail(`the Status List Token has no ${input.format === 'jwt' ? 'x5c' : 'x5chain in its protected header'}`);
    const path = await validatePath(token?.chain ?? [], input.issuer?.statusAnchors ?? [], now);
    if (!path.ok) fail(`not under a revocation anchor of ${input.issuer?.name}: ${path.reason}`);
    return path.ok ? `${path.leaf.subject.commonName} under ${path.anchor.subject.commonName}` : undefined;
  });

  await recorder.run('status-list-signature', ['status-list-format'], async () => {
    const expectedAlg = input.format === 'jwt' ? 'ES256' : COSE_ALG.ES256;
    if (token?.alg !== expectedAlg) fail(`alg ${String(token?.alg)} is not accepted`);
    if (!token?.chain?.length) return new NotApplicable('no signer certificate, so no key to verify with');
    const jwk = leafJwk(token.chain);
    if (!jwk || jwk.crv !== 'P-256') fail('the signing certificate has no P-256 key');
    if (!(await token.verify(jwk as JsonWebKey))) fail('the Status List Token signature does not verify');
  });

  await recorder.run('status-list-claims', ['status-list-format'], () => {
    const missing = [
      typeof token?.sub !== 'string' && 'sub',
      typeof token?.iat !== 'number' && 'iat',
      !isMap(token?.list) && 'status_list',
    ].filter(Boolean);
    if (missing.length) fail(`missing ${missing.join(', ')}`);
    const list = token?.list;
    const listMissing = [field(list, 'bits') === undefined && 'bits', field(list, 'lst') === undefined && 'lst'].filter(Boolean);
    if (listMissing.length) fail(`status_list has no ${listMissing.join(', ')}`);
  });

  await recorder.run('status-list-subject', ['status-list-format'], () => {
    if (token?.sub === undefined) return new NotApplicable('no sub');
    if (token.sub !== reference?.uri) fail(`sub ${String(token.sub)} is not the credential's status uri`);
  });

  await recorder.run('status-list-validity', ['status-list-format'], () => {
    const exp = token?.exp;
    if (exp === undefined) return new NotApplicable('no exp');
    if (typeof exp !== 'number') fail('exp is not a number');
    if (nowSeconds > (exp as number) + skew) fail(`expired: exp ${exp}, now ${nowSeconds}, T_skew ${skew}`);
  });

  await recorder.run('status-list-decoding', ['status-list-format'], () => {
    const list = token?.list;
    const listBits = field(list, 'bits');
    const lst = field(list, 'lst');
    if (!isMap(list) || listBits === undefined || lst === undefined) return new NotApplicable('no bits or lst');
    if (![1, 2, 4, 8].includes(listBits as number)) fail(`bits ${String(listBits)} is not 1, 2, 4 or 8`);
    bits = listBits as number;
    let compressed: Uint8Array;
    if (input.format === 'jwt') {
      if (typeof lst !== 'string' || !/^[A-Za-z0-9_-]+$/.test(lst)) fail('lst is not base64url');
      compressed = Buffer.from(lst as string, 'base64url');
    } else {
      if (!(lst instanceof Uint8Array)) fail('lst is not a byte string');
      compressed = lst as Uint8Array;
    }
    try {
      decoded = new Uint8Array(inflateSync(compressed, { maxOutputLength: input.maxStatusListBytes }));
    } catch (error) {
      const tooLarge = (error as { code?: string }).code === 'ERR_BUFFER_TOO_LARGE' || error instanceof RangeError;
      fail(tooLarge ? `the status list decompresses to more than ${input.maxStatusListBytes} bytes` : `lst is not valid ZLIB data: ${(error as Error).message}`);
    }
    return `${decoded?.length} bytes, ${bits} bits per status`;
  });

  await recorder.run('status-index', ['status-list-decoding', 'status-reference'], () => {
    const entries = ((decoded?.length ?? 0) * 8) / bits;
    if (!reference || reference.idx >= entries) fail(`index ${reference?.idx} is outside the ${entries} entries of the status list`);
  });

  await recorder.run('status', ['status-index'], () => {
    const idx = reference?.idx ?? 0;
    const byte = decoded?.[Math.floor((idx * bits) / 8)] ?? 0;
    const value = (byte >> ((idx * bits) % 8)) & ((1 << bits) - 1);
    const hex = `0x${value.toString(16).padStart(2, '0')}`;
    if (value === 0) return `${hex} (VALID)`;
    if (input.validStatuses?.includes(value)) return `${hex}, declared as valid`;
    fail(`status ${hex} at index ${idx}${value === 1 ? ' (INVALID)' : value === 2 ? ' (SUSPENDED)' : ''}`);
  });
}

const isMap = (value: unknown): boolean => value instanceof Map || (Boolean(value) && typeof value === 'object' && !Array.isArray(value));
/** A member of a JSON object or an entry of a CBOR map. */
export const field = (value: unknown, key: string | number): unknown =>
  value instanceof Map ? value.get(key) : value && typeof value === 'object' ? (value as Record<string, unknown>)[key] : undefined;

/** Runs `fn`, failing the check with its error message (prefixed with `what`) when it throws. */
export function attempt<T>(fn: () => T, what?: string): T {
  try {
    return fn();
  } catch (error) {
    if (error instanceof CheckFailure) throw error;
    throw new CheckFailure(what ? `${what}: ${(error as Error).message}` : (error as Error).message);
  }
}

/** A Status List Token in JWT format (Token Status List section 5.1). */
function decodeJwt(compact: string): DecodedToken {
  const parts = compact.split('.');
  if (parts.length !== 3) fail(`not a compact JWS (${parts.length} parts)`);
  const header = decodeSegment(parts[0], 'the Status List Token header');
  const payload = decodeSegment(parts[1], 'the Status List Token payload');
  const x5c = header.x5c;
  return {
    typ: header.typ,
    alg: header.alg,
    chain: Array.isArray(x5c) && x5c.length > 0 && x5c.every((c) => typeof c === 'string') ? (x5c as string[]) : undefined,
    sub: payload.sub,
    iat: payload.iat,
    exp: payload.exp,
    list: payload.status_list,
    verify: (jwk) => verifyEs256(jwk, `${parts[0]}.${parts[1]}`, base64url.decode(parts[2] ?? '')),
  };
}

/**
 * A token in CWT format: a COSE_Sign1 (tag 18) or COSE_Mac0 (tag 17) whose payload is a CWT claims set. The signer
 * chain is read from the protected header, as ISO/IEC 18013-5 section 12.3.6.3 requires.
 */
export function decodeCoseToken(bytes: Uint8Array): { structure: ReturnType<typeof readCose>; claims: CborMap; chain?: string[] } {
  const structure = attempt(() => readCose(attempt(() => decodeCbor(bytes), 'not CBOR')));
  if (structure.tag !== 18 && structure.tag !== 17) fail(`not a tagged COSE_Sign1 or COSE_Mac0 (tag ${String(structure.tag)})`);
  if (!structure.payload) fail('the CWT has no payload');
  const claims = attempt(() => decodeCbor(structure.payload as Uint8Array), 'the claims set is not CBOR');
  if (!(claims instanceof Map)) fail('the claims set is not a map');
  const chain = x5chainOf(structure.protectedHeader.get(COSE.x5chain));
  return { structure, claims: claims as CborMap, chain: chain && base64Of(chain) };
}

/** Verifies a COSE_Sign1 with ES256; a COSE_Mac0 never verifies, since a MAC is no signature. */
export async function verifyCoseSign1(structure: ReturnType<typeof readCose>, jwk: JsonWebKey): Promise<boolean> {
  if (structure.tag === 17 || !structure.payload) return false;
  return verifyEs256(jwk, sigStructure(structure.protectedBytes, structure.payload), structure.signature);
}

/** A Status List Token in CWT format (Token Status List section 5.2). */
function decodeCwt(bytes: Uint8Array): DecodedToken {
  const { structure, claims, chain } = decodeCoseToken(bytes);
  return {
    typ: structure.protectedHeader.get(COSE.typ),
    alg: structure.protectedHeader.get(COSE.alg),
    chain,
    sub: claims.get(CWT.sub),
    iat: claims.get(CWT.iat),
    exp: claims.get(CWT.exp),
    list: claims.get(CWT.statusList),
    verify: (jwk) => verifyCoseSign1(structure, jwk),
  };
}
