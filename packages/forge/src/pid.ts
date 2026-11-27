import { createHash, randomBytes } from 'node:crypto';
import { SDJwtVcInstance } from '@sd-jwt/sd-jwt-vc';
import { base64url, sha256, signEs256 } from './crypto';
import type { CertifiedKey } from './pki';

/** `vct` of the PID in SD-JWT VC format (PID Rulebook, SD-JWT VC encoding). */
export const PID_VCT = 'urn:eudi:pid:1';

/** The attribute values of `default_credential_pid`: at least family name, given name and birth date. */
export const DEFAULT_PID_CLAIMS = {
  family_name: 'Mustermann',
  given_name: 'Erika',
  birthdate: '1964-08-12',
  place_of_birth: { locality: 'Berlin', country: 'DE' },
  nationalities: ['DE'],
} as const;

export const sdJwtHasher = (data: string | ArrayBuffer, alg: string) => {
  if (alg.toLowerCase() !== 'sha-256') throw new Error(`Unsupported hash algorithm ${alg}`);
  return sha256(typeof data === 'string' ? data : new Uint8Array(data));
};

export interface IssuedSdJwtVc {
  /** Compact SD-JWT VC without key binding, as the Test Issuer hands it to the Conformance Wallet. */
  compact: string;
  /** The issuer-signed payload before disclosures were hashed. */
  claims: Record<string, unknown>;
  header: Record<string, unknown>;
}

export interface SdJwtVcIssueOptions {
  /** Signing certificate under the issuance anchor of the issuing entity, with its chain (no anchor). */
  signer: CertifiedKey;
  /** `iss` of the credential. */
  issuer: string;
  /** Public key of the Conformance Wallet the credential is bound to. */
  holderPublicJwk: JsonWebKey;
  /** The credential's status reference; omitted for `default_credential_pid_short`. */
  status?: { uri: string; idx: number };
  now?: Date;
  /** Seconds; default 30 days, `default_credential_pid` requires more than 24 hours. */
  validitySeconds?: number;
  /** SD-JWT VC media type in `typ`; `dc+sd-jwt` per SD-JWT VC. */
  typ?: string;
  /**
   * The disclosure frame of `@sd-jwt/core`; default every top-level attribute selectively disclosable. The attribute
   * variants of the data model test cases make the members of a structured claim disclosable or a claim plain.
   */
  disclosureFrame?: Record<string, unknown>;
}

export interface PidIssueOptions extends SdJwtVcIssueOptions {
  /** Claims that replace or extend those of `default_credential_pid`. */
  claims?: Record<string, unknown>;
}

/**
 * Issues `default_credential_pid` in SD-JWT VC format: signed with ES256 under the issuer's signing
 * certificate carried in `x5c` (without the anchor), device-bound with `cnf.jwk`, every attribute
 * selectively disclosable, with a Token Status List reference.
 */
export async function issuePidSdJwtVc(options: PidIssueOptions): Promise<IssuedSdJwtVc> {
  return issueSdJwtVc({ ...options, vct: PID_VCT, claims: { ...DEFAULT_PID_CLAIMS, ...(options.claims ?? {}) } });
}

/**
 * Issues an SD-JWT VC of type `vct` with the given attributes, as `issuePidSdJwtVc` issues the PID: ES256 under the
 * issuer's signing certificate in `x5c`, device-bound, every attribute selectively disclosable, with a status reference.
 */
export async function issueSdJwtVc(options: SdJwtVcIssueOptions & { vct: string; claims: Record<string, unknown> }): Promise<IssuedSdJwtVc> {
  const now = Math.floor((options.now ?? new Date()).getTime() / 1000);
  const claims = options.claims;
  const payload = {
    iss: options.issuer,
    vct: options.vct,
    iat: now,
    nbf: now,
    exp: now + (options.validitySeconds ?? 30 * 24 * 60 * 60),
    cnf: { jwk: options.holderPublicJwk },
    ...(options.status ? { status: { status_list: options.status } } : {}),
    ...claims,
  };
  const header = {
    alg: 'ES256',
    typ: options.typ ?? 'dc+sd-jwt',
    x5c: options.signer.chain.map((certificate) => Buffer.from(certificate.der).toString('base64')),
  };
  const sdjwt = new SDJwtVcInstance({
    hasher: sdJwtHasher,
    hashAlg: 'sha-256',
    saltGenerator: (length) => randomBytes(length).toString('base64url'),
    signAlg: 'ES256',
    signer: async (data) => base64url.encode(await signEs256(options.signer.key.privateKey, data)),
    omitTyp: true,
  });
  const compact = await sdjwt.issue(payload, (options.disclosureFrame ?? { _sd: Object.keys(claims) }) as never, { header });
  return { compact, claims: payload, header };
}

export interface PresentOptions {
  /** The holder key the credential is bound to (`cnf.jwk`). */
  holderPrivateKey: CryptoKey;
  /** Top-level claims to disclose. */
  disclose: string[];
  /** The requested claim paths; a structured claim requested only by members discloses only those members. */
  paths?: (string | number | null)[][];
  /** KB-JWT `aud`: the Client Identifier of the Relying Party. */
  audience: string;
  nonce: string;
  now?: Date;
}

/**
 * Claim names that cannot be disclosed (RFC 9901 section 4.2.1), and the registered claims SD-JWT VC section 2.2.2.2
 * does not let a disclosure carry; a disclosure with one is presented as it is, as the credential always shows them.
 */
const RESERVED_NAMES = new Set(['_sd', '...', 'iss', 'nbf', 'exp', 'cnf', 'vct', 'vct#integrity', 'status']);

const HASHES: Record<string, string> = { 'sha-256': 'sha256', 'sha-1': 'sha1', md5: 'md5' };

/** The digests a value references: the `_sd` members of its objects and the `...` entries of its arrays, recursively. */
function referencedDigests(value: unknown, root = true): { direct: string[]; nested: string[] } {
  const direct: string[] = [];
  const nested: string[] = [];
  const walk = (v: unknown, top: boolean) => {
    if (Array.isArray(v)) {
      for (const element of v) {
        if (element && typeof element === 'object' && !Array.isArray(element) && typeof (element as Record<string, unknown>)['...'] === 'string') {
          nested.push((element as Record<string, string>)['...']);
        } else walk(element, false);
      }
    } else if (v && typeof v === 'object') {
      for (const [key, member] of Object.entries(v)) {
        if (key === '_sd' && Array.isArray(member)) (top ? direct : nested).push(...member.filter((d): d is string => typeof d === 'string'));
        else walk(member, false);
      }
    }
  };
  walk(value, root);
  return { direct, nested };
}

/**
 * Selects the disclosures of an issued SD-JWT VC for a presentation (RFC 9901 section 4.3): the disclosures of the
 * requested top-level claims and every disclosure they reference, recursively. A disclosure that the payload does not
 * reference at the top level as a claim (a foreign one, an array element, one with a reserved or no claim name) is
 * presented as issued, so a credential fault in the disclosures reaches the Relying Party unchanged.
 */
export function selectDisclosures(compact: string, disclose: string[], paths?: (string | number | null)[][]): string[] {
  const [jwt, ...rest] = compact.split('~');
  const disclosures = rest.filter(Boolean);
  const payload = base64url.decodeJson<Record<string, unknown>>(jwt.split('.')[1] ?? '');
  const alg = HASHES[String(payload._sd_alg ?? 'sha-256')] ?? 'sha256';
  const digestOf = (d: string) => base64url.encode(createHash(alg).update(d).digest());
  const decoded = new Map(disclosures.map((d) => [digestOf(d), (() => {
    try {
      return base64url.decodeJson<unknown[]>(d);
    } catch {
      return undefined;
    }
  })()]));
  const { direct, nested } = referencedDigests(payload);
  const keep = new Set<string>(nested);
  const dropped = new Set<string>();
  const nameOf = (digest: string) => {
    const elements = decoded.get(digest);
    return Array.isArray(elements) && elements.length === 3 ? elements[1] : undefined;
  };
  /** The members of a top-level claim the request names, when it requests the claim only by members. */
  const membersOf = (name: unknown): Set<string> | undefined => {
    const of = (paths ?? []).filter((path) => path[0] === name);
    if (!of.length || of.some((path) => path.length < 2 || path[1] === null)) return undefined;
    return new Set(of.map((path) => String(path[1])));
  };
  const topLevel = new Map<string, unknown>();
  for (const digest of direct) {
    const name = nameOf(digest);
    if (typeof name === 'string' && !RESERVED_NAMES.has(name) && !disclose.includes(name)) dropped.add(digest);
    else keep.add(digest), topLevel.set(digest, name);
  }
  // Disclosures referenced from inside a kept disclosure are kept with it; those inside a dropped one are dropped. Of a
  // structured claim requested by members, only the disclosures of those members are kept.
  const queue = [...keep];
  while (queue.length) {
    const digest = queue.pop() as string;
    const elements = decoded.get(digest);
    if (!Array.isArray(elements)) continue;
    const value = elements[elements.length - 1];
    const members = topLevel.has(digest) ? membersOf(topLevel.get(digest)) : undefined;
    const own = members && value && typeof value === 'object' && !Array.isArray(value) ? ((value as Record<string, unknown>)._sd ?? []) : [];
    for (const d of Array.isArray(own) ? own : []) {
      const name = nameOf(String(d));
      if (typeof name === 'string' && !members?.has(name)) dropped.add(String(d));
    }
    const inner = referencedDigests(value, false);
    for (const d of [...inner.direct, ...inner.nested]) if (!keep.has(d) && !dropped.has(d)) keep.add(d), queue.push(d);
  }
  for (const digest of dropped) {
    const elements = decoded.get(digest);
    if (!Array.isArray(elements)) continue;
    const inner = referencedDigests(elements[elements.length - 1], false);
    for (const d of [...inner.direct, ...inner.nested]) if (!keep.has(d)) dropped.add(d);
  }
  return disclosures.filter((d) => !dropped.has(digestOf(d)));
}

/**
 * Presents an SD-JWT VC: discloses the requested claims (`selectDisclosures`) and appends a KB-JWT (RFC 9901 section
 * 4.3) with `iat`, `aud`, `nonce` and the `sd_hash` (SHA-256) of the presented SD-JWT, signed with ES256.
 */
export async function presentSdJwtVc(compact: string, options: PresentOptions): Promise<string> {
  const [jwt] = compact.split('~');
  const sdJwt = `${[jwt, ...selectDisclosures(compact, options.disclose, options.paths)].join('~')}~`;
  const header = { typ: 'kb+jwt', alg: 'ES256' };
  const payload = {
    iat: Math.floor((options.now ?? new Date()).getTime() / 1000),
    aud: options.audience,
    nonce: options.nonce,
    sd_hash: base64url.encode(sha256(sdJwt)),
  };
  const input = `${base64url.encode(JSON.stringify(header))}.${base64url.encode(JSON.stringify(payload))}`;
  return `${sdJwt}${input}.${base64url.encode(await signEs256(options.holderPrivateKey, input))}`;
}
