// The disclosures of an SD-JWT (RFC 9901 section 7.1, steps 2d to 5), processed by the reference validator itself so
// that each defect of IssuerIntegrity_008 to _012 is named: the hash algorithm, the form of each disclosure, digests that
// occur twice, claim names that are reserved or already present, and disclosures no digest references.
import { base64url, sha256 } from '@rp-conformance/forge';
import { parseCertificate } from '@owf/x509';
import { fail } from './status-list';

/** Named curves of EC keys by OID, for the reason of a rejected key. */
const CURVES: Record<string, string> = {
  '1.2.840.10045.3.1.7': 'P-256',
  '1.2.840.10045.3.1.1': 'P-192',
  '1.3.132.0.10': 'secp256k1',
  '1.3.132.0.34': 'P-384',
  '1.3.132.0.35': 'P-521',
};

/** The key of a certificate as a reason names it: `P-256`, `P-192`, `secp256k1`, `RSA 1024 bit`, … */
export function describeKey(certificate: string | Uint8Array): string {
  let key: ReturnType<typeof parseCertificate>['publicKey'];
  try {
    key = parseCertificate(certificate).publicKey;
  } catch (error) {
    return `that cannot be parsed (${(error as Error).message})`;
  }
  if (key.namedCurve) return CURVES[key.namedCurve] ?? `on curve ${key.namedCurve}`;
  if (key.jwk?.kty === 'RSA' && key.jwk.n) return `RSA ${base64url.decode(key.jwk.n).length * 8} bit`;
  return `of algorithm ${key.algorithm}`;
}

/** The registered claims SD-JWT VC section 2.2.2.2 forbids in disclosures, when used in the SD-JWT. */
const NOT_DISCLOSABLE = new Set(['iss', 'nbf', 'exp', 'cnf', 'vct', 'vct#integrity', 'status']);

interface Disclosure {
  salt: unknown;
  name?: unknown;
  value: unknown;
  length: number;
}

/**
 * Checks the disclosures against the issuer-signed payload and returns the claims with the disclosed values. Fails on an
 * `_sd_alg` other than `sha-256`, a disclosure that is not a JSON array of two (array element) or three (object property)
 * elements where it is referenced, a digest that occurs more than once, a disclosed claim name that is `_sd`, `...` or
 * already present at its level, a top-level disclosure of a claim SD-JWT VC section 2.2.2.2 forbids in one (`iss`,
 * `exp`, …), and a disclosure that no digest references.
 */
export function processDisclosures(payload: Record<string, unknown>, encoded: string[]): { claims: Record<string, unknown>; count: number } {
  const alg = payload._sd_alg ?? 'sha-256';
  if (alg !== 'sha-256') fail(`_sd_alg ${String(alg)} is not supported`);
  const byDigest = new Map<string, Disclosure>();
  for (const d of encoded) {
    let elements: unknown;
    try {
      elements = base64url.decodeJson<unknown>(d);
    } catch {
      fail('a disclosure is not base64url-encoded JSON');
    }
    if (!Array.isArray(elements) || (elements.length !== 2 && elements.length !== 3)) fail('a disclosure is not a JSON array of two or three elements');
    const array = elements as unknown[];
    const digest = base64url.encode(sha256(d));
    if (byDigest.has(digest)) fail('a disclosure is presented twice');
    byDigest.set(digest, array.length === 3 ? { salt: array[0], name: array[1], value: array[2], length: 3 } : { salt: array[0], value: array[1], length: 2 });
  }
  const seen = new Set<string>();
  const used = new Set<string>();
  const reference = (digest: unknown) => {
    if (typeof digest !== 'string') fail('a digest is not a string');
    if (seen.has(digest as string)) fail(`the digest ${String(digest)} occurs more than once`);
    seen.add(digest as string);
    return byDigest.get(digest as string);
  };
  const resolve = (value: unknown, top = false): unknown => {
    if (Array.isArray(value)) {
      const out: unknown[] = [];
      for (const element of value) {
        const ref = element && typeof element === 'object' && !Array.isArray(element) && Object.keys(element).length === 1 ? (element as Record<string, unknown>)['...'] : undefined;
        if (ref === undefined) {
          out.push(resolve(element));
          continue;
        }
        const disclosure = reference(ref);
        if (!disclosure) continue; // a decoy or an element that is not disclosed
        if (disclosure.length !== 2) fail('the disclosure of an array element has three elements instead of two');
        used.add(ref as string);
        out.push(resolve(disclosure.value));
      }
      return out;
    }
    if (value && typeof value === 'object') {
      const out: Record<string, unknown> = {};
      for (const [key, member] of Object.entries(value)) if (key !== '_sd') out[key] = resolve(member);
      const digests = (value as Record<string, unknown>)._sd;
      if (digests !== undefined && !Array.isArray(digests)) fail('_sd is not an array');
      for (const digest of (digests as unknown[] | undefined) ?? []) {
        const disclosure = reference(digest);
        if (!disclosure) continue; // a decoy, or a claim that is not disclosed
        if (disclosure.length !== 3) fail('the disclosure of an object property has two elements instead of three');
        const name = disclosure.name;
        if (typeof name !== 'string') fail('a disclosure has no claim name');
        if (name === '_sd' || name === '...') fail(`a disclosure has the reserved claim name ${String(name)}`);
        if (top && NOT_DISCLOSABLE.has(name as string)) fail(`a disclosure carries the claim ${String(name)}, which SD-JWT VC does not let a disclosure carry`);
        if (Object.hasOwn(out, name as string)) fail(`the disclosed claim ${String(name)} is already present at its level`);
        used.add(digest as string);
        out[name as string] = resolve(disclosure.value);
      }
      return out;
    }
    return value;
  };
  const { _sd_alg: _alg, ...rest } = payload;
  const claims = resolve(rest, true) as Record<string, unknown>;
  const unreferenced = [...byDigest.keys()].filter((d) => !used.has(d));
  if (unreferenced.length) fail(`${unreferenced.length} disclosure(s) are not referenced by a digest in the payload`);
  return { claims, count: encoded.length };
}
