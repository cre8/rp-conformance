// The issuer side's `OBS-SL` (issuer catalogue sections 3.6 and 5.2, issuer harness design section 6.3): the status
// lists a PID or Attestation Provider publishes, fetched anonymously by the harness, checked as a Relying Party relies on
// them. The Status List Token checks of the reference validator (`STATUS_LIST_CHECKS`) run unchanged on the first
// version; the checks here add what the catalogue's `PP_RP_*` and `PP_WS_SM_Revocation_001` objectives ask of the
// publication itself: the URI, anonymous access, the media type per `Accept`, cache headers, privacy of the URIs, the
// token's lifetime claims, the list size, the algorithm, the signer's validity, and that a fresh version is always there.
import { inflateSync } from 'node:zlib';
import type { CheckResult, CheckStatus } from '@eudi-pcaf/core';
import { COSE, COSE_ALG, decodeCbor, decodeEmbedded, readCose, x5chainOf } from '@eudi-pcaf/forge';
import { parseCertificate } from '@owf/x509';
import { CheckRecorder, CheckFailure, NotApplicable } from './checks';
import { base64Of, decodeSegment, decodeStatusListToken, evaluateStatusList, field, type FetchedStatusList } from './status-list';
import type { MatchedIssuer } from './trust';

/** The checks of a published status list beyond the Status List Token checks, in the order they run. */
export const PUBLISHED_STATUS_CHECKS = [
  'sl-uri',
  'sl-anonymous',
  'sl-media-type',
  'sl-cache',
  'sl-uri-privacy',
  'sl-lifetime',
  'sl-entries',
  'sl-algorithm',
  'sl-signer-validity',
  'sl-continuity',
] as const;

export type PublishedStatusCheck = (typeof PUBLISHED_STATUS_CHECKS)[number];

/** A check result of `OBS-SL`: a Status List Token check of the reference validator or a publication check. */
export interface PublishedCheckResult {
  check: CheckResult['check'] | PublishedStatusCheck;
  status: CheckStatus;
  detail?: string;
}

export type StatusListFormat = 'jwt' | 'cwt';

/** The media type a Relying Party asks for in `Accept` for each format (Token Status List section 8.1). */
export const STATUS_LIST_MEDIA_TYPES: Record<StatusListFormat, string> = {
  jwt: 'application/statuslist+jwt',
  cwt: 'application/statuslist+cwt',
};

/** One anonymous GET of a status list URI: when, with which `Accept`, and the answer as received. */
export interface FetchedVersion {
  at: Date;
  format: StatusListFormat;
  status: number;
  /** Response headers, names lower case. */
  headers: Record<string, string>;
  body: string | Uint8Array;
  /** Why no answer arrived. */
  error?: string;
}

/** A credential's status reference (Token Status List section 6). */
export interface StatusReference {
  uri: string;
  idx: number;
}

/**
 * The Status List Token algorithms the ECCG agreed mechanisms allow (OIA_03): ECDSA on the NIST and Brainpool curves, as
 * JOSE `alg` and COSE algorithm identifiers (RFC 9053, RFC 9864).
 */
export const ECCG_JOSE_ALGORITHMS = ['ES256', 'ES384', 'ES512', 'BP256R1', 'BP384R1', 'BP512R1'];
export const ECCG_COSE_ALGORITHMS = [COSE_ALG.ES256, -35, -36, -9, -51, -52];

/** The status reference an issued credential carries: `status.status_list` of an SD-JWT VC, or the MSO's `status`. */
export function statusReferenceOfIssued(format: string, credential: string): StatusReference | undefined {
  if (format === 'dc+sd-jwt') {
    const payload = decodeSegment(credential.split('~')[0]?.split('.')[1], 'the issuer-signed JWT payload');
    const list = (payload.status as { status_list?: { idx?: unknown; uri?: unknown } } | undefined)?.status_list;
    if (!list || typeof list.uri !== 'string' || !Number.isInteger(list.idx)) return undefined;
    return { uri: list.uri, idx: list.idx as number };
  }
  if (format === 'mso_mdoc') {
    const issuerSigned = decodeCbor(Buffer.from(credential, 'base64url'));
    const issuerAuth = readCose(field(issuerSigned, 'issuerAuth'));
    const mso = decodeEmbedded(decodeCbor(issuerAuth.payload as Uint8Array));
    const list = field(field(mso, 'status'), 'status_list');
    const uri = field(list, 'uri');
    const idx = field(list, 'idx');
    if (typeof uri !== 'string' || !Number.isInteger(idx)) return undefined;
    return { uri, idx: idx as number };
  }
  return undefined;
}

/** The signer chain of an issued credential, base64 DER, leaf first: `x5c` of an SD-JWT VC, `x5chain` of an mdoc. */
export function signerChainOfIssued(format: string, credential: string): string[] {
  if (format === 'dc+sd-jwt') {
    const x5c = decodeSegment(credential.split('~')[0]?.split('.')[0], 'the issuer-signed JWT header').x5c;
    return Array.isArray(x5c) ? (x5c as string[]) : [];
  }
  const issuerAuth = readCose(field(decodeCbor(Buffer.from(credential, 'base64url')), 'issuerAuth'));
  const chain = x5chainOf(issuerAuth.unprotectedHeader.get(COSE.x5chain) ?? issuerAuth.protectedHeader.get(COSE.x5chain));
  return chain ? base64Of(chain) : [];
}

/** What one version of a published list says: its time claims and the status value at an index. */
export interface PublishedVersion {
  iat?: number;
  exp?: number;
  ttl?: number;
  /** The status value at the index, or undefined when the list cannot be decoded. */
  value?: number;
  error?: string;
}

/** Decodes a fetched version (without verifying it) and reads the status value at `idx`. */
export function readPublishedVersion(fetched: FetchedVersion, idx: number, maxBytes: number): PublishedVersion {
  if (fetched.error) return { error: fetched.error };
  if (fetched.status !== 200) return { error: `HTTP ${fetched.status}` };
  try {
    const token = decodeStatusListToken(fetched.format, fetched.body);
    const num = (v: unknown) => (typeof v === 'number' ? v : undefined);
    const version: PublishedVersion = { iat: num(token.iat), exp: num(token.exp), ttl: num(token.ttl) };
    const { bits, decoded } = decodeList(token.list, fetched.format, maxBytes);
    if (idx * bits >= decoded.length * 8) return { ...version, error: `index ${idx} is outside the ${(decoded.length * 8) / bits} entries` };
    return { ...version, value: (decoded[Math.floor((idx * bits) / 8)] >> ((idx * bits) % 8)) & ((1 << bits) - 1) };
  } catch (error) {
    return { error: (error as Error).message };
  }
}

function decodeList(list: unknown, format: StatusListFormat, maxBytes: number): { bits: number; decoded: Uint8Array } {
  const bits = field(list, 'bits');
  const lst = field(list, 'lst');
  if (![1, 2, 4, 8].includes(bits as number)) throw new Error(`bits ${String(bits)} is not 1, 2, 4 or 8`);
  const compressed = format === 'jwt' ? Buffer.from(String(lst), 'base64url') : (lst as Uint8Array);
  return { bits: bits as number, decoded: new Uint8Array(inflateSync(compressed, { maxOutputLength: maxBytes })) };
}

export interface PublishedStatusInput {
  /** The format of the token the credential's format implies: `jwt` for an SD-JWT VC, `cwt` for an mdoc. */
  format: StatusListFormat;
  reference: StatusReference;
  /** The references of every credential the test case observes, for `sl-uri-privacy`. */
  references: StatusReference[];
  /** The issuer the credential matched, with the revocation anchors its lists must chain to. */
  issuer: MatchedIssuer | undefined;
  /** Every poll of `reference.uri` with the credential's format, in order; at least one. */
  polls: FetchedVersion[];
  /** One fetch per format the Provider declares (ICS-05), with its `Accept`, for `sl-media-type`. */
  perFormat: FetchedVersion[];
  /** The formats the Provider declares it serves (ICS-05). */
  declaredFormats: StatusListFormat[];
  /** The minimum number of entries (ICS-16, at least 10 000, catalogue decision 4). */
  minEntries: number;
  /** A local run: an http URL on a loopback host stands for https, as on the RP side. */
  allowLoopbackHttp: boolean;
  skewSeconds: number;
  maxStatusListBytes: number;
}

const LOOPBACK = ['127.0.0.1', 'localhost', '[::1]'];

/** Runs `fn` as one publication check, recording pass, fail (`CheckFailure` or any error) or skip (`NotApplicable`). */
async function check(results: PublishedCheckResult[], id: PublishedStatusCheck, fn: () => Promise<string | void | NotApplicable> | string | void | NotApplicable) {
  try {
    const outcome = await fn();
    if (outcome instanceof NotApplicable) results.push({ check: id, status: 'skip', detail: outcome.reason });
    else results.push({ check: id, status: 'pass', ...(outcome ? { detail: outcome } : {}) });
  } catch (error) {
    results.push({ check: id, status: 'fail', detail: (error as Error).message });
  }
}

const failWith = (message: string): never => {
  throw new CheckFailure(message);
};

/** `Cache-Control` directives, lower case, with their values. */
function cacheDirectives(value: string | undefined): Map<string, string | undefined> {
  const directives = new Map<string, string | undefined>();
  for (const part of (value ?? '').split(',')) {
    const [name, arg] = part.trim().split('=');
    if (name) directives.set(name.toLowerCase(), arg?.replace(/"/g, ''));
  }
  return directives;
}

/**
 * Every check of the published status list a credential references: the Status List Token checks of the reference
 * validator on the first poll, then the publication checks. Each check that cannot apply (no second poll, no `exp`) is
 * skipped with the reason.
 */
export async function evaluatePublishedStatus(input: PublishedStatusInput): Promise<PublishedCheckResult[]> {
  const first = input.polls[0];
  if (!first) throw new Error('no version of the status list was fetched');
  const recorder = new CheckRecorder('all');
  // The prerequisites of the Status List Token checks, settled by the issuer side's `OBS-CRED` before the list is read.
  recorder.record('status-reference', 'pass', `${input.reference.uri} index ${input.reference.idx}`);
  recorder.record('issuer-trust', input.issuer ? 'pass' : 'fail', input.issuer ? input.issuer.name : 'the credential matches no trusted issuer');
  await evaluateStatusList(recorder, {
    format: input.format,
    reference: input.reference,
    issuer: input.issuer,
    fetchStatusList: async (): Promise<FetchedStatusList> => {
      if (first.error) throw new Error(first.error);
      return { status: first.status, body: first.body, contentType: first.headers['content-type'] };
    },
    maxStatusListBytes: input.maxStatusListBytes,
    skewSeconds: input.skewSeconds,
    now: first.at,
  });
  const results: PublishedCheckResult[] = [...recorder.results];
  const now = Math.floor(first.at.getTime() / 1000);
  const token = (() => {
    try {
      return first.status === 200 ? decodeStatusListToken(input.format, first.body) : undefined;
    } catch {
      return undefined;
    }
  })();
  const undecodable = () => new NotApplicable(first.error ?? (first.status !== 200 ? `HTTP ${first.status}` : 'the token cannot be decoded'));

  await check(results, 'sl-uri', () => {
    const url = new URL(input.reference.uri);
    if (url.protocol !== 'https:' && !(input.allowLoopbackHttp && url.protocol === 'http:' && LOOPBACK.includes(url.hostname))) {
      failWith(`${input.reference.uri} is not an https URL`);
    }
    if (url.username || url.password) failWith('the URI carries credentials');
    return url.protocol === 'https:' ? 'https' : `http on the loopback host ${url.hostname} (local run, stands for https)`;
  });

  await check(results, 'sl-anonymous', () => {
    if (first.error) failWith(`no answer: ${first.error}`);
    if (first.status === 401 || first.status === 403 || first.headers['www-authenticate']) failWith(`HTTP ${first.status} ${first.headers['www-authenticate'] ?? ''}: the list requires authentication`);
    if (first.status !== 200) failWith(`HTTP ${first.status} to a GET without credentials`);
    return 'HTTP 200 to a GET without Authorization header or cookie';
  });

  await check(results, 'sl-media-type', () => {
    const answers: string[] = [];
    for (const format of input.declaredFormats) {
      const fetched = input.perFormat.find((f) => f.format === format);
      if (!fetched) failWith(`no fetch with Accept ${STATUS_LIST_MEDIA_TYPES[format]}`);
      const got = fetched?.headers['content-type']?.split(';')[0]?.trim().toLowerCase();
      if (fetched?.status !== 200) failWith(`Accept ${STATUS_LIST_MEDIA_TYPES[format]}: HTTP ${fetched?.status}${fetched?.error ? ` (${fetched.error})` : ''}`);
      if (got !== STATUS_LIST_MEDIA_TYPES[format]) failWith(`Accept ${STATUS_LIST_MEDIA_TYPES[format]} was answered with Content-Type ${got ?? 'none'}`);
      try {
        decodeStatusListToken(format, (fetched as FetchedVersion).body);
      } catch (error) {
        failWith(`Accept ${STATUS_LIST_MEDIA_TYPES[format]}: the body is no Status List Token in ${format.toUpperCase()} format (${(error as Error).message})`);
      }
      answers.push(`${STATUS_LIST_MEDIA_TYPES[format]} for Accept ${STATUS_LIST_MEDIA_TYPES[format]}`);
    }
    return answers.join(', ');
  });

  await check(results, 'sl-cache', () => {
    if (!token) return undecodable();
    const ttl = typeof token.ttl === 'number' ? token.ttl : undefined;
    const exp = typeof token.exp === 'number' ? token.exp : undefined;
    const directives = cacheDirectives(first.headers['cache-control']);
    const expires = first.headers.expires ? Date.parse(first.headers.expires) / 1000 : undefined;
    // Token Status List (draft 21) puts no cache-header duty on the Status Provider: section 8.2 only says that "If
    // caching-related HTTP headers are present", Relying Parties prioritise exp and ttl. Missing headers pass; headers
    // that are present must not let an HTTP cache (which does not read the token) serve it beyond ttl or exp.
    if (!first.headers['cache-control'] && expires === undefined) return 'no caching-related headers (none required; Relying Parties follow ttl and exp)';
    if (directives.has('no-store') || directives.has('no-cache')) return `Cache-Control ${first.headers['cache-control']}: never served from a cache`;
    const maxAge = directives.get('s-maxage') ?? directives.get('max-age');
    if (maxAge !== undefined) {
      const seconds = Number(maxAge);
      if (!Number.isInteger(seconds) || seconds < 0) failWith(`max-age ${maxAge} is not a number of seconds`);
      if (ttl !== undefined && seconds > ttl) failWith(`max-age ${seconds} exceeds ttl ${ttl}`);
      if (exp !== undefined && now + seconds > exp + input.skewSeconds) failWith(`max-age ${seconds} lets a cache serve the token after its exp ${exp}`);
      return `max-age ${seconds}${ttl !== undefined ? `, ttl ${ttl}` : ''}${exp !== undefined ? `, exp in ${exp - now} s` : ''}`;
    }
    if (expires === undefined || Number.isNaN(expires)) failWith(`Cache-Control ${first.headers['cache-control']} sets no lifetime and there is no valid Expires`);
    if (exp !== undefined && (expires as number) > exp + input.skewSeconds) failWith(`Expires ${first.headers.expires} is after the token's exp ${exp}`);
    return `Expires ${first.headers.expires}`;
  });

  await check(results, 'sl-uri-privacy', () => {
    const tracking = input.references.filter((r) => {
      const url = new URL(r.uri);
      return url.search || url.hash;
    });
    if (tracking.length) failWith(`${tracking.length} status URI(s) carry a query or fragment, for example ${tracking[0]?.uri}`);
    if (first.headers['set-cookie']) failWith('the status list response sets a cookie');
    const uris = new Set(input.references.map((r) => r.uri));
    if (input.references.length < 2) return new NotApplicable('one credential: whether URIs are per credential needs several');
    if (uris.size === input.references.length) failWith(`each of the ${input.references.length} credentials has a status URI of its own`);
    return `${input.references.length} credentials share ${uris.size} status URI(s); no query, fragment or cookie`;
  });

  await check(results, 'sl-lifetime', () => {
    if (!token) return undecodable();
    const missing = [typeof token.iat !== 'number' && 'iat', typeof token.exp !== 'number' && 'exp', typeof token.ttl !== 'number' && 'ttl'].filter(Boolean);
    if (missing.length) failWith(`the token has no ${missing.join(', ')}`);
    const [iat, exp, ttl] = [token.iat as number, token.exp as number, token.ttl as number];
    if (!(ttl > 0)) failWith(`ttl ${ttl} is not positive`);
    if (exp <= iat) failWith(`exp ${exp} is not after iat ${iat}`);
    if (exp <= now - input.skewSeconds) failWith(`exp ${exp} has passed (fetched at ${now})`);
    if (iat > now + input.skewSeconds) failWith(`iat ${iat} lies in the future (fetched at ${now})`);
    return `iat ${iat}, exp in ${exp - now} s, ttl ${ttl} s`;
  });

  await check(results, 'sl-entries', () => {
    if (!token) return undecodable();
    const { bits, decoded } = decodeList(token.list, input.format, input.maxStatusListBytes);
    const entries = (decoded.length * 8) / bits;
    if (entries < input.minEntries) failWith(`${entries} entries, fewer than the minimum ${input.minEntries}`);
    return `${entries} entries of ${bits} bit(s)`;
  });

  await check(results, 'sl-algorithm', () => {
    if (!token) return undecodable();
    const allowed: unknown[] = input.format === 'jwt' ? ECCG_JOSE_ALGORITHMS : ECCG_COSE_ALGORITHMS;
    if (!allowed.includes(token.alg)) failWith(`alg ${String(token.alg)} is not an ECCG agreed signature algorithm`);
    const leaf = token.chain?.[0];
    if (!leaf) failWith('the token carries no signer certificate');
    const key = parseCertificate(leaf as string).publicKey.jwk as JsonWebKey;
    if (key.kty !== 'EC' || !['P-256', 'P-384', 'P-521', 'brainpoolP256r1', 'brainpoolP384r1', 'brainpoolP512r1'].includes(String(key.crv))) {
      failWith(`the signer key is ${key.kty} ${String(key.crv)}, not on an ECCG agreed curve`);
    }
    return `${String(token.alg)} with a ${key.crv} key`;
  });

  await check(results, 'sl-signer-validity', () => {
    if (!token) return undecodable();
    const leaf = token.chain?.[0];
    if (!leaf) failWith('the token carries no signer certificate');
    const certificate = parseCertificate(leaf as string);
    const from = typeof token.iat === 'number' ? token.iat : now;
    const until = typeof token.exp === 'number' ? token.exp : now;
    const notBefore = Math.floor(certificate.notBefore.getTime() / 1000);
    const notAfter = Math.floor(certificate.notAfter.getTime() / 1000);
    if (from < notBefore) failWith(`the token's iat ${from} is before the signer certificate's notBefore ${certificate.notBefore.toISOString()}`);
    if (until > notAfter) failWith(`the token's exp ${until} is after the signer certificate's notAfter ${certificate.notAfter.toISOString()}`);
    return `${certificate.subject.commonName} valid ${certificate.notBefore.toISOString()} to ${certificate.notAfter.toISOString()}`;
  });

  await check(results, 'sl-continuity', () => {
    if (!token || typeof token.exp !== 'number') return token ? new NotApplicable('the first version has no exp') : undecodable();
    const firstExp = token.exp;
    const after = input.polls.filter((p) => p.at.getTime() / 1000 > firstExp);
    if (!after.length) return new NotApplicable(`no poll after the first version's exp ${firstExp}: the step ended before it`);
    for (const poll of input.polls) {
      const at = Math.floor(poll.at.getTime() / 1000);
      const version = readPublishedVersion(poll, input.reference.idx, input.maxStatusListBytes);
      if (version.error) failWith(`poll at ${poll.at.toISOString()}: ${version.error}`);
      if (version.exp === undefined) failWith(`poll at ${poll.at.toISOString()}: a version without exp`);
      if ((version.exp as number) <= at - input.skewSeconds) failWith(`poll at ${poll.at.toISOString()} got only an expired token (exp ${version.exp})`);
    }
    const versions = new Set(input.polls.map((p) => readPublishedVersion(p, input.reference.idx, input.maxStatusListBytes).iat));
    return `${input.polls.length} polls across the first version's exp, ${versions.size} version(s), none expired when fetched`;
  });
  return results;
}
