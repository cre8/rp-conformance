// Issue 26: the reference validator's checks over what a Provider signs (issuer catalogue section 5.1.3,
// `PP_WS_SM_IssuerIntegrity`), over several issued credentials (`PP_WS_SM_Unlinkability`), and over the requests the
// Provider sends to the harness (`PP_Inf_SM_TrustMechanisms_008`). Each check is a pure function of the captured
// artifacts; an `inspect` step names the checks its `CONF` requires.
import type { CheckResult, IssuerInspectionCheck } from '@eudi-pcaf/core';
import { base64url, COSE, type CborMap, decodeCbor, decodeEmbedded, readCose, x5chainOf } from '@eudi-pcaf/forge';
import { parseCertificate } from '@owf/x509';
import { deviceKeyOfMso, readIssuerSigned, asMap } from './mdoc';
import { statusReferenceOfIssued } from './published-status';

type Check = IssuerInspectionCheck;

/** What the checks read of one issued credential, in either format. */
export interface InspectedCredential {
  /** Where the credential comes from in the report, for example `step 3 #2`. */
  label: string;
  format: 'dc+sd-jwt' | 'mso_mdoc';
  /** The issuance step (1-based); the credentials of one step form one batch. */
  step: number;
  /** When the step received it. */
  receivedAt: Date;
  /** The signature algorithm as a JOSE name (`ES256`), or `COSE <n>` for an unknown COSE algorithm. */
  alg: string;
  /** SD-JWT VC `typ`. */
  typ?: string;
  /** The signer chain, base64 DER, leaf first. */
  chain: string[];
  signature: string;
  /** Salts (SD-JWT VC) or `random` values (mdoc), as base64url of their bytes, or as the string the disclosure carries. */
  salts: { value: string; bytes: number }[];
  digests: string[];
  status?: { uri: string; idx: number };
  deviceKey?: JsonWebKey;
  /** `iat`, `nbf`, `exp`; for an mdoc `signed`, `validFrom`, `validUntil`, seconds. */
  times: Record<string, number>;
  /** SD-JWT VC: the issuer-signed payload and the decoded disclosures. */
  payload?: Record<string, unknown>;
  disclosures?: unknown[][];
  /** The decoded content as JSON text, to search for identifiers. */
  text: string;
  /** mdoc: `digestAlgorithm`. */
  digestAlgorithm?: string;
}

const COSE_ALG_NAMES: Record<number, string> = { [-7]: 'ES256', [-35]: 'ES384', [-36]: 'ES512', [-47]: 'ES256K', [-8]: 'EdDSA' };
const json = (value: unknown) =>
  JSON.stringify(value, (_key, v) => (v instanceof Uint8Array ? base64url.encode(v) : v instanceof Map ? Object.fromEntries([...v.entries()].map(([k, x]) => [String(k), x])) : v instanceof Date ? v.toISOString() : v));
const seconds = (value: unknown) => {
  const date = value instanceof Date ? value : typeof value === 'string' ? new Date(value) : (value as { value?: unknown } | undefined)?.value !== undefined ? new Date(String((value as { value: unknown }).value)) : undefined;
  return date && !Number.isNaN(date.getTime()) ? Math.floor(date.getTime() / 1000) : undefined;
};
const b64 = (bytes: Uint8Array) => Buffer.from(bytes).toString('base64');

/** Collects every `_sd` digest and every `...` array reference of an issuer-signed payload or disclosed value. */
function collectDigests(value: unknown, into: string[]) {
  if (Array.isArray(value)) {
    for (const element of value) {
      if (element && typeof element === 'object' && !Array.isArray(element) && Object.keys(element).length === 1 && '...' in element) into.push(String((element as Record<string, unknown>)['...']));
      else collectDigests(element, into);
    }
  } else if (value && typeof value === 'object') {
    for (const [key, member] of Object.entries(value)) {
      if (key === '_sd' && Array.isArray(member)) into.push(...member.map(String));
      else collectDigests(member, into);
    }
  }
}

/** Reads what the checks need of an issued SD-JWT VC or mdoc (base64url `IssuerSigned`). Throws on an unreadable credential. */
export function inspectIssued(format: string, credential: string, label: string, step: number, receivedAt = new Date()): InspectedCredential {
  if (format === 'dc+sd-jwt') {
    const parts = credential.split('~');
    const [h, p, s] = (parts[0] ?? '').split('.');
    const header = base64url.decodeJson<Record<string, unknown>>(h ?? '');
    const payload = base64url.decodeJson<Record<string, unknown>>(p ?? '');
    const disclosures = parts.slice(1).filter(Boolean).map((d) => base64url.decodeJson<unknown[]>(d));
    const digests: string[] = [];
    collectDigests(payload, digests);
    for (const disclosure of disclosures) collectDigests(disclosure.at(-1), digests);
    const times: Record<string, number> = {};
    for (const claim of ['iat', 'nbf', 'exp']) if (typeof payload[claim] === 'number') times[claim] = payload[claim] as number;
    return {
      label,
      format,
      step,
      receivedAt,
      alg: String(header.alg),
      typ: typeof header.typ === 'string' ? header.typ : undefined,
      chain: Array.isArray(header.x5c) ? (header.x5c as string[]) : [],
      signature: s ?? '',
      salts: disclosures.map((d) => {
        const salt = String(d[0]);
        let bytes: number;
        try {
          bytes = /^[A-Za-z0-9_-]+$/.test(salt) ? base64url.decode(salt).length : salt.length * 0.75;
        } catch {
          bytes = salt.length * 0.75;
        }
        // A hex string carries 4 bits per character, whatever base64url decoding makes of it.
        if (/^[0-9a-f]+$/i.test(salt)) bytes = Math.min(bytes, salt.length / 2);
        return { value: salt, bytes };
      }),
      digests,
      ...(statusOf(format, credential) ? { status: statusOf(format, credential) } : {}),
      ...((payload.cnf as { jwk?: JsonWebKey } | undefined)?.jwk ? { deviceKey: (payload.cnf as { jwk: JsonWebKey }).jwk } : {}),
      times,
      payload,
      disclosures,
      text: json({ header, payload, disclosures }),
    };
  }
  if (format !== 'mso_mdoc') throw new Error(`format ${format} is not inspected`);
  const issuerSigned = asMap(decodeCbor(base64url.decode(credential)), 'IssuerSigned');
  const parsed = readIssuerSigned(issuerSigned);
  const salts: { value: string; bytes: number }[] = [];
  const items: unknown[] = [];
  for (const [, list] of parsed.issuerSigned.get('nameSpaces') as CborMap) {
    for (const item of list as unknown[]) {
      const signed = decodeEmbedded<CborMap>(item);
      items.push(signed);
      const random = signed.get('random');
      salts.push(random instanceof Uint8Array ? { value: base64url.encode(random), bytes: random.length } : { value: String(random), bytes: 0 });
    }
  }
  const digests: string[] = [];
  for (const [, byId] of parsed.mso.get('valueDigests') as CborMap) for (const [, digest] of byId as CborMap) digests.push(base64url.encode(digest as Uint8Array));
  const validity = parsed.mso.get('validityInfo') as CborMap;
  const times: Record<string, number> = {};
  for (const key of ['signed', 'validFrom', 'validUntil']) {
    const t = seconds(validity.get(key));
    if (t !== undefined) times[key] = t;
  }
  const algNumber = parsed.issuerAuth.protectedHeader.get(COSE.alg) as number;
  let deviceKey: JsonWebKey | undefined;
  try {
    deviceKey = deviceKeyOfMso(parsed.mso);
  } catch {
    deviceKey = undefined;
  }
  const status = statusOf(format, credential);
  return {
    label,
    format,
    step,
    receivedAt,
    alg: COSE_ALG_NAMES[algNumber] ?? `COSE ${String(algNumber)}`,
    chain: parsed.x5chain.map(b64),
    signature: base64url.encode(parsed.issuerAuth.signature),
    salts,
    digests,
    ...(status ? { status } : {}),
    ...(deviceKey ? { deviceKey } : {}),
    times,
    text: json({ items, mso: parsed.mso }),
    digestAlgorithm: String(parsed.mso.get('digestAlgorithm')),
  };
}

function statusOf(format: string, credential: string) {
  try {
    return statusReferenceOfIssued(format, credential);
  } catch {
    return undefined;
  }
}

/** The issuer signer chain of an mdoc as stored: tagged or untagged COSE_Sign1, x5chain protected or unprotected. */
export function mdocChain(credential: string): string[] {
  const auth = readCose((decodeCbor(base64url.decode(credential)) as CborMap).get('issuerAuth'));
  return (x5chainOf(auth.unprotectedHeader.get(COSE.x5chain) ?? auth.protectedHeader.get(COSE.x5chain)) ?? []).map(b64);
}

const pass = (check: Check, detail: string): CheckResult => ({ check, status: 'pass', detail });
const failed = (check: Check, detail: string): CheckResult => ({ check, status: 'fail', detail });
const skip = (check: Check, detail: string): CheckResult => ({ check, status: 'skip', detail });

/** ECCG agreed signature algorithms (SOG-IS / ECCG ACM) for credentials, with the curve of their key. */
const ECCG_ALGORITHMS: Record<string, string> = { ES256: 'P-256', ES384: 'P-384', ES512: 'P-521' };
const CURVE_OIDS: Record<string, string> = { '1.2.840.10045.3.1.7': 'P-256', '1.3.132.0.34': 'P-384', '1.3.132.0.35': 'P-521' };
/** ISO/IEC 18013-5 Annex B: extended key usage of a document signer. */
const MDOC_DS_EKU = '1.0.18013.5.1.2';
/** Claims SD-JWT VC section 3.2.2 keeps out of selective disclosure, and the SD-JWT structure members. */
const NOT_DISCLOSABLE = new Set(['iss', 'nbf', 'exp', 'iat', 'cnf', 'vct', 'vct#integrity', 'status', '_sd', '_sd_alg']);

const sameName = (a: { rfc4514: string }, b: { rfc4514: string }) => a.rfc4514 === b.rfc4514;
const selfIssued = (cert: ReturnType<typeof parseCertificate>) =>
  sameName(cert.subject, cert.issuer) && (!cert.authorityKeyIdentifier || cert.authorityKeyIdentifier === cert.subjectKeyIdentifier);
const keyOf = (cert: ReturnType<typeof parseCertificate>) => JSON.stringify([cert.publicKey.jwk?.crv, cert.publicKey.jwk?.x, cert.publicKey.jwk?.y]);

export interface IntegrityContext {
  /** base64 DER of the credential signing certificates the Test Registrar enrolled for the Provider. */
  enrolledSigners?: string[];
  /** base64 DER of the access certificate the Test Registrar issued for the Provider. */
  accessCertificate?: string;
  /** `credential_signing_alg_values_supported` of the credential configuration (names or COSE numbers). */
  advertisedAlgorithms?: (string | number)[];
  now?: Date;
}

/**
 * `PP_WS_SM_IssuerIntegrity`: runs the named checks of `ISSUER_INTEGRITY_CHECKS` on one credential. A check that does
 * not apply to the credential's format is skipped with the reason.
 */
export function checkIssuerIntegrity(credential: InspectedCredential, checks: Check[], ctx: IntegrityContext = {}): CheckResult[] {
  const sd = credential.format === 'dc+sd-jwt';
  const results: CheckResult[] = [];
  const leaf = () => parseCertificate(credential.chain[0] as string);
  for (const check of checks) {
    try {
      switch (check) {
        case 'sd-jwt-typ':
          results.push(!sd ? skip(check, 'applies to SD-JWT VC') : credential.typ === 'dc+sd-jwt' ? pass(check, 'typ dc+sd-jwt') : failed(check, `typ is ${String(credential.typ)}, not dc+sd-jwt`));
          break;
        case 'signer-algorithm': {
          const curve = ECCG_ALGORITHMS[credential.alg];
          if (!curve) results.push(failed(check, `${credential.alg} is not an ECCG agreed signature algorithm (ES256, ES384, ES512)`));
          else if (!credential.chain.length) results.push(failed(check, 'no signer certificate'));
          else {
            const keyCurve = CURVE_OIDS[leaf().publicKey.namedCurve ?? ''] ?? leaf().publicKey.namedCurve ?? leaf().publicKey.algorithm;
            results.push(keyCurve === curve ? pass(check, `${credential.alg} with a key on ${curve}`) : failed(check, `${credential.alg} with a key on ${keyCurve}, not ${curve}`));
          }
          break;
        }
        case 'signer-chain': {
          const field = sd ? 'x5c' : 'x5chain';
          if (!credential.chain.length) {
            results.push(failed(check, `${field} is missing`));
            break;
          }
          const certs = credential.chain.map((c) => parseCertificate(c));
          const problems: string[] = [];
          if (certs[0]?.basicConstraints?.cA) problems.push('the first certificate is a CA certificate, not the signer');
          certs.forEach((cert, i) => {
            if (selfIssued(cert)) problems.push(`certificate ${i + 1} (${cert.subject.rfc4514}) is self-issued: the trust anchor is included`);
            const next = certs[i + 1];
            if (next && !sameName(cert.issuer, next.subject)) problems.push(`certificate ${i + 1} is not issued by certificate ${i + 2}`);
          });
          results.push(problems.length ? failed(check, `${field}: ${problems.join('; ')}`) : pass(check, `${field} carries ${certs.length} certificate(s), leaf first, without the anchor`));
          break;
        }
        case 'mdoc-digest-algorithm':
          results.push(sd ? skip(check, 'applies to mdoc') : credential.digestAlgorithm === 'SHA-256' ? pass(check, 'digestAlgorithm SHA-256') : failed(check, `digestAlgorithm ${String(credential.digestAlgorithm)}`));
          break;
        case 'signer-profile': {
          if (!credential.chain.length) {
            results.push(failed(check, 'no signer certificate'));
            break;
          }
          const cert = leaf();
          const now = ctx.now ?? new Date();
          const problems: string[] = [];
          if (ctx.enrolledSigners && !ctx.enrolledSigners.some((e) => Buffer.from(parseCertificate(e).der).equals(Buffer.from(cert.der)))) {
            problems.push('the signer certificate is none the Test Registrar enrolled for the Provider');
          }
          if (cert.basicConstraints?.cA) problems.push('basicConstraints cA is true');
          if (!cert.keyUsage?.includes('digitalSignature')) problems.push(`keyUsage ${JSON.stringify(cert.keyUsage ?? [])} lacks digitalSignature`);
          const ca = cert.keyUsage?.filter((u) => (u as string) === 'keyCertSign' || u === 'crlSign') ?? [];
          if (ca.length) problems.push(`keyUsage carries ${ca.join(', ')}`);
          for (const [name, value] of [['countryName', cert.subject.attributes.find((a) => a.type === '2.5.4.6')], ['organizationName', cert.subject.organizationName], ['commonName', cert.subject.commonName]] as const) {
            if (!value) problems.push(`the subject has no ${name}`);
          }
          if (!cert.authorityKeyIdentifier) problems.push('no authorityKeyIdentifier');
          if (now < cert.notBefore || now > cert.notAfter) problems.push(`not valid now (${cert.notBefore.toISOString()} to ${cert.notAfter.toISOString()})`);
          if (!sd && !cert.extendedKeyUsage?.includes(MDOC_DS_EKU)) problems.push(`no extended key usage ${MDOC_DS_EKU} (document signer)`);
          results.push(problems.length ? failed(check, problems.join('; ')) : pass(check, `${cert.subject.rfc4514}: end-entity, digitalSignature, subject C/O/CN, AKI${sd ? '' : ', document signer EKU'}${ctx.enrolledSigners ? ', as enrolled' : ''}`));
          break;
        }
        case 'signer-not-access': {
          if (!ctx.accessCertificate) {
            results.push(skip(check, 'the access certificate of the Provider is not known'));
            break;
          }
          const access = parseCertificate(ctx.accessCertificate);
          const cert = leaf();
          if (Buffer.from(access.der).equals(Buffer.from(cert.der))) results.push(failed(check, 'the credential is signed with the access certificate'));
          else if (keyOf(access) === keyOf(cert)) results.push(failed(check, "the signer certificate holds the access certificate's key"));
          else results.push(pass(check, `signer ${cert.subject.rfc4514} differs in certificate and key from the access certificate ${access.subject.rfc4514}`));
          break;
        }
        case 'selective-disclosure':
          results.push(sd ? checkSelectiveDisclosure(credential) : skip(check, 'applies to SD-JWT VC'));
          break;
        case 'salt-entropy': {
          const what = sd ? 'salt' : 'random';
          const short = credential.salts.filter((s) => s.bytes < 16);
          const seen = new Set<string>();
          const repeated = credential.salts.filter((s) => (seen.has(s.value) ? true : (seen.add(s.value), false)));
          // RFC 9901 section 9.3: a new salt per claim is a MUST, 128 bits only "The RECOMMENDED minimum length": a
          // shorter SD-JWT VC salt is recorded, not failed (spec review 2026-11-20). For the mdoc `random` the suite keeps
          // the 16-byte minimum it attributes to ISO/IEC 18013-5 section 9.1.2.5 (not verified against the standard).
          const shortFails = !sd;
          const shortText = short.length ? `${short.length} of ${credential.salts.length} ${what} value(s) shorter than 128 bits (e.g. ${short[0]?.value}, ${short[0]?.bytes * 8} bits)` : undefined;
          const problems = [
            ...(shortText && shortFails ? [shortText] : []),
            ...(repeated.length ? [`${repeated.length} ${what} value(s) repeated`] : []),
            ...(credential.salts.length ? [] : [`no ${what} values`]),
          ];
          const min = Math.min(...credential.salts.map((s) => s.bytes));
          results.push(
            problems.length
              ? failed(check, problems.join('; '))
              : pass(check, `${credential.salts.length} ${what} values, unique, at least ${min * 8} bits${shortText ? `; ${shortText}, below the RECOMMENDED minimum of RFC 9901 section 9.3 (recorded)` : ''}`),
          );
          break;
        }
        case 'algorithm-advertised': {
          const advertised = ctx.advertisedAlgorithms;
          if (!advertised?.length) {
            results.push(failed(check, 'the credential configuration advertises no credential_signing_alg_values_supported'));
            break;
          }
          const names = advertised.map((a) => (typeof a === 'number' ? (COSE_ALG_NAMES[a] ?? `COSE ${a}`) : a));
          results.push(names.includes(credential.alg) ? pass(check, `${credential.alg} is advertised (${names.join(', ')})`) : failed(check, `${credential.alg} is not advertised (${names.join(', ')})`));
          break;
        }
        default:
          break;
      }
    } catch (error) {
      results.push(failed(check, `could not be evaluated: ${(error as Error).message}`));
    }
  }
  return results;
}

/**
 * `selective-disclosure` (PID_21, ARB_30, RFC 9901 section 4): no PID claim is in the clear in the issuer-signed payload,
 * `_sd_alg` is `sha-256`, and every disclosed object carries its members as disclosures and every disclosed array its
 * elements as array element disclosures, so each claim can be disclosed on its own.
 */
export function checkSelectiveDisclosure(credential: Pick<InspectedCredential, 'payload' | 'disclosures'>): CheckResult {
  const check = 'selective-disclosure';
  const payload = credential.payload ?? {};
  const problems: string[] = [];
  if (payload._sd_alg !== 'sha-256') problems.push(`_sd_alg is ${JSON.stringify(payload._sd_alg)}, not sha-256`);
  const clear = Object.keys(payload).filter((k) => !NOT_DISCLOSABLE.has(k));
  if (clear.length) problems.push(`in the clear: ${clear.join(', ')}`);
  const walk = (path: string, value: unknown) => {
    if (Array.isArray(value)) {
      value.forEach((element, i) => {
        const reference = element && typeof element === 'object' && !Array.isArray(element) && Object.keys(element).length === 1 && '...' in element;
        if (!reference) problems.push(`${path}[${i}] is not an array element disclosure`);
      });
    } else if (value && typeof value === 'object') {
      for (const [key, member] of Object.entries(value)) {
        if (key === '_sd') continue;
        problems.push(`${path}.${key} is not a disclosure of its own`);
        walk(`${path}.${key}`, member);
      }
    }
  };
  for (const disclosure of credential.disclosures ?? []) {
    if (disclosure.length === 3) walk(String(disclosure[1]), disclosure[2]);
    else walk('[element]', disclosure[1]);
  }
  return problems.length ? { check, status: 'fail', detail: problems.join('; ') } : { check, status: 'pass', detail: `${credential.disclosures?.length ?? 0} disclosures, each claim, member and element on its own, _sd_alg sha-256` };
}

export interface UnlinkabilityContext {
  /** The declared timestamp precision (ICS-16), seconds; default 1. */
  precisionSeconds?: number;
}

/** Values of one kind that occur in more than one place, with where. */
function repeats(credentials: InspectedCredential[], values: (c: InspectedCredential) => string[]): string[] {
  const where = new Map<string, string[]>();
  for (const credential of credentials) for (const value of values(credential)) where.set(value, [...(where.get(value) ?? []), credential.label]);
  return [...where.entries()].filter(([, at]) => at.length > 1).map(([value, at]) => `${value.length > 24 ? `${value.slice(0, 24)}…` : value} in ${[...new Set(at)].join(', ')}`);
}

/**
 * `PP_WS_SM_Unlinkability`: the named checks of `UNLINKABILITY_CHECKS` over the credentials of several issuances (one
 * Provider, both Wallet Units). `no-wallet-identifier` is per credential (`checkNoWalletIdentifier`).
 */
export function checkUnlinkability(credentials: InspectedCredential[], checks: Check[], ctx: UnlinkabilityContext = {}): CheckResult[] {
  const results: CheckResult[] = [];
  const n = credentials.length;
  const unique = (check: Check, what: string, values: (c: InspectedCredential) => string[]) => {
    const found = repeats(credentials, values);
    const total = credentials.reduce((sum, c) => sum + values(c).length, 0);
    if (!total) return results.push(skip(check, `no ${what} in ${n} credential(s)`));
    return results.push(found.length ? failed(check, `${found.length} ${what} value(s) repeat: ${found.slice(0, 3).join('; ')}`) : pass(check, `${total} ${what} value(s) in ${n} credentials, none repeats`));
  };
  for (const check of checks) {
    switch (check) {
      case 'unique-salts':
        unique(check, 'salt or random', (c) => c.salts.map((s) => s.value));
        break;
      case 'unique-digests':
        unique(check, 'digest', (c) => [...new Set(c.digests)]);
        break;
      case 'unique-status-index':
        unique(check, 'status index', (c) => (c.status ? [`${c.status.uri}#${c.status.idx}`] : []));
        break;
      case 'unique-device-key':
        unique(check, 'device key', (c) => (c.deviceKey ? [`${c.deviceKey.crv}:${c.deviceKey.x}:${c.deviceKey.y}`] : []));
        break;
      case 'unique-signature':
        unique(check, 'signature', (c) => [c.signature]);
        break;
      case 'status-index-order':
        results.push(checkStatusIndexOrder(credentials));
        break;
      case 'batch-timestamps':
        results.push(checkBatchTimestamps(credentials, ctx.precisionSeconds ?? 1));
        break;
      case 'batch-spread':
        results.push(checkBatchSpread(credentials));
        break;
      default:
        break;
    }
  }
  return results;
}

/**
 * `status-index-order` (VCR_17, HAIP 6.1): per status list, the indices in issuance order are neither strictly monotonic
 * (from five credentials on) nor contain four consecutive indices in arithmetic progression. For random indices from a
 * list of 10 000 entries either happens with a probability below 10⁻⁶.
 */
export function checkStatusIndexOrder(credentials: InspectedCredential[]): CheckResult {
  const check = 'status-index-order';
  const byList = new Map<string, number[]>();
  for (const c of credentials) if (c.status) byList.set(c.status.uri, [...(byList.get(c.status.uri) ?? []), c.status.idx]);
  const problems: string[] = [];
  let counted = 0;
  for (const [uri, indices] of byList) {
    counted += indices.length;
    const steps = indices.slice(1).map((idx, i) => idx - (indices[i] as number));
    if (indices.length >= 5 && (steps.every((d) => d > 0) || steps.every((d) => d < 0))) problems.push(`${uri}: the ${indices.length} indices are strictly monotonic (${indices.join(', ')})`);
    for (let i = 0; i + 2 < steps.length; i++) {
      if (steps[i] === steps[i + 1] && steps[i] === steps[i + 2]) {
        problems.push(`${uri}: indices ${indices.slice(i, i + 4).join(', ')} of consecutive issuances step by ${steps[i]}`);
        break;
      }
    }
  }
  if (counted < 2) return { check, status: 'skip', detail: `${counted} credential(s) with a status index` };
  return problems.length ? { check, status: 'fail', detail: problems.join('; ') } : { check, status: 'pass', detail: `${counted} indices in ${byList.size} list(s): neither monotonic nor in arithmetic runs (${[...byList.values()].flat().slice(0, 10).join(', ')}…)` };
}

/**
 * `batch-timestamps` (ISSU_36): the credentials compared, issued within one precision window, carry the same timestamps
 * at the declared precision. Credentials received in different precision windows are compared only with those of
 * their own window.
 */
export function checkBatchTimestamps(credentials: InspectedCredential[], precisionSeconds: number): CheckResult {
  const check = 'batch-timestamps';
  const windows = new Map<number, InspectedCredential[]>();
  for (const c of credentials) {
    const key = Math.floor(c.receivedAt.getTime() / 1000 / precisionSeconds);
    windows.set(key, [...(windows.get(key) ?? []), c]);
  }
  const problems: string[] = [];
  let compared = 0;
  for (const group of windows.values()) {
    const steps = new Set(group.map((c) => c.step));
    if (steps.size < 2) continue;
    compared += group.length;
    for (const name of new Set(group.flatMap((c) => Object.keys(c.times)))) {
      const values = new Set(group.map((c) => (c.times[name] === undefined ? 'absent' : String(Math.floor((c.times[name] as number) / precisionSeconds)))));
      if (values.size > 1) problems.push(`${name} differs at a precision of ${precisionSeconds} s: ${group.map((c) => `${c.label} ${c.times[name]}`).join(', ')}`);
    }
  }
  if (!compared) return { check, status: 'skip', detail: 'no two batches were issued within one precision window' };
  return problems.length ? { check, status: 'fail', detail: problems.join('; ') } : { check, status: 'pass', detail: `${compared} credentials of ${credentials.length > 0 ? new Set(credentials.map((c) => c.step)).size : 0} batches share every timestamp at a precision of ${precisionSeconds} s` };
}

/** `batch-spread` (VCR_17, ISSU_36): no two credentials of one batch (one step) are on adjacent indices of one list. */
export function checkBatchSpread(credentials: InspectedCredential[]): CheckResult {
  const check = 'batch-spread';
  const batches = new Map<string, InspectedCredential[]>();
  for (const c of credentials) if (c.status) batches.set(`${c.step} ${c.status.uri}`, [...(batches.get(`${c.step} ${c.status.uri}`) ?? []), c]);
  const problems: string[] = [];
  let compared = 0;
  for (const batch of batches.values()) {
    if (batch.length < 2) continue;
    compared += batch.length;
    const sorted = batch.map((c) => c.status!.idx).sort((a, b) => a - b);
    const adjacent = sorted.slice(1).filter((idx, i) => idx - (sorted[i] as number) <= 1);
    if (adjacent.length) problems.push(`batch of step ${batch[0]?.step}: indices ${sorted.join(', ')} include adjacent ones`);
  }
  if (!compared) return { check, status: 'skip', detail: 'no batch of two or more credentials with status indices in one list' };
  return problems.length ? { check, status: 'fail', detail: problems.join('; ') } : { check, status: 'pass', detail: `${compared} credentials in ${batches.size} batch list(s), none on adjacent indices` };
}

/**
 * `no-wallet-identifier` (WUA_08, ISSU_35b): the decoded credential contains no identifier of the Wallet Instance, its
 * WIA or its KA: the WIA's `sub` (`client_id`), `jti`, `cnf` key and status reference, the KA's `jti` and status
 * reference. The device key the KA attests is the credential's binding and is not such an identifier.
 */
export function checkNoWalletIdentifier(credential: InspectedCredential, sent: { wia?: string; ka?: string }): CheckResult {
  const check = 'no-wallet-identifier';
  if (!sent.wia && !sent.ka) return { check, status: 'skip', detail: 'the step sent no WIA or KA to compare with' };
  const decode = (jwt?: string) => (jwt ? base64url.decodeJson<Record<string, unknown>>(jwt.split('.')[1] ?? '') : {});
  const wia = decode(sent.wia);
  const ka = decode(sent.ka);
  const wiaKey = (wia.cnf as { jwk?: JsonWebKey } | undefined)?.jwk;
  const statusOfAttestation = (payload: Record<string, unknown>, member: string) =>
    ((payload[member] as { status?: { status_list?: { uri?: string } } } | undefined)?.status?.status_list ?? (payload.status as { status_list?: { uri?: string } } | undefined)?.status_list)?.uri;
  const identifiers: [string, unknown][] = [
    ['WIA sub (client_id)', wia.sub],
    ['WIA jti', wia.jti],
    ['WIA cnf x', wiaKey?.x],
    ['WIA cnf y', wiaKey?.y],
    ['WIA status uri', statusOfAttestation(wia, 'client_status')],
    ['KA jti', ka.jti],
    ['KA status uri', statusOfAttestation(ka, 'key_storage_status')],
  ];
  const found = identifiers.filter(([, value]) => typeof value === 'string' && value.length >= 8 && credential.text.includes(value));
  const looked = identifiers.filter(([, value]) => typeof value === 'string' && value.length >= 8).map(([name]) => name);
  return found.length
    ? { check, status: 'fail', detail: `the credential contains ${found.map(([name, value]) => `${name} ${String(value)}`).join(', ')}` }
    : { check, status: 'pass', detail: `none of ${looked.join(', ')} occurs in the credential` };
}

/** One request the Provider sent to a harness service (`OBS-NET`), as the Test Trust Infrastructure or Status Provider logged it. */
export interface OutboundRequest {
  at: string;
  method: string;
  url: string;
  headers: Record<string, string | string[] | undefined>;
}

/**
 * `outbound-privacy` (VCR_16 analogue, ISSU_35b): every request the Provider sent to `TL-WP` or the Test Status Provider
 * is a GET of a URL the harness published (`published`, without query or fragment), with no body, no cookie and no
 * `Authorization`, so it carries nothing about the User or the transaction.
 */
export function checkOutboundPrivacy(requests: OutboundRequest[], published: string[]): CheckResult {
  const check = 'outbound-privacy';
  if (!requests.length) return { check, status: 'skip', detail: 'the Provider sent no request to TL-WP or the Test Status Provider during the test case' };
  const problems: string[] = [];
  for (const request of requests) {
    const header = (name: string) => request.headers[name] ?? request.headers[name.toLowerCase()];
    const issues: string[] = [];
    if (request.method !== 'GET') issues.push(`method ${request.method}`);
    if (/[?#]/.test(request.url)) issues.push('a query or fragment');
    if (!published.includes(request.url.replace(/[?#].*$/, ''))) issues.push('a URL the harness did not publish');
    if (header('cookie')) issues.push('a cookie');
    if (header('authorization')) issues.push('an Authorization header');
    const length = Number(header('content-length') ?? 0);
    if (length > 0 || header('transfer-encoding')) issues.push('a body');
    if (issues.length) problems.push(`${request.method} ${request.url} at ${request.at}: ${issues.join(', ')}`);
  }
  const urls = [...new Set(requests.map((r) => r.url))];
  return problems.length ? { check, status: 'fail', detail: problems.join('; ') } : { check, status: 'pass', detail: `${requests.length} request(s) to ${urls.length} URL(s) (${urls.join(', ')}): GET of the published URL, no query, body, cookie or Authorization` };
}
