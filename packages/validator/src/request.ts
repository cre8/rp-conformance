// The request-side checks of the reference validator (catalogue scenario SCN-Q: `RP_WS_MS_*` and
// `RP_WS_SM_RpIntegrity`): one named check per property of the requests a Relying Party sends, evaluated over every
// request a step captured, so a request fault can be shown to fail exactly one of them.
import { createHash } from 'node:crypto';
import { type CapturedRequest, type CheckResult, type Flow, REQUEST_CHECKS, type RequestCheck } from '@eudi-pcaf/core';
import { base64url, PID_DOCTYPE, PID_VCT, verifyEs256 } from '@eudi-pcaf/forge';
import { parseAccessCertificate, validateAccessCertificate } from '@owf/eudi-access-certificate';
import { checkOverAsking, parseWRPRC, validateWRPRCPayload } from '@owf/eudi-registration-certificate';
import { type Certificate, parseCertificate } from '@owf/x509';
import { CheckRecorder, NotApplicable, type ValidationResult } from './checks';
import { fail } from './status-list';
import { validatePath } from './x509-path';

export interface RequestCheckOptions {
  /** Anchors of `TL-AC`, for the access certificate. */
  accessCertificateAnchors: Certificate[];
  /** Anchors of `TL-RC`, for the registration certificate. */
  registrationCertificateAnchors: Certificate[];
  /**
   * The key identifiers (base64url) a `trusted_authorities` entry of type `aki` may name: those of the anchors of the
   * list that is the root of trust of the requested category.
   */
  trustedAuthorityKeyIds: string[];
  /** The step requests the variant of its query with `trusted_authorities` (ICS RP.P.3), so the request must carry it. */
  requireTrustedAuthorities?: boolean;
  /** Accept `http` URLs on loopback hosts, for runs on one machine. */
  allowLoopbackHttp?: boolean;
  now?: Date;
}

/** One request, decoded. */
interface Decoded {
  captured: CapturedRequest;
  /** The protected header of the request object (signed) or of its signature by the access certificate (multi-signed). */
  header: Record<string, unknown>;
  payload: Record<string, unknown>;
  /** Signing inputs and signatures of the request object, one per signature. */
  signatures: { header: Record<string, unknown>; input: string; signature: string }[];
  signed: boolean;
}

/** Algorithms of the ECCG agreed cryptographic mechanisms that a request may name: JOSE names and COSE identifiers. */
// ECDSA on P-256, P-384 and P-521 with SHA-2, also as the fully-specified algorithms of RFC 9864 (ESP256, ESP384,
// ESP512), and RSASSA-PSS.
const ECCG_JOSE = new Set(['ES256', 'ES384', 'ES512', 'ESP256', 'ESP384', 'ESP512', 'PS256', 'PS384', 'PS512']);
const ECCG_COSE = new Set([-7, -35, -36, -9, -51, -52, -37, -38, -39]);
const PRIVATE_MEMBERS = ['d', 'p', 'q', 'dp', 'dq', 'qi', 'k', 'oth'];
const ALLOWED_INVOCATION = new Set(['client_id', 'request_uri', 'request_uri_method']);
const SIGNED_PROTOCOLS = ['openid4vp-v1-signed', 'openid4vp-v1-multisigned'];
/** Same-device invocation schemes: HAIP section 5.1, OpenID4VP section 9, or a claimed https URL. */
const INVOCATION_SCHEMES = ['haip-vp:', 'openid4vp:', 'https:'];
const REQUEST_OBJECT_TYPE = 'application/oauth-authz-req+jwt';
const mediaTypeOf = (contentType: string | null | undefined) => contentType?.split(';')[0]?.trim().toLowerCase();

const decodeJson = (segment: unknown, what: string): Record<string, unknown> => {
  try {
    const value = base64url.decodeJson<unknown>(String(segment ?? ''));
    if (value && typeof value === 'object' && !Array.isArray(value)) return value as Record<string, unknown>;
  } catch {
    // falls through
  }
  return fail(`${what} cannot be decoded`);
};

/** Decodes a captured request: the request object of the redirect flow, or the DC API request in its protocol. */
function decode(captured: CapturedRequest): Decoded {
  const compact = (jws: string) => {
    const [h, p, s] = jws.split('.');
    const header = decodeJson(h, 'the request object header');
    return { header, payload: decodeJson(p, 'the request object payload'), signatures: [{ header, input: `${h}.${p}`, signature: s ?? '' }] };
  };
  const signedOf = (signatures: Decoded['signatures']) => signatures.some((s) => s.header.alg !== 'none' && s.signature.length > 0);
  if (captured.flow === 'redirect') {
    const body = captured.requestUri?.body;
    if (!body) fail('no request object was retrieved from request_uri');
    const parts = compact(body as string);
    return { captured, ...parts, signed: signedOf(parts.signatures) };
  }
  const data = (captured.data ?? {}) as Record<string, unknown>;
  if (captured.protocol === 'openid4vp-v1-signed') {
    if (typeof data.request !== 'string') fail('data.request is not a request object');
    const parts = compact(data.request as string);
    return { captured, ...parts, signed: signedOf(parts.signatures) };
  }
  if (captured.protocol === 'openid4vp-v1-multisigned') {
    const jws = (data.request && typeof data.request === 'object' ? data.request : data) as { payload?: string; signatures?: { protected?: string; signature?: string }[] };
    const payload = decodeJson(jws.payload, 'the request object payload');
    const signatures = (jws.signatures ?? []).map((s) => ({ header: decodeJson(s.protected, 'a signature header'), input: `${s.protected}.${jws.payload}`, signature: s.signature ?? '' }));
    // client_id and verifier_info of a multi-signed request are in the protected header of their signature (A.3.2.2).
    const own = signatures.find((s) => Array.isArray(s.header.x5c)) ?? signatures[0];
    return {
      captured,
      header: own?.header ?? {},
      payload: { ...payload, ...(own?.header.client_id ? { client_id: own.header.client_id } : {}), ...(own?.header.verifier_info ? { verifier_info: own.header.verifier_info } : {}) },
      signatures,
      signed: signedOf(signatures),
    };
  }
  return { captured, header: {}, payload: data, signatures: [], signed: false };
}

const isHttpsOrLoopback = (value: unknown, allowLoopbackHttp: boolean) => {
  if (typeof value !== 'string') return false;
  try {
    const url = new URL(value);
    return url.protocol === 'https:' || (allowLoopbackHttp && url.protocol === 'http:' && ['127.0.0.1', 'localhost', '[::1]'].includes(url.hostname));
  } catch {
    return false;
  }
};

/** At least 128 bits from a base64url alphabet: 22 characters or more of the unreserved URL characters. */
const strongRandom = (value: unknown) => typeof value === 'string' && /^[A-Za-z0-9_.~-]{22,}$/.test(value);

type CredentialQuery = { id?: unknown; format?: unknown; meta?: Record<string, unknown>; claims?: { path?: unknown }[]; trusted_authorities?: { type?: unknown; values?: unknown }[]; require_cryptographic_holder_binding?: unknown };
const credentialQueries = (payload: Record<string, unknown>): CredentialQuery[] =>
  ((payload.dcql_query as { credentials?: unknown } | undefined)?.credentials as CredentialQuery[] | undefined) ?? [];

const encryptionKeyOf = (payload: Record<string, unknown>) => {
  const keys = ((payload.client_metadata as { jwks?: { keys?: unknown } } | undefined)?.jwks?.keys ?? []) as Record<string, unknown>[];
  return { keys, key: keys.find((k) => k.use === undefined || k.use === 'enc') };
};

const thumbprintOf = (jwk: Record<string, unknown>) => createHash('sha256').update(JSON.stringify({ crv: jwk.crv, kty: jwk.kty, x: jwk.x, y: jwk.y })).digest('base64url');

const certificateOf = (entry: unknown) => parseCertificate(String(entry));
const selfSigned = (certificate: Certificate) => Buffer.from(certificate.subject.rfc4514).equals(Buffer.from(certificate.issuer.rfc4514));

/** The result of the request-side checks over every captured request. */
export interface RequestValidation extends ValidationResult {
  /** The checks of each request, in the order captured. */
  perRequest: CheckResult[][];
}

/**
 * Checks the captured requests of a step. Each check passes only if it passes for every request; `nonce`, `state` and
 * `ephemeral-key` also fail when two requests share their value. Checks for the other flow, or for a condition the
 * request does not have (no `state`), are skipped.
 */
export async function validateRequests(captured: CapturedRequest[], options: RequestCheckOptions): Promise<RequestValidation> {
  const now = options.now ?? new Date();
  const perRequest: CheckResult[][] = [];
  const decoded: (Decoded | undefined)[] = [];
  for (const request of captured) {
    const recorder = new CheckRecorder('all');
    let d: Decoded | undefined;
    const flowOnly = (flow: Flow) => (request.flow !== flow ? new NotApplicable(`only via ${flow === 'redirect' ? 'redirects' : 'the DC API'}`) : undefined);
    await recorder.collect(async () => {
      await recorder.run('signed-request', [], () => {
        d = decode(request);
        if (request.flow === 'dc-api' && !SIGNED_PROTOCOLS.includes(String(request.protocol))) fail(`the DC API request uses protocol ${String(request.protocol)}, not a signed one`);
        if (!d.signed) fail('the request object is not signed');
      });
      const payload = () => (d as Decoded).payload;
      await recorder.run('request-by-reference', [], () => {
        const skip = flowOnly('redirect');
        if (skip) return skip;
        const params = [...new URL(String(request.invocationUri)).searchParams.keys()];
        const extra = params.filter((p) => !ALLOWED_INVOCATION.has(p));
        if (!params.includes('request_uri')) fail('the invocation URI carries no request_uri');
        if (extra.length) fail(`the invocation URI carries the request parameter(s) ${extra.join(', ')} besides client_id and request_uri`);
      });
      await recorder.run('request-object', ['signed-request'], () => {
        const skip = flowOnly('redirect');
        if (skip) return skip;
        const p = payload();
        if (p.response_type !== 'vp_token') fail(`response_type is ${String(p.response_type)}`);
        if (p.response_mode !== 'direct_post.jwt') fail(`response_mode is ${String(p.response_mode)}, not direct_post.jwt`);
        if (!isHttpsOrLoopback(p.response_uri, options.allowLoopbackHttp ?? false)) fail(`response_uri ${String(p.response_uri)} is not an https URL`);
        if (p.redirect_uri !== undefined) fail('the request object carries a redirect_uri');
        const outer = new URL(String(request.invocationUri)).searchParams.get('client_id');
        if (p.client_id !== outer) fail('the client_id of the request object differs from that of the invocation URI');
        if (typeof p.nonce !== 'string' || !p.dcql_query) fail('the request object lacks nonce or dcql_query');
        if (p.aud !== 'https://self-issued.me/v2') fail(`aud is ${String(p.aud)}, not https://self-issued.me/v2`);
      });
      await recorder.run('nonce', ['signed-request'], () => {
        if (!strongRandom(payload().nonce)) fail(`nonce ${JSON.stringify(payload().nonce)} is not a random value of at least 128 bits`);
      });
      await recorder.run('state', ['signed-request'], () => {
        const skip = flowOnly('redirect');
        if (skip) return skip;
        if (payload().state === undefined) return new NotApplicable('the request carries no state');
        if (!strongRandom(payload().state)) fail(`state ${JSON.stringify(payload().state)} is not a random value of at least 128 bits`);
      });
      await recorder.run('dc-api-request', ['signed-request'], () => {
        const skip = flowOnly('dc-api');
        if (skip) return skip;
        const p = payload();
        if (p.response_mode !== 'dc_api.jwt') fail(`response_mode is ${String(p.response_mode)}, not dc_api.jwt`);
        if (!Array.isArray(p.expected_origins) || p.expected_origins.length === 0) fail('the request carries no expected_origins');
        // OpenID4VP 1.0 Appendix A.2: "Additional request parameters MAY be defined and used" and "The Wallet MUST ignore
        // any unrecognized parameters"; a response_uri is recorded, not failed (spec review 2026-11-20).
        if (p.response_uri !== undefined) return 'dc_api.jwt with expected_origins; also carries a response_uri, which a Wallet ignores over the DC API (recorded)';
      });
      await recorder.run('expected-origins', ['signed-request'], () => {
        const skip = flowOnly('dc-api');
        if (skip) return skip;
        const origins = payload().expected_origins;
        if (!Array.isArray(origins) || origins.length === 0) fail('the request carries no expected_origins');
        const other = (origins as unknown[]).filter((o) => o !== request.origin);
        if (other.length) fail(`expected_origins names ${other.join(', ')} besides the Relying Party's own Origin ${String(request.origin)}`);
      });
      await recorder.run('encryption-key', ['signed-request'], () => {
        const { keys, key } = encryptionKeyOf(payload());
        if (!key) fail('client_metadata.jwks holds no encryption key');
        const k = key as Record<string, unknown>;
        if (k.kty !== 'EC' || k.crv !== 'P-256') fail(`the encryption key is not an EC key on P-256 (${String(k.kty)} ${String(k.crv)})`);
        if (k.alg !== 'ECDH-ES') fail(`the encryption key names alg ${String(k.alg)}, not ECDH-ES`);
        if (typeof k.kid !== 'string' || !k.kid) fail('the encryption key has no kid');
        const leaked = keys.flatMap((entry) => PRIVATE_MEMBERS.filter((m) => m in entry));
        if (leaked.length) fail(`client_metadata.jwks carries the private key member(s) ${leaked.join(', ')}`);
      });
      await recorder.run('enc-values', ['signed-request'], () => {
        const values = (payload().client_metadata as { encrypted_response_enc_values_supported?: unknown } | undefined)?.encrypted_response_enc_values_supported;
        if (!Array.isArray(values) || !values.includes('A128GCM') || !values.includes('A256GCM')) {
          fail(`encrypted_response_enc_values_supported ${JSON.stringify(values)} does not list both A128GCM and A256GCM`);
        }
      });
      await recorder.run('ephemeral-key', ['signed-request'], () => {
        if (!encryptionKeyOf(payload()).key) fail('client_metadata.jwks holds no encryption key');
      });
      await recorder.run('vp-formats', ['signed-request'], () => {
        const formats = (payload().client_metadata as { vp_formats_supported?: Record<string, Record<string, unknown>> } | undefined)?.vp_formats_supported;
        if (!formats) fail('client_metadata has no vp_formats_supported');
        for (const query of credentialQueries(payload())) {
          const entry = formats?.[String(query.format)];
          if (!entry) fail(`vp_formats_supported has no entry for the requested format ${String(query.format)}`);
          for (const [name, values] of Object.entries(entry ?? {})) {
            if (!Array.isArray(values)) continue;
            const other = values.filter((v) => (typeof v === 'number' ? !ECCG_COSE.has(v) : !ECCG_JOSE.has(String(v))));
            if (other.length) fail(`vp_formats_supported ${String(query.format)} ${name} lists ${other.join(', ')}, outside the agreed cryptographic mechanisms`);
          }
        }
      });
      await recorder.run('dcql', ['signed-request'], () => {
        const queries = credentialQueries(payload());
        if (!queries.length) fail('the DCQL query has no credential queries');
        const ids = queries.map((q) => q.id);
        if (new Set(ids).size !== ids.length) fail('two credential queries of the DCQL query have the same id');
        for (const q of queries) {
          if (typeof q.id !== 'string' || !/^[A-Za-z0-9_-]+$/.test(q.id)) fail(`credential query id ${JSON.stringify(q.id)} is not valid`);
          if (q.format === 'dc+sd-jwt' && !Array.isArray(q.meta?.vct_values)) fail(`credential query ${String(q.id)} has no meta.vct_values`);
          else if (q.format === 'mso_mdoc' && typeof q.meta?.doctype_value !== 'string') fail(`credential query ${String(q.id)} has no meta.doctype_value`);
          else if (q.format !== 'dc+sd-jwt' && q.format !== 'mso_mdoc') fail(`credential query ${String(q.id)} has the format ${String(q.format)}`);
          for (const claim of q.claims ?? []) {
            const path = claim.path;
            if (!Array.isArray(path) || path.length === 0 || path.some((s) => s !== null && typeof s !== 'string' && !Number.isInteger(s))) {
              fail(`credential query ${String(q.id)} has an invalid claims path ${JSON.stringify(path)}`);
            }
            if (q.format === 'mso_mdoc' && ((path as unknown[]).length !== 2 || (path as unknown[]).some((s) => typeof s !== 'string'))) {
              fail(`credential query ${String(q.id)} has an mdoc claims path ${JSON.stringify(path)} other than [namespace, element]`);
            }
          }
        }
      });
      await recorder.run('holder-binding', ['signed-request'], () => {
        const pid = credentialQueries(payload()).filter(
          (q) => (q.meta?.vct_values as unknown[] | undefined)?.includes(PID_VCT) || q.meta?.doctype_value === PID_DOCTYPE,
        );
        if (!pid.length) return new NotApplicable('the request asks for no PID');
        const unbound = pid.filter((q) => q.require_cryptographic_holder_binding === false);
        if (unbound.length) fail(`the credential query ${String(unbound[0].id)} for a PID sets require_cryptographic_holder_binding to false`);
      });
      await recorder.run('trusted-authorities', ['signed-request'], () => {
        const authorities = credentialQueries(payload()).flatMap((q) => q.trusted_authorities ?? []);
        if (!authorities.length) {
          if (options.requireTrustedAuthorities) fail('the request carries no trusted_authorities');
          return new NotApplicable('the request carries no trusted_authorities');
        }
        for (const authority of authorities) {
          if (authority.type !== 'aki') fail(`trusted_authorities type ${String(authority.type)} is not aki`);
          const values = Array.isArray(authority.values) ? authority.values : [];
          const unknown = values.filter((v) => !options.trustedAuthorityKeyIds.includes(String(v)));
          if (!values.length || unknown.length) fail(`trusted_authorities names key identifier(s) ${unknown.join(', ') || '(none)'} of no anchor of the list`);
        }
      });
      await recorder.run('request-signature', ['signed-request'], async () => {
        const decodedRequest = d as Decoded;
        const own = decodedRequest.signatures.find((s) => Array.isArray(s.header.x5c));
        if (!own) fail('the request object carries no x5c');
        const header = (own as Decoded['signatures'][number]).header;
        if (header.typ !== 'oauth-authz-req+jwt') fail(`typ is ${String(header.typ)}, not oauth-authz-req+jwt`);
        if (!['ES256', 'ES384', 'ES512'].includes(String(header.alg))) fail(`alg ${String(header.alg)} is not an agreed algorithm`);
        const jwk = certificateOf((header.x5c as string[])[0]).publicKey.jwk;
        if (!jwk || header.alg !== 'ES256' || !(await verifyEs256(jwk, own?.input ?? '', base64url.decode(own?.signature ?? '')))) {
          fail('the request signature does not verify with the leaf certificate in x5c');
        }
      });
      const x5c = () => (((d as Decoded).signatures.find((s) => Array.isArray(s.header.x5c))?.header.x5c ?? []) as string[]);
      await recorder.run('client-id', ['signed-request'], () => {
        const leaf = x5c()[0];
        if (!leaf) fail('the request object carries no x5c');
        const expected = `x509_hash:${createHash('sha256').update(Buffer.from(leaf, 'base64')).digest('base64url')}`;
        if (payload().client_id !== expected) fail(`client_id ${String(payload().client_id)} is not the x509_hash of the leaf certificate`);
      });
      await recorder.run('access-certificate-chain', ['signed-request'], async () => {
        const chain = x5c().map(certificateOf);
        if (!chain.length) fail('the request object carries no x5c');
        const anchors = options.accessCertificateAnchors;
        if (chain.some((c) => anchors.some((a) => Buffer.from(a.der).equals(Buffer.from(c.der))))) fail('x5c carries a trust anchor of TL-AC');
        if (chain.some(selfSigned)) fail('x5c carries a self-signed certificate');
        const path = await validatePath(x5c(), anchors, now);
        if (!path.ok) fail(`the access certificate does not validate to an anchor of TL-AC: ${path.reason}`);
      });
      await recorder.run('access-certificate', ['signed-request'], () => {
        const leaf = x5c()[0];
        if (!leaf) fail('the request object carries no x5c');
        const parsed = parseAccessCertificate(new Uint8Array(Buffer.from(leaf, 'base64')));
        const validation = validateAccessCertificate(parsed, { now });
        const errors = validation.issues.filter((i: { severity: string }) => i.severity === 'error');
        if (errors.length) fail(`not an access certificate per ETSI TS 119 411-8: ${errors.map((i: { code: string }) => i.code).join(', ')}`);
        if (!parsed.subjectIdentifier) fail('the access certificate carries no entity identifier');
      });
      await recorder.run('registration-certificate', ['signed-request', 'access-certificate'], async () => {
        const entries = (payload().verifier_info as { format?: unknown; data?: unknown }[] | undefined)?.filter((e) => e.format === 'registration_cert') ?? [];
        if (entries.length !== 1) fail(`verifier_info carries ${entries.length} registration certificates, not one`);
        const jws = entries[0]?.data;
        if (typeof jws !== 'string') fail('the registration certificate is not given by value');
        const { header, payload: wrprc } = parseWRPRC(jws as string) as { header: { x5c?: string[]; alg?: string }; payload: unknown };
        const path = await validatePath(header.x5c ?? [], options.registrationCertificateAnchors, now);
        if (!path.ok) fail(`the registration certificate is not issued under TL-RC: ${path.reason}`);
        const [h, p, s] = (jws as string).split('.');
        const jwk = path.ok ? path.leaf.publicKey.jwk : undefined;
        if (!jwk || header.alg !== 'ES256' || !(await verifyEs256(jwk, `${h}.${p}`, base64url.decode(s ?? '')))) fail('the registration certificate signature does not verify');
        const subject = parseAccessCertificate(new Uint8Array(Buffer.from(x5c()[0], 'base64'))).subjectIdentifier?.value ?? '';
        const validation = validateWRPRCPayload(wrprc, subject);
        const errors = validation.issues.filter((i: { severity: string }) => i.severity === 'error');
        if (errors.length) fail(`the registration certificate is not valid for the access certificate: ${errors.map((i: { code: string }) => i.code).join(', ')}`);
        const exp = (wrprc as { exp?: number }).exp;
        if (typeof exp === 'number' && exp * 1000 < now.getTime()) fail('the registration certificate has expired');
      });
      await recorder.run('registered-attributes', ['signed-request', 'registration-certificate'], () => {
        const jws = (payload().verifier_info as { format?: unknown; data?: string }[]).find((e) => e.format === 'registration_cert')?.data as string;
        const registered = ((parseWRPRC(jws).payload as { credentials?: unknown[] }).credentials ?? []) as Parameters<typeof checkOverAsking>[1];
        const result = checkOverAsking(payload().dcql_query, registered);
        const errors = result.issues.filter((i: { severity: string }) => i.severity === 'error');
        if (errors.length) fail(`the request asks for more than the registration certificate lists: ${errors.map((i: { code: string; path: (string | number)[] }) => `${i.code} at ${i.path.join('.')}`).join('; ')}`);
      });
      // RP_WS_IA_Engagement and RP_WS_IA_ProtocolFlow: the invocation and the answers at request_uri.
      await recorder.run('invocation-scheme', [], () => {
        const skip = flowOnly('redirect');
        if (skip) return skip;
        let scheme: string;
        try {
          scheme = new URL(String(request.invocationUri)).protocol;
        } catch {
          return fail(`the invocation URI ${String(request.invocationUri)} is not a URI`);
        }
        if (!INVOCATION_SCHEMES.includes(scheme)) fail(`the invocation URI uses the scheme ${scheme}//, not haip-vp://, openid4vp:// or an https URL`);
      });
      await recorder.run('request-uri-content-type', [], () => {
        const skip = flowOnly('redirect');
        if (skip) return skip;
        const contentType = request.requestUri?.contentType;
        if (mediaTypeOf(contentType) !== REQUEST_OBJECT_TYPE) fail(`request_uri answers with Content-Type ${String(contentType)}, not ${REQUEST_OBJECT_TYPE}`);
      });
      await recorder.run('request-uri-refetch', ['signed-request'], () => {
        const skip = flowOnly('redirect');
        if (skip) return skip;
        const refetch = request.refetch;
        if (!refetch) return new NotApplicable('the request_uri was retrieved once');
        if (refetch.status !== 200) fail(`request_uri answers a second retrieval with HTTP ${String(refetch.status)}`);
        let again: Record<string, unknown> | undefined;
        try {
          again = decode({ ...request, requestUri: refetch }).payload;
        } catch {
          again = undefined;
        }
        if (!again) fail('request_uri answers a second retrieval without a request object');
        if (again?.client_id !== payload().client_id) fail('the request object of the second retrieval carries another client_id');
      });
      await recorder.run('wallet-nonce', ['signed-request'], () => {
        const skip = flowOnly('redirect');
        if (skip) return skip;
        if (request.walletNonce === undefined) return new NotApplicable('the request object was not retrieved with POST');
        const method = new URL(String(request.invocationUri)).searchParams.get('request_uri_method');
        if (method !== 'post') fail(`the invocation URI carries request_uri_method ${String(method)}, not post`);
        if (payload().wallet_nonce !== request.walletNonce) fail(`the request object carries wallet_nonce ${JSON.stringify(payload().wallet_nonce)}, not the one the Conformance Wallet posted`);
      });
    });
    perRequest.push(recorder.results);
    decoded.push(d);
  }
  // Freshness across the requests: no two share their nonce, state or encryption key.
  const shared = (values: unknown[]) => values.filter((v, i) => v !== undefined && values.indexOf(v) !== i);
  const across: Partial<Record<RequestCheck, string>> = {};
  const nonces = shared(decoded.map((d) => d?.payload.nonce));
  if (nonces.length) across.nonce = `${nonces.length} request(s) repeat the nonce of an earlier one`;
  const states = shared(decoded.map((d) => d?.payload.state));
  if (states.length) across.state = `${states.length} request(s) repeat the state of an earlier one`;
  const keys = shared(decoded.map((d) => (d && encryptionKeyOf(d.payload).key ? thumbprintOf(encryptionKeyOf(d.payload).key as Record<string, unknown>) : undefined)));
  if (keys.length) across['ephemeral-key'] = `${keys.length} request(s) repeat the encryption key of an earlier one`;

  // A check fails if it failed for any request or across them, passes if it passed for every request it applied to.
  const checks: CheckResult[] = REQUEST_CHECKS.map((check) => {
    const results = perRequest.map((r) => r.find((c) => c.check === check)).filter((r): r is CheckResult => Boolean(r));
    const failed = results.find((r) => r.status === 'fail');
    if (failed) return { check, status: 'fail', detail: failed.detail };
    if (across[check]) return { check, status: 'fail', detail: across[check] };
    if (results.some((r) => r.status === 'pass')) return { check, status: 'pass', detail: results.find((r) => r.status === 'pass')?.detail };
    return { check, status: 'skip', detail: results[0]?.detail };
  });
  const failures = checks.filter((c) => c.status === 'fail').map((c) => c.check);
  return { valid: failures.length === 0, checks, failed: failures[0], failures, perRequest };
}
