// The reference validator over what a PID Provider or Attestation Provider publishes (`OBS-META`, issuer harness design
// sections 2 and 6.3), over the credential offer it hands out, and over the credential request the Conformance Wallet
// sends (point `credential-request`, section 6.2). Each check is named (`METADATA_CHECKS`, `OFFER_CHECKS`,
// `CREDENTIAL_REQUEST_CHECKS`), so a `CONF` test case names the checks it requires and a credential request fault can be
// shown to fail exactly one of them. The functions are pure: the runner hands them what it fetched.
import { base64url, PID_DOCTYPE } from '@eudi-pcaf/forge';
import { parseAccessCertificate, validateAccessCertificate } from '@owf/eudi-access-certificate';
import { parseWRPRC, validateWRPRCPayload } from '@owf/eudi-registration-certificate';
import { type Certificate, parseCertificate } from '@owf/x509';
import { compactVerify, importJWK } from 'jose';
import { CheckFailure, CheckRecorder, NotApplicable, type ValidationResult } from './checks';
import { validatePath } from './x509-path';

/** Algorithms of the ECCG agreed cryptographic mechanisms: ECDSA on P-256, P-384, P-521 (also RFC 9864), RSASSA-PSS. */
const ECCG_JOSE = new Set(['ES256', 'ES384', 'ES512', 'ESP256', 'ESP384', 'ESP512', 'PS256', 'PS384', 'PS512']);
const ECCG_COSE = new Set([-7, -35, -36, -9, -51, -52, -37, -38, -39]);
/** OpenID4VCI 1.0 section 12.2.3. */
export const SIGNED_METADATA_TYPE = 'openidvci-issuer-metadata+jwt';
const PRE_AUTHORIZED_CODE_GRANT = 'urn:ietf:params:oauth:grant-type:pre-authorized_code';
/** The entitlement of each Provider category (ETSI TS 119 475 Annex A). */
const ENTITLEMENTS = {
  pid: 'https://uri.etsi.org/19475/Entitlement/PID_Provider',
  qeaa: 'https://uri.etsi.org/19475/Entitlement/QEAA_Provider',
  'pub-eaa': 'https://uri.etsi.org/19475/Entitlement/PUB_EAA_Provider',
  eaa: 'https://uri.etsi.org/19475/Entitlement/Non_Q_EAA_Provider',
} as const;
export type ProviderCategory = keyof typeof ENTITLEMENTS;

type Json = Record<string, unknown>;

/** Fails the running check (a declaration, so the compiler narrows after it). */
function fail(message: string): never {
  throw new CheckFailure(message);
}
const isObject = (value: unknown): value is Json => typeof value === 'object' && value !== null && !Array.isArray(value);
const mediaTypeOf = (contentType: string | undefined) => contentType?.split(';')[0]?.trim().toLowerCase();
const LOOPBACK = new Set(['127.0.0.1', 'localhost', '[::1]']);

/** An `https` URL, or with `allowLoopbackHttp` an `http` URL on a loopback host (runs on one machine). */
function secureUrl(value: unknown, what: string, allowLoopbackHttp?: boolean): URL {
  if (typeof value !== 'string') fail(`${what} is not a URL`);
  let url: URL;
  try {
    url = new URL(value as string);
  } catch {
    return fail(`${what} ${String(value)} is not a URL`);
  }
  if (url.protocol !== 'https:' && !(allowLoopbackHttp && url.protocol === 'http:' && LOOPBACK.has(url.hostname))) fail(`${what} ${url.href} is not https`);
  return url;
}

/** The URL of the Credential Issuer metadata (OpenID4VCI 1.0 section 12.2.2): well-known segment before the path. */
export function wellKnownMetadataUrl(credentialIssuer: string): string {
  const url = new URL(credentialIssuer);
  const path = url.pathname === '/' ? '' : url.pathname.replace(/\/$/, '');
  return `${url.origin}/.well-known/openid-credential-issuer${path}`;
}

/** JSON with sorted keys, so two values compare independently of member order. */
function canonical(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  if (isObject(value)) return `{${Object.keys(value).sort().map((k) => `${JSON.stringify(k)}:${canonical(value[k])}`).join(',')}}`;
  return JSON.stringify(value);
}

const decodeJson = (segment: string | undefined): Json => {
  try {
    const value = base64url.decodeJson<unknown>(segment ?? '');
    if (isObject(value)) return value;
  } catch {
    // falls through
  }
  return fail('a segment is not a base64url-encoded JSON object');
};

/** Verifies a compact JWS with the public key of a certificate, for any ECCG algorithm. */
async function verifiesWith(jws: string, certificate: Certificate, alg: string): Promise<boolean> {
  const jwk = certificate.publicKey.jwk;
  if (!jwk) return false;
  try {
    await compactVerify(jws, await importJWK(jwk as never, alg), { algorithms: [alg] });
    return true;
  } catch {
    return false;
  }
}

const anchorIn = (chain: Certificate[], anchors: Certificate[]) => chain.some((c) => anchors.some((a) => Buffer.from(a.der).equals(Buffer.from(c.der))));
const selfSigned = (c: Certificate) => c.subject.rfc4514 === c.issuer.rfc4514;

/** The trade name of an access certificate: its subject `commonName` (ETSI TS 119 411-8 GEN-6.1.1-04). */
function tradeNameOf(certificate: Certificate): string | undefined {
  return /(?:^|,)CN=((?:\\,|[^,])+)/.exec(certificate.subject.rfc4514)?.[1]?.replace(/\\(.)/g, '$1');
}

/** Every key of a JSON value, recursively. */
function keysOf(value: unknown, path = ''): string[] {
  if (Array.isArray(value)) return value.flatMap((v, i) => keysOf(v, `${path}[${i}]`));
  if (!isObject(value)) return [];
  return Object.entries(value).flatMap(([k, v]) => [`${path}${path ? '.' : ''}${k}`, ...keysOf(v, `${path}${path ? '.' : ''}${k}`)]);
}

// ----------------------------------------------------------------------------------------------------- metadata

/** An HTTP answer as the runner recorded it. */
export interface FetchedArtifact {
  url: string;
  status: number;
  contentType?: string;
  /** The `Cache-Control` header. */
  cacheControl?: string;
  body: string;
}

/** What `SCN-M` fetched (`OBS-META`). */
export interface MetadataObservation {
  /** The Credential Issuer identifier the Conformance Wallet starts from (the `credential_issuer` of an offer). */
  credentialIssuer: string;
  /** The Credential Issuer metadata as JSON. */
  unsigned?: FetchedArtifact;
  /** The Credential Issuer metadata fetched with `Accept: application/jwt`. */
  signed?: FetchedArtifact;
  /** The metadata of every Authorization Server the Credential Issuer names (or of the Credential Issuer itself). */
  authorizationServers: Json[];
  /** Two or more POSTs to the nonce endpoint. */
  nonces?: FetchedArtifact[];
  /** The probe for a server retrieval endpoint (ISO/IEC 18013-5 section 8.3.3.2): `{issuer}/.well-known/openid-configuration`. */
  serverRetrievalProbe?: FetchedArtifact;
}

export interface MetadataCheckOptions {
  /** Anchors of `TL-AC`, for the access certificate in the signed metadata. */
  accessCertificateAnchors: Certificate[];
  /** Anchors of `TL-RC`, for the registration certificate. */
  registrationCertificateAnchors: Certificate[];
  /** The Provider's category (ICS-01). */
  category: ProviderCategory;
  /** The Provider declares the pre-authorized code grant (ICS-03, `P-PA`). */
  preAuthorized: boolean;
  /** Accept `http` URLs on loopback hosts, for runs on one machine. */
  allowLoopbackHttp?: boolean;
  now?: Date;
}

/** Every check of `SCN-M` over the Credential Issuer and Authorization Server metadata. All checks run (mode `all`). */
export async function validateIssuerMetadata(observation: MetadataObservation, options: MetadataCheckOptions): Promise<ValidationResult> {
  const recorder = new CheckRecorder('all');
  const now = options.now ?? new Date();
  let metadata: Json = {};
  let signedPayload: Json = {};
  let accessCertificate: Certificate | undefined;
  const configurations = () => (isObject(metadata.credential_configurations_supported) ? metadata.credential_configurations_supported : {}) as Record<string, Json>;

  return recorder.collect(async () => {
    await recorder.run('metadata-location', [], () => {
      const fetched = observation.unsigned;
      if (!fetched) fail('the Credential Issuer metadata was not fetched');
      const expected = wellKnownMetadataUrl(observation.credentialIssuer);
      if (fetched.url !== expected) fail(`fetched from ${fetched.url}, not from ${expected}`);
      if (fetched.status !== 200) fail(`HTTP ${fetched.status} at ${fetched.url}`);
      if (mediaTypeOf(fetched.contentType) !== 'application/json') fail(`content type ${fetched.contentType ?? 'none'}, not application/json`);
      try {
        const parsed = JSON.parse(fetched.body) as unknown;
        if (!isObject(parsed)) fail('the metadata is not a JSON object');
        metadata = parsed as Json;
      } catch (error) {
        fail(`the metadata is not JSON: ${(error as Error).message}`);
      }
      const url = secureUrl(metadata.credential_issuer, 'credential_issuer', options.allowLoopbackHttp);
      if (url.search || url.hash) fail('credential_issuer carries a query or fragment');
      if (metadata.credential_issuer !== observation.credentialIssuer) fail(`credential_issuer ${String(metadata.credential_issuer)} differs from the identifier ${observation.credentialIssuer}`);
      return `served at ${expected}`;
    });

    await recorder.run('metadata-signed', [], async () => {
      const fetched = observation.signed;
      if (!fetched) fail('the signed metadata was not fetched');
      if (fetched.status !== 200) fail(`HTTP ${fetched.status} for Accept: application/jwt`);
      if (mediaTypeOf(fetched.contentType) !== 'application/jwt') fail(`content type ${fetched.contentType ?? 'none'}, not application/jwt`);
      const jws = fetched.body.trim();
      const [h, p, s] = jws.split('.');
      if (!h || !p || !s || jws.split('.').length !== 3) fail('the answer is not a compact JWS');
      const header = decodeJson(h);
      signedPayload = decodeJson(p);
      if (header.typ !== SIGNED_METADATA_TYPE) fail(`typ is ${String(header.typ)}, not ${SIGNED_METADATA_TYPE}`);
      if (typeof header.alg !== 'string' || !ECCG_JOSE.has(header.alg)) fail(`alg ${String(header.alg)} is not an agreed algorithm`);
      const x5c = header.x5c;
      if (!Array.isArray(x5c) || x5c.length === 0 || x5c.some((c) => typeof c !== 'string')) fail('the header carries no x5c');
      const chain = (x5c as string[]).map((c) => parseCertificate(c));
      if (anchorIn(chain, options.accessCertificateAnchors)) fail('x5c carries a trust anchor of TL-AC');
      if (chain.some(selfSigned)) fail('x5c carries a self-signed certificate');
      const path = await validatePath(x5c as string[], options.accessCertificateAnchors, now);
      if (!path.ok) fail(`the signing certificate does not validate to an anchor of TL-AC: ${path.reason}`);
      const leaf = (path as { leaf: Certificate }).leaf;
      const parsed = parseAccessCertificate(new Uint8Array(leaf.der));
      const errors = validateAccessCertificate(parsed, { now }).issues.filter((i: { severity: string }) => i.severity === 'error');
      if (errors.length) fail(`the signing certificate is not an access certificate per ETSI TS 119 411-8: ${errors.map((i: { code: string }) => i.code).join(', ')}`);
      if (!(await verifiesWith(jws, leaf, header.alg as string))) fail('the signature does not verify with the leaf certificate in x5c');
      if (signedPayload.sub !== observation.credentialIssuer) fail(`sub ${String(signedPayload.sub)} is not the Credential Issuer identifier ${observation.credentialIssuer}`);
      if (typeof signedPayload.iat !== 'number') fail('the payload carries no iat');
      if (typeof signedPayload.exp === 'number' && signedPayload.exp * 1000 < now.getTime()) fail('the signed metadata has expired');
      accessCertificate = leaf;
      return `signed with ${String(header.alg)} by ${leaf.subject.rfc4514}, ${chain.length} certificate(s) in x5c`;
    });

    await recorder.run('metadata-signed-equal', ['metadata-location', 'metadata-signed'], () => {
      const { iss: _iss, sub: _sub, iat: _iat, exp: _exp, nbf: _nbf, jti: _jti, ...signedValues } = signedPayload;
      const keys = new Set([...Object.keys(signedValues), ...Object.keys(metadata)]);
      const differing = [...keys].filter((k) => canonical(signedValues[k]) !== canonical(metadata[k]));
      if (differing.length) fail(`signed and unsigned metadata differ in ${differing.join(', ')}`);
      return `${keys.size} members equal`;
    });

    let registration: Json = {};
    await recorder.run('metadata-registration-certificate', ['metadata-location', 'metadata-signed'], async () => {
      const entries = (Array.isArray(metadata.issuer_info) ? metadata.issuer_info : []).filter((e): e is Json => isObject(e) && e.format === 'registration_cert');
      if (entries.length !== 1) fail(`issuer_info carries ${entries.length} registration certificates, not one`);
      const jws = entries[0]?.data;
      if (typeof jws !== 'string') fail('the registration certificate is not given by value');
      const { header, payload } = parseWRPRC(jws as string) as { header: { x5c?: string[]; alg?: string }; payload: unknown };
      const path = await validatePath(header.x5c ?? [], options.registrationCertificateAnchors, now);
      if (!path.ok) fail(`the registration certificate is not issued under TL-RC: ${path.reason}`);
      const leaf = (path as { leaf: Certificate }).leaf;
      if (!header.alg || !ECCG_JOSE.has(header.alg) || !(await verifiesWith(jws as string, leaf, header.alg))) fail('the registration certificate signature does not verify');
      const subject = parseAccessCertificate(new Uint8Array((accessCertificate as Certificate).der)).subjectIdentifier?.value ?? '';
      const errors = validateWRPRCPayload(payload, subject).issues.filter((i: { severity: string }) => i.severity === 'error');
      if (errors.length) fail(`the registration certificate is not valid for the access certificate (${subject}): ${errors.map((i: { code: string }) => i.code).join(', ')}`);
      const exp = (payload as { exp?: number }).exp;
      if (typeof exp === 'number' && exp * 1000 < now.getTime()) fail('the registration certificate has expired');
      registration = payload as Json;
      return `issued by ${leaf.issuer.rfc4514} for ${subject}`;
    });

    await recorder.run('metadata-registration-entitlement', ['metadata-registration-certificate'], () => {
      const entitlements = Array.isArray(registration.entitlements) ? registration.entitlements : [];
      const expected = ENTITLEMENTS[options.category];
      if (!entitlements.includes(expected)) fail(`entitlements ${JSON.stringify(entitlements)} lack ${expected}`);
      const provided = (Array.isArray(registration.provides_attestations) ? registration.provides_attestations : []).filter(isObject);
      const missing = Object.entries(configurations()).filter(([, c]) => {
        const meta = (entry: Json) => (isObject(entry.meta) ? entry.meta : {});
        if (c.format === 'dc+sd-jwt') return !provided.some((e) => e.format === 'dc+sd-jwt' && Array.isArray(meta(e).vct_values) && (meta(e).vct_values as unknown[]).includes(c.vct));
        if (c.format === 'mso_mdoc') return !provided.some((e) => e.format === 'mso_mdoc' && meta(e).doctype_value === c.doctype);
        return !provided.some((e) => e.format === c.format);
      });
      if (missing.length) fail(`provides_attestations does not list ${missing.map(([id]) => id).join(', ')}`);
      return `${expected}; ${Object.keys(configurations()).length} configuration(s) listed`;
    });

    await recorder.run('metadata-pid-configurations', ['metadata-location'], () => {
      if (options.category !== 'pid') return new NotApplicable('the Provider is not a PID Provider');
      const all = Object.values(configurations());
      const sd = all.some((c) => c.format === 'dc+sd-jwt' && typeof c.vct === 'string' && (c.vct === 'urn:eudi:pid:1' || /^urn:eudi:pid:[a-z]{2}:/.test(c.vct)));
      const md = all.some((c) => c.format === 'mso_mdoc' && c.doctype === PID_DOCTYPE);
      const missing = [...(sd ? [] : ['dc+sd-jwt with vct urn:eudi:pid:1']), ...(md ? [] : [`mso_mdoc with doctype ${PID_DOCTYPE}`])];
      if (missing.length) fail(`no PID configuration ${missing.join(' and none ')}`);
      return 'PID in dc+sd-jwt and mso_mdoc';
    });

    await recorder.run('metadata-algorithms', ['metadata-location'], () => {
      const bad: string[] = [];
      const agreed = (value: unknown) => (typeof value === 'number' ? ECCG_COSE.has(value) : typeof value === 'string' && ECCG_JOSE.has(value));
      for (const [id, c] of Object.entries(configurations())) {
        for (const alg of Array.isArray(c.credential_signing_alg_values_supported) ? c.credential_signing_alg_values_supported : []) {
          if (!agreed(alg)) bad.push(`${id} credential_signing_alg_values_supported ${String(alg)}`);
        }
        for (const [type, proof] of Object.entries(isObject(c.proof_types_supported) ? c.proof_types_supported : {})) {
          const algs = isObject(proof) && Array.isArray(proof.proof_signing_alg_values_supported) ? proof.proof_signing_alg_values_supported : [];
          for (const alg of algs) if (!agreed(alg)) bad.push(`${id} ${type} proof_signing_alg_values_supported ${String(alg)}`);
        }
      }
      for (const as of observation.authorizationServers) {
        for (const alg of Array.isArray(as.dpop_signing_alg_values_supported) ? as.dpop_signing_alg_values_supported : []) {
          if (!agreed(alg)) bad.push(`${String(as.issuer)} dpop_signing_alg_values_supported ${String(alg)}`);
        }
      }
      if (bad.length) fail(`not an agreed algorithm: ${bad.join('; ')}`);
      return 'every advertised algorithm is an ECCG agreed mechanism';
    });

    await recorder.run('metadata-key-attestation', ['metadata-location'], () => {
      const problems: string[] = [];
      let bound = 0;
      for (const [id, c] of Object.entries(configurations())) {
        if (!Array.isArray(c.cryptographic_binding_methods_supported) || c.cryptographic_binding_methods_supported.length === 0) continue;
        bound++;
        const proofTypes = Object.entries(isObject(c.proof_types_supported) ? c.proof_types_supported : {});
        if (!proofTypes.length) problems.push(`${id} has no proof_types_supported`);
        for (const [type, proof] of proofTypes) {
          const required = isObject(proof) ? proof.key_attestations_required : undefined;
          if (!isObject(required)) {
            problems.push(`${id} proof type ${type} requires no key attestation`);
            continue;
          }
          if (options.category !== 'pid') continue;
          for (const level of ['key_storage', 'user_authentication']) {
            const values = required[level];
            if (!Array.isArray(values) || values.length === 0) problems.push(`${id} ${type} key_attestations_required.${level} is missing`);
            else if (values.some((v) => v !== 'iso_18045_high')) problems.push(`${id} ${type} key_attestations_required.${level} ${JSON.stringify(values)} accepts less than iso_18045_high`);
          }
        }
      }
      if (problems.length) fail(problems.join('; '));
      if (!bound) return new NotApplicable('no device-bound configuration');
      return `${bound} device-bound configuration(s) require a key attestation`;
    });

    await recorder.run('metadata-reuse-policy', ['metadata-location'], () => {
      const problems: string[] = [];
      const batch = isObject(metadata.batch_credential_issuance) ? metadata.batch_credential_issuance.batch_size : undefined;
      for (const [id, c] of Object.entries(configurations())) {
        const policy = c.credential_reuse_policy ?? (isObject(c.credential_metadata) ? c.credential_metadata.credential_reuse_policy : undefined);
        if (!isObject(policy)) {
          problems.push(`${id} has no credential_reuse_policy`);
          continue;
        }
        const policyOptions = Array.isArray(policy.options) ? policy.options.filter(isObject) : [];
        if (!policyOptions.length) {
          problems.push(`${id} credential_reuse_policy has no options`);
          continue;
        }
        const details = policyOptions.flatMap((o) => (Array.isArray(o.details) ? o.details : []));
        if (!details.some((d) => d === 'once_only' || d === 'limited_time' || d === 'limited-time')) problems.push(`${id} credential_reuse_policy names neither method A (once_only) nor B (limited_time)`);
        for (const option of policyOptions) {
          const size = option.batch_size;
          if (size === undefined) continue;
          if (typeof size !== 'number' || !Number.isInteger(size) || size < 1) problems.push(`${id} batch_size ${String(size)} is not a positive integer`);
          else if (typeof batch !== 'number') problems.push(`${id} names batch_size ${size}, but the metadata has no batch_credential_issuance`);
          else if (size > batch) problems.push(`${id} batch_size ${size} exceeds batch_credential_issuance.batch_size ${batch}`);
          if (typeof option.reissue_trigger_unused === 'number' && typeof size === 'number' && option.reissue_trigger_unused >= size) {
            problems.push(`${id} reissue_trigger_unused ${option.reissue_trigger_unused} is not below batch_size ${size}`);
          }
        }
      }
      if (problems.length) fail(problems.join('; '));
      return `${Object.keys(configurations()).length} configuration(s) with a reuse policy`;
    });

    await recorder.run('metadata-nonce-endpoint', ['metadata-location'], () => {
      secureUrl(metadata.nonce_endpoint, 'nonce_endpoint', options.allowLoopbackHttp);
      const answers = observation.nonces ?? [];
      if (answers.length < 2) fail(`${answers.length} nonce request(s) were sent, not two`);
      const nonces: string[] = [];
      for (const [i, answer] of answers.entries()) {
        if (answer.status !== 200) fail(`nonce request ${i + 1}: HTTP ${answer.status}`);
        if (!/(^|,)\s*no-store\s*(,|$)/i.test(answer.cacheControl ?? '')) fail(`nonce request ${i + 1}: no Cache-Control: no-store`);
        const body = (() => {
          try {
            return JSON.parse(answer.body) as unknown;
          } catch {
            return undefined;
          }
        })();
        const cNonce = isObject(body) ? body.c_nonce : undefined;
        if (typeof cNonce !== 'string' || !cNonce) fail(`nonce request ${i + 1}: no c_nonce`);
        nonces.push(cNonce as string);
      }
      if (new Set(nonces).size !== nonces.length) fail('the nonce endpoint answered the same c_nonce twice');
      return `${nonces.length} distinct c_nonce values, Cache-Control: no-store`;
    });

    await recorder.run('metadata-authorization-server', ['metadata-location'], () => {
      if (!observation.authorizationServers.length) fail('no Authorization Server metadata was fetched');
      const problems: string[] = [];
      for (const as of observation.authorizationServers) {
        const name = String(as.issuer);
        if (as.require_pushed_authorization_requests !== true) problems.push(`${name}: require_pushed_authorization_requests is not true`);
        if (typeof as.pushed_authorization_request_endpoint !== 'string') problems.push(`${name}: no pushed_authorization_request_endpoint`);
        if (canonical(as.code_challenge_methods_supported) !== canonical(['S256'])) problems.push(`${name}: code_challenge_methods_supported ${JSON.stringify(as.code_challenge_methods_supported)} is not ["S256"]`);
        if (!Array.isArray(as.dpop_signing_alg_values_supported) || as.dpop_signing_alg_values_supported.length === 0) problems.push(`${name}: no dpop_signing_alg_values_supported`);
        if (!Array.isArray(as.token_endpoint_auth_methods_supported) || !as.token_endpoint_auth_methods_supported.includes('attest_jwt_client_auth')) {
          problems.push(`${name}: token_endpoint_auth_methods_supported lacks attest_jwt_client_auth`);
        }
        if (options.preAuthorized) {
          if (Array.isArray(as.grant_types_supported) && !as.grant_types_supported.includes(PRE_AUTHORIZED_CODE_GRANT)) problems.push(`${name}: grant_types_supported lacks the pre-authorized code grant`);
          if (as['pre-authorized_grant_anonymous_access_supported'] === true) problems.push(`${name}: pre-authorized_grant_anonymous_access_supported is true, while the wallet must authenticate with its WIA`);
        }
      }
      if (problems.length) fail(problems.join('; '));
      return `${observation.authorizationServers.length} Authorization Server(s): PAR required, PKCE S256, DPoP, attest_jwt_client_auth`;
    });

    await recorder.run('metadata-display', ['metadata-location', 'metadata-signed'], () => {
      const trade = tradeNameOf(accessCertificate as Certificate);
      if (!trade) fail('the access certificate carries no commonName (trade name)');
      const names = (Array.isArray(metadata.display) ? metadata.display : []).filter(isObject).map((d) => d.name).filter((n): n is string => typeof n === 'string');
      if (!names.length) fail('display carries no name');
      const t = (trade as string).toLowerCase();
      if (!names.some((n) => n.toLowerCase().includes(t) || t.includes(n.toLowerCase()))) fail(`no display name (${names.join(', ')}) is consistent with the trade name ${trade}`);
      return `display name consistent with ${trade}`;
    });

    await recorder.run('metadata-no-server-retrieval', ['metadata-location'], () => {
      const pattern = /server_?retrieval|userinfo_endpoint|webapi/i;
      const found = [...keysOf(metadata), ...observation.authorizationServers.flatMap((as) => keysOf(as))].filter((k) => pattern.test(k));
      if (found.length) fail(`the metadata advertises ${found.join(', ')}`);
      const probe = observation.serverRetrievalProbe;
      if (probe && probe.status === 200) {
        try {
          const body = JSON.parse(probe.body) as unknown;
          if (isObject(body) && body.userinfo_endpoint) fail(`${probe.url} advertises userinfo_endpoint ${String(body.userinfo_endpoint)}`);
        } catch (error) {
          if (!(error instanceof SyntaxError)) throw error;
        }
      }
      return `no server retrieval endpoint advertised${probe ? ` (probe ${probe.url}: HTTP ${probe.status})` : ''}`;
    });

    // Issue 27: the configurations of an Attestation Provider (AP_WS_MS_Metadata_100 to _103).
    const bound = (c: Json) => Array.isArray(c.cryptographic_binding_methods_supported) && c.cryptographic_binding_methods_supported.length > 0;
    const proofTypes = (c: Json) => Object.entries(isObject(c.proof_types_supported) ? c.proof_types_supported : {});

    await recorder.run('metadata-no-key-binding', ['metadata-location'], () => {
      const unbound = Object.entries(configurations()).filter(([, c]) => !bound(c));
      if (!unbound.length) return new NotApplicable('every configuration is device-bound (cryptographic_binding_methods_supported)');
      const problems = unbound.flatMap(([id, c]) =>
        proofTypes(c).map(([type, proof]) => `${id} offers proof type ${type}${isObject(proof) && isObject(proof.key_attestations_required) ? ' that requires a key attestation' : ''}`),
      );
      if (problems.length) fail(`a configuration that is not device-bound still asks for a key proof: ${problems.join('; ')}`);
      return `${unbound.map(([id]) => id).join(', ')}: no cryptographic binding, no proof type, no key attestation`;
    });

    // After `metadata-key-attestation`, which it refines with the levels for every category.
    await recorder.run('metadata-key-attestation-levels', ['metadata-key-attestation'], () => {
      const devices = Object.entries(configurations()).filter(([, c]) => bound(c));
      if (!devices.length) return new NotApplicable('no device-bound configuration');
      const problems: string[] = [];
      for (const [id, c] of devices) {
        const types = proofTypes(c);
        if (!types.length) problems.push(`${id} has no proof_types_supported`);
        for (const [type, proof] of types) {
          const required = isObject(proof) ? proof.key_attestations_required : undefined;
          if (!isObject(required)) {
            problems.push(`${id} proof type ${type} states no key_attestations_required`);
            continue;
          }
          for (const level of ['key_storage', 'user_authentication']) {
            const values = required[level];
            if (!Array.isArray(values) || values.length === 0 || values.some((v) => typeof v !== 'string')) problems.push(`${id} ${type} key_attestations_required.${level} is not a non-empty list of levels`);
          }
        }
      }
      if (problems.length) fail(problems.join('; '));
      return `${devices.length} device-bound configuration(s) state key_storage and user_authentication`;
    });

    await recorder.run('metadata-disclosure-policy', ['metadata-location'], () => {
      // ETSI TS 119 472-3 and EDP_09: the embedded disclosure policy by value in the configuration's metadata. The
      // suite looks for it under `disclosure_policy` (as EUDIPLO publishes it), `policy` or `credential_metadata.policy`
      // of a configuration (no profile names the member yet); a policy only by reference (`policy_uri`) fails.
      const holder = (c: Json) => (isObject(c.credential_metadata) ? c.credential_metadata : c);
      const byValue = Object.entries(configurations()).filter(([, c]) => isObject(c.disclosure_policy) || isObject(holder(c).policy) || isObject(c.policy));
      const byReference = Object.entries(configurations()).filter(([, c]) => typeof holder(c).policy_uri === 'string' || typeof c.policy_uri === 'string');
      if (byReference.length) fail(`embedded disclosure policy only by reference in ${byReference.map(([id]) => id).join(', ')}`);
      if (!byValue.length) return new NotApplicable('no configuration carries an embedded disclosure policy');
      return `${byValue.map(([id]) => id).join(', ')} carry an embedded disclosure policy by value`;
    });

    await recorder.run('metadata-attestation-formats', ['metadata-location'], () => {
      const other = Object.entries(configurations()).filter(([, c]) => c.format !== 'dc+sd-jwt' && c.format !== 'mso_mdoc');
      if (other.length) fail(`configuration(s) in another format: ${other.map(([id, c]) => `${id} (${String(c.format)})`).join(', ')}`);
      return `${Object.keys(configurations()).length} configuration(s), each dc+sd-jwt or mso_mdoc`;
    });
  });
}

// ----------------------------------------------------------------------------------------------------- offer

/** A captured credential offer (`PP_WS_MS_Offer`). */
export interface OfferObservation {
  /** The resolved offer object. */
  offer: Json;
  byReference: boolean;
  /** The fetch of `credential_offer_uri`, for an offer by reference. */
  reference?: FetchedArtifact;
  /** The Credential Issuer metadata the offer's issuer serves. */
  metadata?: Json;
  /** An offer by value of the same Provider, configuration and grant, to compare an offer by reference with. */
  byValue?: Json;
  /** The adapter asked for a `tx_code`: the pre-authorized code grant must declare one. */
  txCodeExpected?: boolean;
  allowLoopbackHttp?: boolean;
}

/** An offer without its session values (codes, `issuer_state`), for comparing two offers of the same kind. */
function offerShape(offer: Json): unknown {
  const grants = isObject(offer.grants) ? offer.grants : {};
  const shaped: Json = {};
  for (const [type, grant] of Object.entries(grants)) {
    if (!isObject(grant)) continue;
    const { 'pre-authorized_code': _code, issuer_state: _state, ...rest } = grant;
    shaped[type] = { ...rest, ...(_code !== undefined ? { 'pre-authorized_code': typeof _code } : {}), ...(_state !== undefined ? { issuer_state: typeof _state } : {}) };
  }
  return canonical({ ...offer, grants: shaped });
}

/** Looks like a JWS or JWE, or base64url-encoded JSON: values that are not opaque. */
function transparent(code: string): string | undefined {
  const segments = code.split('.');
  if (segments.length === 3 || segments.length === 5) {
    try {
      if (isObject(base64url.decodeJson<unknown>(segments[0] ?? ''))) return 'it is a JWT';
    } catch {
      // not a JOSE header
    }
  }
  try {
    if (isObject(base64url.decodeJson<unknown>(code))) return 'it is base64url-encoded JSON';
  } catch {
    // opaque
  }
  return undefined;
}

export function validateCredentialOffer(observation: OfferObservation): Promise<ValidationResult> {
  const recorder = new CheckRecorder('all');
  const { offer } = observation;
  const grants = isObject(offer.grants) ? offer.grants : {};
  return recorder.collect(async () => {
    await recorder.run('offer-issuer', [], () => {
      const url = secureUrl(offer.credential_issuer, 'credential_issuer', observation.allowLoopbackHttp);
      if (url.search || url.hash) fail('credential_issuer carries a query or fragment');
      if (observation.metadata && observation.metadata.credential_issuer !== offer.credential_issuer) {
        fail(`the offer names ${String(offer.credential_issuer)}, the metadata ${String(observation.metadata.credential_issuer)}`);
      }
      return `credential_issuer ${url.href}`;
    });
    await recorder.run('offer-configurations', [], () => {
      const ids = offer.credential_configuration_ids;
      if (!Array.isArray(ids) || ids.length === 0 || ids.some((id) => typeof id !== 'string' || !id)) fail('credential_configuration_ids is not a non-empty array of strings');
      if (new Set(ids as string[]).size !== (ids as string[]).length) fail('credential_configuration_ids repeats an ID');
      if (!observation.metadata) fail('the metadata was not fetched');
      const supported = isObject(observation.metadata?.credential_configurations_supported) ? observation.metadata.credential_configurations_supported : {};
      const unknown = (ids as string[]).filter((id) => !(id in supported));
      if (unknown.length) fail(`the metadata offers no configuration ${unknown.join(', ')}`);
      return (ids as string[]).join(', ');
    });
    await recorder.run('offer-reference-fetch', [], () => {
      if (!observation.byReference) return new NotApplicable('the offer is given by value');
      const fetched = observation.reference;
      if (!fetched) fail('credential_offer_uri was not fetched');
      secureUrl(fetched.url, 'credential_offer_uri', observation.allowLoopbackHttp);
      if (fetched.status !== 200) fail(`HTTP ${fetched.status} at ${fetched.url}`);
      if (mediaTypeOf(fetched.contentType) !== 'application/json') fail(`content type ${fetched.contentType ?? 'none'}, not application/json`);
      return `HTTP 200 application/json at ${fetched.url}`;
    });
    await recorder.run('offer-reference-equal', [], () => {
      if (!observation.byReference) return new NotApplicable('the offer is given by value');
      if (!observation.byValue) fail('no offer by value to compare with');
      if (offerShape(offer) !== offerShape(observation.byValue as Json)) fail(`the offer by reference ${JSON.stringify(offer)} differs from the offer by value ${JSON.stringify(observation.byValue)} beyond its session values`);
      return 'equal to the offer by value except for the session values';
    });
    await recorder.run('offer-pre-authorized-code', [], () => {
      const grant = grants[PRE_AUTHORIZED_CODE_GRANT];
      if (!isObject(grant)) return new NotApplicable('the offer has no pre-authorized code grant');
      const code = grant['pre-authorized_code'];
      if (typeof code !== 'string' || !code) fail('pre-authorized_code is missing');
      const why = transparent(code as string);
      if (why) fail(`pre-authorized_code is not opaque: ${why}`);
      const tx = grant.tx_code;
      if (tx === undefined) {
        if (observation.txCodeExpected) fail('the offer is protected by a transaction code but declares no tx_code');
        return 'opaque pre-authorized_code without tx_code';
      }
      if (!isObject(tx)) fail('tx_code is not an object');
      const t = tx as Json;
      if (t.input_mode !== 'numeric' && t.input_mode !== 'text') fail(`tx_code input_mode ${String(t.input_mode)} is not numeric or text`);
      if (typeof t.length !== 'number' || !Number.isInteger(t.length) || t.length < 1) fail(`tx_code length ${String(t.length)} is not a positive integer`);
      if (typeof t.description !== 'string' || !t.description) fail('tx_code carries no description');
      if ((t.description as string).length > 300) fail('tx_code description is longer than 300 characters');
      return `opaque pre-authorized_code; tx_code ${String(t.input_mode)}, length ${String(t.length)}`;
    });
    await recorder.run('offer-issuer-state', [], () => {
      const grant = grants.authorization_code;
      if (!isObject(grant)) return new NotApplicable('the offer has no authorization code grant');
      if (grant.issuer_state === undefined) return 'no issuer_state';
      if (typeof grant.issuer_state !== 'string' || !grant.issuer_state) fail('issuer_state is not a non-empty string');
      return 'issuer_state present';
    });
  });
}

// ----------------------------------------------------------------------------------------------------- request

/** What a credential request is checked against: the metadata, the access token and its token response. */
export interface CredentialRequestContext {
  /** The `credential_configurations_supported` keys of the metadata. */
  configurationIds: string[];
  /** The configurations the access token covers (`authorization_details`, else the offer's IDs). */
  authorizedConfigurationIds: string[];
  /** The `credential_identifiers` of the token response's `authorization_details`. */
  credentialIdentifiers: string[];
}

/** The `credential_identifiers` and configurations of a token response's `authorization_details`. */
export function authorizationDetailsOf(tokenResponse: Json | undefined): { configurations: string[]; identifiers: string[] } {
  const details = (Array.isArray(tokenResponse?.authorization_details) ? tokenResponse.authorization_details : []).filter(isObject);
  return {
    configurations: details.map((d) => d.credential_configuration_id).filter((id): id is string => typeof id === 'string'),
    identifiers: details.flatMap((d) => (Array.isArray(d.credential_identifiers) ? d.credential_identifiers : [])).filter((id): id is string => typeof id === 'string'),
  };
}

/** The credential request checks (OpenID4VCI 1.0 section 8.2) over the JSON body the Conformance Wallet sends. */
export function validateCredentialRequest(body: unknown, context: CredentialRequestContext): Promise<ValidationResult> {
  const recorder = new CheckRecorder('all');
  const request = isObject(body) ? body : {};
  const hasIdentifier = request.credential_identifier !== undefined;
  const hasConfiguration = request.credential_configuration_id !== undefined;
  return recorder.collect(async () => {
    await recorder.run('credential-request-identifier', [], () => {
      if (hasIdentifier && hasConfiguration) fail('the request carries both credential_identifier and credential_configuration_id');
      if (!hasIdentifier && !hasConfiguration) fail('the request carries neither credential_identifier nor credential_configuration_id');
      return hasIdentifier ? 'credential_identifier' : 'credential_configuration_id';
    });
    await recorder.run('credential-request-configuration', [], () => {
      if (!hasConfiguration) return new NotApplicable('no credential_configuration_id');
      if (!context.configurationIds.includes(request.credential_configuration_id as string)) fail(`the metadata offers no configuration ${String(request.credential_configuration_id)}`);
      return String(request.credential_configuration_id);
    });
    await recorder.run('credential-request-authorized', ['credential-request-configuration'], () => {
      if (!context.authorizedConfigurationIds.includes(request.credential_configuration_id as string)) {
        fail(`the access token covers ${context.authorizedConfigurationIds.join(', ') || 'no configuration'}, not ${String(request.credential_configuration_id)}`);
      }
      return 'covered by the access token';
    });
    await recorder.run('credential-request-credential-identifier', [], () => {
      if (!hasIdentifier) return new NotApplicable('no credential_identifier');
      if (!context.credentialIdentifiers.includes(request.credential_identifier as string)) fail(`the token response issued no credential_identifier ${String(request.credential_identifier)}`);
      return String(request.credential_identifier);
    });
  });
}
