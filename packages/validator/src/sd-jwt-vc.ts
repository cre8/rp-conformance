import { type CheckId, CREDENTIAL_CHECKS, STATUS_LIST_CHECKS } from '@rp-conformance/core';
import { base64url, PID_VCT, sha256, verifyEs256 } from '@rp-conformance/forge';
import { describeKey, processDisclosures } from './disclosures';
import { checkClaims, type RequestedClaim } from './claims';
import { type Certificate, parseCertificate } from '@owf/x509';
import { CheckRecorder, NotApplicable, type ValidationMode, type ValidationResult } from './checks';
import { decodeSegment, evaluateStatusList, type FetchedStatusList, fail, isUri, leafJwk, type StatusListFreshness } from './status-list';
import type { MatchedIssuer, TrustRule, TrustStore } from './trust';
import { duplicateMember } from './json-members';

export type { FetchedStatusList };

/** Every check of an SD-JWT VC presentation and its Status List Token, in the order the reference validator runs them. */
export const SD_JWT_VC_CHECKS: CheckId[] = [...CREDENTIAL_CHECKS, ...STATUS_LIST_CHECKS];

export interface SdJwtVcValidation extends ValidationResult {
  /** Issuer-signed claims with the disclosed values, when the disclosures check passed. */
  claims?: Record<string, unknown>;
  /** The trusted entity the issuer matched. */
  issuer?: string;
  /** Whether the validator retrieved the status list. */
  statusListFetched: boolean;
  /** Whether the issuer matched a trust list that is used within its grace period (`trust-list-stale`). */
  trustListStale: boolean;
}

export interface SdJwtVcValidationOptions {
  trust: TrustStore;
  /** The root of trust of the credential's category (`TRUST_RULES`), for example a PID/Issuance service of `TL-PID`. */
  trustRule: TrustRule;
  /** `vct` the Relying Party requested. */
  expectedVct: string[];
  nonce: string;
  /** The Client Identifier the KB-JWT must be addressed to. */
  audience: string;
  /** Clock tolerance `T_skew`, seconds. */
  skewSeconds: number;
  /** Freshness window `T_kb` of the KB-JWT, seconds. */
  kbMaxAgeSeconds: number;
  /**
   * A PID without reliable revocation status is rejected (catalogue decision 2): it needs a status reference unless its
   * validity period is at most 24 hours ([ARF] Annex 2, VCR_01, VCR_01b).
   */
  requireStatus: boolean;
  /** Maximum decompressed size of a status list, bytes (ICS RP.R.4). */
  maxStatusListBytes: number;
  /** Status values the Relying Party treats as VALID besides 0x00 (ICS RP.R.3); default none. */
  validStatuses?: number[];
  /** `trusted_authorities` of the credential query the Relying Party sent (OpenID4VP section 6.1.1.1). */
  trustedAuthorities?: { type: string; values: string[] }[];
  /** The claims of the credential query, for the check `claims`; left out, the check does not apply. */
  requestedClaims?: RequestedClaim[];
  fetchStatusList: (uri: string) => Promise<FetchedStatusList>;
  mode?: ValidationMode;
  now?: Date;
  /** Freshness policy for Status List Tokens (ICS RP.R.7, RP.R.8). */
  statusListFreshness?: StatusListFreshness;
  /** Reject a PID whose administrative expiry date has passed (ICS RP.P.12 Reject). */
  rejectPastExpiryDate?: boolean;
  /** Require the signing certificate to name the credential's `iss` (ICS RP.P.13 Yes, SD-JWT VC section 2.5). */
  requireIssuerInCertificate?: boolean;
}

const DAY = 24 * 60 * 60;

/**
 * SD-JWT VC section 2.5 under ICS RP.P.13: the signing certificate names `iss`, by a URI subject alternative name equal
 * to it, or, when it names no URI, by a DNS name equal to its host as `URL.host` gives it. Without `iss` the issuer is
 * the subject of the certificate and there is nothing to compare (section 2.2.2.2).
 */
function checkIssuerInCertificate(leaf: Certificate, iss: unknown): void {
  if (iss === undefined) return;
  const { uris, dnsNames } = leaf.subjectAlternativeNames;
  if (uris.length > 0) {
    if (!uris.includes(iss as string)) fail(`the signing certificate names the URI ${uris.join(', ')}, not iss ${String(iss)}`);
    return;
  }
  const host = typeof iss === 'string' && URL.canParse(iss) ? new URL(iss).host : undefined;
  if (!host || !dnsNames.includes(host)) fail(`the signing certificate names neither iss ${String(iss)} nor its host (DNS names: ${dnsNames.join(', ') || 'none'})`);
}

/**
 * The reference validator for an SD-JWT VC presentation with KB-JWT (SD-JWT VC, RFC 9901, Token Status List). Every
 * check is evaluated on its own, so a fault can be shown to fail exactly one of them. Trust follows
 * `default_trust_configuration_rp` through `trustRule`: the issuer's chain ends in an anchor of a service that may sign
 * the credential's category, the Status List Token's chain in an anchor the rule names for that service's status lists. Status list procedures run only for a credential that
 * passed every other check (Token Status List section 8.3) unless `mode` is `all`.
 */
export async function validateSdJwtVcPresentation(presentation: string, options: SdJwtVcValidationOptions): Promise<SdJwtVcValidation> {
  const recorder = new CheckRecorder(options.mode ?? 'first-failure');
  const now = options.now ?? new Date();
  const nowSeconds = Math.floor(now.getTime() / 1000);
  const skew = options.skewSeconds;

  let header: Record<string, unknown> = {};
  let payload: Record<string, unknown> = {};
  let kbHeader: Record<string, unknown> = {};
  let kbPayload: Record<string, unknown> = {};
  let kbJwt = '';
  let x5c: string[] = [];
  let issuer: MatchedIssuer | undefined;
  let claims: Record<string, unknown> | undefined;
  let reference: { idx: number; uri: string } | undefined;
  let statusListFetched = false;
  let trustListStale = false;
  const issuerJwt = presentation.split('~')[0] ?? '';

  const result = await recorder.collect(async () => {
    await recorder.run('format', [], () => {
      const parts = presentation.split('~');
      if (parts.length < 2) fail('not an SD-JWT: no ~ separator');
      header = decodeSegment(issuerJwt.split('.')[0], 'the issuer-signed JWT header');
      payload = decodeSegment(issuerJwt.split('.')[1], 'the issuer-signed JWT payload');
      // A vc+sd-jwt typ is rejected (catalogue decision 6).
      if (header.typ !== 'dc+sd-jwt') fail(`typ is ${String(header.typ)}, expected dc+sd-jwt`);
      if (!Array.isArray(header.x5c) || header.x5c.length === 0 || header.x5c.some((c) => typeof c !== 'string')) fail('x5c is missing');
      x5c = header.x5c as string[];
      if (!options.expectedVct.includes(String(payload.vct))) fail(`vct ${String(payload.vct)} was not requested`);
      // A missing KB-JWT is a failure of key-binding, not of the format (RFC 9901 section 7.3).
      kbJwt = parts[parts.length - 1] ?? '';
      if (kbJwt) {
        kbHeader = decodeSegment(kbJwt.split('.')[0], 'the KB-JWT header');
        kbPayload = decodeSegment(kbJwt.split('.')[1], 'the KB-JWT payload');
      }
    });

    await recorder.run('issuer-trust', ['format'], async () => {
      const match = await options.trust.match(options.trustRule, x5c, now);
      if (!match.ok) fail(match.reason);
      if (match.ok) {
        issuer = { name: match.entity.name, statusAnchors: options.trustRule.statusAnchors(match.entity, match.service) };
        trustListStale = match.stale;
        if (options.requireIssuerInCertificate) checkIssuerInCertificate(match.leaf, payload.iss);
        return `${match.entity.name} under ${match.anchor.subject.commonName} (${match.list.id}${match.stale ? ', stale within the grace period' : ''})`;
      }
    });

    await recorder.run('trusted-authorities', ['format'], () => {
      if (!options.trustedAuthorities?.length) return 'the query has no trusted_authorities';
      const certificates = x5c.map((c) => parseCertificate(c));
      for (const authority of options.trustedAuthorities) {
        if (authority.type !== 'aki') fail(`trusted_authorities type ${authority.type} is not supported`);
        const matching = certificates.find(
          (c) => c.authorityKeyIdentifier && authority.values.includes(Buffer.from(c.authorityKeyIdentifier, 'hex').toString('base64url')),
        );
        if (matching) return `${matching.subject.commonName} has an authority key identifier the query names`;
      }
      fail('no certificate in x5c has an authority key identifier that trusted_authorities names');
    });

    // The algorithm and the key are those of the ECCG agreed cryptographic mechanisms that the profile uses: ES256 with
    // a P-256 key (OIA_03, HAIP section 7).
    await recorder.run('issuer-signature', ['format'], async () => {
      // RFC 7515 section 4.1.11: the validator understands no extension, so a JWS that marks one critical is invalid.
      if (header.crit !== undefined) fail(`the issuer-signed JWT header marks ${JSON.stringify(header.crit)} critical, which the validator does not understand`);
      const key = describeKey(x5c[0]);
      if (key !== 'P-256') fail(`the signing certificate holds a key ${key}, not on P-256`);
      if (header.alg !== 'ES256') fail(`alg ${String(header.alg)} is not supported`);
      const jwk = leafJwk(x5c) as JsonWebKey;
      const [h, p, s] = issuerJwt.split('.');
      if (!(await verifyEs256(jwk as JsonWebKey, `${h}.${p}`, base64url.decode(s ?? '')))) fail('the issuer signature does not verify');
    });

    await recorder.run('disclosures', ['format'], () => {
      const { claims: disclosed, count } = processDisclosures(payload, presentation.split('~').slice(1, -1));
      claims = disclosed;
      return `${count} disclosures`;
    });

    await recorder.run('validity', ['format'], () => {
      if (typeof payload.exp === 'number' && nowSeconds > payload.exp + skew) fail(`expired: exp ${payload.exp}, now ${nowSeconds}, T_skew ${skew}`);
      if (typeof payload.nbf === 'number' && nowSeconds < payload.nbf - skew) fail(`not yet valid: nbf ${payload.nbf}, now ${nowSeconds}, T_skew ${skew}`);
      // A credential iat in the future is recorded only (catalogue decision 5).
      // RP_WS_SM_Validity_020: the administrative expiry date of a PID, under the policy of ICS RP.P.12.
      const expiry = claims?.date_of_expiry;
      if (options.rejectPastExpiryDate && typeof expiry === 'string' && expiry < now.toISOString().slice(0, 10)) fail(`the administrative expiry date ${expiry} has passed`);
      if (typeof payload.iat === 'number' && payload.iat > nowSeconds + skew) return `iat ${payload.iat} lies in the future (informative)`;
    });

    // Device binding and session binding (RFC 9901 section 7.3, OpenID4VP section 14.1.2): the KB-JWT is present,
    // typed, signed with ES256 by the key in cnf.jwk, over this presentation, for this request.
    await recorder.run('key-binding', ['format'], async () => {
      if (!kbJwt) fail('the presentation has no KB-JWT');
      // RFC 7515 section 4 and RFC 7519 section 4: a member name occurs at most once.
      for (const [index, part] of [[0, 'header'], [1, 'payload']] as const) {
        const duplicate = duplicateMember(Buffer.from(kbJwt.split('.')[index] ?? '', 'base64url').toString('utf8'));
        if (duplicate !== undefined) fail(`the KB-JWT ${part} carries the member ${duplicate} twice`);
      }
      if (kbHeader.typ !== 'kb+jwt') fail(`KB-JWT typ is ${String(kbHeader.typ)}`);
      // RFC 7515 section 4.1.11, as for the issuer-signed JWT.
      if (kbHeader.crit !== undefined) fail(`the KB-JWT header marks ${JSON.stringify(kbHeader.crit)} critical, which the validator does not understand`);
      if (kbHeader.alg !== 'ES256') fail(`KB-JWT alg ${String(kbHeader.alg)} is not supported`);
      const jwk = (payload.cnf as { jwk?: JsonWebKey } | undefined)?.jwk;
      if (!jwk) fail('the credential has no cnf.jwk, so it is bound to no key');
      if (jwk?.kty !== 'EC' || jwk.crv !== 'P-256') fail(`cnf.jwk is not a P-256 key (${String(jwk?.crv)})`);
      const [h, p, s] = kbJwt.split('.');
      if (!(await verifyEs256(jwk as JsonWebKey, `${h}.${p}`, base64url.decode(s ?? '')))) fail('the KB-JWT signature does not verify with cnf.jwk');
      const sdHash = base64url.encode(sha256(presentation.slice(0, presentation.length - kbJwt.length)));
      if (kbPayload.sd_hash !== sdHash) fail('KB-JWT sd_hash does not match the presentation');
      if (kbPayload.aud !== options.audience) fail(`KB-JWT aud ${String(kbPayload.aud)} is not ${options.audience}`);
      if (kbPayload.nonce !== options.nonce) fail('KB-JWT nonce does not match the request');
    });

    await recorder.run('kb-freshness', ['format', 'key-binding'], () => {
      if (typeof kbPayload.iat !== 'number') fail('KB-JWT has no iat');
      // RFC 7519 section 4.1.4: an `exp` is a NumericDate, a JSON number.
      if (kbPayload.exp !== undefined && typeof kbPayload.exp !== 'number') fail(`KB-JWT exp ${JSON.stringify(kbPayload.exp)} is not a NumericDate`);
      const iat = kbPayload.iat as number;
      if (nowSeconds - iat > options.kbMaxAgeSeconds + skew) fail(`KB-JWT iat ${iat} is older than T_kb ${options.kbMaxAgeSeconds} s`);
      if (iat > nowSeconds + skew) fail(`KB-JWT iat ${iat} lies in the future`);
    });

    await recorder.run('status-reference', ['format'], () => {
      const status = payload.status as { status_list?: Record<string, unknown> } | undefined;
      if (status === undefined) {
        const start = typeof payload.nbf === 'number' ? payload.nbf : payload.iat;
        const period = typeof payload.exp === 'number' && typeof start === 'number' ? payload.exp - start : Number.POSITIVE_INFINITY;
        if (!options.requireStatus) return 'no status reference (accepted by policy)';
        if (period <= DAY) return `no status reference; validity period ${period} s is at most 24 hours`;
        fail(`no status reference, and the validity period (${Number.isFinite(period) ? `${period} s` : 'unbounded'}) exceeds 24 hours`);
      }
      const list = status?.status_list;
      if (!list || typeof list !== 'object') fail('status has no status_list');
      if (!Number.isInteger(list?.idx) || (list?.idx as number) < 0) fail(`idx ${JSON.stringify(list?.idx)} is not a non-negative integer`);
      if (!isUri(list?.uri)) fail(`uri ${JSON.stringify(list?.uri)} is not a URI`);
      reference = { idx: list?.idx as number, uri: list?.uri as string };
    });

    // The disclosed claims satisfy the query, and a PID's attributes have the types of the PID rulebook.
    await recorder.run('claims', ['format', 'disclosures'], () => {
      if (!options.requestedClaims) return new NotApplicable('no credential query given');
      return checkClaims(claims ?? {}, options.requestedClaims, payload.vct === PID_VCT ? { encoding: 'sd-jwt-vc' } : undefined);
    });

    // Status list procedures (Token Status List section 8). In first-failure mode they run only for a valid credential.
    await evaluateStatusList(recorder, {
      format: 'jwt',
      reference,
      issuer,
      fetchStatusList: options.fetchStatusList,
      maxStatusListBytes: options.maxStatusListBytes,
      validStatuses: options.validStatuses,
      skewSeconds: skew,
      now,
      // Recorded before the request, so a failure that ends validation in first-failure mode still counts the fetch.
      onFetched: () => {
        statusListFetched = true;
      },
      freshness: options.statusListFreshness,
    });
  });
  return { ...result, claims: result.failures.includes('disclosures') ? undefined : claims, issuer: issuer?.name, statusListFetched, trustListStale };
}
