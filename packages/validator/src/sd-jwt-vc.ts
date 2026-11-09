import { inflateSync } from 'node:zlib';
import { type CheckId, CREDENTIAL_CHECKS, STATUS_LIST_CHECKS } from '@rp-conformance/core';
import { base64url, sdJwtHasher, sha256, verifyEs256 } from '@rp-conformance/forge';
import { decodeSdJwtSync, unpackSync } from '@sd-jwt/core';
import { parseCertificate } from '@owf/x509';
import { CheckFailure, CheckRecorder, NotApplicable, type ValidationMode, type ValidationResult } from './checks';
import type { TrustedEntity, TrustStore } from './trust';
import { validatePath } from './x509-path';

/** Every check of an SD-JWT VC presentation and its Status List Token, in the order the reference validator runs them. */
export const SD_JWT_VC_CHECKS: CheckId[] = [...CREDENTIAL_CHECKS, ...STATUS_LIST_CHECKS];

export interface SdJwtVcValidation extends ValidationResult {
  /** Issuer-signed claims with the disclosed values, when the disclosures check passed. */
  claims?: Record<string, unknown>;
  /** The trusted entity the issuer matched. */
  issuer?: string;
  /** Whether the validator retrieved the status list. */
  statusListFetched: boolean;
}

export interface FetchedStatusList {
  status: number;
  body: string;
  contentType?: string | null;
}

export interface SdJwtVcValidationOptions {
  trust: TrustStore;
  /** The list whose `/Issuance` anchors are trusted for this credential type, for example `TL-PID`. */
  issuerList: string;
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
  fetchStatusList: (uri: string) => Promise<FetchedStatusList>;
  mode?: ValidationMode;
  now?: Date;
}

const DAY = 24 * 60 * 60;

const decodeSegment = (segment: string | undefined, what: string): Record<string, unknown> => {
  let value: unknown;
  try {
    value = base64url.decodeJson(segment ?? '');
  } catch {
    throw new CheckFailure(`${what} cannot be decoded`);
  }
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new CheckFailure(`${what} is not a JSON object`);
  return value as Record<string, unknown>;
};

const fail = (message: string): never => {
  throw new CheckFailure(message);
};

const isUri = (value: unknown) => {
  if (typeof value !== 'string') return false;
  try {
    const url = new URL(value);
    return url.protocol === 'https:' || url.protocol === 'http:';
  } catch {
    return false;
  }
};

const leafJwk = (x5c: unknown): JsonWebKey | undefined => {
  if (!Array.isArray(x5c) || typeof x5c[0] !== 'string') return undefined;
  return parseCertificate(x5c[0]).publicKey.jwk;
};

/**
 * The reference validator for an SD-JWT VC presentation with KB-JWT (SD-JWT VC, RFC 9901, Token Status List). Every
 * check is evaluated on its own, so a fault can be shown to fail exactly one of them. Trust follows
 * `default_trust_configuration_rp`: the issuer's chain ends in an `/Issuance` anchor of `issuerList`, the Status List
 * Token's chain in a `/Revocation` anchor of the same entity. Status list procedures run only for a credential that
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
  let entity: TrustedEntity | undefined;
  let claims: Record<string, unknown> | undefined;
  let reference: { idx: number; uri: string } | undefined;
  let statusListFetched = false;
  const issuerJwt = presentation.split('~')[0] ?? '';

  const result = await recorder.collect(async () => {
    await recorder.run('format', [], () => {
      const parts = presentation.split('~');
      if (parts.length < 2) fail('not an SD-JWT: no ~ separator');
      header = decodeSegment(issuerJwt.split('.')[0], 'the issuer-signed JWT header');
      payload = decodeSegment(issuerJwt.split('.')[1], 'the issuer-signed JWT payload');
      // A vc+sd-jwt typ is rejected (catalogue decision 6).
      if (header.typ !== 'dc+sd-jwt') fail(`typ is ${String(header.typ)}, expected dc+sd-jwt`);
      if (header.alg !== 'ES256') fail(`alg ${String(header.alg)} is not supported`);
      if (!Array.isArray(header.x5c) || header.x5c.length === 0 || header.x5c.some((c) => typeof c !== 'string')) fail('x5c is missing');
      x5c = header.x5c as string[];
      if (!options.expectedVct.includes(String(payload.vct))) fail(`vct ${String(payload.vct)} was not requested`);
      if (payload._sd_alg !== undefined && payload._sd_alg !== 'sha-256') fail(`_sd_alg ${String(payload._sd_alg)} is not supported`);
      kbJwt = parts[parts.length - 1] ?? '';
      if (!kbJwt) fail('the presentation has no KB-JWT');
      kbHeader = decodeSegment(kbJwt.split('.')[0], 'the KB-JWT header');
      kbPayload = decodeSegment(kbJwt.split('.')[1], 'the KB-JWT payload');
    });

    await recorder.run('issuer-trust', ['format'], async () => {
      const match = await options.trust.match(options.issuerList, '/Issuance', x5c, now);
      if (!match.ok) fail(match.reason);
      if (match.ok) {
        entity = match.entity;
        return `${match.entity.name} under ${match.anchor.subject.commonName}`;
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

    await recorder.run('issuer-signature', ['format'], async () => {
      const jwk = leafJwk(x5c);
      if (!jwk || jwk.crv !== 'P-256') fail('the signing certificate has no P-256 key');
      const [h, p, s] = issuerJwt.split('.');
      if (!(await verifyEs256(jwk as JsonWebKey, `${h}.${p}`, base64url.decode(s ?? '')))) fail('the issuer signature does not verify');
    });

    await recorder.run('disclosures', ['format'], () => {
      const decoded = decodeSdJwtSync(presentation, sdJwtHasher);
      const digests = decoded.disclosures.map((d) => d._digest);
      if (new Set(digests).size !== digests.length) fail('a disclosure is presented twice');
      const { unpackedObj, disclosureKeymap } = unpackSync(payload, decoded.disclosures, sdJwtHasher);
      const referenced = new Set(Object.values(disclosureKeymap));
      const unreferenced = digests.filter((d) => !referenced.has(d ?? ''));
      if (unreferenced.length) fail(`${unreferenced.length} disclosure(s) are not referenced by a digest in the payload`);
      claims = unpackedObj as Record<string, unknown>;
      return `${digests.length} disclosures`;
    });

    await recorder.run('validity', ['format'], () => {
      if (typeof payload.exp === 'number' && nowSeconds > payload.exp + skew) fail(`expired: exp ${payload.exp}, now ${nowSeconds}, T_skew ${skew}`);
      if (typeof payload.nbf === 'number' && nowSeconds < payload.nbf - skew) fail(`not yet valid: nbf ${payload.nbf}, now ${nowSeconds}, T_skew ${skew}`);
      // A credential iat in the future is recorded only (catalogue decision 5).
      if (typeof payload.iat === 'number' && payload.iat > nowSeconds + skew) return `iat ${payload.iat} lies in the future (informative)`;
    });

    await recorder.run('key-binding', ['format'], async () => {
      if (kbHeader.typ !== 'kb+jwt') fail(`KB-JWT typ is ${String(kbHeader.typ)}`);
      if (kbHeader.alg !== 'ES256') fail(`KB-JWT alg ${String(kbHeader.alg)} is not supported`);
      const jwk = (payload.cnf as { jwk?: JsonWebKey } | undefined)?.jwk;
      if (!jwk) fail('the credential has no cnf.jwk');
      const [h, p, s] = kbJwt.split('.');
      if (!(await verifyEs256(jwk as JsonWebKey, `${h}.${p}`, base64url.decode(s ?? '')))) fail('the KB-JWT signature does not verify');
      if (kbPayload.aud !== options.audience) fail(`KB-JWT aud ${String(kbPayload.aud)} is not ${options.audience}`);
      if (kbPayload.nonce !== options.nonce) fail('KB-JWT nonce does not match the request');
      const sdHash = base64url.encode(sha256(presentation.slice(0, presentation.length - kbJwt.length)));
      if (kbPayload.sd_hash !== sdHash) fail('KB-JWT sd_hash does not match the presentation');
    });

    await recorder.run('kb-freshness', ['format'], () => {
      if (typeof kbPayload.iat !== 'number') fail('KB-JWT has no iat');
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

    // Status list procedures (Token Status List section 8). In first-failure mode they run only for a valid credential.
    const noReference = () => (reference ? undefined : new NotApplicable('the credential has no status reference'));
    let token = { header: {} as Record<string, unknown>, payload: {} as Record<string, unknown>, compact: '' };
    let decoded: Uint8Array | undefined;
    let bits = 0;

    await recorder.run('status-list-fetch', ['status-reference'], async () => {
      if (!reference) return noReference();
      statusListFetched = true;
      const fetched = await options.fetchStatusList(reference.uri);
      if (fetched.status !== 200) fail(`HTTP ${fetched.status}`);
      token.compact = fetched.body.trim();
    });

    await recorder.run('status-list-format', ['status-list-fetch'], () => {
      const parts = token.compact.split('.');
      if (parts.length !== 3) fail(`not a compact JWS (${parts.length} parts)`);
      token = { ...token, header: decodeSegment(parts[0], 'the Status List Token header'), payload: decodeSegment(parts[1], 'the Status List Token payload') };
    });

    await recorder.run('status-list-type', ['status-list-format'], () => {
      if (token.header.typ !== 'statuslist+jwt') fail(`typ is ${String(token.header.typ)}, expected statuslist+jwt`);
    });

    await recorder.run('status-list-trust', ['status-list-format', 'issuer-trust'], async () => {
      const chain = token.header.x5c;
      if (!Array.isArray(chain) || chain.length === 0) fail('the Status List Token has no x5c');
      const anchors = entity ? options.trust.revocationAnchors(entity) : [];
      const path = await validatePath(chain as string[], anchors, now);
      if (!path.ok) fail(`not under a revocation anchor of ${entity?.name}: ${path.reason}`);
      return path.ok ? `${path.leaf.subject.commonName} under ${path.anchor.subject.commonName}` : undefined;
    });

    await recorder.run('status-list-signature', ['status-list-format'], async () => {
      if (token.header.alg !== 'ES256') fail(`alg ${String(token.header.alg)} is not accepted`);
      if (!Array.isArray(token.header.x5c) || token.header.x5c.length === 0) return new NotApplicable('no x5c, so no key to verify with');
      const jwk = leafJwk(token.header.x5c);
      if (!jwk || jwk.crv !== 'P-256') fail('the signing certificate has no P-256 key');
      const [h, p, s] = token.compact.split('.');
      if (!(await verifyEs256(jwk as JsonWebKey, `${h}.${p}`, base64url.decode(s ?? '')))) fail('the Status List Token signature does not verify');
    });

    await recorder.run('status-list-claims', ['status-list-format'], () => {
      const p = token.payload;
      const missing = [
        typeof p.sub !== 'string' && 'sub',
        typeof p.iat !== 'number' && 'iat',
        (!p.status_list || typeof p.status_list !== 'object') && 'status_list',
      ].filter(Boolean);
      if (missing.length) fail(`missing ${missing.join(', ')}`);
      const list = p.status_list as Record<string, unknown>;
      const listMissing = [list.bits === undefined && 'bits', list.lst === undefined && 'lst'].filter(Boolean);
      if (listMissing.length) fail(`status_list has no ${listMissing.join(', ')}`);
    });

    await recorder.run('status-list-subject', ['status-list-format'], () => {
      if (token.payload.sub === undefined) return new NotApplicable('no sub');
      if (token.payload.sub !== reference?.uri) fail(`sub ${String(token.payload.sub)} is not the credential's status uri`);
    });

    await recorder.run('status-list-validity', ['status-list-format'], () => {
      const exp = token.payload.exp;
      if (exp === undefined) return new NotApplicable('no exp');
      if (typeof exp !== 'number') fail('exp is not a number');
      if (nowSeconds > (exp as number) + skew) fail(`expired: exp ${exp}, now ${nowSeconds}, T_skew ${skew}`);
    });

    await recorder.run('status-list-decoding', ['status-list-format'], () => {
      const list = token.payload.status_list as { bits?: unknown; lst?: unknown } | undefined;
      if (!list || list.bits === undefined || list.lst === undefined) return new NotApplicable('no bits or lst');
      if (![1, 2, 4, 8].includes(list.bits as number)) fail(`bits ${String(list.bits)} is not 1, 2, 4 or 8`);
      bits = list.bits as number;
      if (typeof list.lst !== 'string' || !/^[A-Za-z0-9_-]+$/.test(list.lst)) fail('lst is not base64url');
      try {
        decoded = new Uint8Array(inflateSync(Buffer.from(list.lst as string, 'base64url'), { maxOutputLength: options.maxStatusListBytes }));
      } catch (error) {
        const tooLarge = (error as { code?: string }).code === 'ERR_BUFFER_TOO_LARGE' || error instanceof RangeError;
        fail(tooLarge ? `the status list decompresses to more than ${options.maxStatusListBytes} bytes` : `lst is not valid ZLIB data: ${(error as Error).message}`);
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
      if (options.validStatuses?.includes(value)) return `${hex}, declared as valid`;
      fail(`status ${hex} at index ${idx}${value === 1 ? ' (INVALID)' : value === 2 ? ' (SUSPENDED)' : ''}`);
    });
  });
  return { ...result, claims: result.failures.includes('disclosures') ? undefined : claims, issuer: entity?.name, statusListFetched };
}
