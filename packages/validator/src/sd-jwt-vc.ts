import { SDJwtVcInstance } from '@sd-jwt/sd-jwt-vc';
import { base64url, sdJwtHasher, verifyEs256 } from '@rp-conformance/forge';
import type { TrustedEntity, TrustStore } from './trust';
import { validatePath } from './x509-path';

/** The checks of a presentation, in the order the reference validator performs them. */
export const SD_JWT_VC_CHECKS = [
  'format',
  'issuer-trust',
  'issuer-signature',
  'disclosures',
  'validity',
  'key-binding',
  'kb-freshness',
  'status-reference',
  'status-list-fetch',
  'status-list-trust',
  'status-list-signature',
  'status-list-claims',
  'status',
] as const;

export type SdJwtVcCheck = (typeof SD_JWT_VC_CHECKS)[number];

export interface CheckResult {
  check: SdJwtVcCheck;
  ok: boolean;
  detail?: string;
}

export interface SdJwtVcValidation {
  valid: boolean;
  /** Every check that ran; a failed check stops the ones after it. */
  checks: CheckResult[];
  /** The first failed check. */
  failed?: SdJwtVcCheck;
  /** Issuer-signed claims with the disclosed values, when valid. */
  claims?: Record<string, unknown>;
  /** The trusted entity the issuer matched. */
  issuer?: string;
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
  /** A PID without reliable revocation status is rejected (catalogue decision); other categories follow a policy. */
  requireStatus: boolean;
  fetchStatusList: (uri: string) => Promise<string>;
  now?: Date;
}

class CheckFailure extends Error {
  constructor(
    readonly check: SdJwtVcCheck,
    message: string,
  ) {
    super(message);
  }
}

const header = (jwt: string) => base64url.decodeJson<Record<string, unknown>>(jwt.split('.')[0] ?? '');

/**
 * The reference validator for an SD-JWT VC presentation with KB-JWT (SD-JWT VC, RFC 9901, Token Status List),
 * built on `@sd-jwt/sd-jwt-vc`. Trust follows `default_trust_configuration_rp`: the issuer's chain ends in an
 * `/Issuance` anchor of `issuerList`; the Status List Token's chain ends in a `/Revocation` anchor of the same entity.
 */
export async function validateSdJwtVcPresentation(presentation: string, options: SdJwtVcValidationOptions): Promise<SdJwtVcValidation> {
  const checks: CheckResult[] = [];
  const now = options.now ?? new Date();
  const pass = (check: SdJwtVcCheck, detail?: string) => checks.push({ check, ok: true, detail });
  let issuerEntity: TrustedEntity | undefined;
  let phase: 'credential' | 'status' = 'credential';
  try {
    // format: compact SD-JWT with KB-JWT, typ dc+sd-jwt (a vc+sd-jwt typ is rejected, catalogue decision 6), ES256, x5c
    const issuerJwt = presentation.split('~')[0];
    let issuerHeader: Record<string, unknown>;
    try {
      issuerHeader = header(issuerJwt);
    } catch {
      throw new CheckFailure('format', 'the issuer-signed JWT cannot be decoded');
    }
    if (issuerHeader.typ !== 'dc+sd-jwt') throw new CheckFailure('format', `typ is ${String(issuerHeader.typ)}, expected dc+sd-jwt`);
    if (issuerHeader.alg !== 'ES256') throw new CheckFailure('format', `alg ${String(issuerHeader.alg)} is not supported`);
    if (presentation.endsWith('~')) throw new CheckFailure('format', 'the presentation has no KB-JWT');
    const x5c = issuerHeader.x5c;
    if (!Array.isArray(x5c) || x5c.length === 0) throw new CheckFailure('format', 'x5c is missing');
    pass('format');

    const match = await options.trust.match(options.issuerList, '/Issuance', x5c as string[], now);
    if (!match.ok) throw new CheckFailure('issuer-trust', match.reason);
    issuerEntity = match.entity;
    pass('issuer-trust', `${match.entity.name} under ${match.anchor.subject.commonName}`);
    const issuerJwk = match.leaf.publicKey.jwk;
    if (!issuerJwk) throw new CheckFailure('issuer-trust', 'unsupported issuer key');

    let statusChecked = false;
    const sdjwt = new SDJwtVcInstance({
      hasher: sdJwtHasher,
      verifier: (data, signature) => verifyEs256(issuerJwk, data, base64url.decode(signature)),
      kbVerifier: async (data, signature, payload) => {
        const jwk = (payload as { cnf?: { jwk?: JsonWebKey } }).cnf?.jwk;
        if (!jwk) throw new CheckFailure('key-binding', 'the credential has no cnf.jwk');
        return verifyEs256(jwk, data, base64url.decode(signature));
      },
      statusListFetcher: async (uri) => {
        phase = 'status';
        try {
          return await options.fetchStatusList(uri);
        } catch (error) {
          throw new CheckFailure('status-list-fetch', `${uri}: ${(error as Error).message}`);
        }
      },
      statusVerifier: async (data, signature) => {
        const slHeader = base64url.decodeJson<Record<string, unknown>>(data.split('.')[0] ?? '');
        const slX5c = slHeader.x5c;
        if (!Array.isArray(slX5c) || slX5c.length === 0) throw new CheckFailure('status-list-trust', 'the Status List Token has no x5c');
        const anchors = issuerEntity ? options.trust.revocationAnchors(issuerEntity) : [];
        const path = await validatePath(slX5c as string[], anchors, now);
        if (!path.ok) throw new CheckFailure('status-list-trust', `not under a revocation anchor of ${issuerEntity?.name}: ${path.reason}`);
        const jwk = path.leaf.publicKey.jwk;
        if (slHeader.alg !== 'ES256' || !jwk) throw new CheckFailure('status-list-signature', `alg ${String(slHeader.alg)} is not supported`);
        const ok = await verifyEs256(jwk, data, base64url.decode(signature));
        if (!ok) throw new CheckFailure('status-list-signature', 'the Status List Token signature does not verify');
        return true;
      },
      statusValidator: async (status, { uri, idx }) => {
        statusChecked = true;
        if (status !== 0) throw new CheckFailure('status', `status ${status} at index ${idx} of ${uri}`);
      },
    });

    let verified: Awaited<ReturnType<typeof sdjwt.verify>>;
    try {
      verified = await sdjwt.verify(presentation, {
        currentDate: Math.floor(now.getTime() / 1000),
        skewSeconds: options.skewSeconds,
        keyBindingNonce: options.nonce,
        expectedKeyBindingAudience: options.audience,
        keyBindingMaxAgeSeconds: options.kbMaxAgeSeconds,
        allowedIssuerAlgorithms: ['ES256'],
        allowedKeyBindingAlgorithms: ['ES256'],
        expectedVct: options.expectedVct,
      });
    } catch (error) {
      throw classify(error, phase);
    }
    pass('issuer-signature');
    pass('disclosures');
    pass('validity');
    pass('key-binding');
    pass('kb-freshness');
    const status = (verified.payload as { status?: { status_list?: unknown } }).status;
    if (!status?.status_list) {
      if (options.requireStatus) throw new CheckFailure('status-reference', 'the credential has no status_list reference');
      pass('status-reference', 'no status reference (accepted by policy)');
    } else {
      pass('status-reference');
      if (!statusChecked) throw new CheckFailure('status', 'the status was not checked');
      for (const check of ['status-list-fetch', 'status-list-trust', 'status-list-signature', 'status-list-claims', 'status'] as const) pass(check);
    }
    return { valid: true, checks, claims: verified.payload as Record<string, unknown>, issuer: issuerEntity?.name };
  } catch (error) {
    const failure = error instanceof CheckFailure ? error : new CheckFailure('format', (error as Error).message);
    checks.push({ check: failure.check, ok: false, detail: failure.message });
    return { valid: false, checks, failed: failure.check, issuer: issuerEntity?.name };
  }
}

/** Attributes a failure of `@sd-jwt/sd-jwt-vc` to a check. */
function classify(error: unknown, phase: 'credential' | 'status'): CheckFailure {
  if (error instanceof CheckFailure) return error;
  const cause = (error as { cause?: unknown }).cause;
  if (cause instanceof CheckFailure) return cause;
  const code = (error as { code?: string }).code ?? (cause as { code?: string } | undefined)?.code;
  const message = (error as Error).message ?? String(error);
  if (phase === 'status') {
    if (code === 'STATUS_INVALID') return new CheckFailure('status', message);
    return new CheckFailure('status-list-claims', message);
  }
  if (code?.startsWith('KEY_BINDING_JWT_')) return new CheckFailure('kb-freshness', message);
  if (code?.startsWith('JWT_')) return new CheckFailure('validity', message);
  if (/key binding|kb-jwt|nonce|sd_hash/i.test(message)) return new CheckFailure('key-binding', message);
  if (/digest|disclosure/i.test(message)) return new CheckFailure('disclosures', message);
  if (/signature/i.test(message)) return new CheckFailure('issuer-signature', message);
  if (/vct/i.test(message)) return new CheckFailure('format', message);
  return new CheckFailure('issuer-signature', message);
}
