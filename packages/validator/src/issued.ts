// The reference validator on the issuer side (`OBS-CRED`, issuer harness design sections 4 and 6.3): every credential a
// Provider under test issues runs through the credential checks a Relying Party performs, with the suite's trust
// configuration, except that there is no presentation. `key-binding` and `kb-freshness` check a KB-JWT, which an issued
// credential does not carry; `holder-binding` takes their place: the credential is bound (`cnf.jwk`) to a key the
// Conformance Wallet proved possession of and that the Wallet Unit's key attestation attests. `trusted-authorities`
// checks a query, of which there is none.
import { createHash } from 'node:crypto';
import { type AttestationSubject, type CheckId, type CheckResult, type PidSubject, STATUS_LIST_CHECKS } from '@eudi-pcaf/core';
// Issue 27: the rulebook of `default_credential_A` and the device binding of an attestation.
import { checkAttestationAttributes, checkAttestationDisclosure, checkAttestationType, checkAttestationValues, checkQualifiedService, checkRevocationMethod } from './attestation-rulebook';
import { base64url, type CborMap, decodeCbor, verifyEs256 } from '@eudi-pcaf/forge';
import { CheckRecorder, type ValidationMode, type ValidationResult } from './checks';
import { describeKey, processDisclosures } from './disclosures';
import {
  asMap,
  checkDocumentSignerTrust,
  checkMdocValidity,
  checkValueDigests,
  deviceKeyOfMso,
  type IssuerSignedElement,
  readIssuerSigned,
  readMsoStatus,
  validityOf,
  verifyIssuerAuth,
} from './mdoc';
import {
  checkPidDocType,
  checkPidFormats,
  checkPidMdocAttributes,
  checkPidMdocDates,
  checkPidMdocPortraitOptOut,
  checkPidMdocValues,
  checkPidSdJwtAttributes,
  checkPidSdJwtDates,
  checkPidSdJwtExtension,
  checkPidSdJwtPortraitOptOut,
  checkPidSdJwtValues,
  checkPidUnique,
  checkPidVct,
  pidMdocClaims,
} from './pid-rulebook';
import { attempt, decodeSegment, evaluateStatusList, type FetchedStatusList, fail, isUri, leafJwk } from './status-list';
import type { MatchedIssuer, TrustRule, TrustStore } from './trust';

/** The checks of an issued SD-JWT VC, in the order the reference validator runs them. */
export const ISSUED_CREDENTIAL_CHECKS = ['format', 'issuer-trust', 'issuer-signature', 'disclosures', 'validity', 'holder-binding', 'status-reference'] as const satisfies CheckId[];

/** Every check of an issued SD-JWT VC and its Status List Token. */
export const ISSUED_SD_JWT_VC_CHECKS: CheckId[] = [...ISSUED_CREDENTIAL_CHECKS, ...STATUS_LIST_CHECKS];

export interface IssuedSdJwtVcValidation extends ValidationResult {
  /** Issuer-signed claims with the disclosed values, when the disclosures check passed. */
  claims?: Record<string, unknown>;
  /** The trusted entity the issuer matched. */
  issuer?: string;
  statusListFetched: boolean;
}

export interface IssuedSdJwtVcValidationOptions {
  trust: TrustStore;
  /** The root of trust of the Provider's category (`TRUST_RULES`), for a PID Provider `PP-T` on `TL-PID`. */
  trustRule: TrustRule;
  /**
   * The entity the Provider was enrolled as (`PP-T`, `QP-T`, `PB-T`, `EP-T`): a chain to another entity of the same list
   * fails `issuer-trust`, since the Provider under test signs with its enrolled keys only.
   */
  issuerEntity?: string;
  /** The `vct` of the credential configuration the Conformance Wallet requested. */
  expectedVct: string[];
  /** The public keys of the proofs the Conformance Wallet sent in the credential request. */
  proofKeys: JsonWebKey[];
  /** The key attestations the proofs carried; their `attested_keys` must contain the bound key. */
  keyAttestations: string[];
  /** Clock tolerance of the validator, seconds. */
  skewSeconds: number;
  /** A PID needs a status reference unless its validity period is at most 24 hours (VCR_01, VCR_01b). */
  requireStatus: boolean;
  /** Maximum decompressed size of a status list, bytes. */
  maxStatusListBytes: number;
  /**
   * Issue 27: the configuration is device-bound (default). For a configuration without cryptographic binding (ICS-04
   * `P-NDB`), `holder-binding` passes when the credential is bound to no key and fails when it is.
   */
  deviceBound?: boolean;
  fetchStatusList: (uri: string) => Promise<FetchedStatusList>;
  /** Default `all`: every check whose prerequisites passed is evaluated, so the report shows each of them. */
  mode?: ValidationMode;
  now?: Date;
  /** The checks of `ISSUER_OUTPUT_CHECKS` to run after the credential and status list checks, with what they compare. */
  output?: IssuedOutputOptions;
}

/**
 * What the output checks of a test case compare the issued credential with (issuer catalogue sections 5.1.3 and 5.1.4).
 * Only the checks in `checks` run; the credential checks and status list checks always do.
 */
export interface IssuedOutputOptions {
  checks: CheckId[];
  /** `pid-values`: the test subject's data the adapter seeded. */
  subject?: PidSubject;
  /** Issue 27, `attestation-values`: the test subject's `default_credential_A` data the adapter seeded. */
  attestationSubject?: AttestationSubject;
  /** `validity-declared`: the validity period the ICS declares for the configuration, seconds. */
  declaredValiditySeconds?: number;
  /** `validity-declared`: the tolerance, the timestamp precision the ICS declares (ICS-16), seconds. */
  precisionSeconds?: number;
  /** `type-metadata`: fetches the Type Metadata of an https `vct`. */
  fetchTypeMetadata?: (url: string) => Promise<{ status: number; body: Uint8Array }>;
  /** `pid-extension`: the claims a published rulebook documents for a domestic `vct`. */
  documentedClaims?: string[];
}

const DAY = 24 * 60 * 60;
const wants = (output: IssuedOutputOptions | undefined, check: CheckId) => Boolean(output?.checks.includes(check));

/** Two public JWKs name the same EC key. */
export const sameEcKey = (a: JsonWebKey | undefined, b: JsonWebKey | undefined) =>
  Boolean(a && b && a.kty === 'EC' && b.kty === 'EC' && a.crv === b.crv && a.x === b.x && a.y === b.y);

/**
 * `holder-binding`: the credential's `cnf.jwk` is a P-256 key, equal to the key of one of the proofs the Conformance
 * Wallet sent, and listed in the `attested_keys` of one of the key attestations those proofs carried. Returns the
 * detail on success, throws (`fail`) otherwise. The KAs are only decoded here; their signature and trust are the
 * request checks of the issuer side, not checks of what the Provider issued.
 */
export function checkHolderBinding(payload: Record<string, unknown>, proofKeys: JsonWebKey[], keyAttestations: string[]): string {
  const jwk = (payload.cnf as { jwk?: JsonWebKey } | undefined)?.jwk;
  if (!jwk) return fail('the credential has no cnf.jwk, so it is bound to no key');
  if (jwk.kty !== 'EC' || jwk.crv !== 'P-256') fail(`cnf.jwk is not a P-256 key (${String(jwk.kty)} ${String(jwk.crv)})`);
  const proof = proofKeys.findIndex((key) => sameEcKey(key, jwk));
  if (proof < 0) fail(`cnf.jwk is none of the ${proofKeys.length} proof key(s) of the credential request`);
  for (const [index, ka] of keyAttestations.entries()) {
    const attested = decodeSegment(ka.split('.')[1], 'the key attestation payload').attested_keys;
    if (Array.isArray(attested) && attested.some((key) => sameEcKey(key as JsonWebKey, jwk))) {
      return `cnf.jwk is the key of proof ${proof + 1} and attested_keys entry of key attestation ${index + 1}`;
    }
  }
  return fail('cnf.jwk is a proof key, but no key attestation of the request lists it in attested_keys');
}

/**
 * The reference validator for an SD-JWT VC as a Provider issued it (SD-JWT VC, RFC 9901, Token Status List): the same
 * checks and order as `validateSdJwtVcPresentation`, with `holder-binding` instead of `key-binding` and `kb-freshness`.
 * Trust follows `trustRule`: for a PID Provider the issuer's chain ends in the PID/Issuance anchor of `PP-T` on
 * `TL-PID`, the Status List Token's chain in the PID/Revocation anchor of the same entity.
 */
export async function validateIssuedSdJwtVc(credential: string, options: IssuedSdJwtVcValidationOptions): Promise<IssuedSdJwtVcValidation> {
  const recorder = new CheckRecorder(options.mode ?? 'all');
  const now = options.now ?? new Date();
  const nowSeconds = Math.floor(now.getTime() / 1000);
  const skew = options.skewSeconds;
  const parts = credential.split('~');
  const issuerJwt = parts[0] ?? '';

  let header: Record<string, unknown> = {};
  let payload: Record<string, unknown> = {};
  let x5c: string[] = [];
  let issuer: MatchedIssuer | undefined;
  let claims: Record<string, unknown> | undefined;
  let reference: { idx: number; uri: string } | undefined;
  let statusListFetched = false;
  let matched: { service: { type: string; status?: string }; list: string } | undefined;

  const result = await recorder.collect(async () => {
    await recorder.run('format', [], () => {
      if (parts.length < 2) fail('not an SD-JWT: no ~ separator');
      // An issued SD-JWT ends with `~`: no KB-JWT (RFC 9901 section 4).
      if (parts[parts.length - 1] !== '') fail('the issued SD-JWT carries a KB-JWT or does not end with ~');
      header = decodeSegment(issuerJwt.split('.')[0], 'the issuer-signed JWT header');
      payload = decodeSegment(issuerJwt.split('.')[1], 'the issuer-signed JWT payload');
      if (header.typ !== 'dc+sd-jwt') fail(`typ is ${String(header.typ)}, expected dc+sd-jwt`);
      if (!Array.isArray(header.x5c) || header.x5c.length === 0 || header.x5c.some((c) => typeof c !== 'string')) fail('x5c is missing');
      x5c = header.x5c as string[];
      if (!options.expectedVct.includes(String(payload.vct))) fail(`vct ${String(payload.vct)} is not the requested ${options.expectedVct.join(', ')}`);
    });

    await recorder.run('issuer-trust', ['format'], async () => {
      const match = await options.trust.match(options.trustRule, x5c, now);
      if (!match.ok) fail(match.reason);
      if (match.ok && options.issuerEntity && match.entity.name !== options.issuerEntity) {
        fail(`the chain ends in an anchor of ${match.entity.name} (${match.list.id}), not of the enrolled ${options.issuerEntity}`);
      }
      if (match.ok) {
        issuer = { name: match.entity.name, statusAnchors: options.trustRule.statusAnchors(match.entity, match.service) };
        matched = { service: match.service, list: match.list.id };
        return `${match.entity.name} under ${match.anchor.subject.commonName} (${match.list.id})`;
      }
    });

    await recorder.run('issuer-signature', ['format'], async () => {
      const key = describeKey(x5c[0]);
      if (key !== 'P-256') fail(`the signing certificate holds a key ${key}, not on P-256`);
      if (header.alg !== 'ES256') fail(`alg ${String(header.alg)} is not supported`);
      const [h, p, s] = issuerJwt.split('.');
      if (!(await verifyEs256(leafJwk(x5c) as JsonWebKey, `${h}.${p}`, base64url.decode(s ?? '')))) fail('the issuer signature does not verify');
    });

    await recorder.run('disclosures', ['format'], () => {
      const { claims: disclosed, count } = processDisclosures(payload, parts.slice(1, -1));
      claims = disclosed;
      return `${count} disclosures`;
    });

    await recorder.run('validity', ['format'], () => {
      if (typeof payload.exp === 'number' && nowSeconds > payload.exp + skew) fail(`expired: exp ${payload.exp}, now ${nowSeconds}, skew ${skew}`);
      if (typeof payload.nbf === 'number' && nowSeconds < payload.nbf - skew) fail(`not yet valid: nbf ${payload.nbf}, now ${nowSeconds}, skew ${skew}`);
      if (typeof payload.iat === 'number' && payload.iat > nowSeconds + skew) return `iat ${payload.iat} lies in the future (informative)`;
    });

    await recorder.run('holder-binding', ['format'], () => (options.deviceBound === false ? checkNotBound(payload.cnf !== undefined, 'cnf') : checkHolderBinding(payload, options.proofKeys, options.keyAttestations)));

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

    await evaluateStatusList(recorder, {
      format: 'jwt',
      reference,
      issuer,
      fetchStatusList: options.fetchStatusList,
      maxStatusListBytes: options.maxStatusListBytes,
      skewSeconds: skew,
      now,
      onFetched: () => {
        statusListFetched = true;
      },
    });

    const output = options.output;
    if (wants(output, 'validity-period')) await recorder.run('validity-period', ['format'], () => checkSdJwtValidityPeriod(payload, nowSeconds, skew));
    if (wants(output, 'validity-declared')) await recorder.run('validity-declared', ['format'], () => checkDeclaredValidity(sdJwtPeriod(payload), output as IssuedOutputOptions));
    if (wants(output, 'type-metadata')) await recorder.run('type-metadata', ['format'], () => checkTypeMetadata(payload, output?.fetchTypeMetadata));
    if (wants(output, 'pid-type')) await recorder.run('pid-type', ['format'], () => checkPidVct(payload));
    const disclosed = () => claims as Record<string, unknown>;
    if (wants(output, 'pid-attributes')) await recorder.run('pid-attributes', ['disclosures'], () => checkPidSdJwtAttributes(disclosed()));
    if (wants(output, 'pid-values')) await recorder.run('pid-values', ['disclosures'], () => checkPidSdJwtValues(disclosed(), requireSubject(output)));
    if (wants(output, 'pid-dates')) await recorder.run('pid-dates', ['disclosures'], () => checkPidSdJwtDates(disclosed(), skew));
    if (wants(output, 'pid-extension')) await recorder.run('pid-extension', ['disclosures'], () => checkPidSdJwtExtension(disclosed(), output?.documentedClaims));
    if (wants(output, 'pid-portrait')) await recorder.run('pid-portrait', ['disclosures'], () => checkPidSdJwtPortraitOptOut(disclosed()));
    // Issue 27: the rulebook of `default_credential_A`, the revocation method and the qualified service.
    if (wants(output, 'attestation-type')) await recorder.run('attestation-type', ['format'], () => checkAttestationType('dc+sd-jwt', payload.vct));
    if (wants(output, 'attestation-attributes')) await recorder.run('attestation-attributes', ['disclosures'], () => checkAttestationAttributes(disclosed(), now));
    if (wants(output, 'attestation-values')) await recorder.run('attestation-values', ['disclosures'], () => checkAttestationValues(disclosed(), requireAttestationSubject(output)));
    if (wants(output, 'attestation-disclosure')) await recorder.run('attestation-disclosure', ['disclosures'], () => checkAttestationDisclosure(payload, parts.slice(1, -1)));
    if (wants(output, 'revocation-method')) {
      await recorder.run('revocation-method', ['format'], () => {
        const start = typeof payload.nbf === 'number' ? payload.nbf : payload.iat;
        const period = typeof payload.exp === 'number' && typeof start === 'number' ? payload.exp - start : undefined;
        return checkRevocationMethod(isObject(payload.status) && isObject((payload.status as Record<string, unknown>).status_list), period);
      });
    }
    if (wants(output, 'qualified-service')) await recorder.run('qualified-service', ['issuer-trust'], () => checkQualifiedService(matched?.service, matched?.list));
  });
  return { ...result, claims: result.failures.includes('disclosures') ? undefined : claims, issuer: issuer?.name, statusListFetched };
}

const requireSubject = (output: IssuedOutputOptions | undefined): PidSubject => output?.subject ?? fail('the test case names no subject to compare with');
const requireAttestationSubject = (output: IssuedOutputOptions | undefined): AttestationSubject => output?.attestationSubject ?? fail('the test case names no subject to compare with');
const isObject = (value: unknown): value is Record<string, unknown> => typeof value === 'object' && value !== null && !Array.isArray(value);

/** Issue 27: `holder-binding` of a configuration that is not device-bound (ICS-04 `P-NDB`): the credential names no key. */
function checkNotBound(bound: boolean, where: string): string {
  if (bound) fail(`the configuration is not device-bound, but the credential carries ${where}`);
  return `not device-bound: no ${where}, as the configuration declares no cryptographic binding`;
}

/** The validity period of an SD-JWT VC, `exp` minus `nbf` (or `iat`), seconds. */
const sdJwtPeriod = (payload: Record<string, unknown>) => {
  const start = typeof payload.nbf === 'number' ? payload.nbf : payload.iat;
  if (typeof start !== 'number' || typeof payload.exp !== 'number') return fail('the credential has no exp, or neither nbf nor iat');
  return payload.exp - start;
};

/**
 * `validity-period` of an SD-JWT VC (SD-JWT VC section 3.2.2, `SM_Validity_001`): `iat` and `exp` present as NumericDate,
 * `nbf` optional, the period not empty, and the credential valid at the time of issuance within `T_skew`.
 */
export function checkSdJwtValidityPeriod(payload: Record<string, unknown>, nowSeconds: number, skew: number): string {
  for (const claim of ['iat', 'exp']) if (typeof payload[claim] !== 'number') fail(`${claim} is missing or not a NumericDate`);
  if (payload.nbf !== undefined && typeof payload.nbf !== 'number') fail('nbf is not a NumericDate');
  const [iat, exp] = [payload.iat as number, payload.exp as number];
  const start = typeof payload.nbf === 'number' ? payload.nbf : iat;
  if (exp <= start) fail(`exp ${exp} is not after ${typeof payload.nbf === 'number' ? 'nbf' : 'iat'} ${start}`);
  if (iat > nowSeconds + skew) fail(`iat ${iat} lies in the future at issuance (now ${nowSeconds}, T_skew ${skew} s)`);
  if (start > nowSeconds + skew) fail(`not valid at issuance: nbf ${start}, now ${nowSeconds}, T_skew ${skew} s`);
  if (exp < nowSeconds - skew) fail(`not valid at issuance: exp ${exp}, now ${nowSeconds}, T_skew ${skew} s`);
  return `iat ${iat}${typeof payload.nbf === 'number' ? `, nbf ${payload.nbf}` : ''}, exp ${exp}: ${exp - start} s, valid at issuance`;
}

/** `validity-declared` (`SM_Validity_004`, ISSU_38): the period equals the declared one within the declared precision. */
export function checkDeclaredValidity(periodSeconds: number, output: IssuedOutputOptions): string {
  const declared = output.declaredValiditySeconds;
  if (declared === undefined) return fail('the ICS declares no validity period for the configuration');
  // Issuance time rounded down and expiry rounded up to the precision (ICS-16) widen the period by up to two steps.
  const tolerance = 2 * (output.precisionSeconds ?? 0);
  if (Math.abs(periodSeconds - declared) > tolerance) fail(`the validity period is ${periodSeconds} s, the ICS declares ${declared} s (tolerance ${tolerance} s)`);
  return `${periodSeconds} s, declared ${declared} s (tolerance ${tolerance} s)`;
}

/** The Type Metadata URL of an https `vct` (SD-JWT VC section 6.3.1): `/.well-known/vct` inserted before the path. */
export function typeMetadataUrl(vct: string): string {
  const url = new URL(vct);
  return `${url.origin}/.well-known/vct${url.pathname === '/' ? '' : url.pathname}${url.search}`;
}

/**
 * `type-metadata` (`DM_PidSdJwt_006`, SD-JWT VC section 6): for an https `vct`, the Type Metadata is retrievable, names
 * the same `vct`, and matches `vct#integrity` when present (W3C Subresource Integrity). A URN `vct` has no retrieval
 * the specification defines; the check records that.
 */
export async function checkTypeMetadata(payload: Record<string, unknown>, fetchTypeMetadata?: (url: string) => Promise<{ status: number; body: Uint8Array }>): Promise<string> {
  const vct = payload.vct;
  if (typeof vct !== 'string') return fail('vct is not a string');
  const integrity = payload['vct#integrity'];
  if (!/^https:\/\//.test(vct)) {
    return `vct ${vct} is not an https URL, so SD-JWT VC defines no retrieval of its Type Metadata${integrity !== undefined ? '; vct#integrity cannot be matched' : ''} (recorded)`;
  }
  if (!fetchTypeMetadata) return fail('the harness cannot fetch Type Metadata');
  const url = typeMetadataUrl(vct);
  const response = await fetchTypeMetadata(url);
  if (response.status !== 200) fail(`GET ${url}: HTTP ${response.status}`);
  const metadata = attempt(() => JSON.parse(Buffer.from(response.body).toString('utf8')) as Record<string, unknown>, `the Type Metadata at ${url} is not JSON`);
  if (metadata.vct !== vct) fail(`the Type Metadata at ${url} names vct ${JSON.stringify(metadata.vct)}`);
  if (integrity !== undefined) {
    if (typeof integrity !== 'string') fail('vct#integrity is not a string');
    const matches = (integrity as string).split(/\s+/).some((entry) => {
      const [alg, digest] = entry.split('-', 2);
      const node = { sha256: 'sha256', sha384: 'sha384', sha512: 'sha512' }[alg ?? ''];
      return node !== undefined && createHash(node).update(response.body).digest('base64') === digest;
    });
    if (!matches) fail(`vct#integrity ${String(integrity)} does not match the Type Metadata at ${url}`);
  }
  return `Type Metadata retrieved from ${url}${integrity !== undefined ? ', vct#integrity matches' : ''}`;
}

// ---------------------------------------------------------------------------------------------------------------------
// mdoc

/** The checks of an issued mdoc, in the order the reference validator runs them. */
export const ISSUED_MDOC_CHECKS: CheckId[] = [...ISSUED_CREDENTIAL_CHECKS, ...STATUS_LIST_CHECKS];

export interface IssuedMdocValidation extends ValidationResult {
  /** The issuer-signed elements by namespace, as JSON values, when the disclosures check passed. */
  claims?: Record<string, Record<string, unknown>>;
  /** The PID attributes of namespace `eu.europa.ec.eudi.pid.1` under their mdoc identifiers, for `pid-formats`. */
  pidClaims?: Record<string, unknown>;
  issuer?: string;
  statusListFetched: boolean;
}

export interface IssuedMdocValidationOptions extends Omit<IssuedSdJwtVcValidationOptions, 'expectedVct' | 'output'> {
  /** The doctype of the credential configuration the Conformance Wallet requested. */
  expectedDocType: string;
  output?: IssuedOutputOptions;
}

/**
 * The reference validator for an mdoc as a Provider issued it over OpenID4VCI (Appendix A.2.4: base64url of the
 * `IssuerSigned` structure): the checks of an mdoc presentation (ISO/IEC 18013-5 section 9.3.1), from the same helpers,
 * with `holder-binding` (the MSO's `deviceKeyInfo` is a proof key and attested) instead of `key-binding`, since there is no
 * DeviceAuth; then the status list the MSO references, as a Status List Token in CWT format.
 */
export async function validateIssuedMdoc(credential: string, options: IssuedMdocValidationOptions): Promise<IssuedMdocValidation> {
  const recorder = new CheckRecorder(options.mode ?? 'all');
  const now = options.now ?? new Date();
  const skew = options.skewSeconds;
  let parsed: ReturnType<typeof readIssuerSigned> | undefined;
  let issuer: MatchedIssuer | undefined;
  let claims: Record<string, Record<string, unknown>> | undefined;
  let elements: IssuerSignedElement[] = [];
  let reference: { idx: number; uri: string } | undefined;
  let statusListFetched = false;
  let matched: { service: { type: string; status?: string }; list: string } | undefined;
  const mso = () => (parsed as ReturnType<typeof readIssuerSigned>).mso;

  const result = await recorder.collect(async () => {
    await recorder.run('format', [], () => {
      if (!/^[A-Za-z0-9_-]+$/.test(credential)) fail('the credential is not base64url');
      const issuerSigned = asMap(attempt(() => decodeCbor(base64url.decode(credential)), 'the credential is not CBOR'), 'IssuerSigned');
      parsed = readIssuerSigned(issuerSigned);
      if (parsed.mso.get('docType') !== options.expectedDocType) fail(`MSO docType ${String(parsed.mso.get('docType'))} is not the requested ${options.expectedDocType}`);
    });

    await recorder.run('issuer-trust', ['format'], async () => {
      const match = await checkDocumentSignerTrust(options.trust, options.trustRule, (parsed as ReturnType<typeof readIssuerSigned>).x5chain, mso(), now);
      if (options.issuerEntity && match.entity.name !== options.issuerEntity) {
        fail(`the chain ends in an anchor of ${match.entity.name} (${match.list.id}), not of the enrolled ${options.issuerEntity}`);
      }
      issuer = { name: match.entity.name, statusAnchors: options.trustRule.statusAnchors(match.entity, match.service) };
      matched = { service: match.service, list: match.list.id };
      return `${match.entity.name} under ${match.anchor.subject.commonName} (${match.list.id})`;
    });

    await recorder.run('issuer-signature', ['format'], () => verifyIssuerAuth((parsed as ReturnType<typeof readIssuerSigned>).issuerAuth, (parsed as ReturnType<typeof readIssuerSigned>).x5chain));

    await recorder.run('disclosures', ['format'], () => {
      const digests = checkValueDigests((parsed as ReturnType<typeof readIssuerSigned>).issuerSigned, mso(), { rejectDuplicates: false });
      claims = digests.claims;
      elements = digests.elements;
      return `${elements.length} elements`;
    });

    await recorder.run('validity', ['format'], () => checkMdocValidity(mso(), now, skew));

    await recorder.run('holder-binding', ['format'], () => checkHolderBinding({ cnf: { jwk: deviceKeyOfMso(mso()) } }, options.proofKeys, options.keyAttestations).replaceAll('cnf.jwk', 'deviceKeyInfo'));

    await recorder.run('status-reference', ['format'], () => {
      const read = readMsoStatus(mso(), options.requireStatus);
      if (read.identifierList && !read.statusList) fail('the MSO references an identifier list, which the reference validator does not check for an issued mdoc yet');
      reference = read.statusList;
      return read.detail;
    });

    await evaluateStatusList(recorder, {
      format: 'cwt',
      reference,
      issuer,
      fetchStatusList: options.fetchStatusList,
      maxStatusListBytes: options.maxStatusListBytes,
      skewSeconds: skew,
      now,
      onFetched: () => {
        statusListFetched = true;
      },
    });

    const output = options.output;
    const nowSeconds = Math.floor(now.getTime() / 1000);
    if (wants(output, 'validity-period')) await recorder.run('validity-period', ['format'], () => checkMdocValidityPeriod(mso(), nowSeconds, skew));
    if (wants(output, 'validity-declared')) {
      await recorder.run('validity-declared', ['format'], () => {
        const { validFrom, validUntil } = validityOf(mso());
        return checkDeclaredValidity((validUntil.getTime() - validFrom.getTime()) / 1000, output as IssuedOutputOptions);
      });
    }
    if (wants(output, 'pid-type')) await recorder.run('pid-type', ['disclosures'], () => checkPidDocType(options.expectedDocType, mso().get('docType'), elements));
    if (wants(output, 'pid-attributes')) await recorder.run('pid-attributes', ['disclosures'], () => checkPidMdocAttributes(elements));
    if (wants(output, 'pid-unique')) await recorder.run('pid-unique', ['disclosures'], () => checkPidUnique(elements));
    if (wants(output, 'pid-values')) await recorder.run('pid-values', ['disclosures'], () => checkPidMdocValues(elements, requireSubject(output), validityOf(mso()).validFrom));
    if (wants(output, 'pid-dates')) {
      await recorder.run('pid-dates', ['disclosures'], () => {
        const { validFrom, validUntil } = validityOf(mso());
        return checkPidMdocDates(elements, validFrom, validUntil, skew);
      });
    }
    if (wants(output, 'pid-portrait')) await recorder.run('pid-portrait', ['disclosures'], () => checkPidMdocPortraitOptOut(elements));
    // Issue 27: the rulebook of `default_credential_A`, the revocation method and the qualified service.
    if (wants(output, 'attestation-type')) await recorder.run('attestation-type', ['disclosures'], () => checkAttestationType('mso_mdoc', mso().get('docType'), elements));
    if (wants(output, 'attestation-attributes')) await recorder.run('attestation-attributes', ['disclosures'], () => checkAttestationAttributes(elements, now));
    if (wants(output, 'attestation-values')) await recorder.run('attestation-values', ['disclosures'], () => checkAttestationValues(elements, requireAttestationSubject(output)));
    if (wants(output, 'revocation-method')) {
      await recorder.run('revocation-method', ['format'], () => {
        const { validFrom, validUntil } = validityOf(mso());
        return checkRevocationMethod(readMsoStatus(mso(), false).statusList !== undefined, (validUntil.getTime() - validFrom.getTime()) / 1000);
      });
    }
    if (wants(output, 'qualified-service')) await recorder.run('qualified-service', ['issuer-trust'], () => checkQualifiedService(matched?.service, matched?.list));
  });
  const disclosed = !result.failures.includes('disclosures') && claims !== undefined;
  return {
    ...result,
    claims: disclosed ? claims : undefined,
    pidClaims: disclosed ? pidMdocClaims(elements) : undefined,
    issuer: issuer?.name,
    statusListFetched,
  };
}

/**
 * `validity-period` of an mdoc (ISO/IEC 18013-5 section 9.1.2.4, `SM_Validity_001`): `validFrom` not after `validUntil`,
 * `signed` and `validFrom` not in the future and `validUntil` not past at the time of issuance within `T_skew`: the mdoc valid at the time of issuance.
 */
export function checkMdocValidityPeriod(mso: CborMap, nowSeconds: number, skew: number): string {
  const { signed, validFrom, validUntil } = validityOf(mso);
  const [from, until, at] = [validFrom.getTime() / 1000, validUntil.getTime() / 1000, signed.getTime() / 1000];
  if (until <= from) fail(`validUntil ${validUntil.toISOString()} is not after validFrom ${validFrom.toISOString()}`);
  if (at > nowSeconds + skew) fail(`signed ${signed.toISOString()} lies in the future at issuance`);
  if (from > nowSeconds + skew) fail(`not valid at issuance: validFrom ${validFrom.toISOString()}`);
  if (until < nowSeconds - skew) fail(`not valid at issuance: validUntil ${validUntil.toISOString()}`);
  return `signed ${signed.toISOString()}, validFrom ${validFrom.toISOString()}, validUntil ${validUntil.toISOString()}: ${until - from} s, valid at issuance`;
}

/**
 * `pid-formats` (`DM_PidMdoc_006`): compares the SD-JWT VC and the mdoc a step received for the same subject, as the
 * reference validator disclosed them. A step check: it belongs to the issuance, not to one credential.
 */
export function comparePidFormats(sdJwtClaims: Record<string, unknown> | undefined, mdocPidClaims: Record<string, unknown> | undefined): CheckResult {
  if (!sdJwtClaims || !mdocPidClaims) {
    return { check: 'pid-formats', status: 'skip', detail: `the step has no ${!sdJwtClaims ? 'SD-JWT VC' : 'mdoc'} whose disclosures passed` };
  }
  try {
    return { check: 'pid-formats', status: 'pass', detail: checkPidFormats(sdJwtClaims, mdocPidClaims) };
  } catch (error) {
    return { check: 'pid-formats', status: 'fail', detail: (error as Error).message };
  }
}
