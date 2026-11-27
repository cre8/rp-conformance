// The reference validator for an mdoc presentation (ISO/IEC 18013-5 section 9.3.1, OpenID4VP 1.0 Appendix B.2): one
// named check per property, so a fault can be shown to fail exactly one of them. It decodes the DeviceResponse as raw
// CBOR and computes the SessionTranscript itself; nothing of @owf/mdoc, which built the artifacts, is used here.
import { type CheckId, IDENTIFIER_LIST_CHECKS, MDOC_CREDENTIAL_CHECKS, STATUS_LIST_CHECKS } from '@rp-conformance/core';
import {
  base64url,
  type CborMap,
  COSE,
  COSE_ALG,
  dateOf,
  decodeCbor,
  decodeEmbedded,
  embedded,
  encodeCbor,
  MDOC_DS_EXTENDED_KEY_USAGE,
  type Oid4vpHandover,
  PID_DOCTYPE,
  PID_NAMESPACE,
  readCose,
  sha256,
  sigStructure,
  Tagged,
  verifyEs256,
  x5chainOf,
} from '@rp-conformance/forge';
import { parseCertificate } from '@owf/x509';
import { describeKey } from './disclosures';
import { checkClaims, type RequestedClaim } from './claims';
import { CheckRecorder, NotApplicable, type ValidationMode, type ValidationResult } from './checks';
import { evaluateIdentifierList } from './identifier-list';
import { attempt, base64Of, evaluateStatusList, type FetchedStatusList, fail, isUri, type StatusListFreshness } from './status-list';
import type { MatchedIssuer, TrustRule, TrustStore } from './trust';

/** The checks of an mdoc presentation that references a Status List Token in CWT format. */
export const MDOC_STATUS_LIST_CHECKS: CheckId[] = [...MDOC_CREDENTIAL_CHECKS, ...STATUS_LIST_CHECKS];
/** The checks of an mdoc presentation that references an identifier list. */
export const MDOC_IDENTIFIER_LIST_CHECKS: CheckId[] = [...MDOC_CREDENTIAL_CHECKS, ...IDENTIFIER_LIST_CHECKS];

export interface MdocValidation extends ValidationResult {
  /** The disclosed attributes by namespace, as JSON values (`full-date` and `tdate` as strings). */
  claims?: Record<string, Record<string, unknown>>;
  issuer?: string;
  statusListFetched: boolean;
  identifierListFetched: boolean;
  /** Whether the issuer matched a trust list that is used within its grace period (`trust-list-stale`). */
  trustListStale: boolean;
}

export interface MdocValidationOptions {
  trust: TrustStore;
  /** The root of trust of the credential's category (`TRUST_RULES`), for example a PID/Issuance service of `TL-PID`. */
  trustRule: TrustRule;
  /** The doctype the Relying Party requested (`meta.doctype_value`). */
  expectedDocType: string;
  /**
   * What the SessionTranscript binds: `client_id` and `response_uri` of the request (redirects, B.2.6.1), or the
   * Origin of the page (DC API, B.2.6.2); with the `nonce` and the thumbprint of the request's encryption key.
   */
  handover: Oid4vpHandover;
  nonce: string;
  jwkThumbprint: Uint8Array | null;
  /** Clock tolerance `T_skew`, seconds. */
  skewSeconds: number;
  /** A PID without reliable revocation status is rejected unless valid for at most 24 hours (catalogue decision 2). */
  requireStatus: boolean;
  maxStatusListBytes: number;
  validStatuses?: number[];
  trustedAuthorities?: { type: string; values: string[] }[];
  /** The claims of the credential query, for the check `claims`; left out, the check does not apply. */
  requestedClaims?: RequestedClaim[];
  fetchStatusList: (uri: string) => Promise<FetchedStatusList>;
  fetchIdentifierList: (uri: string) => Promise<FetchedStatusList>;
  mode?: ValidationMode;
  now?: Date;
  /** Freshness policy for Status List Tokens (ICS RP.R.7, RP.R.8). */
  statusListFreshness?: StatusListFreshness;
  /** Reject a PID whose administrative expiry date has passed (ICS RP.P.12 Reject). */
  rejectPastExpiryDate?: boolean;
  /**
   * The `client_id` of a request made through the DC API. It only names the defect of a device signature over an
   * `OpenID4VPHandover`, which such a request does not take (B.2.6.2); left out, that defect fails without its name.
   */
  clientId?: string;
}

const DAY_MS = 24 * 60 * 60 * 1000;

/**
 * The SessionTranscript of OpenID4VP 1.0 Appendix B.2.6: `OpenID4VPHandover` over `[client_id, nonce, jwkThumbprint,
 * response_uri]` via redirects (B.2.6.1), `OpenID4VPDCAPIHandover` over `[origin, nonce, jwkThumbprint]` via the DC
 * API (B.2.6.2), the origin without the `origin:` prefix.
 */
export function openid4vpSessionTranscript(options: Pick<MdocValidationOptions, 'handover' | 'nonce' | 'jwkThumbprint'>) {
  const { handover } = options;
  if (handover.flow === 'dc-api') {
    return [null, null, ['OpenID4VPDCAPIHandover', sha256(encodeCbor([handover.origin, options.nonce, options.jwkThumbprint]))]];
  }
  const info = encodeCbor([handover.clientId, options.nonce, options.jwkThumbprint, handover.responseUri]);
  return [null, null, ['OpenID4VPHandover', sha256(info)]];
}

const HANDOVER_NAMES = { redirect: 'OpenID4VPHandover', 'dc-api': 'OpenID4VPDCAPIHandover' } as const;

/**
 * The handover of the other flow that a wallet could build from the same request: an `OpenID4VPDCAPIHandover` over the
 * Origin of `response_uri`, or an `OpenID4VPHandover` over `clientId` with the Origin of the page as `response_uri`.
 */
function otherHandover(options: Pick<MdocValidationOptions, 'handover' | 'clientId'>): Oid4vpHandover | undefined {
  const { handover } = options;
  if (handover.flow === 'redirect') return URL.canParse(handover.responseUri) ? { flow: 'dc-api', origin: new URL(handover.responseUri).origin } : undefined;
  return options.clientId ? { flow: 'redirect', clientId: options.clientId, responseUri: handover.origin } : undefined;
}

/** An attribute value as JSON: `full-date` and `tdate` as their text, maps as objects. */
export function jsonOf(value: unknown): unknown {
  if (value instanceof Tagged) return value.tag === 1004 || value.tag === 0 ? value.value : jsonOf(value.value);
  if (value instanceof Map) return Object.fromEntries([...value].map(([k, v]) => [String(k), jsonOf(v)]));
  if (Array.isArray(value)) return value.map(jsonOf);
  if (value instanceof Uint8Array) return base64url.encode(value);
  return value;
}

/** The key type of each COSE elliptic curve: EC2 (2) for P-256, P-384, P-521 and secp256k1, OKP (1) for X25519, X448, Ed25519 and Ed448 (RFC 9053 section 7.1, RFC 8812). */
const KEY_TYPE_OF_CURVE: Record<number, number> = { 1: 2, 2: 2, 3: 2, 4: 1, 5: 1, 6: 1, 7: 1, 8: 2 };

/** The JWK of an EC2 P-256 COSE key (RFC 9053 section 7.1). */
export function jwkOfCoseKey(key: unknown): JsonWebKey {
  if (!(key instanceof Map)) fail('the device key is not a COSE key');
  const map = key as CborMap;
  const [kty, crv, x, y] = [map.get(1), map.get(-1), map.get(-2), map.get(-3)];
  // RFC 9053 section 7.1: "Applications MUST check that the curve and the key type are consistent".
  const keyType = KEY_TYPE_OF_CURVE[crv as number];
  if (keyType !== undefined && kty !== keyType) fail(`the device key has the key type ${String(kty)} with the curve ${String(crv)}, which do not belong together`);
  if (kty !== 2 || crv !== 1 || !(x instanceof Uint8Array) || !(y instanceof Uint8Array)) fail('the device key is not an EC2 key on P-256');
  return { kty: 'EC', crv: 'P-256', x: base64url.encode(x as Uint8Array), y: base64url.encode(y as Uint8Array) };
}

export const asMap = (value: unknown, what: string): CborMap => {
  if (!(value instanceof Map)) fail(`${what} is not a map`);
  return value as CborMap;
};

/** An `IssuerSigned` structure (ISO/IEC 18013-5 section 8.3.2.1.2.2) with its IssuerAuth and MSO decoded. */
export interface ParsedIssuerSigned {
  issuerSigned: CborMap;
  issuerAuth: ReturnType<typeof readCose>;
  mso: CborMap;
  x5chain: Uint8Array[];
}

/**
 * Reads an `IssuerSigned` structure: `nameSpaces`, an IssuerAuth COSE_Sign1 (tag 18 or untagged) with `x5chain`, and its
 * payload, the MSO, with version 1.x, `valueDigests` and a `validityInfo` of `tdate`s. Fails (`fail`) on the first
 * structural defect; used by the `format` check of a presentation and of an issued mdoc.
 */
export function readIssuerSigned(value: unknown): ParsedIssuerSigned {
  const issuerSigned = asMap(value, 'issuerSigned');
  asMap(issuerSigned.get('nameSpaces'), 'issuerSigned.nameSpaces');
  const issuerAuth = attempt(() => readCose(issuerSigned.get('issuerAuth')), 'IssuerAuth');
  // RFC 9052 section 3: "Labels in each of the maps MUST be unique. When processing messages, if a label appears
  // multiple times, the message MUST be rejected as malformed."
  if (issuerAuth.protectedBytes.length > 0) {
    attempt(() => decodeCbor(issuerAuth.protectedBytes, { rejectDuplicateKeys: true }), 'the IssuerAuth protected header');
  }
  if (issuerAuth.tag !== undefined && issuerAuth.tag !== 18) fail(`IssuerAuth carries tag ${issuerAuth.tag}`);
  const chain = x5chainOf(issuerAuth.unprotectedHeader.get(COSE.x5chain) ?? issuerAuth.protectedHeader.get(COSE.x5chain));
  if (!chain) fail('IssuerAuth carries no x5chain');
  if (!issuerAuth.payload) fail('IssuerAuth has no payload');
  const mso = asMap(attempt(() => decodeEmbedded(decodeCbor(issuerAuth.payload as Uint8Array)), 'the IssuerAuth payload is not MobileSecurityObjectBytes'), 'the MSO');
  if (typeof mso.get('version') !== 'string' || !/^1\./.test(mso.get('version') as string)) fail(`MSO version ${String(mso.get('version'))}`);
  asMap(mso.get('valueDigests'), 'valueDigests');
  const validityInfo = asMap(mso.get('validityInfo'), 'validityInfo');
  for (const key of ['signed', 'validFrom', 'validUntil']) if (!dateOf(validityInfo.get(key))) fail(`validityInfo.${key} is not a tdate`);
  return { issuerSigned, issuerAuth, mso, x5chain: chain as Uint8Array[] };
}

/**
 * `issuer-trust` of an mdoc: the document signer chains to an anchor of `rule`, carries the extended key usage of
 * ISO/IEC 18013-5 Annex B, and the MSO was signed within its validity period (section 9.3.1).
 */
export async function checkDocumentSignerTrust(trust: TrustStore, rule: TrustRule, x5chain: Uint8Array[], mso: CborMap, now: Date) {
  const match = await trust.match(rule, base64Of(x5chain), now);
  if (!match.ok) return fail(match.reason);
  // ISO/IEC 18013-5 Annex B, Table B.3: a document signer certificate carries this extended key usage.
  if (!match.leaf.extendedKeyUsage?.includes(MDOC_DS_EXTENDED_KEY_USAGE)) fail('the signing certificate is not a document signer (no extended key usage 1.0.18013.5.1.2)');
  // ISO/IEC 18013-5 section 9.3.1: the MSO was signed within the validity period of the document signer certificate.
  const signed = dateOf((mso.get('validityInfo') as CborMap).get('signed')) as Date;
  if (signed < match.leaf.notBefore || signed > match.leaf.notAfter) {
    fail(`the MSO was signed (${signed.toISOString()}) outside the validity period of the document signer certificate`);
  }
  return match;
}

/**
 * The curve of each ECDSA algorithm other than P-256: fixed by the fully specified ones (RFC 9864 section 2.1),
 * suggested for the polymorphic ones (RFC 9053 section 2.1). It is consulted once the document signer key is known to
 * be on P-256, so `ES256` (-7) and `ESP256` (-9) have no entry: they never disagree with the key.
 */
const ECDSA_CURVES: Record<number, { curve: string; fixed: boolean }> = {
  [-35]: { curve: 'P-384', fixed: false },
  [-36]: { curve: 'P-521', fixed: false },
  [-51]: { curve: 'P-384', fixed: true },
  [-52]: { curve: 'P-521', fixed: true },
};

/** The protected header labels the validator processes, and so understands when `crit` lists them (RFC 9052 section 3.1). */
const UNDERSTOOD_LABELS = new Set<unknown>([COSE.alg, COSE.x5chain]);

/**
 * `issuer-signature` of an mdoc: `crit` lists no label the validator does not understand, the algorithm fits the curve
 * of the document signer's key, ES256 by a P-256 document signer, the IssuerAuth signature verifies.
 */
export async function verifyIssuerAuth(issuerAuth: ReturnType<typeof readCose>, x5chain: Uint8Array[]): Promise<void> {
  const crit = issuerAuth.protectedHeader.get(COSE.crit);
  const unknown = crit === undefined ? [] : Array.isArray(crit) ? crit.filter((label) => !UNDERSTOOD_LABELS.has(label)) : [crit];
  if (unknown.length) fail(`IssuerAuth crit lists the label ${unknown.map(String).join(', ')}, which the validator does not understand`);
  const key = describeKey(x5chain[0]);
  if (key !== 'P-256') fail(`the document signer certificate holds a key ${key}, not on P-256`);
  // RFC 9360 section 5: the key is checked against the algorithm before it is used.
  const alg = issuerAuth.protectedHeader.get(COSE.alg);
  const pairing = ECDSA_CURVES[alg as number];
  if (pairing && pairing.curve !== key) {
    fail(`IssuerAuth alg ${String(alg)} ${pairing.fixed ? 'is ECDSA on' : 'pairs with'} ${pairing.curve}, and the document signer holds a key on ${key}`);
  }
  if (issuerAuth.protectedHeader.get(COSE.alg) !== COSE_ALG.ES256) fail(`IssuerAuth alg ${String(issuerAuth.protectedHeader.get(COSE.alg))} is not supported`);
  const jwk = parseCertificate(x5chain[0]).publicKey.jwk as JsonWebKey;
  if (!(await verifyEs256(jwk as JsonWebKey, sigStructure(issuerAuth.protectedBytes, issuerAuth.payload as Uint8Array), issuerAuth.signature))) {
    fail('the IssuerAuth signature does not verify');
  }
}

/** One `IssuerSignedItem` as decoded from `nameSpaces`, with its raw CBOR value. */
export interface IssuerSignedElement {
  namespace: string;
  identifier: string;
  value: unknown;
}

/**
 * `disclosures` of an mdoc: SHA-256 digests, every `IssuerSignedItemBytes` of `nameSpaces` matches its value digest in
 * the MSO. A presentation also rejects an element disclosed twice (`rejectDuplicates`); for an issued mdoc that is the
 * data model check `pid-unique`. Returns the elements as JSON by namespace, and as decoded.
 */
export function checkValueDigests(issuerSigned: CborMap, mso: CborMap, options: { rejectDuplicates: boolean }) {
  if (mso.get('digestAlgorithm') !== 'SHA-256') fail(`digestAlgorithm ${String(mso.get('digestAlgorithm'))} is not supported`);
  const digests = mso.get('valueDigests') as CborMap;
  const claims: Record<string, Record<string, unknown>> = {};
  const elements: IssuerSignedElement[] = [];
  for (const [namespace, items] of issuerSigned.get('nameSpaces') as CborMap) {
    if (typeof namespace !== 'string' || !Array.isArray(items)) fail('issuerSigned.nameSpaces is not a map of arrays');
    const namespaceDigests = digests.get(namespace);
    if (!(namespaceDigests instanceof Map)) fail(`the MSO has no value digests for namespace ${String(namespace)}`);
    claims[namespace as string] ??= {};
    for (const item of items as unknown[]) {
      const signedItem = asMap(attempt(() => decodeEmbedded(item), 'an IssuerSignedItem is not IssuerSignedItemBytes'), 'an IssuerSignedItem');
      const [digestId, identifier] = [signedItem.get('digestID'), signedItem.get('elementIdentifier')];
      if (typeof identifier !== 'string') fail('an IssuerSignedItem has no elementIdentifier');
      if (options.rejectDuplicates && Object.hasOwn(claims[namespace as string], identifier as string)) fail(`${String(identifier)} is disclosed twice`);
      const expected = (namespaceDigests as CborMap).get(digestId);
      if (!(expected instanceof Uint8Array)) fail(`the MSO has no digest with ID ${String(digestId)} for ${String(identifier)}`);
      if (!Buffer.from(sha256(encodeCbor(item))).equals(Buffer.from(expected as Uint8Array))) fail(`the digest of ${String(identifier)} does not match the MSO`);
      claims[namespace as string][identifier as string] = jsonOf(signedItem.get('elementValue'));
      elements.push({ namespace: namespace as string, identifier: identifier as string, value: signedItem.get('elementValue') });
    }
  }
  return { claims, elements };
}

/** The MSO's `validityInfo` as dates (after `readIssuerSigned`). */
export function validityOf(mso: CborMap) {
  const validityInfo = mso.get('validityInfo') as CborMap;
  return {
    signed: dateOf(validityInfo.get('signed')) as Date,
    validFrom: dateOf(validityInfo.get('validFrom')) as Date,
    validUntil: dateOf(validityInfo.get('validUntil')) as Date,
    expectedUpdate: dateOf(validityInfo.get('expectedUpdate')),
  };
}

/** `validity` of an mdoc: `now` lies within `validFrom` and `validUntil`, with `T_skew`. */
export function checkMdocValidity(mso: CborMap, now: Date, skewSeconds: number): string | void {
  const { validFrom, validUntil, expectedUpdate } = validityOf(mso);
  const skewMs = skewSeconds * 1000;
  if (now.getTime() > validUntil.getTime() + skewMs) fail(`expired: validUntil ${validUntil.toISOString()}, T_skew ${skewSeconds} s`);
  if (now.getTime() < validFrom.getTime() - skewMs) fail(`not yet valid: validFrom ${validFrom.toISOString()}, T_skew ${skewSeconds} s`);
  // expectedUpdate is informative (ISO/IEC 18013-5 section 9.1.2.4): Validity_012.
  if (expectedUpdate && expectedUpdate < now) return `expectedUpdate ${expectedUpdate.toISOString()} has passed (informative)`;
}

/**
 * `status-reference` of an mdoc: the MSO's `status` with a `status_list` (`idx`, `uri`) or an `identifier_list` (`id`,
 * `uri`) entry; without `status`, the validity period must be at most 24 hours unless `requireStatus` is false.
 */
export function readMsoStatus(mso: CborMap, requireStatus: boolean) {
  const status = mso.get('status');
  let statusList: { uri: string; idx: number; certificate?: Uint8Array } | undefined;
  let identifierList: { uri: string; id: Uint8Array } | undefined;
  if (status === undefined) {
    const { validFrom, validUntil } = validityOf(mso);
    const period = validUntil.getTime() - validFrom.getTime();
    if (!requireStatus) return { detail: 'no status (accepted by policy)' };
    if (period <= DAY_MS) return { detail: `no status; validity period ${period / 1000} s is at most 24 hours` };
    fail(`no status, and the validity period (${period / 1000} s) exceeds 24 hours`);
  }
  const entries = asMap(status, 'status');
  const statusListEntry = entries.get('status_list');
  const identifierListEntry = entries.get('identifier_list');
  if (statusListEntry === undefined && identifierListEntry === undefined) fail('status has neither a status_list nor an identifier_list entry');
  if (statusListEntry !== undefined) {
    const entry = asMap(statusListEntry, 'status_list');
    const idx = entry.get('idx');
    if (typeof idx !== 'number' || !Number.isInteger(idx) || idx < 0) fail(`idx ${JSON.stringify(jsonOf(idx))} is not an unsigned integer`);
    if (!isUri(entry.get('uri'))) fail(`uri ${JSON.stringify(entry.get('uri'))} is not a URI`);
    const certificate = entry.get('certificate');
    if (certificate !== undefined && !(certificate instanceof Uint8Array)) fail('the status_list certificate is not a byte string');
    statusList = { idx: idx as number, uri: entry.get('uri') as string, ...(certificate ? { certificate: certificate as Uint8Array } : {}) };
  }
  if (identifierListEntry !== undefined) {
    const entry = asMap(identifierListEntry, 'identifier_list');
    if (!(entry.get('id') instanceof Uint8Array)) fail('the identifier_list id is not a byte string');
    if (!isUri(entry.get('uri'))) fail(`uri ${JSON.stringify(entry.get('uri'))} is not a URI`);
    identifierList = { id: entry.get('id') as Uint8Array, uri: entry.get('uri') as string };
  }
  return { statusList, identifierList };
}

/** The device key of the MSO (`deviceKeyInfo.deviceKey`) as a JWK; fails without one. */
export function deviceKeyOfMso(mso: CborMap): JsonWebKey {
  const deviceKeyInfo = mso.get('deviceKeyInfo');
  if (!(deviceKeyInfo instanceof Map) || !deviceKeyInfo.has('deviceKey')) fail('the MSO carries no deviceKeyInfo, so it is bound to no device key');
  return jwkOfCoseKey((deviceKeyInfo as CborMap).get('deviceKey'));
}

/**
 * Validates an mdoc presentation: a base64url DeviceResponse with one document (`vp_token` entry, OpenID4VP B.2.4).
 * Trust follows `default_trust_configuration_rp` as for SD-JWT VC (`trustRule`): the document signer chains to an
 * anchor of a service that may sign the credential's category and carries the extended key usage of ISO/IEC 18013-5
 * Annex B; the status list or identifier list chains to an anchor the rule names for that service's status lists. Status procedures run only for an otherwise valid credential
 * unless `mode` is `all`.
 */
export async function validateMdocPresentation(presentation: string, options: MdocValidationOptions): Promise<MdocValidation> {
  const recorder = new CheckRecorder(options.mode ?? 'first-failure');
  const now = options.now ?? new Date();
  let document: CborMap = new Map();
  let issuerSigned: CborMap = new Map();
  let issuerAuth: ReturnType<typeof readCose> | undefined;
  let mso: CborMap = new Map();
  let x5chain: Uint8Array[] = [];
  let issuer: MatchedIssuer | undefined;
  let claims: Record<string, Record<string, unknown>> | undefined;
  /** The disclosed element values as decoded CBOR, for the data types of the PID rulebook. */
  const rawClaims: Record<string, Record<string, unknown>> = {};
  let statusListReference: { uri: string; idx: number } | undefined;
  let identifierListReference: { uri: string; id: Uint8Array } | undefined;
  let statusListFetched = false;
  let trustListStale = false;
  let identifierListFetched = false;

  const result = await recorder.collect(async () => {
    await recorder.run('format', [], () => {
      if (!/^[A-Za-z0-9_-]+$/.test(presentation)) fail('the vp_token entry is not base64url');
      const response = asMap(attempt(() => decodeCbor(base64url.decode(presentation)), 'the DeviceResponse is not CBOR'), 'the DeviceResponse');
      if (typeof response.get('version') !== 'string' || !/^1\./.test(response.get('version') as string)) fail(`DeviceResponse version ${String(response.get('version'))}`);
      if (response.get('status') !== 0) fail(`DeviceResponse status ${String(response.get('status'))}`);
      const documents = response.get('documents');
      if (!Array.isArray(documents) || documents.length !== 1) fail('the DeviceResponse does not carry exactly one document');
      document = asMap((documents as unknown[])[0], 'the document');
      if (document.get('docType') !== options.expectedDocType) fail(`docType ${String(document.get('docType'))} was not requested`);
      ({ issuerSigned, issuerAuth, mso, x5chain } = readIssuerSigned(document.get('issuerSigned')));
      if (mso.get('docType') !== document.get('docType')) fail('the MSO docType differs from the document docType');
      // deviceKeyInfo and deviceAuth are checked by key-binding, so a credential without device binding fails there.
      const deviceSigned = asMap(document.get('deviceSigned'), 'deviceSigned');
      attempt(() => decodeEmbedded(deviceSigned.get('nameSpaces')), 'deviceSigned.nameSpaces');
    });

    await recorder.run('issuer-trust', ['format'], async () => {
      const match = await checkDocumentSignerTrust(options.trust, options.trustRule, x5chain, mso, now);
      issuer = { name: match.entity.name, statusAnchors: options.trustRule.statusAnchors(match.entity, match.service) };
      trustListStale = match.stale;
      return `${match.entity.name} under ${match.anchor.subject.commonName} (${match.list.id}${match.stale ? ', stale within the grace period' : ''})`;
    });

    await recorder.run('trusted-authorities', ['format'], () => {
      if (!options.trustedAuthorities?.length) return 'the query has no trusted_authorities';
      const certificates = x5chain.map((c) => parseCertificate(c));
      for (const authority of options.trustedAuthorities) {
        if (authority.type !== 'aki') fail(`trusted_authorities type ${authority.type} is not supported`);
        const matching = certificates.find(
          (c) => c.authorityKeyIdentifier && authority.values.includes(Buffer.from(c.authorityKeyIdentifier, 'hex').toString('base64url')),
        );
        if (matching) return `${matching.subject.commonName} has an authority key identifier the query names`;
      }
      fail('no certificate in x5chain has an authority key identifier that trusted_authorities names');
    });

    await recorder.run('issuer-signature', ['format'], () => verifyIssuerAuth(issuerAuth as ReturnType<typeof readCose>, x5chain));

    await recorder.run('disclosures', ['format'], () => {
      const disclosed = checkValueDigests(issuerSigned, mso, { rejectDuplicates: true });
      claims = disclosed.claims;
      for (const element of disclosed.elements) (rawClaims[element.namespace] ??= {})[element.identifier] = element.value;
      return `${disclosed.elements.length} elements`;
    });

    await recorder.run('validity', ['format'], () => {
      const detail = checkMdocValidity(mso, now, options.skewSeconds);
      // RP_WS_SM_Validity_020: the administrative expiry date of a PID, under the policy of ICS RP.P.12.
      const expiry = claims?.[PID_NAMESPACE]?.expiry_date;
      if (options.rejectPastExpiryDate && typeof expiry === 'string' && expiry < now.toISOString().slice(0, 10)) fail(`the administrative expiry date ${expiry} has passed`);
      return detail;
    });

    // Device binding and session binding (ISO/IEC 18013-5 section 9.1.3, OpenID4VP Appendix B.2.6): a device signature
    // by the MSO's device key over the SessionTranscript of this request, with no unauthorised device-signed element.
    await recorder.run('key-binding', ['format'], async () => {
      const deviceSigned = document.get('deviceSigned') as CborMap;
      const deviceAuth = deviceSigned.get('deviceAuth');
      if (!(deviceAuth instanceof Map)) fail('the document carries no deviceAuth');
      if (!(deviceAuth as CborMap).has('deviceSignature')) fail('deviceAuth carries no deviceSignature (a deviceMac needs a reader key, which OpenID4VP has not)');
      const signature = attempt(() => readCose((deviceAuth as CborMap).get('deviceSignature')), 'deviceSignature');
      if (signature.protectedHeader.get(COSE.alg) !== COSE_ALG.ES256) fail(`deviceSignature alg ${String(signature.protectedHeader.get(COSE.alg))} is not supported`);
      if (signature.payload !== null) fail('the deviceSignature payload is not detached');
      const deviceNameSpaces = deviceSigned.get('nameSpaces') as Tagged;
      const elements = decodeEmbedded<unknown>(deviceNameSpaces);
      if (!(elements instanceof Map) || elements.size > 0) fail('DeviceNameSpaces is not empty, and the MSO authorizes no device-signed element');
      const jwk = deviceKeyOfMso(mso);
      const transcript = openid4vpSessionTranscript(options);
      const deviceAuthentication = encodeCbor(embedded(['DeviceAuthentication', transcript, document.get('docType'), deviceNameSpaces]));
      if (!(await verifyEs256(jwk, sigStructure(signature.protectedBytes, deviceAuthentication), signature.signature))) {
        // OpenID4VP 1.0 B.2.6.1 and B.2.6.2: the handover follows how the request was made. A signature over the other
        // handover of this request is named as such.
        const other = otherHandover(options);
        const otherAuthentication = other && encodeCbor(embedded(['DeviceAuthentication', openid4vpSessionTranscript({ ...options, handover: other }), document.get('docType'), deviceNameSpaces]));
        if (otherAuthentication && (await verifyEs256(jwk, sigStructure(signature.protectedBytes, otherAuthentication), signature.signature))) {
          fail(`the deviceSignature covers an ${HANDOVER_NAMES[other.flow]} instead of the ${HANDOVER_NAMES[options.handover.flow]} of this request`);
        }
        fail('the deviceSignature does not verify over the SessionTranscript of this request');
      }
    });

    await recorder.run('status-reference', ['format'], () => {
      const read = readMsoStatus(mso, options.requireStatus);
      statusListReference = read.statusList;
      identifierListReference = read.identifierList;
      return read.detail;
    });

    // The disclosed elements satisfy the query, and a PID's elements have the types of the PID rulebook.
    await recorder.run('claims', ['format', 'disclosures'], () => {
      if (!options.requestedClaims) return new NotApplicable('no credential query given');
      const pid = mso.get('docType') === PID_DOCTYPE ? { encoding: 'mdoc' as const, namespace: PID_NAMESPACE, raw: rawClaims } : undefined;
      return checkClaims(claims ?? {}, options.requestedClaims, pid);
    });

    // Status procedures (Token Status List section 8.3, ISO/IEC 18013-5 section 12.3.6): in first-failure mode only for
    // a valid credential. The status list checks are recorded unless the MSO references only an identifier list.
    const status = mso.get('status');
    const hasIdentifierList = status instanceof Map && status.has('identifier_list');
    const hasStatusList = status instanceof Map && status.has('status_list');
    if (hasStatusList || !hasIdentifierList) {
      await evaluateStatusList(recorder, {
        format: 'cwt',
        reference: statusListReference,
        issuer,
        fetchStatusList: options.fetchStatusList,
        maxStatusListBytes: options.maxStatusListBytes,
        validStatuses: options.validStatuses,
        skewSeconds: options.skewSeconds,
        now,
        onFetched: () => {
          statusListFetched = true;
        },
        freshness: options.statusListFreshness,
      });
    }
    if (hasIdentifierList) {
      await evaluateIdentifierList(recorder, {
        reference: identifierListReference,
        issuer,
        fetchIdentifierList: options.fetchIdentifierList,
        skewSeconds: options.skewSeconds,
        now,
        onFetched: () => {
          identifierListFetched = true;
        },
      });
    }
  });
  return {
    ...result,
    claims: result.failures.includes('disclosures') ? undefined : claims,
    issuer: issuer?.name,
    statusListFetched,
    identifierListFetched,
    trustListStale,
  };
}
