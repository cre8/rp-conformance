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
  readCose,
  sha256,
  sigStructure,
  Tagged,
  verifyEs256,
  x5chainOf,
} from '@rp-conformance/forge';
import { parseCertificate } from '@owf/x509';
import { CheckRecorder, type ValidationMode, type ValidationResult } from './checks';
import { evaluateIdentifierList } from './identifier-list';
import { attempt, base64Of, evaluateStatusList, type FetchedStatusList, fail, isUri } from './status-list';
import type { TrustedEntity, TrustStore } from './trust';

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
}

export interface MdocValidationOptions {
  trust: TrustStore;
  /** The list whose `/Issuance` anchors are trusted for this credential type, for example `TL-PID`. */
  issuerList: string;
  /** The doctype the Relying Party requested (`meta.doctype_value`). */
  expectedDocType: string;
  /** `client_id`, `nonce` and `response_uri` of the request, and the thumbprint of its encryption key (B.2.6.1). */
  clientId: string;
  nonce: string;
  responseUri: string;
  jwkThumbprint: Uint8Array | null;
  /** Clock tolerance `T_skew`, seconds. */
  skewSeconds: number;
  /** A PID without reliable revocation status is rejected unless valid for at most 24 hours (catalogue decision 2). */
  requireStatus: boolean;
  maxStatusListBytes: number;
  validStatuses?: number[];
  trustedAuthorities?: { type: string; values: string[] }[];
  fetchStatusList: (uri: string) => Promise<FetchedStatusList>;
  fetchIdentifierList: (uri: string) => Promise<FetchedStatusList>;
  mode?: ValidationMode;
  now?: Date;
}

const DAY_MS = 24 * 60 * 60 * 1000;

/** The SessionTranscript of OpenID4VP 1.0 Appendix B.2.6.1 for a response via redirects. */
export function openid4vpSessionTranscript(options: Pick<MdocValidationOptions, 'clientId' | 'nonce' | 'responseUri' | 'jwkThumbprint'>) {
  const info = encodeCbor([options.clientId, options.nonce, options.jwkThumbprint, options.responseUri]);
  return [null, null, ['OpenID4VPHandover', sha256(info)]];
}

/** An attribute value as JSON: `full-date` and `tdate` as their text, maps as objects. */
function jsonOf(value: unknown): unknown {
  if (value instanceof Tagged) return value.tag === 1004 || value.tag === 0 ? value.value : jsonOf(value.value);
  if (value instanceof Map) return Object.fromEntries([...value].map(([k, v]) => [String(k), jsonOf(v)]));
  if (Array.isArray(value)) return value.map(jsonOf);
  if (value instanceof Uint8Array) return base64url.encode(value);
  return value;
}

/** The JWK of an EC2 P-256 COSE key (RFC 9053 section 7.1). */
function jwkOfCoseKey(key: unknown): JsonWebKey {
  if (!(key instanceof Map)) fail('the device key is not a COSE key');
  const map = key as CborMap;
  const [kty, crv, x, y] = [map.get(1), map.get(-1), map.get(-2), map.get(-3)];
  if (kty !== 2 || crv !== 1 || !(x instanceof Uint8Array) || !(y instanceof Uint8Array)) fail('the device key is not an EC2 key on P-256');
  return { kty: 'EC', crv: 'P-256', x: base64url.encode(x as Uint8Array), y: base64url.encode(y as Uint8Array) };
}

const asMap = (value: unknown, what: string): CborMap => {
  if (!(value instanceof Map)) fail(`${what} is not a map`);
  return value as CborMap;
};

/**
 * Validates an mdoc presentation: a base64url DeviceResponse with one document (`vp_token` entry, OpenID4VP B.2.4).
 * Trust follows `default_trust_configuration_rp` as for SD-JWT VC: the document signer chains to an `/Issuance` anchor
 * of `issuerList` and carries the extended key usage of ISO/IEC 18013-5 Annex B; the status list or identifier list
 * chains to a `/Revocation` anchor of the same entity. Status procedures run only for an otherwise valid credential
 * unless `mode` is `all`.
 */
export async function validateMdocPresentation(presentation: string, options: MdocValidationOptions): Promise<MdocValidation> {
  const recorder = new CheckRecorder(options.mode ?? 'first-failure');
  const now = options.now ?? new Date();
  const skewMs = options.skewSeconds * 1000;
  let document: CborMap = new Map();
  let issuerSigned: CborMap = new Map();
  let issuerAuth: ReturnType<typeof readCose> | undefined;
  let mso: CborMap = new Map();
  let x5chain: Uint8Array[] = [];
  let entity: TrustedEntity | undefined;
  let claims: Record<string, Record<string, unknown>> | undefined;
  let statusListReference: { uri: string; idx: number } | undefined;
  let identifierListReference: { uri: string; id: Uint8Array } | undefined;
  let statusListFetched = false;
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
      issuerSigned = asMap(document.get('issuerSigned'), 'issuerSigned');
      asMap(issuerSigned.get('nameSpaces'), 'issuerSigned.nameSpaces');
      issuerAuth = attempt(() => readCose(issuerSigned.get('issuerAuth')), 'IssuerAuth');
      if (issuerAuth.tag !== undefined && issuerAuth.tag !== 18) fail(`IssuerAuth carries tag ${issuerAuth.tag}`);
      if (issuerAuth.protectedHeader.get(COSE.alg) !== COSE_ALG.ES256) fail(`IssuerAuth alg ${String(issuerAuth.protectedHeader.get(COSE.alg))} is not supported`);
      const chain = x5chainOf(issuerAuth.unprotectedHeader.get(COSE.x5chain) ?? issuerAuth.protectedHeader.get(COSE.x5chain));
      if (!chain) fail('IssuerAuth carries no x5chain');
      x5chain = chain as Uint8Array[];
      if (!issuerAuth.payload) fail('IssuerAuth has no payload');
      mso = asMap(attempt(() => decodeEmbedded(decodeCbor(issuerAuth?.payload as Uint8Array)), 'the IssuerAuth payload is not MobileSecurityObjectBytes'), 'the MSO');
      if (typeof mso.get('version') !== 'string' || !/^1\./.test(mso.get('version') as string)) fail(`MSO version ${String(mso.get('version'))}`);
      if (mso.get('digestAlgorithm') !== 'SHA-256') fail(`digestAlgorithm ${String(mso.get('digestAlgorithm'))} is not supported`);
      if (mso.get('docType') !== document.get('docType')) fail('the MSO docType differs from the document docType');
      asMap(mso.get('valueDigests'), 'valueDigests');
      asMap(asMap(mso.get('deviceKeyInfo'), 'deviceKeyInfo').get('deviceKey'), 'deviceKey');
      const validityInfo = asMap(mso.get('validityInfo'), 'validityInfo');
      for (const key of ['signed', 'validFrom', 'validUntil']) if (!dateOf(validityInfo.get(key))) fail(`validityInfo.${key} is not a tdate`);
      const deviceSigned = asMap(document.get('deviceSigned'), 'deviceSigned');
      asMap(deviceSigned.get('deviceAuth'), 'deviceAuth');
      attempt(() => decodeEmbedded(deviceSigned.get('nameSpaces')), 'deviceSigned.nameSpaces');
    });

    await recorder.run('issuer-trust', ['format'], async () => {
      const match = await options.trust.match(options.issuerList, '/Issuance', base64Of(x5chain), now);
      if (!match.ok) fail(match.reason);
      if (match.ok) {
        // ISO/IEC 18013-5 Annex B, Table B.3: a document signer certificate carries this extended key usage.
        if (!match.leaf.extendedKeyUsage?.includes(MDOC_DS_EXTENDED_KEY_USAGE)) fail('the signing certificate is not a document signer (no extended key usage 1.0.18013.5.1.2)');
        entity = match.entity;
        return `${match.entity.name} under ${match.anchor.subject.commonName}`;
      }
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

    await recorder.run('issuer-signature', ['format'], async () => {
      const jwk = parseCertificate(x5chain[0]).publicKey.jwk;
      if (!jwk || jwk.crv !== 'P-256') fail('the document signer certificate has no P-256 key');
      const auth = issuerAuth as ReturnType<typeof readCose>;
      if (!(await verifyEs256(jwk as JsonWebKey, sigStructure(auth.protectedBytes, auth.payload as Uint8Array), auth.signature))) {
        fail('the IssuerAuth signature does not verify');
      }
    });

    await recorder.run('disclosures', ['format'], () => {
      const digests = mso.get('valueDigests') as CborMap;
      const disclosed: Record<string, Record<string, unknown>> = {};
      let count = 0;
      for (const [namespace, items] of issuerSigned.get('nameSpaces') as CborMap) {
        if (typeof namespace !== 'string' || !Array.isArray(items)) fail('issuerSigned.nameSpaces is not a map of arrays');
        const namespaceDigests = digests.get(namespace);
        if (!(namespaceDigests instanceof Map)) fail(`the MSO has no value digests for namespace ${String(namespace)}`);
        disclosed[namespace as string] = {};
        for (const item of items as unknown[]) {
          const signedItem = asMap(attempt(() => decodeEmbedded(item), 'an IssuerSignedItem is not IssuerSignedItemBytes'), 'an IssuerSignedItem');
          const [digestId, identifier] = [signedItem.get('digestID'), signedItem.get('elementIdentifier')];
          if (typeof identifier !== 'string') fail('an IssuerSignedItem has no elementIdentifier');
          if (Object.hasOwn(disclosed[namespace as string], identifier as string)) fail(`${String(identifier)} is disclosed twice`);
          const expected = (namespaceDigests as CborMap).get(digestId);
          if (!(expected instanceof Uint8Array)) fail(`the MSO has no digest with ID ${String(digestId)} for ${String(identifier)}`);
          if (!Buffer.from(sha256(encodeCbor(item))).equals(Buffer.from(expected as Uint8Array))) fail(`the digest of ${String(identifier)} does not match the MSO`);
          disclosed[namespace as string][identifier as string] = jsonOf(signedItem.get('elementValue'));
          count++;
        }
      }
      claims = disclosed;
      return `${count} elements`;
    });

    await recorder.run('validity', ['format'], () => {
      const validityInfo = mso.get('validityInfo') as CborMap;
      const validFrom = dateOf(validityInfo.get('validFrom')) as Date;
      const validUntil = dateOf(validityInfo.get('validUntil')) as Date;
      if (now.getTime() > validUntil.getTime() + skewMs) fail(`expired: validUntil ${validUntil.toISOString()}, T_skew ${options.skewSeconds} s`);
      if (now.getTime() < validFrom.getTime() - skewMs) fail(`not yet valid: validFrom ${validFrom.toISOString()}, T_skew ${options.skewSeconds} s`);
      // expectedUpdate is informative (ISO/IEC 18013-5 section 9.1.2.4): Validity_012.
      const expectedUpdate = dateOf(validityInfo.get('expectedUpdate'));
      if (expectedUpdate && expectedUpdate < now) return `expectedUpdate ${expectedUpdate.toISOString()} has passed (informative)`;
    });

    await recorder.run('key-binding', ['format'], async () => {
      const deviceSigned = document.get('deviceSigned') as CborMap;
      const deviceAuth = deviceSigned.get('deviceAuth') as CborMap;
      if (!deviceAuth.has('deviceSignature')) fail('deviceAuth carries no deviceSignature (a deviceMac needs a reader key, which OpenID4VP has not)');
      const signature = attempt(() => readCose(deviceAuth.get('deviceSignature')), 'deviceSignature');
      if (signature.protectedHeader.get(COSE.alg) !== COSE_ALG.ES256) fail(`deviceSignature alg ${String(signature.protectedHeader.get(COSE.alg))} is not supported`);
      if (signature.payload !== null) fail('the deviceSignature payload is not detached');
      const deviceNameSpaces = deviceSigned.get('nameSpaces') as Tagged;
      const elements = decodeEmbedded<unknown>(deviceNameSpaces);
      if (!(elements instanceof Map) || elements.size > 0) fail('DeviceNameSpaces is not empty, and the MSO authorizes no device-signed element');
      const jwk = jwkOfCoseKey((mso.get('deviceKeyInfo') as CborMap).get('deviceKey'));
      const transcript = openid4vpSessionTranscript(options);
      const deviceAuthentication = encodeCbor(embedded(['DeviceAuthentication', transcript, document.get('docType'), deviceNameSpaces]));
      if (!(await verifyEs256(jwk, sigStructure(signature.protectedBytes, deviceAuthentication), signature.signature))) {
        fail('the deviceSignature does not verify over the SessionTranscript of this request');
      }
    });

    await recorder.run('status-reference', ['format'], () => {
      const status = mso.get('status');
      if (status === undefined) {
        const validityInfo = mso.get('validityInfo') as CborMap;
        const period = (dateOf(validityInfo.get('validUntil')) as Date).getTime() - (dateOf(validityInfo.get('validFrom')) as Date).getTime();
        if (!options.requireStatus) return 'no status (accepted by policy)';
        if (period <= DAY_MS) return `no status; validity period ${period / 1000} s is at most 24 hours`;
        fail(`no status, and the validity period (${period / 1000} s) exceeds 24 hours`);
      }
      const entries = asMap(status, 'status');
      const statusList = entries.get('status_list');
      const identifierList = entries.get('identifier_list');
      if (statusList === undefined && identifierList === undefined) fail('status has neither a status_list nor an identifier_list entry');
      if (statusList !== undefined) {
        const entry = asMap(statusList, 'status_list');
        const idx = entry.get('idx');
        if (typeof idx !== 'number' || !Number.isInteger(idx) || idx < 0) fail(`idx ${JSON.stringify(jsonOf(idx))} is not an unsigned integer`);
        if (!isUri(entry.get('uri'))) fail(`uri ${JSON.stringify(entry.get('uri'))} is not a URI`);
        statusListReference = { idx: idx as number, uri: entry.get('uri') as string };
      }
      if (identifierList !== undefined) {
        const entry = asMap(identifierList, 'identifier_list');
        if (!(entry.get('id') instanceof Uint8Array)) fail('the identifier_list id is not a byte string');
        if (!isUri(entry.get('uri'))) fail(`uri ${JSON.stringify(entry.get('uri'))} is not a URI`);
        identifierListReference = { id: entry.get('id') as Uint8Array, uri: entry.get('uri') as string };
      }
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
        entity,
        trust: options.trust,
        fetchStatusList: options.fetchStatusList,
        maxStatusListBytes: options.maxStatusListBytes,
        validStatuses: options.validStatuses,
        skewSeconds: options.skewSeconds,
        now,
        onFetched: () => {
          statusListFetched = true;
        },
      });
    }
    if (hasIdentifierList) {
      await evaluateIdentifierList(recorder, {
        reference: identifierListReference,
        entity,
        trust: options.trust,
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
    issuer: entity?.name,
    statusListFetched,
    identifierListFetched,
  };
}
