// The PID in mdoc format (ISO/IEC 18013-5, PID Rulebook): issued with @owf/mdoc, presented by the Conformance Wallet
// as a DeviceResponse with a device signature over the SessionTranscript of OpenID4VP Appendix B.2.6.1.
import { randomBytes } from 'node:crypto';
import { DateOnly, Issuer, SessionTranscript, SignatureAlgorithm } from '@owf/mdoc';
import { type CborMap, COSE, COSE_ALG, decodeCbor, decodeEmbedded, embedded, encodeCbor, readCose, signCoseSign1, type Tagged } from './cbor';
import { base64url } from './crypto';
import { coseSigningKey, deviceKeyOf, mdocContext } from './mdoc-context';
import type { CertifiedKey } from './pki';

/** DocType and namespace of the PID in mdoc format (PID Rulebook, ISO/IEC 18013-5 encoding). */
export const PID_DOCTYPE = 'eu.europa.ec.eudi.pid.1';
export const PID_NAMESPACE = 'eu.europa.ec.eudi.pid.1';

const DAY = 24 * 60 * 60 * 1000;

/** The attribute values of `default_credential_pid` in mdoc format, with `full-date` values as `YYYY-MM-DD`. */
export const DEFAULT_PID_MDOC_CLAIMS = {
  family_name: 'Mustermann',
  given_name: 'Erika',
  birth_date: '1964-08-12',
  place_of_birth: { locality: 'Berlin', country: 'DE' },
  nationality: ['DE'],
  issuing_authority: 'DE',
  issuing_country: 'DE',
  expiry_date: '2031-08-31',
} as const;

const FULL_DATES = new Set(['birth_date', 'expiry_date']);

export interface IssuedMdoc {
  /** The `IssuerSigned` structure (CBOR) the Test Issuer hands to the Conformance Wallet. */
  issuerSigned: Uint8Array;
  /** The issued attributes by namespace, as JSON values (`full-date` as `YYYY-MM-DD`), for comparing released attributes. */
  claims: Record<string, Record<string, unknown>>;
  /** The MSO identifier in the identifier list reference, when there is one. */
  identifier?: Uint8Array;
}

export interface MdocIssueOptions {
  /** The document signer certificate under the issuance anchor of the issuing entity, with its chain (no anchor). */
  signer: CertifiedKey;
  /** Public key of the Conformance Wallet the mdoc is bound to (`deviceKeyInfo`). */
  holderPublicJwk: JsonWebKey;
  /** The MSO's `status`: a status list entry, or an identifier list entry; none for `default_credential_pid_short`. */
  status?: { statusList?: { uri: string; idx: number }; identifierList?: { uri: string; id: Uint8Array } };
  now?: Date;
  /** `true` for `default_credential_pid_short`: valid for 12 hours. */
  short?: boolean;
}

/**
 * The validity of an issued mdoc: `default_credential_pid` was signed two days ago and is valid for 30 days, so an
 * `expectedUpdate` one day in the past still lies after `signed` (Validity_012); `default_credential_pid_short` was
 * signed an hour ago and is valid for 12 hours.
 */
export function mdocValidity(now: Date, short = false) {
  const signed = new Date(Math.floor((now.getTime() - (short ? 60 * 60 * 1000 : 2 * DAY)) / 1000) * 1000);
  return { signed, validFrom: signed, validUntil: new Date(signed.getTime() + (short ? 12 * 60 * 60 * 1000 : 30 * DAY)) };
}

/**
 * Issues `default_credential_pid` in mdoc format with @owf/mdoc: every attribute an `IssuerSignedItem` of namespace
 * `eu.europa.ec.eudi.pid.1`, the MSO (SHA-256 digests, `validityInfo`, `deviceKeyInfo`, `status`) signed with ES256 in
 * a COSE_Sign1 `IssuerAuth` that carries the document signer certificate in `x5chain`.
 */
export async function issuePidMdoc(options: MdocIssueOptions): Promise<IssuedMdoc> {
  const now = options.now ?? new Date();
  const values = Object.fromEntries(
    Object.entries(DEFAULT_PID_MDOC_CLAIMS).map(([name, value]) => [name, FULL_DATES.has(name) ? new DateOnly(value as string) : value]),
  );
  const issuer = new Issuer(PID_DOCTYPE, mdocContext).addIssuerNamespace(PID_NAMESPACE, values);
  const status = options.status && {
    ...(options.status.statusList ? { statusList: options.status.statusList } : {}),
    ...(options.status.identifierList ? { identifierList: options.status.identifierList } : {}),
  };
  const issuerSigned = await issuer.sign({
    signingKey: coseSigningKey(options.signer.key.privateJwk),
    algorithm: SignatureAlgorithm.ES256,
    digestAlgorithm: 'SHA-256',
    validityInfo: mdocValidity(now, options.short),
    deviceKeyInfo: { deviceKey: deviceKeyOf(options.holderPublicJwk) },
    certificates: options.signer.chain.map((certificate) => certificate.der),
    ...(status ? { status } : {}),
  });
  return {
    issuerSigned: issuerSigned.encode(),
    claims: { [PID_NAMESPACE]: structuredClone(DEFAULT_PID_MDOC_CLAIMS) as Record<string, unknown> },
    identifier: options.status?.identifierList?.id,
  };
}

/** A new random MSO identifier for an identifier list reference (ISO/IEC 18013-5 second edition section 12.3.6.4). */
export const newMdocIdentifier = () => new Uint8Array(randomBytes(16));

/** The JWK SHA-256 thumbprint (RFC 7638) of an EC public key. */
export async function jwkThumbprint(jwk: JsonWebKey): Promise<Uint8Array> {
  const canonical = JSON.stringify({ crv: jwk.crv, kty: jwk.kty, x: jwk.x, y: jwk.y });
  return new Uint8Array(await globalThis.crypto.subtle.digest('SHA-256', new TextEncoder().encode(canonical)));
}

export interface MdocPresentOptions {
  /** The device key the MSO binds (`deviceKeyInfo`). */
  holderPrivateKey: CryptoKey;
  /** `client_id` of the request, with its prefix. */
  clientId: string;
  nonce: string;
  /** `response_uri` of the request. */
  responseUri: string;
  /** Thumbprint of the Verifier's encryption key, for an encrypted response (`direct_post.jwt`); otherwise null. */
  jwkThumbprint: Uint8Array | null;
  /** The elements to disclose, by namespace. */
  elements: Record<string, string[]>;
}

/** The SessionTranscript of OpenID4VP 1.0 Appendix B.2.6.1, computed with @owf/mdoc, as a CBOR value. */
export async function oid4vpSessionTranscript(options: Pick<MdocPresentOptions, 'clientId' | 'nonce' | 'responseUri' | 'jwkThumbprint'>) {
  const transcript = await SessionTranscript.forOid4Vp(
    { clientId: options.clientId, nonce: options.nonce, responseUri: options.responseUri, jwkThumbprint: options.jwkThumbprint ?? undefined },
    mdocContext,
  );
  return decodeCbor<unknown[]>(transcript.encode());
}

/**
 * Presents an mdoc (OpenID4VP Appendix B.2): a DeviceResponse with one document that discloses the requested
 * `IssuerSignedItem`s as issued, and a device signature (ES256) over `DeviceAuthenticationBytes` with an empty
 * `DeviceNameSpaces`. The `IssuerSigned` structure is passed through as raw CBOR, so a credential the fault layer
 * changed is presented exactly as it was changed. Returns the DeviceResponse as CBOR.
 */
export async function presentMdoc(issuerSignedBytes: Uint8Array, options: MdocPresentOptions): Promise<Uint8Array> {
  const issuerSigned = decodeCbor<CborMap>(issuerSignedBytes);
  const issuerAuth = readCose(issuerSigned.get('issuerAuth'));
  const mso = decodeEmbedded<CborMap>(decodeCbor(issuerAuth.payload ?? new Uint8Array()));
  const docType = String(mso.get('docType'));
  const namespaces = new Map<string, Tagged[]>();
  for (const [namespace, items] of (issuerSigned.get('nameSpaces') as Map<string, Tagged[]>) ?? new Map()) {
    const requested = options.elements[namespace] ?? [];
    const disclosed = items.filter((item) => requested.includes(String(decodeEmbedded<CborMap>(item).get('elementIdentifier'))));
    if (disclosed.length) namespaces.set(namespace, disclosed);
  }
  const deviceNameSpaces = embedded(new Map());
  const deviceAuthentication = encodeCbor(embedded(['DeviceAuthentication', await oid4vpSessionTranscript(options), docType, deviceNameSpaces]));
  const deviceSignature = await signCoseSign1({
    protectedHeader: new Map([[COSE.alg, COSE_ALG.ES256]]),
    payload: null,
    detached: deviceAuthentication,
    privateKey: options.holderPrivateKey,
  });
  const document = new Map<string, unknown>([
    ['docType', docType],
    ['issuerSigned', new Map<string, unknown>([['nameSpaces', namespaces], ['issuerAuth', issuerSigned.get('issuerAuth')]])],
    ['deviceSigned', new Map<string, unknown>([['nameSpaces', deviceNameSpaces], ['deviceAuth', new Map([['deviceSignature', deviceSignature]])]])],
  ]);
  return encodeCbor(new Map<string, unknown>([['version', '1.0'], ['documents', [document]], ['status', 0]]));
}

/** A DeviceResponse as the `vp_token` entry of OpenID4VP Appendix B.2.4: base64url without padding. */
export const encodeDeviceResponse = (deviceResponse: Uint8Array) => base64url.encode(deviceResponse);

/** The elements a DCQL credential query requests from an mdoc, by namespace (claim paths `[namespace, element]`). */
export function requestedElements(claims: { path: (string | number | null)[] }[] = []): Record<string, string[]> {
  const elements: Record<string, string[]> = {};
  for (const { path } of claims) {
    const [namespace, element] = path.map(String);
    if (namespace && element) (elements[namespace] ??= []).push(element);
  }
  return elements;
}
