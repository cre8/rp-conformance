// The named faults of the baseline (harness design section 4.3). Each one is applied after a valid build, at one point
// of the artifact chain and to one format, and must fail exactly its `target` check of the reference validator and no other (section 7);
// `null` marks a variant that must pass every check. `text` is the FCAF wording of the difference, so a test case
// names a fault and describes it in one place. The implementations are in packages/forge/src/faults.
import type { CheckId } from './checks';
import type { Flow } from './definition';

export type FaultPoint = 'credential' | 'status-list' | 'identifier-list' | 'response';

/** The artifact format a fault applies to: a credential format, or the format of a status or identifier list. */
export type FaultFormat = 'dc+sd-jwt' | 'mso_mdoc' | 'jwt' | 'cwt';

export interface FaultInfo {
  point: FaultPoint;
  /** The format of the artifact at `point`; left out for response faults, which apply to every credential format. */
  format?: FaultFormat;
  target: CheckId | null;
  /** The difference from the valid artifact, as the FCAF scenario words it (after "except that" / "only in that"). */
  text: string;
  /** The presentation flow a response fault belongs to; left out when it applies to both. */
  flow?: Flow;
}

const credential = (target: CheckId | null, text: string): FaultInfo => ({ point: 'credential', format: 'dc+sd-jwt', target, text });
const mdoc = (target: CheckId | null, text: string): FaultInfo => ({ point: 'credential', format: 'mso_mdoc', target, text });
const statusList = (target: CheckId | null, text: string): FaultInfo => ({ point: 'status-list', format: 'jwt', target, text });
const statusListCwt = (target: CheckId | null, text: string): FaultInfo => ({ point: 'status-list', format: 'cwt', target, text });
const identifierList = (target: CheckId | null, text: string): FaultInfo => ({ point: 'identifier-list', format: 'cwt', target, text });
const response = (target: CheckId | null, text: string, flow?: Flow): FaultInfo => ({ point: 'response', target, text, ...(flow ? { flow } : {}) });

/** Wording shared by faults of both formats. */
const SHARED_TEXT = {
  ppB: 'it is signed by a certificate under the revocation anchor of `PP-B`',
  wpA: 'it is signed by a certificate under the revocation anchor of the Wallet Provider `WP-A` in `TL-WP`',
  acA: 'it is signed by a certificate under the anchor of `AC-A` in `TL-AC`',
  credentialCertificate: 'it is signed with the key and certificate that signed the presented credential',
  otherIssuanceCertificate: 'it is signed by another certificate issued under the issuance CA `CA-PP-A` of `PP-A`',
  selfSigned: 'it is signed by a self-signed certificate that is not part of `default_trust_configuration_rp`',
  expired: 'its signer certificate has expired',
  notYetValid: 'its signer certificate is not yet valid',
  es256k: 'it is signed with `ES256K` (curve secp256k1)',
  bits3: 'the `bits` value of its status list is 3',
  bomb: 'its `lst` value decompresses to more bytes than the maximum status list size the Relying Party declares, for example a ZLIB stream that inflates to 1 GiB of zero bytes',
  outOfRange: 'the index in its status reference equals the number of entries in the referenced status list, one past the last valid index',
};

export const FAULTS = {
  // Credential (SD-JWT VC), after a valid issuance: the issuer-signed JWT is decoded, changed and signed again.
  'credential.exp-past': credential(
    'validity',
    'its Issuer-signed JWT carries an `exp` claim set to the current time minus `T_skew` minus one hour',
  ),
  'credential.exp-within-skew': credential(null, 'its Issuer-signed JWT carries an `exp` claim set to the current time minus half of `T_skew`'),
  'credential.nbf-future': credential('validity', 'its Issuer-signed JWT carries an `nbf` claim set to the current time plus `T_skew` plus one hour'),
  'credential.signature-bitflip': credential('issuer-signature', 'one bit of the signature value of its Issuer-signed JWT is flipped'),
  'credential.status-no-idx': credential('status-reference', 'its `status.status_list` object has no `idx` member'),
  'credential.status-no-uri': credential('status-reference', 'its `status.status_list` object has no `uri` member'),
  'credential.status-idx-negative': credential('status-reference', 'the `idx` member of its `status.status_list` object is -1'),
  'credential.status-idx-string': credential(
    'status-reference',
    'the `idx` member of its `status.status_list` object is the string `7` instead of a number',
  ),
  'credential.status-uri-invalid': credential('status-reference', 'the `uri` member of its `status.status_list` object is the string `not a uri`'),
  'credential.status-idx-out-of-range': credential('status-index', SHARED_TEXT.outOfRange),
  'credential.no-status': credential('status-reference', 'it carries no `status` claim'),

  // Credential (mdoc), after a valid issuance: the MSO is decoded, changed and its IssuerAuth signed again.
  'mdoc.valid-until-past': mdoc(
    'validity',
    'the `validUntil` value in the `validityInfo` of its MSO is set to the current time minus `T_skew` minus one hour',
  ),
  'mdoc.valid-from-future': mdoc(
    'validity',
    'the `validFrom` value in the `validityInfo` of its MSO is set to the current time plus `T_skew` plus one hour',
  ),
  'mdoc.expected-update-past': mdoc(
    null,
    'the `expectedUpdate` value in the `validityInfo` of its MSO lies one day in the past, while `validUntil` lies in the future',
  ),
  'mdoc.signature-bitflip': mdoc('issuer-signature', 'one bit of the signature value of its `IssuerAuth` structure is flipped'),
  'mdoc.status-no-idx': mdoc('status-reference', 'the `status_list` map in the `status` element of its MSO has no `idx` entry'),
  'mdoc.status-no-uri': mdoc('status-reference', 'the `status_list` map in the `status` element of its MSO has no `uri` entry'),
  'mdoc.status-idx-negative': mdoc('status-reference', 'the `idx` entry of the `status_list` map in its MSO is -1'),
  'mdoc.status-idx-text': mdoc(
    'status-reference',
    'the `idx` entry of the `status_list` map in its MSO is the text string `7` instead of an unsigned integer',
  ),
  'mdoc.status-uri-invalid': mdoc('status-reference', 'the `uri` entry of the `status_list` map in its MSO is the text string `not a uri`'),
  'mdoc.status-idx-out-of-range': mdoc('status-index', SHARED_TEXT.outOfRange),
  'mdoc.no-status': mdoc('status-reference', 'its MSO carries no `status` element'),

  // Status List Token (JWT), after a valid build: decoded, changed and signed again, or served in another form.
  'status-list.signature-bitflip': statusList('status-list-signature', 'one bit of its signature value is flipped'),
  'status-list.alg-none': statusList('status-list-signature', 'it is an unsecured JWT with `alg` `none` and an empty signature'),
  'status-list.bare-list': statusList(
    'status-list-format',
    'the Test Status Provider serves the bare status list JSON object (`bits`, `lst`) instead of a Status List Token',
  ),
  'status-list.exp-past': statusList('status-list-validity', 'its `exp` claim is set to the current time minus `T_skew` minus one hour'),
  'status-list.sub-other': statusList('status-list-subject', 'its `sub` claim is the URI of a different status list'),
  'status-list.typ-jwt': statusList('status-list-type', 'its `typ` header is `JWT`'),
  'status-list.no-sub': statusList('status-list-claims', 'its payload has no `sub` claim'),
  'status-list.no-iat': statusList('status-list-claims', 'its payload has no `iat` claim'),
  'status-list.no-status-list': statusList('status-list-claims', 'its payload has no `status_list` claim'),
  'status-list.no-bits': statusList('status-list-claims', 'its `status_list` claim has no `bits` member'),
  'status-list.no-lst': statusList('status-list-claims', 'its `status_list` claim has no `lst` member'),
  'status-list.signer-ca-x': statusList('status-list-trust', 'it is signed by a certificate issued by `CA-X`, with that certificate chain in `x5c`'),
  'status-list.no-x5c': statusList('status-list-trust', 'it carries no `x5c` header, so its signer cannot be validated'),
  'status-list.signer-self-signed': statusList('status-list-trust', SHARED_TEXT.selfSigned),
  'status-list.signer-pp-b-revocation': statusList('status-list-trust', SHARED_TEXT.ppB),
  'status-list.signer-wp-a-revocation': statusList('status-list-trust', SHARED_TEXT.wpA),
  'status-list.signer-ac-a': statusList('status-list-trust', SHARED_TEXT.acA),
  'status-list.signer-credential-certificate': statusList('status-list-trust', SHARED_TEXT.credentialCertificate),
  'status-list.signer-other-issuance-certificate': statusList('status-list-trust', SHARED_TEXT.otherIssuanceCertificate),
  'status-list.embedded-root': statusList(
    'status-list-trust',
    'its signer certificate chains to a self-signed root that `x5c` includes and that is not part of `default_trust_configuration_rp`',
  ),
  'status-list.signer-expired': statusList('status-list-trust', SHARED_TEXT.expired),
  'status-list.signer-not-yet-valid': statusList('status-list-trust', SHARED_TEXT.notYetValid),
  'status-list.lst-not-base64url': statusList('status-list-decoding', 'the `lst` member of its `status_list` claim is not valid base64url'),
  'status-list.lst-not-zlib': statusList(
    'status-list-decoding',
    'the `lst` member of its `status_list` claim decodes to bytes that are not valid ZLIB data',
  ),
  'status-list.decompression-bomb': statusList('status-list-decoding', SHARED_TEXT.bomb),
  'status-list.bits-3': statusList('status-list-decoding', SHARED_TEXT.bits3),
  'status-list.es256k': statusList('status-list-signature', SHARED_TEXT.es256k),
  'status-list.hs256-public-key': statusList(
    'status-list-signature',
    'it is protected with `HS256`, keyed with the encoded public key of the certificate in its `x5c` header',
  ),

  // Status List Token (CWT), after a valid build: the COSE_Sign1 is decoded, changed and signed again.
  'status-list-cwt.signature-bitflip': statusListCwt('status-list-signature', 'one bit of its signature value is flipped'),
  'status-list-cwt.bare-list': statusListCwt(
    'status-list-format',
    'the Test Status Provider serves the bare status list CBOR map (`bits`, `lst`) instead of a Status List Token',
  ),
  'status-list-cwt.exp-past': statusListCwt('status-list-validity', 'its expiration time (4) is set to the current time minus `T_skew` minus one hour'),
  'status-list-cwt.sub-other': statusListCwt('status-list-subject', 'its subject (2) is the URI of a different status list'),
  'status-list-cwt.typ-cwt': statusListCwt('status-list-type', 'its type header (16) is `application/cwt`'),
  'status-list-cwt.no-sub': statusListCwt('status-list-claims', 'its claims set has no subject (2)'),
  'status-list-cwt.no-iat': statusListCwt('status-list-claims', 'its claims set has no issued at claim (6)'),
  'status-list-cwt.no-status-list': statusListCwt('status-list-claims', 'its claims set has no status list claim (65533)'),
  'status-list-cwt.no-bits': statusListCwt('status-list-claims', 'its status list claim has no `bits` entry'),
  'status-list-cwt.no-lst': statusListCwt('status-list-claims', 'its status list claim has no `lst` entry'),
  'status-list-cwt.signer-ca-x': statusListCwt(
    'status-list-trust',
    'it is signed by a certificate issued by `CA-X`, with that certificate chain in `x5chain`',
  ),
  'status-list-cwt.no-x5chain': statusListCwt('status-list-trust', 'it carries no `x5chain` header, so its signer cannot be validated'),
  'status-list-cwt.signer-self-signed': statusListCwt('status-list-trust', SHARED_TEXT.selfSigned),
  'status-list-cwt.signer-pp-b-revocation': statusListCwt('status-list-trust', SHARED_TEXT.ppB),
  'status-list-cwt.signer-wp-a-revocation': statusListCwt('status-list-trust', SHARED_TEXT.wpA),
  'status-list-cwt.signer-ac-a': statusListCwt('status-list-trust', SHARED_TEXT.acA),
  'status-list-cwt.signer-credential-certificate': statusListCwt('status-list-trust', SHARED_TEXT.credentialCertificate),
  'status-list-cwt.signer-other-issuance-certificate': statusListCwt('status-list-trust', SHARED_TEXT.otherIssuanceCertificate),
  'status-list-cwt.embedded-root': statusListCwt(
    'status-list-trust',
    'its signer certificate chains to a self-signed root that `x5chain` includes and that is not part of `default_trust_configuration_rp`',
  ),
  'status-list-cwt.signer-expired': statusListCwt('status-list-trust', SHARED_TEXT.expired),
  'status-list-cwt.signer-not-yet-valid': statusListCwt('status-list-trust', SHARED_TEXT.notYetValid),
  'status-list-cwt.lst-not-zlib': statusListCwt('status-list-decoding', 'the `lst` entry of its status list claim is not valid ZLIB data'),
  'status-list-cwt.decompression-bomb': statusListCwt('status-list-decoding', SHARED_TEXT.bomb),
  'status-list-cwt.bits-3': statusListCwt('status-list-decoding', SHARED_TEXT.bits3),
  'status-list-cwt.es256k': statusListCwt('status-list-signature', SHARED_TEXT.es256k),
  'status-list-cwt.mac0-public-key': statusListCwt(
    'status-list-signature',
    'it is protected with a `COSE_Mac0` structure using HMAC 256/256, keyed with the encoded public key of the certificate in its `x5chain` header',
  ),

  // Identifier list (CWT, ISO/IEC 18013-5 second edition), after a valid build.
  'identifier-list.signature-bitflip': identifierList(
    'identifier-list-signature',
    'one bit of the signature value of the referenced identifier list is flipped',
  ),
  'identifier-list.exp-past': identifierList(
    'identifier-list-validity',
    'the expiration time (4) of the referenced identifier list lies `T_skew` plus one hour in the past',
  ),
  'identifier-list.signer-ca-x': identifierList('identifier-list-trust', 'the referenced identifier list is signed by a certificate issued by `CA-X`'),

  // Authorization Response (direct_post.jwt via redirects, dc_api.jwt via the W3C Digital Credentials API): built from
  // the valid payload and the Relying Party's encryption key. Only the unencrypted response differs between the flows.
  'response.unencrypted': response(
    'response-encrypted',
    'it is not encrypted: the Conformance Wallet posts `vp_token` and `state` as form parameters to the `response_uri`, as in response mode `direct_post`',
    'redirect',
  ),
  'response.dc-api-unencrypted': response(
    'response-encrypted',
    'it is not encrypted: the `data` object returned through the Digital Credentials API carries the `vp_token` directly instead of an encrypted `response`',
    'dc-api',
  ),
  'response.foreign-key': response(
    'response-decryption',
    "it is encrypted to a newly generated P-256 key that the Relying Party did not issue, while the JWE header carries the `kid` of the Relying Party's encryption key",
  ),
  'response.other-transaction-key': response(
    'response-decryption',
    'the Conformance Wallet encrypts an otherwise valid Authorization Response for T2 to the encryption key recorded for T1, with the `kid` of that key',
  ),
  'response.alg-ecdh-es-a128kw': response('response-alg', "its JWE uses `alg` `ECDH-ES+A128KW` with the Relying Party's encryption key"),
  'response.alg-ecdh-es-a256kw': response('response-alg', "its JWE uses `alg` `ECDH-ES+A256KW` with the Relying Party's encryption key"),
  'response.enc-a128cbc-hs256': response('response-enc', 'its JWE uses `enc` `A128CBC-HS256`'),
  'response.ciphertext-bitflip': response('response-decryption', 'one bit of its JWE ciphertext is flipped'),
  'response.tag-bitflip': response('response-decryption', 'one bit of its JWE authentication tag is flipped'),
  'response.epk-off-curve': response('response-epk', 'the `epk` header of its JWE holds coordinates that are not a point on P-256'),
  'response.epk-p384': response('response-epk', 'the `epk` header of its JWE holds a key on curve P-384'),
  'response.jws': response('response-format', 'the `response` parameter is a JWS signed with a key of the Conformance Wallet instead of a JWE'),
  'response.alg-none': response('response-format', 'the `response` parameter is an unsecured JWT with `alg` `none` instead of a JWE'),
  'response.extra-member': response(null, 'its decrypted payload additionally contains the member `foo` with the value `bar`'),
} as const satisfies Record<string, FaultInfo>;

export type FaultId = keyof typeof FAULTS;

export const FAULT_IDS = Object.keys(FAULTS) as FaultId[];

export function faultInfo(id: FaultId): FaultInfo {
  const info = FAULTS[id];
  if (!info) throw new Error(`unknown fault ${id}`);
  return info;
}
