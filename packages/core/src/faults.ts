// The named faults of the baseline (harness design section 4.3). Each one is applied after a valid build, at one point
// of the artifact chain and to one format, and must fail exactly its `target` check of the reference validator and no other (section 7);
// `null` marks a variant that must pass every check. `text` is the FCAF wording of the difference, so a test case
// names a fault and describes it in one place. The implementations are in packages/forge/src/faults.
import type { CheckId } from './checks';
import type { Flow } from './definition';

/**
 * Where a fault is applied: the issued credential, the status list or identifier list the Test Status Provider serves,
 * the presentation the Conformance Wallet builds for the request (KB-JWT, DeviceAuth), or the Authorization Response.
 */
export type FaultPoint = 'credential' | 'status-list' | 'identifier-list' | 'presentation' | 'response' | 'trust-list' | 'request';

/** The artifact format a fault applies to: a credential format, or the format of a status or identifier list. */
export type FaultFormat = 'dc+sd-jwt' | 'mso_mdoc' | 'jwt' | 'cwt' | 'lote' | 'trusted-list';

export interface FaultInfo {
  point: FaultPoint;
  /** The format of the artifact at `point`; left out for response faults, which apply to every credential format. */
  format?: FaultFormat;
  target: CheckId | null;
  /** The difference from the valid artifact, as the FCAF scenario words it (after "except that" / "only in that"). */
  text: string;
  /** The presentation flow a response or presentation fault belongs to; left out when it applies to both. */
  flow?: Flow;
  /**
   * The curve of the Conformance Wallet key the credential is bound to, when it is not P-256: the device authentication
   * faults with `ES256K` need a credential bound to a key on secp256k1.
   */
  holderCurve?: 'secp256k1';
  /**
   * The entity of `default_trust_configuration_rp` that must issue the credential, when it is not `PP-A`: the faults of
   * the certificate path with an intermediate CA need `PP-I`, whose signers are under one.
   */
  issuer?: string;
}

const credential = (target: CheckId | null, text: string): FaultInfo => ({ point: 'credential', format: 'dc+sd-jwt', target, text });
const mdoc = (target: CheckId | null, text: string): FaultInfo => ({ point: 'credential', format: 'mso_mdoc', target, text });
const statusList = (target: CheckId | null, text: string): FaultInfo => ({ point: 'status-list', format: 'jwt', target, text });
const statusListCwt = (target: CheckId | null, text: string): FaultInfo => ({ point: 'status-list', format: 'cwt', target, text });
const identifierList = (target: CheckId | null, text: string): FaultInfo => ({ point: 'identifier-list', format: 'cwt', target, text });
const response = (target: CheckId | null, text: string, flow?: Flow): FaultInfo => ({ point: 'response', target, text, ...(flow ? { flow } : {}) });
const lote = (target: CheckId | null, text: string): FaultInfo => ({ point: 'trust-list', format: 'lote', target, text });
const trustedList = (target: CheckId | null, text: string): FaultInfo => ({ point: 'trust-list', format: 'trusted-list', target, text });
const request = (target: CheckId, text: string, flow?: Flow): FaultInfo => ({ point: 'request', target, text, ...(flow ? { flow } : {}) });
const kbJwt = (target: CheckId, text: string, flow?: Flow): FaultInfo => ({ point: 'presentation', format: 'dc+sd-jwt', target, text, ...(flow ? { flow } : {}) });
const deviceAuth = (target: CheckId, text: string, flow?: Flow): FaultInfo => ({ point: 'presentation', format: 'mso_mdoc', target, text, ...(flow ? { flow } : {}) });

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
  signerExpired: 'its signing certificate, issued under the same anchor, has expired one hour ago',
  signerNotYetValid: 'its signing certificate, issued under the same anchor, becomes valid only one day from now',
  intermediateExpired: 'its signing certificate is issued by an intermediate CA of `PP-I` under the anchor `CA-PP-I` whose certificate has expired',
  intermediateMissing: 'the certificate chain it carries holds only the signing certificate, without the intermediate CA `CA-PP-I-INT` that issued it',
  issuerNotCa: 'its signing certificate is issued, under the anchor `CA-PP-I`, by a certificate whose `basicConstraints` have `cA` false',
  keyP192: 'its signing certificate, issued under the same anchor, holds a key on curve P-192 (secp192r1), with which it is signed',
  keyRsa1024: 'its signing certificate, issued under the same anchor, holds a 1024-bit RSA key, with which it is signed (RSASSA-PKCS1-v1_5 with SHA-256)',
  criticalExtension: 'its signing certificate additionally carries a private extension (OID 1.3.6.1.4.1.55555.1.1) marked critical',
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
  'credential.signature-der': credential(
    'issuer-signature',
    'the signature value of its Issuer-signed JWT is the valid `ES256` signature in its DER encoding (an ASN.1 `SEQUENCE` of the two integers) instead of the 64 octets `R || S`',
  ),
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
  'credential.no-cnf': credential('key-binding', 'its Issuer-signed JWT carries no `cnf` claim, so it is bound to no key'),
  'credential.minimal-cnf-jwk': credential(null, 'the `jwk` member of its `cnf` claim carries only the members `kty`, `crv`, `x` and `y`'),

  // Credential (SD-JWT VC), IssuerIntegrity: the issuer-signed JWT, its disclosures or its signing certificate.
  'credential.alg-none': credential('issuer-signature', 'its Issuer-signed JWT is an unsecured JWT with `alg` `none` and an empty signature'),
  'credential.alg-hs256': credential(
    'issuer-signature',
    'its Issuer-signed JWT is protected with `HS256`, keyed with the PEM encoding of the public key of the signing certificate in its `x5c` header',
  ),
  'credential.es256k': credential(
    'issuer-signature',
    'its Issuer-signed JWT is signed with `ES256K` by a key on curve secp256k1, whose certificate is issued under the same anchor and carried in `x5c`',
  ),
  'credential.no-x5c': credential('format', 'the header of its Issuer-signed JWT carries no `x5c` member'),
  'credential.embedded-root': credential(
    'issuer-trust',
    'it is signed by a certificate issued by `CA-X`, and its `x5c` header carries that certificate followed by the self-signed certificate of `CA-X`',
  ),
  'credential.self-signed': credential('issuer-trust', 'it is signed by a self-signed certificate, which is the only certificate in its `x5c` header'),
  'credential.typ-missing': credential('format', 'the header of its Issuer-signed JWT has no `typ` member'),
  'credential.typ-jwt': credential('format', 'the `typ` header of its Issuer-signed JWT is `JWT`'),
  'credential.typ-vc-sd-jwt': credential('format', 'the `typ` header of its Issuer-signed JWT is the former media type `vc+sd-jwt`'),
  'credential.disclosure-foreign': credential(
    'disclosures',
    'it carries an additional disclosure for the claim `family_name` with the value `Musterfrau`, whose digest does not occur in the Issuer-signed JWT',
  ),
  'credential.disclosure-modified': credential(
    'disclosures',
    'the value in its disclosure of `family_name` is changed to `Musterfrau`, with the salt and the claim name kept',
  ),
  'credential.disclosure-duplicate': credential('disclosures', 'its disclosure of `family_name` is presented twice'),
  'credential.digest-duplicate': credential('disclosures', 'the digest of its disclosure of `family_name` occurs twice in the `_sd` array of the Issuer-signed JWT'),
  'credential.disclosure-name-sd': credential(
    'disclosures',
    'it carries an additional disclosure, referenced from the `_sd` array of the Issuer-signed JWT, whose claim name is `_sd`',
  ),
  'credential.disclosure-name-ellipsis': credential(
    'disclosures',
    'it carries an additional disclosure, referenced from the `_sd` array of the Issuer-signed JWT, whose claim name is `...`',
  ),
  'credential.disclosure-name-present': credential(
    'disclosures',
    'its Issuer-signed JWT also carries `family_name` as a plain claim, at the same level as the disclosure of `family_name`',
  ),
  'credential.disclosure-two-elements': credential(
    'disclosures',
    'its disclosure of `family_name`, referenced from the `_sd` array of an object, has two elements (salt and value) instead of three',
  ),
  'credential.disclosure-four-elements': credential(
    'disclosures',
    'its disclosure of `family_name`, referenced from the `_sd` array of an object, has four elements (salt, claim name, value and a further string) instead of three',
  ),
  'credential.disclosure-array-three-elements': credential(
    'disclosures',
    'its claim `nationalities` is a plain array whose element is a selectively disclosable array element, and the disclosure of that element has three elements (salt, name and value) instead of two',
  ),
  'credential.sd-alg-md5': credential('disclosures', 'its `_sd_alg` claim is `md5`, and every digest is computed with MD5'),
  'credential.sd-alg-sha1': credential('disclosures', 'its `_sd_alg` claim is `sha-1`, and every digest is computed with SHA-1'),
  'credential.vct-other': credential('format', 'its `vct` claim is `urn:eudi:other:1` instead of the type the request asks for'),
  'credential.decoys': credential(null, 'the `_sd` array of its Issuer-signed JWT additionally contains three decoy digests'),
  'credential.recursive-disclosures': credential(
    null,
    'its claim `place_of_birth` is disclosed recursively: the disclosure of `place_of_birth` holds an object whose members `locality` and `country` are themselves selectively disclosable',
  ),
  'credential.signer-expired': credential('issuer-trust', SHARED_TEXT.signerExpired),
  'credential.signer-not-yet-valid': credential('issuer-trust', SHARED_TEXT.signerNotYetValid),
  'credential.intermediate-expired': { ...credential('issuer-trust', SHARED_TEXT.intermediateExpired), issuer: 'PP-I' },
  'credential.intermediate-missing': { ...credential('issuer-trust', SHARED_TEXT.intermediateMissing), issuer: 'PP-I' },
  'credential.issuer-not-ca': { ...credential('issuer-trust', SHARED_TEXT.issuerNotCa), issuer: 'PP-I' },
  'credential.key-p192': credential('issuer-signature', SHARED_TEXT.keyP192),
  'credential.key-rsa1024': credential('issuer-signature', SHARED_TEXT.keyRsa1024),
  'credential.critical-extension': credential('issuer-trust', SHARED_TEXT.criticalExtension),

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
  'mdoc.signature-der': mdoc(
    'issuer-signature',
    'the signature value of its `IssuerAuth` structure is the valid `ES256` signature in its DER encoding (an ASN.1 `SEQUENCE` of the two integers) instead of the 64 octets `r || s`',
  ),
  'mdoc.issuer-auth-duplicate-label': mdoc(
    'format',
    'the protected header of its `IssuerAuth` structure carries the label `alg` (1) twice, both times with the value -7 (ES256), and the signature is made over those bytes',
  ),
  'mdoc.mso-not-tag24': mdoc(
    'format',
    'the payload of its `IssuerAuth` structure is the MSO itself instead of `MobileSecurityObjectBytes` (the MSO as an embedded CBOR data item, tag 24), and the signature is made over that payload',
  ),
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
  'mdoc.no-device-key': mdoc('key-binding', 'its MSO carries no `deviceKeyInfo`, so it is bound to no device key'),

  // Credential (mdoc), IssuerIntegrity: the IssuerSigned structure, the MSO or the document signer certificate.
  'mdoc.element-value-changed': mdoc(
    'disclosures',
    'the `elementValue` of its `IssuerSignedItem` for `family_name` is changed to `Musterfrau`, so its digest no longer matches the MSO',
  ),
  'mdoc.digest-id-unknown': mdoc(
    'disclosures',
    'the `digestID` of its `IssuerSignedItem` for `family_name` is changed to a value for which the MSO holds no digest',
  ),
  'mdoc.mso-doctype-other': mdoc(
    'format',
    'the `docType` in its MSO is `org.iso.18013.5.1.mDL`, while the document in the DeviceResponse keeps the `docType` `eu.europa.ec.eudi.pid.1`',
  ),
  'mdoc.digest-sha1': mdoc('disclosures', 'the `digestAlgorithm` of its MSO is `SHA-1`, and every value digest is computed with SHA-1'),
  'mdoc.digest-reencoded-item': mdoc(
    'disclosures',
    'its `IssuerSignedItem` for `family_name` is encoded again with the same content, the `digestID` written in more bytes than its shortest form, so that its bytes are not those the MSO digests',
  ),
  'mdoc.digest-truncated': mdoc(
    'disclosures',
    'the value digest of its `IssuerSignedItem` for `family_name` in the MSO is cut to its first 20 bytes',
  ),
  'mdoc.doctype-other': mdoc(
    'format',
    'it is of the `docType` `org.iso.18013.5.1.mDL`, in its MSO and in the document, instead of the `docType` the request asks for',
  ),
  'mdoc.embedded-root': mdoc(
    'issuer-trust',
    'it is signed by a document signer certificate issued by `CA-X`, and the `x5chain` of its `IssuerAuth` carries that certificate followed by the self-signed certificate of `CA-X`',
  ),
  'mdoc.ds-no-eku': mdoc(
    'issuer-trust',
    'its document signer certificate, issued under the same anchor, has no extended key usage `1.0.18013.5.1.2`',
  ),
  'mdoc.signed-after-ds-expiry': mdoc(
    'issuer-trust',
    'the `signed` value in the `validityInfo` of its MSO lies one hour after the end of the validity period of its document signer certificate, which is still valid',
  ),
  'mdoc.signer-expired': mdoc('issuer-trust', SHARED_TEXT.signerExpired),
  'mdoc.signer-not-yet-valid': mdoc('issuer-trust', SHARED_TEXT.signerNotYetValid),
  'mdoc.intermediate-expired': { ...mdoc('issuer-trust', SHARED_TEXT.intermediateExpired), issuer: 'PP-I' },
  'mdoc.intermediate-missing': { ...mdoc('issuer-trust', SHARED_TEXT.intermediateMissing), issuer: 'PP-I' },
  'mdoc.issuer-not-ca': { ...mdoc('issuer-trust', SHARED_TEXT.issuerNotCa), issuer: 'PP-I' },
  'mdoc.key-p192': mdoc('issuer-signature', SHARED_TEXT.keyP192),
  'mdoc.key-rsa1024': mdoc('issuer-signature', SHARED_TEXT.keyRsa1024),
  'mdoc.critical-extension': mdoc('issuer-trust', SHARED_TEXT.criticalExtension),

  // Status List Token (JWT), after a valid build: decoded, changed and signed again, or served in another form.
  'status-list.signature-bitflip': statusList('status-list-signature', 'one bit of its signature value is flipped'),
  'status-list.alg-none': statusList('status-list-signature', 'it is an unsecured JWT with `alg` `none` and an empty signature'),
  'status-list.bare-list': statusList(
    'status-list-format',
    'the Test Status Provider serves the bare status list JSON object (`bits`, `lst`) instead of a Status List Token',
  ),
  'status-list.html-error-page': statusList(
    'status-list-fetch',
    'the Test Status Provider answers with HTTP status 503 and an HTML error page (`text/html`) instead of a Status List Token',
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

  // Presentation (SD-JWT VC): the KB-JWT the Conformance Wallet appends for the request, decoded, changed and signed
  // again with the holder key, or replaced.
  'presentation.kb-nonce-other': kbJwt('key-binding', 'the `nonce` claim of its KB-JWT is a newly generated random value instead of the `nonce` of the request'),
  'presentation.kb-aud-other-client': kbJwt(
    'key-binding',
    'the `aud` claim of its KB-JWT is the Client Identifier of another Relying Party: the prefix `x509_hash:` followed by the hash of a different certificate',
    'redirect',
  ),
  'presentation.kb-aud-no-prefix': kbJwt(
    'key-binding',
    'the `aud` claim of its KB-JWT is the Client Identifier of the request without its prefix `x509_hash:`',
    'redirect',
  ),
  'presentation.kb-aud-missing': kbJwt('key-binding', 'its KB-JWT has no `aud` claim'),
  'presentation.kb-aud-array': kbJwt(
    'key-binding',
    'the `aud` claim of its KB-JWT is an array that holds the Client Identifier of the request as its only element, instead of the string',
    'redirect',
  ),
  'presentation.kb-nonce-missing': kbJwt('key-binding', 'its KB-JWT has no `nonce` claim'),
  'presentation.kb-iat-nan': kbJwt(
    'format',
    'the payload of its KB-JWT is not valid JSON: the value of its `iat` claim is `NaN`, and the KB-JWT is signed with the holder key over that payload',
  ),
  'presentation.kb-aud-client-id': kbJwt(
    'key-binding',
    'the `aud` claim of its KB-JWT is the Client Identifier of the request instead of `origin:` followed by the Origin of the page',
    'dc-api',
  ),
  'presentation.kb-aud-other-origin': kbJwt(
    'key-binding',
    'the `aud` claim of its KB-JWT is `origin:https://other.example` instead of `origin:` followed by the Origin of the page',
    'dc-api',
  ),
  'presentation.kb-iat-past': kbJwt('kb-freshness', 'the `iat` claim of its KB-JWT is set to the current time minus `T_kb` minus one hour'),
  'presentation.kb-iat-future': kbJwt('kb-freshness', 'the `iat` claim of its KB-JWT is set to the current time plus `T_skew` plus one hour'),
  'presentation.kb-signature-bitflip': kbJwt('key-binding', 'one bit of the signature value of its KB-JWT is flipped'),
  'presentation.kb-other-key': kbJwt(
    'key-binding',
    'its KB-JWT is signed with a newly generated P-256 key instead of the key in the `cnf` claim of the credential',
  ),
  'presentation.no-kb-jwt': kbJwt('key-binding', 'it carries no KB-JWT: the presented SD-JWT ends with `~` after its last disclosure'),
  'presentation.kb-typ-missing': kbJwt('key-binding', 'the header of its KB-JWT has no `typ` member'),
  'presentation.kb-typ-jwt': kbJwt('key-binding', 'the `typ` header of its KB-JWT is `JWT`'),
  'presentation.kb-sd-hash-other': kbJwt(
    'key-binding',
    'the `sd_hash` claim of its KB-JWT is computed over the presented SD-JWT without its last disclosure',
  ),
  'presentation.kb-alg-none': kbJwt('key-binding', 'its KB-JWT is an unsecured JWT with `alg` `none` and an empty signature'),
  'presentation.kb-hs256-public-key': kbJwt(
    'key-binding',
    'its KB-JWT is protected with `HS256`, keyed with the PEM encoding of the public key in the `cnf` claim of the credential',
  ),
  'presentation.kb-es256k': {
    ...kbJwt(
      'key-binding',
      'the credential is bound (`cnf`) to a key of the Conformance Wallet on curve secp256k1, and its KB-JWT is signed with that key and `alg` `ES256K`',
    ),
    holderCurve: 'secp256k1',
  },

  // Presentation (mdoc): the DeviceResponse the Conformance Wallet builds for the request, with the SessionTranscript
  // computed from different values, or the DeviceSigned structure changed.
  'presentation.transcript-nonce': deviceAuth(
    'key-binding',
    'the SessionTranscript its device signature covers is computed with a newly generated `nonce` instead of the `nonce` of the request',
  ),
  'presentation.transcript-client-id': deviceAuth(
    'key-binding',
    'the `OpenID4VPHandover` in the SessionTranscript its device signature covers is computed with the Client Identifier of another Relying Party instead of the `client_id` of the request',
    'redirect',
  ),
  'presentation.transcript-client-id-no-prefix': deviceAuth(
    'key-binding',
    'the `OpenID4VPHandover` in the SessionTranscript its device signature covers is computed with the Client Identifier of the request without its prefix `x509_hash:`',
    'redirect',
  ),
  'presentation.transcript-response-uri': deviceAuth(
    'key-binding',
    'the `OpenID4VPHandover` in the SessionTranscript its device signature covers is computed with a `response_uri` other than that of the request',
    'redirect',
  ),
  'presentation.transcript-jwk-thumbprint': deviceAuth(
    'key-binding',
    'the SessionTranscript its device signature covers is computed with the JWK thumbprint of a newly generated key instead of that of the encryption key of the request',
  ),
  'presentation.transcript-jwk-thumbprint-null': deviceAuth(
    'key-binding',
    'the SessionTranscript its device signature covers is computed with `null` as the JWK thumbprint, although the response is encrypted to the encryption key of the request',
  ),
  'presentation.transcript-origin': deviceAuth(
    'key-binding',
    'the `OpenID4VPDCAPIHandover` in the SessionTranscript its device signature covers is computed with the Origin `https://other.example` instead of the Origin of the page',
    'dc-api',
  ),
  'presentation.transcript-origin-prefixed': deviceAuth(
    'key-binding',
    'the `OpenID4VPDCAPIHandover` in the SessionTranscript its device signature covers is computed with the Origin of the page written with the prefix `origin:`',
    'dc-api',
  ),
  'presentation.device-signature-bitflip': deviceAuth('key-binding', 'one bit of the signature value of its `DeviceSignature` is flipped'),
  'presentation.device-signature-other-key': deviceAuth(
    'key-binding',
    'its `DeviceSignature` is made with a newly generated P-256 key instead of the device key in the `deviceKeyInfo` of the MSO',
  ),
  'presentation.no-device-auth': deviceAuth('key-binding', 'the `deviceSigned` structure of its document has no `deviceAuth`'),
  'presentation.device-signature-missing': deviceAuth('key-binding', 'the `deviceAuth` of its document is present and empty, without a `deviceSignature`'),
  'presentation.device-signature-doctype-other': deviceAuth(
    'key-binding',
    'its `DeviceSignature` covers a `DeviceAuthentication` structure that names the `docType` `org.iso.18013.5.1.mDL`, while its document has the `docType` of the PID',
  ),
  'presentation.device-signature-not-detached': deviceAuth(
    'key-binding',
    'its `DeviceSignature` carries its payload (`DeviceAuthenticationBytes`) instead of `nil`, and is made over that payload',
  ),
  'presentation.device-signed-element': deviceAuth(
    'key-binding',
    'the `DeviceNameSpaces` its device signature covers contain the element `family_name` with the value `Musterfrau` in the namespace `eu.europa.ec.eudi.pid.1`, which the MSO does not authorise through `keyAuthorizations`',
  ),
  'presentation.device-signature-es256k': {
    ...deviceAuth(
      'key-binding',
      'the mdoc is bound (`deviceKeyInfo`) to a key of the Conformance Wallet on curve secp256k1, and its `DeviceSignature` is made with that key and algorithm `ES256K` (-47)',
    ),
    holderCurve: 'secp256k1',
  },

  // Presentation in either format: the `vp_token` entry of an earlier transaction (SessionBinding_005).
  'presentation.replay': {
    point: 'presentation',
    target: 'key-binding',
    text: 'its `vp_token` carries, unchanged, the presentation the Conformance Wallet sent in T1, while the Authorization Response itself is encrypted to the encryption key of T2',
  },

  // Trust list: a new version of a LoTE or of a Trusted List that the Test Trust Infrastructure publishes, with one
  // property that makes it unusable, or (stale-within-grace) usable only as stale.
  'trust-list.seal-bitflip': lote('trust-list-signature', 'one bit of the signature value of its JAdES seal is flipped'),
  'trust-list.sealed-by-ca-x': lote(
    'trust-list-signer',
    'it is sealed by a certificate issued by `CA-X`, which its `x5c` header carries, instead of the scheme operator certificate',
  ),
  'trust-list.wrong-type': lote(
    'trust-list-type',
    'its `LoTEType` is that of a Wallet Providers list (`http://uri.etsi.org/19602/LoTEType/EUWalletProvidersList`), while it is published at the location of `TL-PID` and sealed by its scheme operator',
  ),
  'trust-list.stale-within-grace': lote(
    null,
    'its `NextUpdate` lies half of the grace period `G` in the past, and its `ListIssueDateTime` one month before that',
  ),
  'trust-list.stale-after-grace': lote(
    'trust-list-freshness',
    'its `NextUpdate` lies the grace period `G` plus one hour in the past, and its `ListIssueDateTime` one month before that',
  ),
  'trust-list.rollback': lote(
    'trust-list-sequence',
    'its `LoTESequenceNumber` is one lower than that of the version the Relying Party retrieved before, and its `ListIssueDateTime` one day earlier',
  ),
  'trusted-list.signer-ca-x': trustedList(
    'trust-list-signer',
    'it is signed by a certificate issued by `CA-X`, which is not the certificate the LOTL names in its pointer to `TL-QEAA`',
  ),

  // Request (self-validation of the request-side checks only): a valid request of the reference Relying Party's form,
  // changed in one property. The harness never sends these; it checks the requests the Relying Party sends.
  'request.unsigned-parameter': request('request-by-reference', 'its invocation URI additionally carries the parameter `nonce`', 'redirect'),
  'request.response-mode-direct-post': request('request-object', 'its request object asks for response mode `direct_post`', 'redirect'),
  'request.nonce-short': request('nonce', 'its `nonce` is `abc123`'),
  'request.nonce-reused': request('nonce', 'it carries the `nonce` of an earlier request'),
  'request.state-short': request('state', 'its `state` is `1`', 'redirect'),
  'request.dc-api-response-uri': request('dc-api-request', 'its request object carries a `response_uri`', 'dc-api'),
  'request.expected-origins-other': request('expected-origins', 'its `expected_origins` also names `https://other.example`', 'dc-api'),
  'request.enc-key-private': request('encryption-key', 'the encryption key in its `client_metadata` carries the private key member `d`'),
  'request.enc-values-one': request('enc-values', 'its `encrypted_response_enc_values_supported` lists only `A128GCM`'),
  'request.enc-key-reused': request('ephemeral-key', 'it carries the encryption key of an earlier request'),
  'request.vp-formats-es256k': request('vp-formats', 'its `vp_formats_supported` also lists the algorithm `ES256K` for SD-JWT VC and -47 for mdoc'),
  'request.dcql-duplicate-id': request('dcql', 'its DCQL query carries a second credential query with the same `id`'),
  'request.holder-binding-false': request('holder-binding', 'its credential query for the PID sets `require_cryptographic_holder_binding` to false'),
  'request.trusted-authorities-other': request('trusted-authorities', 'its `trusted_authorities` names the key identifier of `CA-X`'),
  'request.typ-jwt': request('request-signature', 'the `typ` header of its request object is `JWT`'),
  'request.client-id-other': request('client-id', 'its `client_id` is the `x509_hash` Client Identifier of another certificate'),
  'request.x5c-anchor': request('access-certificate-chain', 'the `x5c` header of its request object also carries the trust anchor of `AC-A`'),
  'request.access-certificate-plain': request(
    'access-certificate',
    'it is signed with an end-entity certificate of `AC-A` without the policy, contact and subject of an access certificate',
  ),
  'request.registration-certificate-missing': request('registration-certificate', 'it carries no `verifier_info`'),
  'request.unregistered-claim': request('registered-attributes', 'its DCQL query also requests the claim `nationalities`, which its registration certificate does not list'),
  'request.unsigned': request('signed-request', 'it is not signed: an unsigned request object (`alg` `none`) via redirects, protocol `openid4vp-v1-unsigned` via the DC API'),

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
  const info = FAULTS[id] as FaultInfo | undefined;
  if (!info) throw new Error(`unknown fault ${id}`);
  return info;
}
