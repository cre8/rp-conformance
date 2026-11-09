// The named faults of the baseline (harness design section 4.3). Each one is applied after a valid build, at one point
// of the artifact chain, and must fail exactly its `target` check of the reference validator and no other (section 7);
// `null` marks a variant that must pass every check. `text` is the FCAF wording of the difference, so a test case
// names a fault and describes it in one place. The implementations are in packages/forge/src/faults.
import type { CheckId } from './checks';

export type FaultPoint = 'credential' | 'status-list' | 'response';

export interface FaultInfo {
  point: FaultPoint;
  target: CheckId | null;
  /** The difference from the valid artifact, as the FCAF scenario words it (after "except that" / "only in that"). */
  text: string;
}

const credential = (target: CheckId | null, text: string): FaultInfo => ({ point: 'credential', target, text });
const statusList = (target: CheckId | null, text: string): FaultInfo => ({ point: 'status-list', target, text });
const response = (target: CheckId | null, text: string): FaultInfo => ({ point: 'response', target, text });

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
  'credential.status-idx-out-of-range': credential(
    'status-index',
    'the index in its status reference equals the number of entries in the referenced status list, one past the last valid index',
  ),
  'credential.no-status': credential('status-reference', 'it carries no `status` claim'),

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
  'status-list.signer-self-signed': statusList(
    'status-list-trust',
    'it is signed by a self-signed certificate that is not part of `default_trust_configuration_rp`',
  ),
  'status-list.signer-pp-b-revocation': statusList('status-list-trust', 'it is signed by a certificate under the revocation anchor of `PP-B`'),
  'status-list.signer-wp-a-revocation': statusList(
    'status-list-trust',
    'it is signed by a certificate under the revocation anchor of the Wallet Provider `WP-A` in `TL-WP`',
  ),
  'status-list.signer-ac-a': statusList('status-list-trust', 'it is signed by a certificate under the anchor of `AC-A` in `TL-AC`'),
  'status-list.signer-credential-certificate': statusList(
    'status-list-trust',
    'it is signed with the key and certificate that signed the presented credential',
  ),
  'status-list.signer-other-issuance-certificate': statusList(
    'status-list-trust',
    'it is signed by another certificate issued under the issuance CA `CA-PP-A` of `PP-A`',
  ),
  'status-list.embedded-root': statusList(
    'status-list-trust',
    'its signer certificate chains to a self-signed root that `x5c` includes and that is not part of `default_trust_configuration_rp`',
  ),
  'status-list.signer-expired': statusList('status-list-trust', 'its signer certificate has expired'),
  'status-list.signer-not-yet-valid': statusList('status-list-trust', 'its signer certificate is not yet valid'),
  'status-list.lst-not-base64url': statusList('status-list-decoding', 'the `lst` member of its `status_list` claim is not valid base64url'),
  'status-list.lst-not-zlib': statusList(
    'status-list-decoding',
    'the `lst` member of its `status_list` claim decodes to bytes that are not valid ZLIB data',
  ),
  'status-list.decompression-bomb': statusList(
    'status-list-decoding',
    'its `lst` value decompresses to more bytes than the maximum status list size the Relying Party declares, for example a ZLIB stream that inflates to 1 GiB of zero bytes',
  ),
  'status-list.bits-3': statusList('status-list-decoding', 'the `bits` value of its status list is 3'),
  'status-list.es256k': statusList('status-list-signature', 'it is signed with `ES256K` (curve secp256k1)'),
  'status-list.hs256-public-key': statusList(
    'status-list-signature',
    'it is protected with `HS256`, keyed with the encoded public key of the certificate in its `x5c` header',
  ),

  // Authorization Response (direct_post.jwt): built from the valid payload and the Relying Party's encryption key.
  'response.unencrypted': response(
    'response-encrypted',
    'it is not encrypted: the Conformance Wallet posts `vp_token` and `state` as form parameters to the `response_uri`, as in response mode `direct_post`',
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
