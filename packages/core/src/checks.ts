// The named checks of the reference validator (harness design section 7). Every fault names the one check it must fail.

/**
 * Checks of a credential presentation, in the order the reference validator performs them. For an SD-JWT VC with
 * KB-JWT all of them; for an mdoc (`MDOC_CREDENTIAL_CHECKS`) `disclosures` is the check of the presented
 * `IssuerSignedItem`s against the value digests of the MSO, `key-binding` the check of the DeviceAuth over the
 * SessionTranscript, and `kb-freshness` does not apply, since device authentication carries no time.
 */
export const CREDENTIAL_CHECKS = [
  'format',
  'issuer-trust',
  'trusted-authorities',
  'issuer-signature',
  'disclosures',
  'validity',
  'key-binding',
  'kb-freshness',
  'status-reference',
] as const;

/** The credential checks of an mdoc presentation (ISO/IEC 18013-5 section 9.3.1, OpenID4VP Appendix B.2). */
export const MDOC_CREDENTIAL_CHECKS = CREDENTIAL_CHECKS.filter((check) => check !== 'kb-freshness');

/**
 * Checks of the Status List Token a credential references (Token Status List sections 4, 5.1 and 8). They run only after
 * every credential check passed, because no status list procedure may run for an invalid credential (section 8.3).
 */
export const STATUS_LIST_CHECKS = [
  'status-list-fetch',
  'status-list-format',
  'status-list-type',
  'status-list-trust',
  'status-list-signature',
  'status-list-claims',
  'status-list-subject',
  'status-list-validity',
  'status-list-decoding',
  'status-index',
  'status',
] as const;

/**
 * Checks of the identifier list an mdoc references (ISO/IEC 18013-5 second edition section 12.3.6.4): the same
 * procedure as for a Status List Token in CWT format, and `identifier-status`, absence of the MSO's identifier.
 */
export const IDENTIFIER_LIST_CHECKS = [
  'identifier-list-fetch',
  'identifier-list-format',
  'identifier-list-type',
  'identifier-list-trust',
  'identifier-list-signature',
  'identifier-list-claims',
  'identifier-list-subject',
  'identifier-list-validity',
  'identifier-status',
] as const;

/** Checks of an Authorization Response in response mode `direct_post.jwt` (OpenID4VP section 8.3, HAIP section 5). */
export const RESPONSE_CHECKS = [
  'response-encrypted',
  'response-format',
  'response-alg',
  'response-enc',
  'response-epk',
  'response-decryption',
  'response-payload',
] as const;

export type CredentialCheck = (typeof CREDENTIAL_CHECKS)[number];
export type StatusListCheck = (typeof STATUS_LIST_CHECKS)[number];
export type IdentifierListCheck = (typeof IDENTIFIER_LIST_CHECKS)[number];
export type ResponseCheck = (typeof RESPONSE_CHECKS)[number];
export type CheckId = CredentialCheck | StatusListCheck | IdentifierListCheck | ResponseCheck;

/** `pass`; `fail`; `skip` when a check could not be evaluated because a check it depends on did not pass, or does not apply. */
export type CheckStatus = 'pass' | 'fail' | 'skip';

export interface CheckResult {
  check: CheckId;
  status: CheckStatus;
  detail?: string;
}
