// The named checks of the reference validator (harness design section 7). Every fault names the one check it must fail.

/** Checks of an SD-JWT VC presentation with KB-JWT, in the order the reference validator performs them. */
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
export type ResponseCheck = (typeof RESPONSE_CHECKS)[number];
export type CheckId = CredentialCheck | StatusListCheck | ResponseCheck;

/** `pass`; `fail`; `skip` when a check could not be evaluated because a check it depends on did not pass, or does not apply. */
export type CheckStatus = 'pass' | 'fail' | 'skip';

export interface CheckResult {
  check: CheckId;
  status: CheckStatus;
  detail?: string;
}
