// `default_credential_A` of the FCAF defaults, which the Test Issuers issue as a QEAA (`QP-A`), a PuB-EAA (`PB-A`) or a
// non-qualified EAA (`EP-A`): one credential type with the attributes `attribute_A` (numerical), `attribute_B` (string)
// and `attribute_C` (date), in SD-JWT VC and in mdoc format. The category follows from the issuer, not from the type.
import { issueMdoc } from './mdoc';
import { issueSdJwtVc, type SdJwtVcIssueOptions } from './pid';
import type { MdocIssueOptions } from './mdoc';

/** `vct` of `default_credential_A` in SD-JWT VC format. A URN, so a Relying Party has no type metadata to fetch. */
export const CREDENTIAL_A_VCT = 'urn:rp-conformance:credential_a:1';
/** DocType and namespace of `default_credential_A` in mdoc format, under the reserved top-level domain `test`. */
export const CREDENTIAL_A_DOCTYPE = 'test.rp-conformance.credential_a.1';
export const CREDENTIAL_A_NAMESPACE = 'test.rp-conformance.credential_a.1';

/**
 * The attribute values of `default_credential_A`: a positive number, a Latin-1 string of at most 64 characters, and a
 * date in the past (`full-date` in mdoc format).
 */
export const DEFAULT_CREDENTIAL_A_CLAIMS = {
  attribute_A: 42,
  attribute_B: 'Beispielwert für Attribut B',
  attribute_C: '2001-04-21',
} as const;

/** `default_credential_A` in SD-JWT VC format, issued like the PID. */
export function issueCredentialASdJwtVc(options: SdJwtVcIssueOptions) {
  return issueSdJwtVc({ ...options, vct: CREDENTIAL_A_VCT, claims: { ...DEFAULT_CREDENTIAL_A_CLAIMS } });
}

/** `default_credential_A` in mdoc format, issued like the PID. */
export function issueCredentialAMdoc(options: MdocIssueOptions) {
  return issueMdoc({
    ...options,
    docType: CREDENTIAL_A_DOCTYPE,
    namespace: CREDENTIAL_A_NAMESPACE,
    claims: { ...DEFAULT_CREDENTIAL_A_CLAIMS },
    fullDates: new Set(['attribute_C']),
  });
}
