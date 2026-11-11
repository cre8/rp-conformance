import type { DcqlQuery, DefaultQueryId } from '@rp-conformance/core';
import { PID_DOCTYPE, PID_NAMESPACE } from './mdoc';
import { PID_VCT } from './pid';
import type { TestPki } from './pki';

/**
 * `default_query_pid` in SD-JWT VC format (FCAF defaults, "Relying Party testing"): family name, given name and birth
 * date, cryptographic holder binding required, no `trusted_authorities`.
 */
export const PID_QUERY: DcqlQuery = {
  credentials: [
    {
      id: 'pid',
      format: 'dc+sd-jwt',
      meta: { vct_values: [PID_VCT] },
      claims: [{ path: ['family_name'] }, { path: ['given_name'] }, { path: ['birthdate'] }],
      require_cryptographic_holder_binding: true,
    },
  ],
};

/**
 * `default_query_pid` in mdoc format: the same attributes in namespace `eu.europa.ec.eudi.pid.1` of doctype
 * `eu.europa.ec.eudi.pid.1` (OpenID4VP Appendix B.2.3), cryptographic holder binding required.
 */
export const PID_MDOC_QUERY: DcqlQuery = {
  credentials: [
    {
      id: 'pid',
      format: 'mso_mdoc',
      meta: { doctype_value: PID_DOCTYPE },
      claims: [{ path: [PID_NAMESPACE, 'family_name'] }, { path: [PID_NAMESPACE, 'given_name'] }, { path: [PID_NAMESPACE, 'birth_date'] }],
      require_cryptographic_holder_binding: true,
    },
  ],
};

/** OpenID4VP section 6.1.1.1, type `aki`: the base64url key identifier of a CA in the credential's certificate chain. */
export function akiOf(subjectKeyIdentifierHex: string): string {
  return Buffer.from(subjectKeyIdentifierHex, 'hex').toString('base64url');
}

/**
 * The default queries of a run, `default_query_pid` in SD-JWT VC and in mdoc format. The `…_trusted_authorities`
 * variants restrict them with a `trusted_authorities` entry of type `aki` that names only the PID/Issuance anchor of
 * `PP-A` (TrustMechanisms_016).
 */
export function defaultQueries(pki: TestPki): Record<DefaultQueryId, DcqlQuery> {
  const ski = pki.entities['PP-A'].anchors.issuance.certificate.subjectKeyIdentifier;
  if (!ski) throw new Error('CA-PP-A has no subject key identifier');
  const restricted = (query: DcqlQuery): DcqlQuery => ({
    credentials: query.credentials.map((credential) => ({ ...credential, trusted_authorities: [{ type: 'aki', values: [akiOf(ski)] }] })),
  });
  return {
    default_query_pid: PID_QUERY,
    default_query_pid_trusted_authorities: restricted(PID_QUERY),
    default_query_pid_mdoc: PID_MDOC_QUERY,
    default_query_pid_mdoc_trusted_authorities: restricted(PID_MDOC_QUERY),
  };
}
