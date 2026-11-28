import type { DcqlQuery, DefaultQueryId } from '@eudi-pcaf/core';
import { CREDENTIAL_A_DOCTYPE, CREDENTIAL_A_NAMESPACE, CREDENTIAL_A_VCT } from './attestation';
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

/**
 * The variant of `default_query_pid` in SD-JWT VC format that also requests the structured claim `place_of_birth`
 * (IssuerIntegrity_015, recursive disclosures).
 */
export const PID_PLACE_OF_BIRTH_QUERY: DcqlQuery = {
  credentials: [{ ...PID_QUERY.credentials[0], claims: [...(PID_QUERY.credentials[0].claims ?? []), { path: ['place_of_birth'] }] }],
};

/**
 * The variants of `default_query_pid` that also request the administrative expiry date of the PID: `date_of_expiry` in
 * SD-JWT VC format, `expiry_date` in mdoc format (PID Rulebook; RP_WS_SM_Validity_020).
 */
export const PID_EXPIRY_DATE_QUERY: DcqlQuery = {
  credentials: [{ ...PID_QUERY.credentials[0], claims: [...(PID_QUERY.credentials[0].claims ?? []), { path: ['date_of_expiry'] }] }],
};
export const PID_MDOC_EXPIRY_DATE_QUERY: DcqlQuery = {
  credentials: [{ ...PID_MDOC_QUERY.credentials[0], claims: [...(PID_MDOC_QUERY.credentials[0].claims ?? []), { path: [PID_NAMESPACE, 'expiry_date'] }] }],
};
/** A variant of `default_query_pid` (SD-JWT VC) or of its mdoc form that requests the claims at `paths` instead. */
const pidQueryWith = (base: DcqlQuery, paths: (string | number)[][], values?: (string | number | boolean)[]): DcqlQuery => ({
  credentials: [{ ...base.credentials[0], claims: paths.map((path) => ({ path, ...(values ? { values } : {}) })) }],
});

/**
 * The data model variants of `default_query_pid` (RP_WS_DM_IdentifyingData, RP_WS_DM_CredentialMetadata): every
 * mandatory attribute of the PID rulebook, the age-over attribute for 18 without and with the `values` constraint
 * `true`, and three members of the structured address (SD-JWT VC only; the mdoc PID has no structured address).
 */
export const PID_DATA_MODEL_QUERIES = {
  default_query_pid_mandatory: pidQueryWith(PID_QUERY, [
    ['family_name'],
    ['given_name'],
    ['birthdate'],
    ['place_of_birth'],
    ['nationalities'],
    ['date_of_expiry'],
    ['issuing_authority'],
    ['issuing_country'],
  ]),
  default_query_pid_mandatory_mdoc: pidQueryWith(
    PID_MDOC_QUERY,
    ['family_name', 'given_name', 'birth_date', 'place_of_birth', 'nationality', 'expiry_date', 'issuing_authority', 'issuing_country'].map((e) => [PID_NAMESPACE, e]),
  ),
  default_query_pid_age_over_18: pidQueryWith(PID_QUERY, [['age_equal_or_over', '18']]),
  default_query_pid_age_over_18_mdoc: pidQueryWith(PID_MDOC_QUERY, [[PID_NAMESPACE, 'age_over_18']]),
  default_query_pid_age_over_18_true: pidQueryWith(PID_QUERY, [['age_equal_or_over', '18']], [true]),
  default_query_pid_age_over_18_true_mdoc: pidQueryWith(PID_MDOC_QUERY, [[PID_NAMESPACE, 'age_over_18']], [true]),
  default_query_pid_address: pidQueryWith(PID_QUERY, [
    ['address', 'locality'],
    ['address', 'postal_code'],
    ['address', 'country'],
  ]),
} satisfies Partial<Record<DefaultQueryId, DcqlQuery>>;

const ATTRIBUTES_A = ['attribute_A', 'attribute_B', 'attribute_C'];

/**
 * `default_query_qeaa`, `default_query_pubeaa` and `default_query_eaa` in SD-JWT VC format: one credential query for
 * `default_credential_A`, requesting `attribute_A`, `attribute_B` and `attribute_C`, cryptographic holder binding
 * required. The three differ only in their credential query ID; the category of the credential follows from the root of
 * trust the Relying Party applies to each.
 */
export const attestationQuery = (id: string): DcqlQuery => ({
  credentials: [
    {
      id,
      format: 'dc+sd-jwt',
      meta: { vct_values: [CREDENTIAL_A_VCT] },
      claims: ATTRIBUTES_A.map((name) => ({ path: [name] })),
      require_cryptographic_holder_binding: true,
    },
  ],
});

/** The same queries in mdoc format: the attributes in the namespace of the doctype of `default_credential_A`. */
export const attestationMdocQuery = (id: string): DcqlQuery => ({
  credentials: [
    {
      id,
      format: 'mso_mdoc',
      meta: { doctype_value: CREDENTIAL_A_DOCTYPE },
      claims: ATTRIBUTES_A.map((name) => ({ path: [CREDENTIAL_A_NAMESPACE, name] })),
      require_cryptographic_holder_binding: true,
    },
  ],
});

/** OpenID4VP section 6.1.1.1, type `aki`: the base64url key identifier of a CA in the credential's certificate chain. */
export function akiOf(subjectKeyIdentifierHex: string): string {
  return Buffer.from(subjectKeyIdentifierHex, 'hex').toString('base64url');
}

/**
 * The default queries of a run, each in SD-JWT VC and in mdoc format: `default_query_pid`, `default_query_qeaa`,
 * `default_query_pubeaa` and `default_query_eaa`. The `…_trusted_authorities` variants of `default_query_pid` restrict
 * it with a `trusted_authorities` entry of type `aki` that names only the PID/Issuance anchor of `PP-A`
 * (TrustMechanisms_016); `default_query_pid_place_of_birth` also requests `place_of_birth` (IssuerIntegrity_015).
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
    default_query_pid_place_of_birth: PID_PLACE_OF_BIRTH_QUERY,
    default_query_pid_mdoc: PID_MDOC_QUERY,
    default_query_pid_mdoc_trusted_authorities: restricted(PID_MDOC_QUERY),
    default_query_qeaa: attestationQuery('qeaa'),
    default_query_qeaa_mdoc: attestationMdocQuery('qeaa'),
    default_query_pubeaa: attestationQuery('pubeaa'),
    default_query_pubeaa_mdoc: attestationMdocQuery('pubeaa'),
    default_query_eaa: attestationQuery('eaa'),
    default_query_eaa_mdoc: attestationMdocQuery('eaa'),
    default_query_pid_expiry_date: PID_EXPIRY_DATE_QUERY,
    default_query_pid_mdoc_expiry_date: PID_MDOC_EXPIRY_DATE_QUERY,
    default_query_pid_eaa: pidAndEaaQuery(PID_QUERY, attestationQuery('eaa')),
    default_query_pid_eaa_mdoc: pidAndEaaQuery(PID_MDOC_QUERY, attestationMdocQuery('eaa')),
    default_query_pid_or_eaa: pidOrEaaQuery(PID_QUERY, attestationQuery('eaa'), attestationQuery('pubeaa')),
    default_query_pid_or_eaa_mdoc: pidOrEaaQuery(PID_MDOC_QUERY, attestationMdocQuery('eaa'), attestationMdocQuery('pubeaa')),
    default_query_pid_eaa_identifying: pidAndEaaQuery(PID_QUERY, withIdentifyingClaims(attestationQuery('eaa'), ['family_name', 'given_name', 'birthdate'])),
    default_query_pid_eaa_identifying_mdoc: pidAndEaaQuery(
      PID_MDOC_QUERY,
      withIdentifyingClaims(attestationMdocQuery('eaa'), ['family_name', 'given_name', 'birth_date'].map((name) => [CREDENTIAL_A_NAMESPACE, name])),
    ),
    ...PID_DATA_MODEL_QUERIES,
  };
}

/**
 * `default_query_pid_eaa` (UC_Presentation): the credential queries of `default_query_pid` and `default_query_eaa` in
 * one DCQL query, both required, without `credential_sets`.
 */
export function pidAndEaaQuery(pidQuery: DcqlQuery, eaaQuery: DcqlQuery): DcqlQuery {
  return { credentials: [...pidQuery.credentials, ...eaaQuery.credentials] };
}

/**
 * `default_query_pid_or_eaa` (UC_Presentation_006 to _008): the credential queries `pid`, `eaa` and `pubeaa`, with a
 * required credential set whose options are the PID or the non-qualified EAA, and an optional credential set with the
 * PuB-EAA (OpenID4VP 1.0 section 6.2).
 */
export function pidOrEaaQuery(pidQuery: DcqlQuery, eaaQuery: DcqlQuery, pubEaaQuery: DcqlQuery): DcqlQuery {
  return {
    credentials: [...pidQuery.credentials, ...eaaQuery.credentials, ...pubEaaQuery.credentials],
    credential_sets: [{ options: [['pid'], ['eaa']] }, { options: [['pubeaa']], required: false }],
  };
}

/**
 * The query of `default_credential_A` that also requests identifying attributes (UC_Presentation_010, _011): names in
 * SD-JWT VC format, `[namespace, element]` paths in mdoc format.
 */
function withIdentifyingClaims(query: DcqlQuery, claims: (string | string[])[]): DcqlQuery {
  return {
    credentials: query.credentials.map((credential) => ({
      ...credential,
      claims: [...(credential.claims ?? []), ...claims.map((claim) => ({ path: Array.isArray(claim) ? claim : [claim] }))],
    })),
  };
}
