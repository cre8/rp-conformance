// PP_WS_MS_Metadata (`SCN-M`, issuer catalogue section 5.1.1): what the Provider publishes as Credential Issuer
// metadata, plain and signed with its access certificate, and as Authorization Server metadata (`OBS-META`). The
// metadata does not depend on the grant or the format of an issuance, so these test cases have no variant, except
// `_013`, which concerns mdoc only.
import { defineIssuerTestCase, type IssuerArtifactCheck, issuerProfiles, relevancy } from '@eudi-pcaf/core';
import { preconditions } from '../../wording';
import { conf } from './conf';

const SCN_M =
  'The Conformance Wallet runs `SCN-M`: it takes the Credential Issuer identifier from an offer the adapter creates, fetches the Credential Issuer metadata from `/.well-known/openid-credential-issuer` inserted before the path of that identifier, once as JSON and once with `Accept: application/jwt`, the metadata of every Authorization Server it names, sends two requests to the nonce endpoint, and fetches `/.well-known/openid-configuration` under the identifier as a probe.';

const metadata = (
  number: string,
  objective: string,
  references: string[],
  checks: Partial<Record<IssuerArtifactCheck, string>>,
  options: { relevancy?: (typeof relevancy)[keyof typeof relevancy]; comments?: string[]; mdoc?: boolean } = {},
) =>
  defineIssuerTestCase({
    id: `PP_WS_MS_Metadata_${number}`,
    ...(options.mdoc ? { variants: ['MD' as const] } : {}),
    objective,
    references,
    profile: [issuerProfiles['P-PID'], ...(options.mdoc ? [issuerProfiles['P-MD']] : [])],
    relevancy: options.relevancy ?? relevancy.specificRequired,
    technology: ['OpenID4VCI', 'HAIP'],
    preconditions: preconditions.base,
    steps: [{ text: SCN_M, run: { kind: 'metadata' }, expect: conf(checks) }],
    ...(options.comments ? { comments: options.comments } : {}),
  });

export const definitions = [
  metadata(
    '001',
    'Verify that the Credential Issuer metadata is served at `/.well-known/openid-credential-issuer` under the Credential Issuer identifier, and that its `credential_issuer` equals that identifier.',
    ['[OpenID4VCI] sections 12.2.2 and 12.2.4', '[ARF] Annex 2, ISSU_01a'],
    { 'metadata-location': 'HTTP 200, `application/json`, at the well-known URL of the identifier; `credential_issuer` is that identifier, an https URL without query or fragment' },
    { relevancy: relevancy.genericRequired },
  ),
  metadata(
    '002',
    'Verify that the signed Credential Issuer metadata is a JWS signed with the key of the access certificate, carrying the access certificate and its intermediates up to `AC-A` (not the anchor) in `x5c`, and that it validates to `TL-AC`.',
    ['[ARF] Annex 2, ISSU_22, PPNot_04', '[OpenID4VCI] section 12.2.3', '[HAIP] section 4.1'],
    {
      'metadata-signed':
        'HTTP 200, `application/jwt`; `typ` `openidvci-issuer-metadata+jwt`, an agreed `alg`; `x5c` without the anchor validates to an anchor of `TL-AC`; the leaf is an access certificate per ETSI TS 119 411-8 and verifies the signature; `sub` is the Credential Issuer identifier, `iat` present',
    },
  ),
  metadata(
    '003',
    'Verify that the signed and the unsigned Credential Issuer metadata carry the same values.',
    ['[OpenID4VCI] section 12.2.3'],
    { 'metadata-signed-equal': 'every member of the signed payload except `iss`, `sub`, `iat`, `exp`, `nbf`, `jti` equals the member of the JSON metadata, and no member is in one only' },
    { relevancy: relevancy.genericRequired },
  ),
  metadata(
    '004',
    'Verify that the registration certificate is included in the metadata by value, valid, issued by `RC-A`, with the same entity identifier as the access certificate.',
    ['[ARF] Annex 2, RPRC_22, RPRC_22b', '[ETSI TS 119 472-3] section 4.2.3'],
    {
      'metadata-registration-certificate':
        'exactly one `issuer_info` entry of format `registration_cert` carries the certificate by value; it validates to an anchor of `TL-RC`, its signature verifies, it is not expired, and it is valid for the entity identifier of the access certificate in the signed metadata',
    },
  ),
  metadata(
    '005',
    "Verify that the registration certificate's `entitlement` matches the Provider's category, and that `providesAttestations` lists every credential type in `credential_configurations_supported`.",
    ['[ARF] Annex 2, RPRC_15, RPRC_23, ISSU_24a, ISSU_24b, Reg_10e'],
    {
      'metadata-registration-entitlement':
        '`entitlements` contains `https://uri.etsi.org/19475/Entitlement/PID_Provider`; `provides_attestations` lists the `vct` of every `dc+sd-jwt` configuration and the doctype of every `mso_mdoc` configuration',
    },
  ),
  metadata(
    '006',
    'Verify that a PID configuration exists in both formats: `dc+sd-jwt` with `vct` `urn:eudi:pid:1` (or a domestic extension) and `mso_mdoc` with doctype `eu.europa.ec.eudi.pid.1`.',
    ['[ARF] Annex 2, PID_02, PID_04, PID_14, ISSU_12'],
    { 'metadata-pid-configurations': 'a `dc+sd-jwt` configuration with `vct` `urn:eudi:pid:1` or `urn:eudi:pid:<country>:…`, and a `mso_mdoc` configuration with `doctype` `eu.europa.ec.eudi.pid.1`' },
    { comments: ['PID only: an Attestation Provider has no counterpart of this test case.'] },
  ),
  metadata(
    '007',
    'Verify that `credential_signing_alg_values_supported`, `proof_signing_alg_values_supported` and the DPoP algorithms list only ECCG agreed cryptographic mechanisms.',
    ['[ARF] Annex 2, OIA_03, WUA_04', '[HAIP] section 7'],
    {
      'metadata-algorithms':
        'every value of `credential_signing_alg_values_supported`, of `proof_signing_alg_values_supported` of every proof type, and of `dpop_signing_alg_values_supported` of every Authorization Server is `ES256`, `ES384`, `ES512`, `ESP256`, `ESP384`, `ESP512`, `PS256`, `PS384`, `PS512` or the COSE identifier of one of them',
    },
  ),
  metadata(
    '008',
    'Verify that device-bound configurations require a key attestation in `proof_types_supported`, with `key_storage` and `user_authentication` at least `iso_18045_high` for a PID.',
    ['[ARF] Annex 2, ISSU_27d, WUA_34', '[OpenID4VCI] section 12.2.4, Appendix D.2 and Appendix F'],
    {
      'metadata-key-attestation':
        'every configuration with `cryptographic_binding_methods_supported` has `proof_types_supported`, every proof type carries `key_attestations_required`, and its `key_storage` and `user_authentication` list `iso_18045_high` only',
    },
  ),
  metadata(
    '009',
    'Verify that `credential_reuse_policy` is present per configuration and names method A or B as required, with the methods ordered by preference, and that batch size and thresholds are consistent with `batch_credential_issuance`.',
    ['[ARF] Annex 2, ISSU_39, ISSU_40, ISSU_45, ISSU_50, ISSU_54', '[ETSI TS 119 472-3] section 4.2.4.2'],
    {
      'metadata-reuse-policy':
        'every configuration carries `credential_reuse_policy` (or `credential_metadata.credential_reuse_policy`) with `options`; an option names `once_only` (method A) or `limited_time` (method B); every `batch_size` is at most `batch_credential_issuance.batch_size`, and `reissue_trigger_unused` is below it',
    },
    { comments: ['The order of the options states the preference of the Provider; it cannot be checked against anything and is recorded only.'] },
  ),
  metadata(
    '010',
    'Verify that `nonce_endpoint` is advertised and returns a fresh `c_nonce` with `Cache-Control: no-store`.',
    ['[OpenID4VCI] section 7.2', '[HAIP] section 4.1'],
    { 'metadata-nonce-endpoint': '`nonce_endpoint` is an https URL; both requests are answered HTTP 200 with `Cache-Control: no-store` and a `c_nonce`, and the two `c_nonce` values differ' },
    { relevancy: relevancy.genericRequired },
  ),
  metadata(
    '011',
    'Verify the Authorization Server metadata: PAR required, PKCE `S256` only, DPoP algorithms advertised, `attest_jwt_client_auth` as client authentication, `pre-authorized_grant_anonymous_access_supported` per ICS-03.',
    ['[HAIP] sections 4, 4.1 and 4.4.1', '[RFC 9126] section 5', '[RFC 7636]', '[RFC 9449] section 5.1', '[ARF] Annex 2, ISSU_01a'],
    {
      'metadata-authorization-server':
        'for every Authorization Server: `require_pushed_authorization_requests` true with a `pushed_authorization_request_endpoint`, `code_challenge_methods_supported` `["S256"]`, a non-empty `dpop_signing_alg_values_supported`, `attest_jwt_client_auth` in `token_endpoint_auth_methods_supported`; where the ICS declares the pre-authorized code grant, it is in `grant_types_supported` and `pre-authorized_grant_anonymous_access_supported` is not true',
    },
  ),
  metadata(
    '012',
    'Verify that `display` contains a name consistent with the trade name in the access certificate.',
    ['[ARF] Annex 2, ISSU_11, Reg_31'],
    { 'metadata-display': 'a `display` name contains the `commonName` of the access certificate in the signed metadata, or is contained in it, ignoring case' },
    { relevancy: relevancy.specificOptional },
  ),
  metadata(
    '013',
    'Verify that the metadata offers no server retrieval and no endpoint that releases attributes to a Relying Party.',
    ['[ARF] Annex 2, ProxId_02', '[ISO/IEC 18013-5] section 8.3.3.2'],
    {
      'metadata-no-server-retrieval':
        'no member of the Credential Issuer or Authorization Server metadata names server retrieval, a `userinfo_endpoint` or a Web API, and `/.well-known/openid-configuration` under the identifier advertises no `userinfo_endpoint`',
    },
    { mdoc: true },
  ),
];
