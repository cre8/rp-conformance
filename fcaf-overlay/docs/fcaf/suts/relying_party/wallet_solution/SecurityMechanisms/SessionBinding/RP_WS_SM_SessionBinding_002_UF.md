# RP_WS_SM_SessionBinding_002_UF

## Objective

Verify that the Relying Party rejects a presentation in SD-JWT VC format via redirects whose KB-JWT is not addressed to its full Client Identifier.

## References

- [OpenID4VP] section 5.9.3, 14.1.2, 14.8, B.3.6
- [RFC9901] section 7.3
- [CIR 2024/2982 amended] Annex II

## Profile applicability

- Relying Party requests credentials in IETF SD-JWT VC format.
- Relying Party supports presentations via redirects.

## EUDI-wallet relevancy

EUDI_generic | EUDI_required

## Technology

- Presentation of a credential in IETF SD-JWT VC format.
- Presentation via redirects with response mode `direct_post.jwt`.

## Preconditions

1. The Relying Party is set to `default_configuration_rp_1`.
2. The test environment publishes `default_trust_configuration_rp`, and the Relying Party has loaded it.
3. Test case `RP_WS_IA_MainInteraction_001a` passed in the same environment.

## Test Scenario

1. Perform a presentation for `default_query_pid` via redirects in which the Conformance Wallet presents `default_credential_pid` in an Authorization Response that is valid except that the `aud` claim of its KB-JWT is the Client Identifier of another Relying Party: the prefix `x509_hash:` followed by the hash of a different certificate.
2. Perform a presentation for `default_query_pid` via redirects in which the Conformance Wallet presents `default_credential_pid` in an Authorization Response that is valid except that the `aud` claim of its KB-JWT is the Client Identifier of the request without its prefix `x509_hash:`.
3. Perform a presentation for `default_query_pid` via redirects in which the Conformance Wallet presents `default_credential_pid` in an Authorization Response that is valid except that its KB-JWT has no `aud` claim.
4. Perform a presentation for `default_query_pid` via redirects in which the Conformance Wallet presents `default_credential_pid` in an Authorization Response that is valid except that the `aud` claim of its KB-JWT is an array that holds the Client Identifier of the request as its only element, instead of the string.

## Expected results

1. The Relying Party rejects the presentation: its verification result reports a failure and releases no attribute value from the presentation, and the endpoint receiving the Authorization Response does not answer with HTTP status 5xx.
2. The Relying Party rejects the presentation: its verification result reports a failure and releases no attribute value from the presentation, and the endpoint receiving the Authorization Response does not answer with HTTP status 5xx.
3. The Relying Party rejects the presentation: its verification result reports a failure and releases no attribute value from the presentation, and the endpoint receiving the Authorization Response does not answer with HTTP status 5xx.
4. The Relying Party rejects the presentation: its verification result reports a failure and releases no attribute value from the presentation, and the endpoint receiving the Authorization Response does not answer with HTTP status 5xx.

## Comments

The OIDF verifier test module `oid4vp-1final-verifier-invalid-kb-jwt-aud` covers the first step.
