# RP_WS_SM_SessionEncryption_009a_UF

## Objective

Verify that the Relying Party rejects an Authorization Response via redirects whose ephemeral public key is not a valid P-256 point.

## References

- [HAIP] section 5, 5.1
- [OpenID4VP] section 8.3, 8.3.1
- [RFC7518] section 4.6
- [RFC8725] section 3.4
- [ARF] Annex 2, OIA_03b, OIA_03c
- [CIR 2024/2982 amended] Annex II

## Profile applicability

- Relying Party supports presentations via redirects.

## EUDI-wallet relevancy

EUDI_generic | EUDI_required

## Technology

- Presentation via redirects with response mode `direct_post.jwt`.

## Preconditions

1. The Relying Party is set to `default_configuration_rp_1`.
2. The test environment publishes `default_trust_configuration_rp`, and the Relying Party has loaded it.
3. Test case `RP_WS_IA_MainInteraction_001a` or `RP_WS_IA_MainInteraction_001b` passed in the same environment for the presentation flow of this test case.

## Test Scenario

1. Perform a presentation for `default_query_pid` via redirects in which the Conformance Wallet presents `default_credential_pid` in an Authorization Response that is valid except that the `epk` header of its JWE holds coordinates that are not a point on P-256.
2. Perform a presentation for `default_query_pid` via redirects in which the Conformance Wallet presents `default_credential_pid` in an Authorization Response that is valid except that the `epk` header of its JWE holds a key on curve P-384.

## Expected results

1. The Relying Party rejects the presentation: its verification result reports a failure and releases no attribute value from the presentation, and the endpoint receiving the Authorization Response does not answer with HTTP status 5xx.
2. The Relying Party rejects the presentation: its verification result reports a failure and releases no attribute value from the presentation, and the endpoint receiving the Authorization Response does not answer with HTTP status 5xx.

## Comments

The credential format does not affect this test case; use `default_credential_pid` in a format the Relying Party requests.
