# RP_WS_SM_SessionEncryption_002b

## Objective

Verify that the Relying Party accepts an Authorization Response via the W3C Digital Credentials API encrypted with `ECDH-ES` on P-256 and `A256GCM`.

## References

- [HAIP] section 5, 5.2
- [OpenID4VP] section 8.3, A.4
- [RFC7516] section 5.2
- [RFC7518] section 4.6, 5.3
- [ARF] Annex 2, OIA_08, OIA_08a
- [CIR 2024/2982 amended] Annex II

## Profile applicability

- Relying Party supports presentations via the W3C Digital Credentials API.

## EUDI-wallet relevancy

EUDI_generic | EUDI_required

## Technology

- Presentation via the W3C Digital Credentials API with response mode `dc_api.jwt`.

## Preconditions

1. The Relying Party is set to `default_configuration_rp_1`.
2. The test environment publishes `default_trust_configuration_rp`, and the Relying Party has loaded it.
3. Test case `RP_WS_IA_MainInteraction_001a` or `RP_WS_IA_MainInteraction_001b` passed in the same environment for the presentation flow of this test case.

## Test Scenario

1. Perform a presentation for `default_query_pid` via the W3C Digital Credentials API in which the Conformance Wallet presents `default_credential_pid` in a valid Authorization Response, encrypted as a JWE with `alg` `ECDH-ES` (P-256) and `enc` `A256GCM` to the encryption key from the `client_metadata` of the request.

## Expected results

1. The Relying Party accepts the presentation: its verification result reports success and releases exactly the attributes requested in `default_query_pid`, with the values of `default_credential_pid`.

## Comments

The credential format does not affect this test case; use `default_credential_pid` in a format the Relying Party requests.
