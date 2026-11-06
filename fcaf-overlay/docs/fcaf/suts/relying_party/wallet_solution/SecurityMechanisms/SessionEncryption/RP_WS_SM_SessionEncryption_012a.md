# RP_WS_SM_SessionEncryption_012a

## Objective

Verify that the Relying Party ignores unrecognised members in a decrypted Authorization Response via redirects.

## References

- [HAIP] section 5, 5.1
- [OpenID4VP] section 8.3, 8.3.1
- [OpenID4VP] section 8.1
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

1. Perform a presentation for `default_query_pid` via redirects in which the Conformance Wallet presents `default_credential_pid` in a valid Authorization Response whose decrypted payload additionally contains the member `foo` with the value `bar`.

## Expected results

1. The Relying Party accepts the presentation: its verification result reports success and releases exactly the attributes requested in `default_query_pid`, with the values of `default_credential_pid`.

## Comments

The credential format does not affect this test case; use `default_credential_pid` in a format the Relying Party requests.
