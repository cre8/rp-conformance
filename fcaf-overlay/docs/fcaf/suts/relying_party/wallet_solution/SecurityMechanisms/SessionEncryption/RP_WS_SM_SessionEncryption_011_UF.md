# RP_WS_SM_SessionEncryption_011_UF

## Objective

Verify that the Relying Party rejects an unencrypted Authorization Response via the W3C Digital Credentials API.

## References

- [HAIP] section 5, 5.2
- [OpenID4VP] section 8.3, A.4
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

1. Perform a presentation for `default_query_pid` via the W3C Digital Credentials API in which the Conformance Wallet presents `default_credential_pid` in an Authorization Response that is valid except that it is not encrypted: the `data` object returned through the Digital Credentials API carries the `vp_token` directly instead of an encrypted `response`.

## Expected results

1. The Relying Party rejects the presentation: its verification result reports a failure and releases no attribute value from the presentation, and the endpoint receiving the Authorization Response does not answer with HTTP status 5xx.

## Comments

The credential format does not affect this test case; use `default_credential_pid` in a format the Relying Party requests.
