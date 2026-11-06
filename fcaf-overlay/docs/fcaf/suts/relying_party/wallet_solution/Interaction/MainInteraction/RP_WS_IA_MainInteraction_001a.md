# RP_WS_IA_MainInteraction_001a

## Objective

Verify that the Relying Party accepts a valid presentation of a PID in SD-JWT VC format and releases exactly the requested attributes.

## References

- [ARF] Annex 2, OIA_03c, OIA_08a, OIA_12
- [HAIP] section 5, 6.1
- [OpenID4VP] section 8.6
- [CIR 2024/2982 amended] Annex II

## Profile applicability

- Relying Party requests credentials in IETF SD-JWT VC format.

## EUDI-wallet relevancy

EUDI_specific | EUDI_required

## Technology

- Presentation of a credential in IETF SD-JWT VC format.

## Preconditions

1. The Relying Party is set to `default_configuration_rp_1`.
2. The test environment publishes `default_trust_configuration_rp`, and the Relying Party has loaded it.

## Test Scenario

1. Perform a presentation for `default_query_pid` in which the Conformance Wallet presents `default_credential_pid` in a valid Authorization Response.

## Expected results

1. The Relying Party accepts the presentation: its verification result reports success and releases exactly the attributes requested in `default_query_pid`, with the values of `default_credential_pid`.

## Comments

This test case is the positive control for the unhappy-flow test cases of the Relying Party SUT that present a credential in SD-JWT VC format. When it fails, those test cases cannot produce a meaningful verdict in the same environment.

Execute this test case once for each presentation flow the Relying Party supports (redirects, W3C Digital Credentials API).
