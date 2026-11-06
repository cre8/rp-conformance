# RP_WS_SM_TrustMechanisms_016b_UF

## Objective

Verify that the Relying Party enforces the `trusted_authorities` of its own request and rejects a PID in mdoc format from another trusted PID Provider.

## References

- [OpenID4VP] section 6.1.1.1, 14.9
- [HAIP] section 5
- [ISO/IEC 18013-5] section 9.3.1
- [RFC5280] section 6.1
- [CIR 2024/2982 amended] Annex II

## Profile applicability

- Relying Party requests credentials in ISO/IEC 18013-5 mdoc format.
- Relying Party uses `trusted_authorities` in DCQL queries.

## EUDI-wallet relevancy

EUDI_generic | EUDI_required

## Technology

- Presentation of a credential in ISO/IEC 18013-5 mdoc format.

## Preconditions

1. The Relying Party is set to `default_configuration_rp_1`.
2. The test environment publishes `default_trust_configuration_rp`, and the Relying Party has loaded it.
3. Test case `RP_WS_IA_MainInteraction_001b` passed in the same environment.
4. The Relying Party is configured to restrict `default_query_pid` with a `trusted_authorities` entry of type `aki` that names only the PID/Issuance anchor of `PP-A`.

## Test Scenario

1. Perform a presentation for `default_query_pid` in which the Conformance Wallet presents, in an otherwise valid Authorization Response, a variant of `default_credential_pid` that differs from it only in that it is issued by `PP-B`.

## Expected results

1. The Relying Party rejects the presentation: its verification result reports a failure and releases no attribute value from the presentation, and the endpoint receiving the Authorization Response does not answer with HTTP status 5xx.

## Comments

[OpenID4VP] section 14.9 states that the Verifier must not rely on the Wallet to enforce the constraints of its request.

Execute this test case once for each presentation flow the Relying Party supports (redirects, W3C Digital Credentials API).
