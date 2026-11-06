# RP_WS_SM_TrustMechanisms_013b_UF

## Objective

Verify that the Relying Party rejects a PuB-EAA in mdoc format signed under a PID Provider anchor.

## References

- [ARF] Annex 2, OIA_14, OIA_15
- [ISO/IEC 18013-5] section 9.3.1
- [RFC5280] section 6.1
- [ETSI TS 119 602]

## Profile applicability

- Relying Party requests credentials in ISO/IEC 18013-5 mdoc format.
- Relying Party requests PuB-EAAs.

## EUDI-wallet relevancy

EUDI_specific | EUDI_required

## Technology

- Presentation of a credential in ISO/IEC 18013-5 mdoc format.

## Preconditions

1. The Relying Party is set to `default_configuration_rp_1`.
2. The test environment publishes `default_trust_configuration_rp`, and the Relying Party has loaded it.
3. Test case `RP_WS_IA_MainInteraction_001b` passed in the same environment.

## Test Scenario

1. Perform a presentation for `default_query_pubeaa` in which the Conformance Wallet presents, in an otherwise valid Authorization Response, a variant of `default_credential_pubeaa` that differs from it only in that it is issued by `PP-A`.

## Expected results

1. The Relying Party rejects the presentation: its verification result reports a failure and releases no attribute value from the presentation, and the endpoint receiving the Authorization Response does not answer with HTTP status 5xx.

## Comments

Execute this test case once for each presentation flow the Relying Party supports (redirects, W3C Digital Credentials API).
