# RP_WS_SM_TrustMechanisms_002a_UF

## Objective

Verify that the Relying Party rejects a PID in SD-JWT VC format signed by a QTSP whose anchor appears only in a Trusted List.

## References

- [ARF] Annex 2, OIA_12, OIA_15
- [SD-JWT VC] section 2.5
- [HAIP] section 6.1.1
- [RFC5280] section 6.1
- [ETSI TS 119 602]
- [ETSI TS 119 612]

## Profile applicability

- Relying Party requests credentials in IETF SD-JWT VC format.

## EUDI-wallet relevancy

EUDI_specific | EUDI_required

## Technology

- Presentation of a credential in IETF SD-JWT VC format.

## Preconditions

1. The Relying Party is set to `default_configuration_rp_1`.
2. The test environment publishes `default_trust_configuration_rp`, and the Relying Party has loaded it.
3. Test case `RP_WS_IA_MainInteraction_001a` passed in the same environment.

## Test Scenario

1. Perform a presentation for `default_query_pid` in which the Conformance Wallet presents, in an otherwise valid Authorization Response, a variant of `default_credential_pid` that differs from it only in that it is issued by `QP-A`.

## Expected results

1. The Relying Party rejects the presentation: its verification result reports a failure and releases no attribute value from the presentation, and the endpoint receiving the Authorization Response does not answer with HTTP status 5xx.

## Comments

Execute this test case once for each presentation flow the Relying Party supports (redirects, W3C Digital Credentials API).
