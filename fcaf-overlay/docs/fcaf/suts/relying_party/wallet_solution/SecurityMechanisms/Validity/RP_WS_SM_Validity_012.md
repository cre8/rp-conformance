# RP_WS_SM_Validity_012

## Objective

Verify that the Relying Party accepts a credential in mdoc format whose expected update time has passed while its validity period has not ended.

## References

- [ISO/IEC 18013-5] section 9.1.2.4
- [ISO/IEC 18013-5] section 9.3.1
- [OpenID4VP] section 8.6
- [HAIP] section 5.3.1
- [CIR 2024/2982 amended] Annex II

## Profile applicability

- Relying Party requests credentials in ISO/IEC 18013-5 mdoc format.

## EUDI-wallet relevancy

EUDI_generic | EUDI_required

## Technology

- Presentation of a credential in ISO/IEC 18013-5 mdoc format.

## Preconditions

1. The Relying Party is set to `default_configuration_rp_1`.
2. The test environment publishes `default_trust_configuration_rp`, and the Relying Party has loaded it.
3. Test case `RP_WS_IA_MainInteraction_001b` passed in the same environment.

## Test Scenario

1. Perform a presentation for `default_query_pid` in which the Conformance Wallet presents, in an otherwise valid Authorization Response, a variant of `default_credential_pid` that differs from it only in that the `expectedUpdate` value in the `validityInfo` of its MSO lies one day in the past, while `validUntil` lies in the future.

## Expected results

1. The Relying Party accepts the presentation: its verification result reports success and releases exactly the attributes requested in `default_query_pid`, with the values of the presented credential.

## Comments

Execute this test case once for each presentation flow the Relying Party supports (redirects, W3C Digital Credentials API).
