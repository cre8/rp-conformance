# RP_WS_SM_TrustMechanisms_012b

## Objective

Verify that the Relying Party accepts a PuB-EAA in mdoc format signed under the root of trust defined for PuB-EAAs.

## References

- [ARF] Annex 2, OIA_14, PuBPNot_06
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

1. Perform a presentation for `default_query_pubeaa` in which the Conformance Wallet presents `default_credential_pubeaa` in a valid Authorization Response.

## Expected results

1. The Relying Party accepts the presentation: its verification result reports success and releases exactly the attributes requested in `default_query_pubeaa`, with the values of `default_credential_pubeaa`.

## Comments

Execute this test case once for each presentation flow the Relying Party supports (redirects, W3C Digital Credentials API).
