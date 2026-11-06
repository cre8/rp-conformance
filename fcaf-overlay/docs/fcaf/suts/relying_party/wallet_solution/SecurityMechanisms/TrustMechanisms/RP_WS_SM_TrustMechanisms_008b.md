# RP_WS_SM_TrustMechanisms_008b

## Objective

Verify that the Relying Party starts accepting PIDs in mdoc format from a PID Provider once its entry is added to the PID Provider list.

## References

- [ARF] Annex 2, OIA_15a
- [ISO/IEC 18013-5] section 9.3.1
- [RFC5280] section 6.1
- [ETSI TS 119 602]

## Profile applicability

- Relying Party requests credentials in ISO/IEC 18013-5 mdoc format.

## EUDI-wallet relevancy

EUDI_specific | EUDI_required

## Technology

- Presentation of a credential in ISO/IEC 18013-5 mdoc format.

## Preconditions

1. The Relying Party is set to `default_configuration_rp_1`.
2. The test environment publishes `default_trust_configuration_rp`, and the Relying Party has loaded it.
3. Test case `RP_WS_IA_MainInteraction_001b` passed in the same environment.

## Test Scenario

1. Perform a presentation for `default_query_pid` in which the Conformance Wallet presents, in an otherwise valid Authorization Response, a variant of `default_credential_pid` that differs from it only in that it is issued by `PP-C`.
2. The Test Trust Infrastructure publishes a new version of `TL-PID` that adds an entry for `PP-C` with a granted PID/Issuance and PID/Revocation service. Wait until the Relying Party has retrieved it, at most `T_refresh`.
3. Perform a presentation for `default_query_pid` in which the Conformance Wallet presents, in an otherwise valid Authorization Response, a variant of `default_credential_pid` that differs from it only in that it is issued by `PP-C`.

## Expected results

1. The Relying Party rejects the presentation: its verification result reports a failure and releases no attribute value from the presentation, and the endpoint receiving the Authorization Response does not answer with HTTP status 5xx.
2. The Test Trust Infrastructure logs a retrieval of the new version of `TL-PID` by the Relying Party.
3. The Relying Party accepts the presentation: its verification result reports success and releases exactly the attributes requested in `default_query_pid`, with the values of the presented credential.

## Comments

Restore the previous version of `TL-PID` after the test case.

Execute this test case once for each presentation flow the Relying Party supports (redirects, W3C Digital Credentials API).
