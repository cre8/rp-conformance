# RP_WS_SM_Revocation_001b

## Objective

Verify that the Relying Party accepts a PID in mdoc format whose revocation status is VALID.

## References

- [Token Status List] section 6.3, 7.1, 8.3
- [ISO/IEC 18013-5 ed2]
- [HAIP] section 5.3.1
- [ARF] Annex 2, VCR_11, VCR_12, VCR_13
- [CIR 2024/2979 amended] Annex II

## Profile applicability

- Relying Party requests credentials in ISO/IEC 18013-5 mdoc format.
- Relying Party checks the revocation status of PIDs.

## EUDI-wallet relevancy

EUDI_specific | EUDI_required

## Technology

- Presentation of a credential in ISO/IEC 18013-5 mdoc format.

## Preconditions

1. The Relying Party is set to `default_configuration_rp_1`.
2. The test environment publishes `default_trust_configuration_rp`, and the Relying Party has loaded it.
3. Test case `RP_WS_IA_MainInteraction_001b` passed in the same environment.
4. Every credential presented in this test case references a status list URI from which the Relying Party has not retrieved a status list before.

## Test Scenario

1. Perform a presentation for `default_query_pid` in which the Conformance Wallet presents `default_credential_pid` in a valid Authorization Response, while the status list referenced by the credential holds the value 0x00 (VALID) at the credential's index.

## Expected results

1. The Relying Party accepts the presentation: its verification result reports success and releases exactly the attributes requested in `default_query_pid`, with the values of `default_credential_pid`. The Test Status Provider has logged a request from the Relying Party for the status list referenced by the credential.

## Comments

Execute this test case once for each presentation flow the Relying Party supports (redirects, W3C Digital Credentials API).
