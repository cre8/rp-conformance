# RP_WS_SM_Validity_005a_UF

## Objective

Verify that the Relying Party rejects an expired credential in SD-JWT VC format whose revocation status is VALID, without retrieving its status list.

## References

- [Token Status List] section 7.1, 8.3
- [ARF] Annex 2, VCR_13
- [RFC9901] section 7.1
- [SD-JWT VC] section 2.4
- [OpenID4VP] section 8.6
- [CIR 2024/2982 amended] Annex II
- [CIR 2024/2979 amended] Annex II

## Profile applicability

- Relying Party requests credentials in IETF SD-JWT VC format.
- Relying Party checks the revocation status of PIDs.

## EUDI-wallet relevancy

EUDI_generic | EUDI_required

## Technology

- Presentation of a credential in IETF SD-JWT VC format.

## Preconditions

1. The Relying Party is set to `default_configuration_rp_1`.
2. The test environment publishes `default_trust_configuration_rp`, and the Relying Party has loaded it.
3. Test case `RP_WS_IA_MainInteraction_001a` passed in the same environment.
4. Every credential presented in this test case references a status list URI from which the Relying Party has not retrieved a status list before.
5. The status list referenced by the presented credential holds the value 0x00 (VALID) at the credential's index.

## Test Scenario

1. Perform a presentation for `default_query_pid` in which the Conformance Wallet presents, in an otherwise valid Authorization Response, a variant of `default_credential_pid` that differs from it only in that its Issuer-signed JWT carries an `exp` claim set to the current time minus `T_skew` minus one hour.

## Expected results

1. The Relying Party rejects the presentation: its verification result reports a failure and releases no attribute value from the presentation, and the endpoint receiving the Authorization Response does not answer with HTTP status 5xx. The Test Status Provider logs no request from the Relying Party for the status list referenced by the credential.

## Comments

[Token Status List] section 8.3 requires the validation of the credential itself to precede any evaluation of its status, and states that status list procedures, such as fetching the Status List Token, must not be performed once the credential is found invalid, unless the use case requires further evaluation. Presenting a PID does not.

Execute this test case once for each presentation flow the Relying Party supports (redirects, W3C Digital Credentials API).
