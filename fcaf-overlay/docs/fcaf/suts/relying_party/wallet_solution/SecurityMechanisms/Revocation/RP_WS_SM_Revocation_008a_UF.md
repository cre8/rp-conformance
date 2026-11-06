# RP_WS_SM_Revocation_008a_UF

## Objective

Verify that the Relying Party rejects a PID in SD-JWT VC format without revocation information whose validity period is longer than 24 hours.

## References

- [Token Status List] section 6.2, 7.1, 8.3
- [SD-JWT VC] section 2.4
- [HAIP] section 6.1
- [ARF] Annex 2, VCR_11a, VCR_13
- [ARF] Annex 2, VCR_01, VCR_01b, VCR_14
- [CIR 2024/2979 amended] Annex II

## Profile applicability

- Relying Party requests credentials in IETF SD-JWT VC format.
- Relying Party checks the revocation status of PIDs.

## EUDI-wallet relevancy

EUDI_specific | EUDI_required

## Technology

- Presentation of a credential in IETF SD-JWT VC format.

## Preconditions

1. The Relying Party is set to `default_configuration_rp_1`.
2. The test environment publishes `default_trust_configuration_rp`, and the Relying Party has loaded it.
3. Test case `RP_WS_IA_MainInteraction_001a` passed in the same environment.
4. Every credential presented in this test case references a status list URI from which the Relying Party has not retrieved a status list before.

## Test Scenario

1. Perform a presentation for `default_query_pid` in which the Conformance Wallet presents, in an otherwise valid Authorization Response, a variant of `default_credential_pid` that differs from it only in that it carries no `status` claim.

## Expected results

1. The Relying Party rejects the presentation: its verification result reports a failure and releases no attribute value from the presentation, and the endpoint receiving the Authorization Response does not answer with HTTP status 5xx.

## Comments

A PID valid for longer than 24 hours must carry revocation information ([ARF] Annex 2, VCR_01 and VCR_01b). Without it no reliable revocation status is available, and the Relying Party SUT rejects PIDs in that case.

Execute this test case once for each presentation flow the Relying Party supports (redirects, W3C Digital Credentials API).
