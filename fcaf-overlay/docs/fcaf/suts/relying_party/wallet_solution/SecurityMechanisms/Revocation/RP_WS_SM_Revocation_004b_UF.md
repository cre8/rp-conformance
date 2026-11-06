# RP_WS_SM_Revocation_004b_UF

## Objective

Verify that the Relying Party does not treat an application-specific status value as VALID for a PID in mdoc format, unless it declared a meaning for that value.

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

EUDI_generic | EUDI_undefined

## Technology

- Presentation of a credential in ISO/IEC 18013-5 mdoc format.

## Preconditions

1. The Relying Party is set to `default_configuration_rp_1`.
2. The test environment publishes `default_trust_configuration_rp`, and the Relying Party has loaded it.
3. Test case `RP_WS_IA_MainInteraction_001b` passed in the same environment.
4. Every credential presented in this test case references a status list URI from which the Relying Party has not retrieved a status list before.

## Test Scenario

1. Perform a presentation for `default_query_pid` in which the Conformance Wallet presents `default_credential_pid` in a valid Authorization Response, while the status list referenced by the credential holds the value 0x03 (application-specific) at the credential's index.

## Expected results

1. If the Relying Party declares no meaning for the status value 0x03 in its ICS: the Relying Party rejects the presentation: its verification result reports a failure and releases no attribute value from the presentation, and the endpoint receiving the Authorization Response does not answer with HTTP status 5xx. If it declares a meaning: it handles the presentation as declared.

## Comments

Execute this test case once for each presentation flow the Relying Party supports (redirects, W3C Digital Credentials API).
