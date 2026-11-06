# RP_PP_SM_Revocation_016a_UF

## Objective

Verify that the Relying Party refuses a Status List Token in JWT format whose status list decompresses to more than its declared maximum size, and stays available.

## References

- [Token Status List] section 5.1, 8.3
- [RFC7519] section 7.2
- [Token Status List] section 4.1, 11.1
- [ARF] Annex 2, PPNot_05, VCR_13, VCR_14
- [ETSI TS 119 602]
- [CIR 2024/2979 amended] Annex II

## Profile applicability

- Relying Party requests credentials in IETF SD-JWT VC format.
- Relying Party checks the revocation status of PIDs.

## EUDI-wallet relevancy

EUDI_generic | EUDI_required

## Technology

- Presentation of a credential in IETF SD-JWT VC format.
- Status List Token in JWT format.

## Preconditions

1. The Relying Party is set to `default_configuration_rp_1`.
2. The test environment publishes `default_trust_configuration_rp`, and the Relying Party has loaded it.
3. Test case `RP_WS_IA_MainInteraction_001a` passed in the same environment.
4. Every credential presented in this test case references a status list URI from which the Relying Party has not retrieved a status list before.

## Test Scenario

1. Perform a presentation for `default_query_pid` in which the Conformance Wallet presents `default_credential_pid` in a valid Authorization Response, while the Test Status Provider serves, for the status list referenced by the credential, a Status List Token that holds the value 0x00 at the credential's index and is valid in every other respect, except that its `lst` value decompresses to more bytes than the maximum status list size the Relying Party declares, for example a ZLIB stream that inflates to 1 GiB of zero bytes.
2. Perform a presentation for `default_query_pid` in which the Conformance Wallet presents a newly issued `default_credential_pid` in a valid Authorization Response, immediately after the previous step, while the status list referenced by that credential is valid and holds the value 0x00 at its index.

## Expected results

1. The Relying Party rejects the presentation: its verification result reports a failure and releases no attribute value from the presentation, and the endpoint receiving the Authorization Response does not answer with HTTP status 5xx.
2. The Relying Party accepts the presentation: its verification result reports success and releases exactly the attributes requested in `default_query_pid`, with the values of the presented credential.

## Comments

Every entry of the inflated list holds 0x00, so a Relying Party that processes the list without a size limit accepts the presentation in the first step.

A Status List Token that cannot be used leaves no reliable revocation status. For PIDs the Relying Party SUT rejects the presentation in that case; for QEAA, PuB-EAA and non-qualified EAA the policy declared in the ICS applies (see [ARF] Annex 2, VCR_14).

Execute this test case once for each presentation flow the Relying Party supports (redirects, W3C Digital Credentials API).
