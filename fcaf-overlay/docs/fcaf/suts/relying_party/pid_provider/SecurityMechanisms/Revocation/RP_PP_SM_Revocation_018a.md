# RP_PP_SM_Revocation_018a

## Objective

Verify that the Relying Party reads the status value at the credential's index correctly from a Status List Token in JWT format, for every permitted number of bits per status.

## References

- [Token Status List] section 5.1, 8.3
- [RFC7519] section 7.2
- [Token Status List] section 4.1
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

1. Perform a presentation for `default_query_pid` in which the Conformance Wallet presents `default_credential_pid`, issued with status index 15, in a valid Authorization Response, while the Test Status Provider serves a valid Status List Token for it with `bits` set to 1, in which the entry at index 15 holds 0x01 and every other entry holds 0x00.
2. Perform a presentation for `default_query_pid` in which the Conformance Wallet presents `default_credential_pid`, issued with status index 15, in a valid Authorization Response, while the Test Status Provider serves a valid Status List Token for it with `bits` set to 1, in which the entry at index 15 holds 0x00 and every other entry holds 0x01.
3. Perform a presentation for `default_query_pid` in which the Conformance Wallet presents `default_credential_pid`, issued with status index 7, in a valid Authorization Response, while the Test Status Provider serves a valid Status List Token for it with `bits` set to 2, in which the entry at index 7 holds 0x01 and every other entry holds 0x00.
4. Perform a presentation for `default_query_pid` in which the Conformance Wallet presents `default_credential_pid`, issued with status index 7, in a valid Authorization Response, while the Test Status Provider serves a valid Status List Token for it with `bits` set to 2, in which the entry at index 7 holds 0x00 and every other entry holds 0x01.
5. Perform a presentation for `default_query_pid` in which the Conformance Wallet presents `default_credential_pid`, issued with status index 3, in a valid Authorization Response, while the Test Status Provider serves a valid Status List Token for it with `bits` set to 4, in which the entry at index 3 holds 0x01 and every other entry holds 0x00.
6. Perform a presentation for `default_query_pid` in which the Conformance Wallet presents `default_credential_pid`, issued with status index 3, in a valid Authorization Response, while the Test Status Provider serves a valid Status List Token for it with `bits` set to 4, in which the entry at index 3 holds 0x00 and every other entry holds 0x01.
7. Perform a presentation for `default_query_pid` in which the Conformance Wallet presents `default_credential_pid`, issued with status index 1, in a valid Authorization Response, while the Test Status Provider serves a valid Status List Token for it with `bits` set to 8, in which the entry at index 1 holds 0x01 and every other entry holds 0x00.
8. Perform a presentation for `default_query_pid` in which the Conformance Wallet presents `default_credential_pid`, issued with status index 1, in a valid Authorization Response, while the Test Status Provider serves a valid Status List Token for it with `bits` set to 8, in which the entry at index 1 holds 0x00 and every other entry holds 0x01.

## Expected results

1. The Relying Party rejects the presentation: its verification result reports a failure and releases no attribute value from the presentation, and the endpoint receiving the Authorization Response does not answer with HTTP status 5xx.
2. The Relying Party accepts the presentation: its verification result reports success and releases exactly the attributes requested in `default_query_pid`, with the values of the presented credential.
3. The Relying Party rejects the presentation: its verification result reports a failure and releases no attribute value from the presentation, and the endpoint receiving the Authorization Response does not answer with HTTP status 5xx.
4. The Relying Party accepts the presentation: its verification result reports success and releases exactly the attributes requested in `default_query_pid`, with the values of the presented credential.
5. The Relying Party rejects the presentation: its verification result reports a failure and releases no attribute value from the presentation, and the endpoint receiving the Authorization Response does not answer with HTTP status 5xx.
6. The Relying Party accepts the presentation: its verification result reports success and releases exactly the attributes requested in `default_query_pid`, with the values of the presented credential.
7. The Relying Party rejects the presentation: its verification result reports a failure and releases no attribute value from the presentation, and the endpoint receiving the Authorization Response does not answer with HTTP status 5xx.
8. The Relying Party accepts the presentation: its verification result reports success and releases exactly the attributes requested in `default_query_pid`, with the values of the presented credential.

## Comments

Each index is the last entry of the second byte of the status list, so a Relying Party that reads the bits in the wrong order within a byte, or computes the byte offset incorrectly, reads a neighbouring entry. Every step uses a newly issued credential.

Execute this test case once for each presentation flow the Relying Party supports (redirects, W3C Digital Credentials API).
