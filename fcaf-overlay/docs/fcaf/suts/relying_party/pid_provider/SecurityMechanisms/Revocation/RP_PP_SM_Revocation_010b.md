# RP_PP_SM_Revocation_010b

## Objective

Verify that the Relying Party uses a Status List Token in CWT format signed under the revocation anchor of the entity that issued the credential.

## References

- [Token Status List] section 5.2, 8.3
- [RFC8392] section 7.2
- [Token Status List] section 11.3
- [ARF] Annex 2, PPNot_05, VCR_13, VCR_14
- [ETSI TS 119 602]
- [CIR 2024/2979 amended] Annex II

## Profile applicability

- Relying Party requests credentials in ISO/IEC 18013-5 mdoc format.
- Relying Party checks the revocation status of PIDs.

## EUDI-wallet relevancy

EUDI_specific | EUDI_required

## Technology

- Presentation of a credential in ISO/IEC 18013-5 mdoc format.
- Status List Token in CWT format.

## Preconditions

1. The Relying Party is set to `default_configuration_rp_1`.
2. The test environment publishes `default_trust_configuration_rp`, and the Relying Party has loaded it.
3. Test case `RP_WS_IA_MainInteraction_001b` passed in the same environment.
4. Every credential presented in this test case references a status list URI from which the Relying Party has not retrieved a status list before.

## Test Scenario

1. Perform a presentation for `default_query_pid` in which the Conformance Wallet presents `default_credential_pid` in a valid Authorization Response, while the Test Status Provider serves a valid Status List Token for it that holds the value 0x00 at the credential's index and is signed by a certificate under the revocation anchor `CA-PP-A-REV` of `PP-A`.
2. Perform a presentation for `default_query_pid` in which the Conformance Wallet presents a variant of `default_credential_pid` issued by `PP-B` in a valid Authorization Response, while the Test Status Provider serves a valid Status List Token for it that holds the value 0x00 at the credential's index and is signed with the same key and certificate as that credential.

## Expected results

1. The Relying Party accepts the presentation: its verification result reports success and releases exactly the attributes requested in `default_query_pid`, with the values of `default_credential_pid`. The Test Status Provider has logged a request from the Relying Party for the status list referenced by the credential.
2. The Relying Party accepts the presentation: its verification result reports success and releases exactly the attributes requested in `default_query_pid`, with the values of the presented credential. The Test Status Provider has logged a request from the Relying Party for the status list referenced by the credential.

## Comments

In the second step the issuance CA of `PP-B` is also published under the revocation service of `PP-B`, which is how `default_trust_configuration_rp` represents an issuer that signs its status lists with its issuance key ([Token Status List] section 11.3).

Execute this test case once for each presentation flow the Relying Party supports (redirects, W3C Digital Credentials API).
