# RP_PP_SM_Revocation_001a

## Objective

Verify that the Relying Party evaluates a valid Status List Token in JWT format and accepts a PID whose status is VALID.

## References

- [Token Status List] section 5.1, 8.3
- [RFC7519] section 7.2
- [HAIP] section 6.1
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

1. Perform a presentation for `default_query_pid` in which the Conformance Wallet presents `default_credential_pid` in a valid Authorization Response, while the Test Status Provider serves, for the status list referenced by the credential, a Status List Token with `typ` `statuslist+jwt`, a `sub` claim equal to the credential's status `uri`, an `iat` claim, an `exp` claim in the future and a `ttl` claim, signed by a certificate under the revocation anchor of `PP-A`, that holds the value 0x00 at the credential's index.

## Expected results

1. The Relying Party accepts the presentation: its verification result reports success and releases exactly the attributes requested in `default_query_pid`, with the values of `default_credential_pid`. The Test Status Provider has logged a request from the Relying Party for the status list referenced by the credential.

## Comments

Execute this test case once for each presentation flow the Relying Party supports (redirects, W3C Digital Credentials API).
