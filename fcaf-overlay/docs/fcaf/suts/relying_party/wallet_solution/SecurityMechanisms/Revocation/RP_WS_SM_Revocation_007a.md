# RP_WS_SM_Revocation_007a

## Objective

Verify that the Relying Party accepts a PID in SD-JWT VC format without revocation information whose validity period is shorter than 24 hours.

## References

- [Token Status List] section 6.2, 7.1, 8.3
- [SD-JWT VC] section 2.4
- [HAIP] section 6.1
- [ARF] Annex 2, VCR_11a, VCR_13
- [ARF] Annex 2, VCR_01, VCR_01b
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

1. Perform a presentation for `default_query_pid` in which the Conformance Wallet presents `default_credential_pid_short` in a valid Authorization Response.

## Expected results

1. The Relying Party accepts the presentation: its verification result reports success and releases exactly the attributes requested in `default_query_pid`, with the values of `default_credential_pid_short`.

## Comments

The OIDF verifier test module `oid4vp-1final-verifier-present-credential-without-status` covers the same objective.

Execute this test case once for each presentation flow the Relying Party supports (redirects, W3C Digital Credentials API).
