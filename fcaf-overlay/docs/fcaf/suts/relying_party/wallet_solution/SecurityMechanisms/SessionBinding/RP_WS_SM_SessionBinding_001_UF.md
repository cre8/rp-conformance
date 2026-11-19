# RP_WS_SM_SessionBinding_001_UF

## Objective

Verify that the Relying Party rejects a presentation in SD-JWT VC format whose KB-JWT carries a `nonce` other than that of its request.

## References

- [OpenID4VP] section 14.1.2, B.3.6
- [RFC9901] section 7.3
- [CIR 2024/2982 amended] Annex II

## Profile applicability

- Relying Party requests credentials in IETF SD-JWT VC format.

## EUDI-wallet relevancy

EUDI_generic | EUDI_required

## Technology

- Presentation of a credential in IETF SD-JWT VC format.

## Preconditions

1. The Relying Party is set to `default_configuration_rp_1`.
2. The test environment publishes `default_trust_configuration_rp`, and the Relying Party has loaded it.
3. Test case `RP_WS_IA_MainInteraction_001a` passed in the same environment.

## Test Scenario

1. Perform a presentation for `default_query_pid` in which the Conformance Wallet presents `default_credential_pid` in an Authorization Response that is valid except that the `nonce` claim of its KB-JWT is a newly generated random value instead of the `nonce` of the request.
2. Perform a presentation for `default_query_pid` in which the Conformance Wallet presents `default_credential_pid` in an Authorization Response that is valid except that its KB-JWT has no `nonce` claim.

## Expected results

1. The Relying Party rejects the presentation: its verification result reports a failure and releases no attribute value from the presentation, and the endpoint receiving the Authorization Response does not answer with HTTP status 5xx.
2. The Relying Party rejects the presentation: its verification result reports a failure and releases no attribute value from the presentation, and the endpoint receiving the Authorization Response does not answer with HTTP status 5xx.

## Comments

The OIDF verifier test module `oid4vp-1final-verifier-invalid-kb-jwt-nonce` covers the same objective.

Execute this test case once for each presentation flow the Relying Party supports (redirects, W3C Digital Credentials API).
