# RP_WS_SM_IssuerIntegrity_018_UF

## Objective

Record whether the Relying Party accepts a credential in SD-JWT VC format whose `iss` claim is in a disclosure instead of the Issuer-signed JWT.

## References

- [SD-JWT VC] section 2.2.2.2
- [RFC9901] section 9.7
- [CIR 2024/2982 amended] Annex II

## Profile applicability

- Relying Party requests credentials in IETF SD-JWT VC format.

## EUDI-wallet relevancy

EUDI_generic | EUDI_optional

## Technology

- Presentation of a credential in IETF SD-JWT VC format.

## Preconditions

1. The Relying Party is set to `default_configuration_rp_1`.
2. The test environment publishes `default_trust_configuration_rp`, and the Relying Party has loaded it.
3. Test case `RP_WS_IA_MainInteraction_001a` passed in the same environment.

## Test Scenario

1. Perform a presentation for `default_query_pid` in which the Conformance Wallet presents, in an otherwise valid Authorization Response, a variant of `default_credential_pid` that differs from it only in that its `iss` claim is not in the payload of its Issuer-signed JWT but in a disclosure referenced from the `_sd` array of the payload.

## Expected results

1. Whether the Relying Party accepts or rejects the presentation is recorded; HTTP 5xx fails.

## Comments

Informational (catalogue section 8.4): [SD-JWT VC] section 2.2.2.2 forbids the Issuer to put `iss` in a disclosure, and no sentence of [SD-JWT VC] or [RFC9901] requires the Relying Party to refuse the credential. [RFC9901] section 9.7 requires that Verifiers "ensure that all claims they deem necessary for checking the validity of an SD-JWT in the given context are present (or disclosed, respectively)".

Execute this test case once for each presentation flow the Relying Party supports (redirects, W3C Digital Credentials API).
