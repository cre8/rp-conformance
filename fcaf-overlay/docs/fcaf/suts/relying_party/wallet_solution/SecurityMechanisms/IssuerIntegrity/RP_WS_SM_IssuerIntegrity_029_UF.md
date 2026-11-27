# RP_WS_SM_IssuerIntegrity_029_UF

## Objective

Record whether the Relying Party accepts a credential in mdoc format whose IssuerAuth lists in `crit` a header parameter that the Relying Party does not understand.

## References

- [RFC9052] section 3.1
- [ISO/IEC 18013-5] section 9.1.2 (not verified)
- [CIR 2024/2982 amended] Annex II

## Profile applicability

- Relying Party requests credentials in ISO/IEC 18013-5 mdoc format.

## EUDI-wallet relevancy

EUDI_generic | EUDI_optional

## Technology

- Presentation of a credential in ISO/IEC 18013-5 mdoc format.

## Preconditions

1. The Relying Party is set to `default_configuration_rp_1`.
2. The test environment publishes `default_trust_configuration_rp`, and the Relying Party has loaded it.
3. Test case `RP_WS_IA_MainInteraction_001b` passed in the same environment.

## Test Scenario

1. Perform a presentation for `default_query_pid` in which the Conformance Wallet presents, in an otherwise valid Authorization Response, a variant of `default_credential_pid` that differs from it only in that the protected header of its `IssuerAuth` structure carries the private label -65537 with the value 1 and lists it in `crit` (label 2), and the signature is made over those bytes.

## Expected results

1. Whether the Relying Party accepts or rejects the presentation is recorded; HTTP 5xx fails.

## Comments

Informational (catalogue section 8.4): [RFC9052] section 3.1 says that `crit` lists the header parameters an application processing the message "is required to understand", but no sentence of [RFC9052] says what a recipient does with a listed parameter it does not understand; the one fatal error it names, a listed label whose header parameter is not in the protected bucket, does not arise here. [ISO/IEC 18013-5] was not verified.

Execute this test case once for each presentation flow the Relying Party supports (redirects, W3C Digital Credentials API).
