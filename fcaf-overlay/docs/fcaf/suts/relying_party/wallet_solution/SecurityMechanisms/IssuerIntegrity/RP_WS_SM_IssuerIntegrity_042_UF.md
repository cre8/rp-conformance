# RP_WS_SM_IssuerIntegrity_042_UF

## Objective

Verify that the Relying Party rejects a credential in mdoc format whose IssuerAuth declares `ESP384` (-51), which is ECDSA on P-384 with SHA-384, and is signed by the document signer's P-256 key.

## References

- [RFC9864] section 2.1
- [RFC9360] section 5
- [ISO/IEC 18013-5] section 9.1.2 (not verified)
- [CIR 2024/2982 amended] Annex II

## Profile applicability

- Relying Party requests credentials in ISO/IEC 18013-5 mdoc format.

## EUDI-wallet relevancy

EUDI_generic | EUDI_required

## Technology

- Presentation of a credential in ISO/IEC 18013-5 mdoc format.

## Preconditions

1. The Relying Party is set to `default_configuration_rp_1`.
2. The test environment publishes `default_trust_configuration_rp`, and the Relying Party has loaded it.
3. Test case `RP_WS_IA_MainInteraction_001b` passed in the same environment.

## Test Scenario

1. Perform a presentation for `default_query_pid` in which the Conformance Wallet presents, in an otherwise valid Authorization Response, a variant of `default_credential_pid` that differs from it only in that the protected header of its `IssuerAuth` structure declares `alg` -51 (`ESP384`, ECDSA on P-384 with SHA-384), and the signature is made with SHA-384 by the P-256 key of the document signer, `r` and `s` 32 octets each.

## Expected results

1. The Relying Party rejects the presentation: its verification result reports a failure and releases no attribute value from the presentation, and the endpoint receiving the Authorization Response does not answer with HTTP status 5xx.

## Comments

[RFC9864] section 2.1 defines `ESP384` as ECDSA using the P-384 curve and SHA-384, and [RFC9360] section 5 requires the key in a certificate to be checked against the algorithm to be used, so the P-256 key of the document signer does not fit it.

Execute this test case once for each presentation flow the Relying Party supports (redirects, W3C Digital Credentials API).
