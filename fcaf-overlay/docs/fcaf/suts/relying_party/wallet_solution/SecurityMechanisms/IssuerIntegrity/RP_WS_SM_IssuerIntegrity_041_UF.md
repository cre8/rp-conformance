# RP_WS_SM_IssuerIntegrity_041_UF

## Objective

Verify that the Relying Party handles a credential in mdoc format whose IssuerAuth declares `ES384` (-35) and is signed with SHA-384 by the document signer's P-256 key, as it declares.

## References

- [RFC9053] section 2.1
- [RFC9864] section 2.1, 4.2.2, 4.4, 7
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

1. Perform a presentation for `default_query_pid` in which the Conformance Wallet presents, in an otherwise valid Authorization Response, a variant of `default_credential_pid` that differs from it only in that the protected header of its `IssuerAuth` structure declares `alg` -35 (`ES384`), and the signature is made with SHA-384 by the P-256 key of the document signer, `r` and `s` 32 octets each.

## Expected results

1. If the Relying Party declares in its ICS that it rejects a credential in mdoc format whose IssuerAuth declares `ES384` (-35) over a P-256 document signer key (RP.P.14 Yes): the Relying Party rejects the presentation: its verification result reports a failure and releases no attribute value from the presentation, and the endpoint receiving the Authorization Response does not answer with HTTP status 5xx. If it declares that it does not (RP.P.14 No), it accepts the presentation: its verification result reports success and releases exactly the attributes requested in `default_query_pid`, with the values of the presented credential.

## Comments

[RFC9053] section 2.1 only suggests that SHA-384 be used with P-384, and [RFC9864] section 2.1 calls `ES384` polymorphic, since it does not name a curve; section 4.2.2 deprecates it, which section 4.4 defines as a SHOULD for new deployments. [RFC9864] section 7 says "A cryptographic key MUST be used with only a single algorithm unless the use of the same key with different algorithms is proven secure.", and the document signer key also signs `ES256` in `RP_WS_IA_MainInteraction_001b`. To hold a key to one algorithm, section 7 recommends the algorithm parameter of a JSON Web Key or a COSE Key "unless there exists some other mechanism for ensuring that the key is used as intended", and names no other mechanism for a signing key; this key comes in an X.509 certificate in `x5chain`, which is neither, so section 7 does not tell the Relying Party which one algorithm the key has. This test case reads the MUST as one the Relying Party can apply only through such a mechanism. [ISO/IEC 18013-5] was not verified, so ICS RP.P.14 declares whether the Relying Party refuses `ES384` over a P-256 key. `IssuerIntegrity_042_UF` presents a signature made the same way under the fully specified `ESP384`.

Execute this test case once for each presentation flow the Relying Party supports (redirects, W3C Digital Credentials API).
