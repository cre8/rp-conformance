# RP_WS_SM_IssuerIntegrity_038_UF

## Objective

Verify that the Relying Party handles a credential in SD-JWT VC format whose signing certificate, issued under the right anchor, names another issuer's URI instead of the credential's `iss`, as it declares.

## References

- [SD-JWT VC] section 2.5, 6.2
- [RFC5280] section 4.2.1.6
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

1. Perform a presentation for `default_query_pid` in which the Conformance Wallet presents, in an otherwise valid Authorization Response, a variant of `default_credential_pid` that differs from it only in that it is signed by another certificate issued under the issuance CA `CA-PP-A` of `PP-A`, whose only subject alternative name is the URI `https://other-issuer.rp-test`, so it does not name the `iss` of the credential.

## Expected results

1. If the Relying Party declares in its ICS that it rejects a credential in SD-JWT VC format whose signing certificate does not name its `iss` by a `uniformResourceIdentifier` SAN equal to `iss` or, when the certificate has no URI SAN, by a `dNSName` SAN equal to the host of `iss`, in ASCII and lower case and with the port only when it is not the default port of the scheme, as a URL parser gives it (RP.P.13 Yes): the Relying Party rejects the presentation: its verification result reports a failure and releases no attribute value from the presentation, and the endpoint receiving the Authorization Response does not answer with HTTP status 5xx. If it declares that it does not (RP.P.13 No), it accepts the presentation: its verification result reports success and releases exactly the attributes requested in `default_query_pid`, with the values of the presented credential.

## Comments

[SD-JWT VC] section 2.5 makes the Issuer the subject of the end-entity certificate and requires the SD-JWT VC to be rejected when the key cannot be validated as the Issuer's, but no sentence of [SD-JWT VC] says how `iss` is compared with that certificate. Whether the Relying Party checks it is declared in ICS RP.P.13. A certificate names `iss` by a URI subject alternative name equal to it, or, when it names no URI, by a DNS name equal to the host of `iss`, in ASCII and lower case and with the port only when it is not the default port of the scheme, as a URL parser gives it.

Execute this test case once for each presentation flow the Relying Party supports (redirects, W3C Digital Credentials API).
