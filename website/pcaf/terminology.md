# Terminology

Terminology builds on the terminology of the [ARF]; see Annex I of the ARF for definitions. As in the FCAF, the term **Relying Party** means a service provider interacting with a Wallet Unit to request and receive attributes; it does not include Attestation Providers (see the [Methodology](index.md#systems-under-test)). **Provider** means a PID Provider or an Attestation Provider.

## Terminology mapping

Test case specifications relate both to the ARF and to the underlying standards and technical specifications, whose Standards Development Organisations (SDOs) often use other terms. The following table maps them, as a best effort; it may be inaccurate or incomplete.

| ARF term | OpenID4VP / OpenID4VCI term | ISO mdoc term |
| --- | --- | --- |
| Attestation | Credential | mobile document, mdoc |
| Attribute | claim | data element |
| PID Provider, Attestation Provider | Credential Issuer | issuing authority, issuer |
| Relying Party Instance | Verifier (client) | mdoc reader |
| Relying Party | Verifier | mdoc verifier |
| Wallet Instance | Wallet | mdoc app |
| WSCA/WSCD | key storage | secure area |
| (Wallet-relying party) access certificate | Verifier's X.509 certificate (`x509_san_dns` or `x509_hash` client identifier prefix) | reader authentication certificate |
| Wallet Provider | Wallet Provider | mdoc app provider |
| Wallet Instance Attestation | client attestation (OAuth attestation-based client authentication) | |
| Wallet Unit Attestation | key attestation | |

## Terms of the test environment

| Term | Meaning |
| --- | --- |
| Conformance Wallet | The test tool acting as Wallet Unit towards the SUT. It sends messages that are valid, or valid except for the one deviation a test step defines. |
| Positive control | The test case with a valid presentation or issuance that a negative test case starts from. It must pass in the same environment before the negative test case is executed. |
| Verification result | The outcome a Relying Party hands to the relying service for a transaction: success with the released attributes, or failure (see the [defaults](defaults.md#verification-result)). |
| Variant | One run of a test case for one declared option of the SUT, such as the credential format, the presentation flow, the grant or the category of an Attestation Provider. |
