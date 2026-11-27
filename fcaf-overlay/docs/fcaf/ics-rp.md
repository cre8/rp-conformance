# Relying Party Implementation Conformance Statement (ICS)

This is the Implementation Conformance Statement (ICS) form for Relying Party implementations under test. It follows the same approach as the [Wallet ICS](ics.md): before testing starts, the implementer completes the `Options` column, and test selection compares the `Profile applicability` conditions of each test case with the declared answers.

Items with the ID `N/A` are surrogate ICS items that select test cases through the Technology section.

## Generic

| ID | ICS item | Options | EUDI specifics |
| --- | --- | --- | --- |
| RP.G.1 | Relying Party requests credentials in IETF SD-JWT VC format. | Yes/No | At least one of RP.G.1 and RP.G.2 is Yes; [HAIP] section 5. |
| RP.G.2 | Relying Party requests credentials in ISO/IEC 18013-5 mdoc format. | Yes/No | At least one of RP.G.1 and RP.G.2 is Yes; [HAIP] section 5. |
| RP.G.3 | Relying Party requests QEAAs. | Yes/No | |
| RP.G.4 | Relying Party requests PuB-EAAs. | Yes/No | |
| RP.G.5 | Relying Party requests non-qualified EAAs. | Yes/No | |
| RP.G.6 | Verification result channel. | API / webhook / user interface | API or webhook for automated execution; see the Verification result section of the defaults. |

## Presentation

| ID | ICS item | Options | EUDI specifics |
| --- | --- | --- | --- |
| RP.P.1 | Relying Party supports presentations via redirects. | Yes/No | [ARF] Annex 2, OIA_03b and OIA_03c. |
| RP.P.2 | Relying Party supports presentations via the W3C Digital Credentials API. | Yes/No | [ARF] Annex 2, OIA_08 and OIA_08a. |
| RP.P.3 | Relying Party uses `trusted_authorities` in DCQL queries. | Yes/No | [OpenID4VP] section 6.1.1. |
| RP.P.4 | Clock tolerance `T_skew`. | Seconds | At most 300. |
| RP.P.5 | Relying Party applies a clock tolerance greater than zero. | Yes/No | |
| RP.P.6 | Freshness window `T_kb` for key binding JWTs and device authentication. | Seconds | At most 300. |
| RP.P.7 | Transaction lifetime `T_tx`. | Duration | After `T_tx` the Relying Party rejects an Authorization Response for the transaction; [OpenID4VP] section 14.1. |
| RP.P.8 | Relying Party sets `request_uri_method` to `post`. | Yes/No | [OpenID4VP] section 5.10. |
| RP.P.9 | Relying Party redeems the response code of a presentation via redirects at its own front end. | Yes/No | [OpenID4VP] section 13.3; [HAIP] section 5.1. No for a Relying Party that is a back end only and leaves the comparison of the response code to the relying service. |
| RP.P.10 | Relying Party binds the credentials of a combined presentation by comparing their identifying attributes (attribute-based binding). | Yes/No | [ARF] section 6.6.3.10. |
| RP.P.11 | Maximum size of an Authorization Response the Relying Party accepts. | Bytes | A larger response is rejected without being processed. |
| RP.P.12 | Policy for a PID whose administrative expiry date has passed while its technical validity has not. | Reject / Accept | PID Rulebook, `expiry_date` (`date_of_expiry` in SD-JWT VC format). |
| RP.P.13 | Relying Party rejects a credential in SD-JWT VC format whose signing certificate does not name its `iss`: a `uniformResourceIdentifier` SAN equal to `iss`, or, when the certificate has no URI SAN, a `dNSName` SAN equal to the host of `iss`, in ASCII and lower case and with the port only when it is not the default port of the scheme, as a URL parser gives it. A credential without `iss` is not checked. | Yes/No | [SD-JWT VC] section 2.5: the Issuer is the subject of the end-entity certificate in `x5c`; no sentence of [SD-JWT VC] prescribes how `iss` is compared with it. Decides the `POLICY` of `RP_WS_SM_IssuerIntegrity_038_UF` to `_040_UF`. |
| RP.P.14 | Relying Party rejects a credential in mdoc format whose IssuerAuth declares `ES384` (-35) over a P-256 document signer key. | Yes/No | [RFC9053] section 2.1 only suggests the pairing of ES256, ES384 and ES512 with a curve, and [RFC9864] section 2.1 calls these identifiers polymorphic. Decides the `POLICY` of `RP_WS_SM_IssuerIntegrity_041_UF`. |
| N/A | Presentation via redirects with response mode `direct_post.jwt`. | Yes/No | [HAIP] section 5.1. |
| N/A | Presentation via the W3C Digital Credentials API with response mode `dc_api.jwt`. | Yes/No | [HAIP] section 5.2. |
| N/A | Presentation of a credential in IETF SD-JWT VC format. | Yes/No | Follows RP.G.1. |
| N/A | Presentation of a credential in ISO/IEC 18013-5 mdoc format. | Yes/No | Follows RP.G.2. |

## Revocation

| ID | ICS item | Options | EUDI specifics |
| --- | --- | --- | --- |
| RP.R.1 | Relying Party checks the revocation status of PIDs. | Yes/No | Recommended by [ARF] Annex 2, VCR_13; a Relying Party that answers No documents its risk analysis. A Relying Party that checks the revocation status of mdocs supports both status lists and identifier lists ([ARF] Annex 2, VCR_12). |
| RP.R.2 | Policy for a QEAA, PuB-EAA or non-qualified EAA without reliable revocation status. | Reject / Accept and flag as status unknown | [ARF] Annex 2, VCR_14. A PID without reliable revocation status is always rejected. |
| RP.R.3 | Meaning assigned to application-specific status values. | Values and meaning, or None | [Token Status List] section 7.1. |
| RP.R.4 | Maximum decompressed size of a status list. | Bytes | |
| RP.R.5 | Relying Party caches Status List Tokens. | Yes/No | [ARF] Annex 2, VCR_15; [Token Status List] section 13.7. A cached token is used until its `ttl` or `exp` has passed. |
| RP.R.6 | Timeout for retrieving a status list or an identifier list. | Duration | After the timeout the Relying Party has no reliable revocation status ([ARF] Annex 2, VCR_14). |
| RP.R.7 | Maximum age of a Status List Token by its `iat`. | Duration, or None | [Token Status List] section 8.3. An older token gives no reliable revocation status. |
| RP.R.8 | Relying Party refuses a Status List Token whose `iat` lies in the future by more than `T_skew`. | Yes/No | [Token Status List] section 8.3. |
| RP.R.9 | Relying Party checks the revocation status of QEAAs, PuB-EAAs and non-qualified EAAs. | Yes/No | [ARF] Annex 2, VCR_13. Applies to the categories the Relying Party requests (RP.G.3 to RP.G.5); selects the `RP_AP` test cases. |
| N/A | Status List Token in JWT format. | Yes/No | Follows RP.G.1 and RP.R.1 or RP.R.9. |
| N/A | Status List Token in CWT format. | Yes/No | Follows RP.G.2 and RP.R.1 or RP.R.9. |
| N/A | Identifier list in CWT format. | Yes/No | Follows RP.G.2 and RP.R.1 or RP.R.9. |

## Trust infrastructure

| ID | ICS item | Options | EUDI specifics |
| --- | --- | --- | --- |
| RP.T.1 | Trust list refresh interval `T_refresh`. | Duration | [ARF] Annex 2, OIA_15a. |
| RP.T.2 | Grace period `G` after the `NextUpdate` of a trust list. | Duration | During `G` the Relying Party keeps using the list and signals that it is stale; afterwards it rejects presentations that depend on it. |
| RP.T.3 | Relying Party keeps using a trust list for a grace period greater than zero after its `NextUpdate`. | Yes/No | Yes when RP.T.2 is longer than zero. |
| RP.T.4 | After retrieving a version of a trust list whose seal does not verify, the Relying Party keeps using the last valid version (Keep), or uses none until a valid version arrives (Discard). | Keep / Discard | No specification prescribes either: ETSI TS 119 602 and the ARF require the seal to be verified before a list is used, not a last-known-good list. Decides the `POLICY` of `RP_Inf_SM_TrustMechanisms_002_UF` and `_003_UF`. |
