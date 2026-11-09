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
| N/A | Status List Token in JWT format. | Yes/No | Follows RP.G.1 and RP.R.1. |
| N/A | Status List Token in CWT format. | Yes/No | Follows RP.G.2 and RP.R.1. |
| N/A | Identifier list in CWT format. | Yes/No | Follows RP.G.2 and RP.R.1. |

## Trust infrastructure

| ID | ICS item | Options | EUDI specifics |
| --- | --- | --- | --- |
| RP.T.1 | Trust list refresh interval `T_refresh`. | Duration | [ARF] Annex 2, OIA_15a. |
| RP.T.2 | Grace period `G` after the `NextUpdate` of a trust list. | Duration | During `G` the Relying Party keeps using the list and signals that it is stale; afterwards it rejects presentations that depend on it. |
