# RP_WS_SM_SessionBinding_011_UF

## Objective

Verify that the Relying Party rejects a presentation in mdoc format via redirects whose device signature covers a SessionTranscript with the handover of the W3C Digital Credentials API (`OpenID4VPDCAPIHandover`) instead of `OpenID4VPHandover`.

## References

- [OpenID4VP] section B.2.6.1
- [OpenID4VP] section B.2.6
- [ISO/IEC 18013-5] section 9.1.3
- [CIR 2024/2982 amended] Annex II

## Profile applicability

- Relying Party requests credentials in ISO/IEC 18013-5 mdoc format.
- Relying Party supports presentations via redirects.

## EUDI-wallet relevancy

EUDI_generic | EUDI_required

## Technology

- Presentation of a credential in ISO/IEC 18013-5 mdoc format.
- Presentation via redirects with response mode `direct_post.jwt`.

## Preconditions

1. The Relying Party is set to `default_configuration_rp_1`.
2. The test environment publishes `default_trust_configuration_rp`, and the Relying Party has loaded it.
3. Test case `RP_WS_IA_MainInteraction_001b` passed in the same environment.

## Test Scenario

1. Perform a presentation for `default_query_pid` via redirects in which the Conformance Wallet presents `default_credential_pid` in an Authorization Response that is valid except that the SessionTranscript its device signature covers carries an `OpenID4VPDCAPIHandover`, computed with the Origin of the `response_uri` of the request, instead of the `OpenID4VPHandover` of a request made by redirect.

## Expected results

1. The Relying Party rejects the presentation: its verification result reports a failure and releases no attribute value from the presentation, and the endpoint receiving the Authorization Response does not answer with HTTP status 5xx.
