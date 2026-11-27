# RP_WS_SM_SessionBinding_012_UF

## Objective

Verify that the Relying Party rejects a presentation in mdoc format via the W3C Digital Credentials API whose device signature covers a SessionTranscript with the handover of redirects (`OpenID4VPHandover`) instead of `OpenID4VPDCAPIHandover`.

## References

- [OpenID4VP] section B.2.6.2
- [OpenID4VP] section B.2.6
- [ISO/IEC 18013-5] section 9.1.3
- [CIR 2024/2982 amended] Annex II

## Profile applicability

- Relying Party requests credentials in ISO/IEC 18013-5 mdoc format.
- Relying Party supports presentations via the W3C Digital Credentials API.

## EUDI-wallet relevancy

EUDI_generic | EUDI_required

## Technology

- Presentation of a credential in ISO/IEC 18013-5 mdoc format.
- Presentation via the W3C Digital Credentials API with response mode `dc_api.jwt`.

## Preconditions

1. The Relying Party is set to `default_configuration_rp_1`.
2. The test environment publishes `default_trust_configuration_rp`, and the Relying Party has loaded it.
3. Test case `RP_WS_IA_MainInteraction_001b` passed in the same environment.

## Test Scenario

1. Perform a presentation for `default_query_pid` via the W3C Digital Credentials API in which the Conformance Wallet presents `default_credential_pid` in an Authorization Response that is valid except that the SessionTranscript its device signature covers carries an `OpenID4VPHandover`, computed with the `client_id` of the request and the Origin of the page as `response_uri`, instead of the `OpenID4VPDCAPIHandover` of a request made through the W3C Digital Credentials API.

## Expected results

1. The Relying Party rejects the presentation: its verification result reports a failure and releases no attribute value from the presentation, and the endpoint receiving the Authorization Response does not answer with HTTP status 5xx.
