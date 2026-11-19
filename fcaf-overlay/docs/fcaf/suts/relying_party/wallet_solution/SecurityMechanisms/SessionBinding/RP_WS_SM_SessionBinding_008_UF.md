# RP_WS_SM_SessionBinding_008_UF

## Objective

Verify that the Relying Party rejects a presentation in mdoc format via redirects whose device signature covers a SessionTranscript that does not match its request.

## References

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

1. Perform a presentation for `default_query_pid` via redirects in which the Conformance Wallet presents `default_credential_pid` in an Authorization Response that is valid except that the SessionTranscript its device signature covers is computed with a newly generated `nonce` instead of the `nonce` of the request.
2. Perform a presentation for `default_query_pid` via redirects in which the Conformance Wallet presents `default_credential_pid` in an Authorization Response that is valid except that the `OpenID4VPHandover` in the SessionTranscript its device signature covers is computed with the Client Identifier of another Relying Party instead of the `client_id` of the request.
3. Perform a presentation for `default_query_pid` via redirects in which the Conformance Wallet presents `default_credential_pid` in an Authorization Response that is valid except that the `OpenID4VPHandover` in the SessionTranscript its device signature covers is computed with a `response_uri` other than that of the request.
4. Perform a presentation for `default_query_pid` via redirects in which the Conformance Wallet presents `default_credential_pid` in an Authorization Response that is valid except that the SessionTranscript its device signature covers is computed with the JWK thumbprint of a newly generated key instead of that of the encryption key of the request.
5. Perform a presentation for `default_query_pid` via redirects in which the Conformance Wallet presents `default_credential_pid` in an Authorization Response that is valid except that the `OpenID4VPHandover` in the SessionTranscript its device signature covers is computed with the Client Identifier of the request without its prefix `x509_hash:`.
6. Perform a presentation for `default_query_pid` via redirects in which the Conformance Wallet presents `default_credential_pid` in an Authorization Response that is valid except that the SessionTranscript its device signature covers is computed with `null` as the JWK thumbprint, although the response is encrypted to the encryption key of the request.

## Expected results

1. The Relying Party rejects the presentation: its verification result reports a failure and releases no attribute value from the presentation, and the endpoint receiving the Authorization Response does not answer with HTTP status 5xx.
2. The Relying Party rejects the presentation: its verification result reports a failure and releases no attribute value from the presentation, and the endpoint receiving the Authorization Response does not answer with HTTP status 5xx.
3. The Relying Party rejects the presentation: its verification result reports a failure and releases no attribute value from the presentation, and the endpoint receiving the Authorization Response does not answer with HTTP status 5xx.
4. The Relying Party rejects the presentation: its verification result reports a failure and releases no attribute value from the presentation, and the endpoint receiving the Authorization Response does not answer with HTTP status 5xx.
5. The Relying Party rejects the presentation: its verification result reports a failure and releases no attribute value from the presentation, and the endpoint receiving the Authorization Response does not answer with HTTP status 5xx.
6. The Relying Party rejects the presentation: its verification result reports a failure and releases no attribute value from the presentation, and the endpoint receiving the Authorization Response does not answer with HTTP status 5xx.

## Comments

The OIDF verifier test module `oid4vp-1final-verifier-invalid-session-transcript` covers one of these steps.
