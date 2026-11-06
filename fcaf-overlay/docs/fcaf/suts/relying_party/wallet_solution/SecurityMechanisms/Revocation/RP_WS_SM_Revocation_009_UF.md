# RP_WS_SM_Revocation_009_UF

## Objective

Verify that the Relying Party rejects a PID in mdoc format whose identifier is listed in the referenced identifier list.

## References

- [Token Status List] section 6.3, 7.1, 8.3
- [ISO/IEC 18013-5 ed2]
- [HAIP] section 5.3.1
- [ARF] Annex 2, VCR_11, VCR_12, VCR_13
- [CIR 2024/2979 amended] Annex II

## Profile applicability

- Relying Party requests credentials in ISO/IEC 18013-5 mdoc format.
- Relying Party checks the revocation status of PIDs.

## EUDI-wallet relevancy

EUDI_specific | EUDI_required

## Technology

- Presentation of a credential in ISO/IEC 18013-5 mdoc format.
- Identifier list in CWT format.

## Preconditions

1. The Relying Party is set to `default_configuration_rp_1`.
2. The test environment publishes `default_trust_configuration_rp`, and the Relying Party has loaded it.
3. Test case `RP_WS_IA_MainInteraction_001b` passed in the same environment.
4. Every credential presented in this test case references a status list URI from which the Relying Party has not retrieved a status list before.
5. The `status` element of the MSO of every presented credential carries an `identifier_list` entry (`id`, `uri`) that references an identifier list in CWT format (`application/identifierlist+cwt`) served by the Test Status Provider.

## Test Scenario

1. Perform a presentation for `default_query_pid` in which the Conformance Wallet presents `default_credential_pid` in a valid Authorization Response, while the referenced identifier list contains the credential's identifier.

## Expected results

1. The Relying Party rejects the presentation: its verification result reports a failure and releases no attribute value from the presentation, and the endpoint receiving the Authorization Response does not answer with HTTP status 5xx.

## Comments

The OIDF verifier test module `oid4vp-1final-verifier-present-credential-on-identifier-list` covers the same objective.

Execute this test case once for each presentation flow the Relying Party supports (redirects, W3C Digital Credentials API).
