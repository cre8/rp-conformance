# Relying Party functional conformance tests: test catalogue

Draft 0.2, 2026-11-05 (decisions on the open questions applied, see §8.1). Phase "Test Objectives" in FCAF terms: every test is defined with its objective, stimulus, expected result, references and applicability. The step-by-step write-up in the FCAF template (phase "Test Cases") and all tooling come later.

## 0. Summary

| Item | Value |
| --- | --- |
| System under test | Relying Party (RP): the RP Instance(s) plus the RP back end that decides whether a presentation is accepted. Not the PID Provider, not the Attestation Provider, not the Wallet. |
| Sources | ARF repository `main` of 2026-10-02 (latest tag v3.0.0), Annex 2 HLRs and main document §6.6.3; FCAF `submitted` branch of 2026-10-16; OpenID4VP 1.0; HAIP 1.0; RFC 9901 (SD-JWT); SD-JWT VC draft-16; Token Status List draft-20; ISO/IEC 18013-5; ETSI TS 119 602, 119 612, 119 475, 119 472-2. Versions follow the FCAF reference table. |
| Structure | FCAF hierarchy, with the RP test classes the FCAF methodology already reserves: `RP_WS`, `RP_PP`, `RP_AP`, `RP_Inf`. Plus a test book `RP_TB` for checks that need inspection instead of a protocol stimulus. |
| Size | 222 test objectives: 138 unhappy flow (`_UF`) and 84 positive or informative (positive controls, request-side conformance checks, one `INFO`). Plus 10 test book items. Counted before format and transport variants are expanded. |
| Already covered elsewhere | 16 objectives correspond to existing OIDF OID4VP 1.0 verifier test modules (marked "OIDF" below). Everything else has no public test today. |

### Why the existing suites are not enough

- **FCAF** (conformance.eudi.dev) tests only the Wallet Solution. Its `WS_RP` class is the wallet's interface towards an RP: the RP is the test tool there, not the SUT. Its methodology names Relying Parties as a future SUT and reserves the classes `RP_WS`, `RP_PP`, `RP_AP` and `RP_Inf`.
- **OIDF verifier suite** (`vp1finalverifier`) has a happy flow, 11 negative modules (invalid credential signature; KB-JWT aud, nonce, signature, iat in past, iat in future; invalid sd_hash; invalid mdoc SessionTranscript; revoked via status list; revoked via identifier list; wrong vct) and 4 further positive modules (credential without status, minimal `cnf` JWK, request_uri fetched twice, request_uri_method post). It has nothing on credential validity periods, status list token validity, trust anchor categories, trust list handling, response encryption, session binding after the redirect, combined presentations, registration certificates or robustness.

## 1. Scope

In scope: everything the RP does in a presentation transaction and the infrastructure interactions that decide the outcome.

- Building and authenticating the request (access certificate, registration certificate, nonce, encryption key, DCQL).
- Receiving, decrypting and validating the response: issuer signature, trust anchor and its category, certificate path, validity period, revocation status, device binding, session binding, query satisfaction, combined presentations.
- Retrieving and validating status lists (Token Status List, ISO identifier list).
- Retrieving and validating trust lists (LoTE per ETSI TS 119 602, Trusted Lists per ETSI TS 119 612).
- Remote flows via redirects and via the W3C Digital Credentials API, and proximity (ISO/IEC 18013-5) where the RP supports it.

Out of scope for now: PID Providers and Attestation Providers as SUT (issuance), Wallet Units, pseudonyms (Topic 11), document signing (Topic 16), payments (Topic 20), Wallet-to-Wallet (Topic 30), non-functional testing (load, penetration). Requirements on RP registration processes (Topic 27) are only tested where they show up in the protocol.

## 2. Structure and conventions

### 2.1 Test classes

| Class | Interface | Contents |
| --- | --- | --- |
| `RP_WS` | RP ↔ Wallet Solution | Request structure and authentication, flow handling, response processing and every validation of the presented credential. |
| `RP_PP` | RP ↔ PID Provider | Retrieval and validation of PID status lists and identifier lists. |
| `RP_AP` | RP ↔ Attestation Provider | Same objectives as `RP_PP` for QEAA, PuB-EAA and non-qualified EAA. Defined once in `RP_PP`; every `RP_PP_*` objective applies to `RP_AP` with the same number and the category variant `Q`, `PB` or `E`. |
| `RP_Inf` | RP ↔ Trust infrastructure | LoTE and Trusted List retrieval, signature, freshness, type and category handling. |
| `RP_TB` | Test book | RP-internal requirements without a standard interface: data minimisation, retention, documented policies. |

Layers and areas follow the FCAF: `MS` message structure, `IA` interaction, `SM` security mechanisms, `DM` data model, `UC` use cases, `SH` shared (robustness). Two areas are new because the RP is the party that checks them: `SM_Validity` and `SM_Revocation`.

### 2.2 Identifiers

`<Class>_<Layer>_<Area>_<nnn>[<variant letter>][_UF]`, for example `RP_WS_SM_Validity_001_UF`. Same convention as the FCAF. Omitted test groups and units leave no empty subdivision, so there is a single underscore before the number; the FCAF lint flags a double underscore (FC013) and most FCAF test case titles already use the single form. `_UF` marks an unhappy flow. Variant letters (`a`, `b`, …) are assigned when an objective is expanded into test cases per variant, and come before `_UF`.

### 2.3 Variant codes

| Code | Meaning |
| --- | --- |
| `SD` | Credential in SD-JWT VC format (`dc+sd-jwt`) |
| `MD` | Credential in mdoc format (`mso_mdoc`) |
| `RD` | OpenID4VP via redirects, response mode `direct_post.jwt` |
| `DC` | OpenID4VP via the W3C Digital Credentials API, response mode `dc_api.jwt` |
| `DCI` | ISO/IEC 18013-7 Annex C over the Digital Credentials API |
| `PX` | ISO/IEC 18013-5 proximity (device retrieval) |
| `PID`, `Q`, `PB`, `E` | Credential category: PID, QEAA, PuB-EAA, non-qualified EAA. Default `PID` when not listed. |

### 2.4 Relevancy

FCAF labels, abbreviated in the `Rel` column: first letter origin (`G` EUDI_generic, `S` EUDI_specific, `A` EUDI_agnostic), second letter scope (`R` EUDI_required, `O` EUDI_optional, `U` EUDI_undefined). `S/R` means EUDI_specific | EUDI_required.

### 2.5 Expected result codes

| Code | Pass criterion |
| --- | --- |
| `ACC` | The RP reports the transaction as successfully verified and releases exactly the requested attributes with the issued values. |
| `REJ` | The RP reports the transaction as failed. No attribute value from the rejected presentation is released to the relying service as verified. No HTTP 5xx, no crash. Rejecting at the `response_uri` (4xx) and rejecting later (200, then failure result) are both acceptable: OpenID4VP 1.0 does not define when verification happens. |
| `NOFETCH` | The RP sends no request to the status provider during the transaction. |
| `POLICY` | The outcome follows the policy the RP declared in its ICS, and the RP signals the condition (for example "status unknown", "trust list stale") towards the relying service. |
| `NOSTAT` | No reliable revocation status. For a PID: `REJ`. For QEAA, PuB-EAA and non-qualified EAA: `POLICY` per ICS-06, and an accepted result carries "status unknown". |
| `NOREL` | The named data is neither released to the relying service nor retained. |
| `CONF` | The captured message conforms to the stated rule (request-side tests). |
| `INFO` | Behaviour is recorded in the report; no verdict. |

## 3. Test environment

The FCAF assumes a controlled environment with its own trust infrastructure. The RP tests need the same, plus a wallet that can produce deliberately wrong responses.

### 3.1 Test roles

| Role | Function |
| --- | --- |
| Conformance Wallet (CW) | Receives the RP's request, checks it, and produces a response that is valid except for the one mutation the test defines. Can skip the redirect, replay, re-encrypt and splice responses. |
| Test Trust Infrastructure (TTI) | Publishes LoTEs and Trusted Lists sealed by a test scheme operator key, and can publish modified versions (removed entry, withdrawn service, bad signature, stale `NextUpdate`, rollback). |
| Test Status Provider (TSP) | Serves status list tokens and identifier lists with controllable content, signature, headers, status codes and latency. Logs every request. |
| Test Issuers | Issue the test credentials, including mutated ones. |
| Tester | Starts transactions at the RP and reads the RP's verdict. |

### 3.2 Trust configuration defined by the suite

The suite defines every root of trust, so there is exactly one correct answer for each test. The RP is configured with the suite's scheme operator certificates only (the test counterpart of the OJEU publication in TLPub_07), never with production anchors, and derives everything else from the lists the suite publishes. Where other specifications allow looser choices (Token Status List §11.3, ISO/IEC 18013-5 second edition §12.3.6.2), the suite's configuration decides.

| Purpose | Root of trust published by the suite |
| --- | --- |
| Trust lists themselves | Scheme operator certificate(s) configured out of band. LOTL pointer certificates for national Trusted Lists. |
| Signing a PID | Anchors under the PID/Issuance service of an entity in `TL-PID`. |
| Signing a QEAA | Anchors of a granted qualified EAA service in a Trusted List reached via `TL-QEAA`. |
| Signing a PuB-EAA | Anchors under the issuance service of an entity in `TL-PUB`. |
| Signing a non-qualified EAA | `TA-EAA`, as its rulebook defines. |
| Signing a status list or identifier list | Anchors under the revocation service of **the same entity** whose issuance anchor validated the credential, in the same list. An issuer that signs status lists with its issuance key lists that CA under both services. |
| Signing a request (access certificate) | Anchors in `TL-AC`. |
| Signing a registration certificate | Anchors in `TL-RC`. |

A signer is trusted for a purpose only if its chain ends in an anchor the suite publishes for that purpose and, where the row says so, for that entity. A valid chain to an anchor published for another purpose, another entity or another list is untrusted.

Logical description of the lists; testers supply concrete keys and lists:

| ID | Content |
| --- | --- |
| `TL-PID` | PID Provider LoTE (`LoTEType` EUPIDProvidersList). Entries: `PP-A` with separate CAs for PID/Issuance and PID/Revocation, granted. `PP-B` lists its issuance CA under both services (status lists signed with the issuance key), granted. `PP-W` withdrawn. |
| `TL-QEAA` | Test LOTL pointing to a test national Trusted List (ETSI TS 119 612) with QTSP `QP-A`, qualified EAA service granted, and `QP-N` with a non-qualified service. |
| `TL-PUB` | PuB-EAA Provider LoTE with `PB-A`. |
| `TA-EAA` | Rulebook-defined anchor for non-qualified EAA Provider `EP-A`. |
| `TL-WP` | Wallet Provider LoTE (used only as the wrong category). |
| `TL-AC` | Access Certificate Authority LoTE; contains `AC-A`, which issued the RP's access certificates. |
| `TL-RC` | Provider of registration certificates LoTE; contains `RC-A`, which issued the RP's registration certificates. |
| `CA-X` | Self-signed CA on no list. |

### 3.3 Default credentials

| ID | Content |
| --- | --- |
| `CRED-PID` | PID per the PID rulebook in both encodings, issued by `PP-A`, device-bound, technical validity > 24 h, status reference into `SL-PP-A` (SD) or an MSO status element (MD). |
| `CRED-PID-SHORT` | Same as `CRED-PID` with validity < 24 h and no status reference. |
| `CRED-Q`, `CRED-PB`, `CRED-E` | FCAF `default_credential_A` (attributes `attribute_A`, `attribute_B`, `attribute_C`) issued by `QP-A`, `PB-A` and `EP-A`, device-bound, with status reference. |
| `SL-PP-A` | Status list for `PP-A`, as JWT (`statuslist+jwt`) and CWT, served by the TSP. |
| `IL-PP-A` | Identifier list (ISO/IEC 18013-5 second edition) for `PP-A`, served by the TSP. |

### 3.4 Default RP configuration (`default_configuration_RP_1`)

- The RP is registered for service `S1` with an access certificate (WRPAC) from `AC-A` and a registration certificate (WRPRC) from `RC-A`. The WRPRC lists the PID attributes `family_name`, `given_name`, `birth_date` / `birthdate` and the EAA attributes `attribute_A` to `attribute_C`.
- The RP trusts only the test lists from §3.2 and has refreshed them before the test.
- The RP has a test trigger to start a transaction for a given query.
- The status list cache is empty at the start of each test unless the test says otherwise.
- The RP clock is synchronised. The suite caps the clock tolerance `T_skew` and the KB-JWT / DeviceAuth freshness window `T_kb` at 5 minutes each; the RP may declare tighter values. Time mutations use the declared value plus one hour, so they never sit on the boundary by accident.

### 3.5 How the verdict is observed

This is the hardest part of RP testing. Decision (§8): the RP must expose its verification result machine-readably (API or webhook) for conformance testing. Observation points:

- `OBS-HTTP`: status code and body the RP returns at its `response_uri`.
- `OBS-RESULT`: the verification result the RP hands to the relying service (API, webhook, UI). This is authoritative. The RP declares in its ICS how a tester reads it.
- `OBS-NET`: requests the RP sends to the TSP and TTI.
- `OBS-REQ`: the request the CW receives.

A 4xx at `OBS-HTTP` is sufficient for `REJ`. A 200 is not a failure in itself, because OpenID4VP lets the RP defer verification; `OBS-RESULT` then decides. An RP that cannot offer a machine-readable `OBS-RESULT` may be tested manually with screenshots of its result; such runs end in REVIEW, never in PASS, as in the OIDF suite.

### 3.6 Generic scenarios

Each test names one scenario and the mutation it applies.

- `SCN-Q` request side: trigger a transaction, capture the request (and request object) at the CW, check it.
- `SCN-R` response side: trigger, CW validates the request, CW builds a response valid in every respect except mutation M, sends it, follows `redirect_uri` if returned, tester reads `OBS-RESULT`.
- `SCN-S` status: as `SCN-R` with a valid presentation, the mutation is applied to what the TSP serves.
- `SCN-T` trust list: the TTI publishes the mutated list, the RP refreshes (trigger or wait `T_refresh`), then `SCN-R` with a credential whose acceptance depends on that list.
- `SCN-F` flow: as `SCN-R` with a valid presentation, the mutation is in the CW's flow behaviour (redirect, response code, replay, timing).

Rule for every `_UF` test: its positive control (same scenario, no mutation) must pass in the same environment first. If it does not, the verdict is INCONCLUSIVE, not PASS. This keeps a broken harness from producing false passes.

Verdicts: PASS, FAIL, INCONCLUSIVE, REVIEW (manual observation only), NOT APPLICABLE (profile not supported per ICS).

## 4. Implementation Conformance Statement (ICS) for RPs

The RP fills these in; profiles in the catalogue refer to them.

| ICS | Question | Profile |
| --- | --- | --- |
| ICS-01 | Credential formats requested: SD-JWT VC, mdoc | `P-SD`, `P-MD` |
| ICS-02 | Remote transports: redirects same-device, redirects cross-device, DC API (OpenID4VP), DC API (18013-7 Annex C) | `P-RD`, `P-DC`, `P-DCI` |
| ICS-03 | Proximity supported (ProxId_01a) | `P-PX` |
| ICS-04 | Categories requested: PID, QEAA, PuB-EAA, non-qualified EAA (which rulebooks) | `P-Q`, `P-PB`, `P-E` |
| ICS-05 | Revocation checking per category and format (VCR_13). If not: reference to the risk analysis | `P-REV` |
| ICS-06 | Policy for QEAA, PuB-EAA and non-qualified EAA when no reliable status information is available (VCR_14): reject, or accept and flag "status unknown". PIDs are always rejected. | used by `NOSTAT` |
| ICS-07 | Status list caching, maximum age, honours `ttl` (VCR_15) | `P-CACHE` |
| ICS-08 | Device binding verified per category (OIA_17) | `P-DB` |
| ICS-09 | `T_skew` and `T_kb` (each at most 5 minutes), transaction lifetime `T_tx` | |
| ICS-10 | How `OBS-RESULT` is read: API or webhook (required for automated runs); UI only for manual runs | |
| ICS-11 | Trust list refresh interval `T_refresh` and grace period `G` after a list's `NextUpdate` | |
| ICS-12 | Combined presentation binding: presentation-based, attribute-based, cryptographic | `P-COMB` |
| ICS-13 | Role: plain RP, intermediary, intermediated RP (Topic 52) | `P-INT` |
| ICS-14 | Several services with separate access and registration certificates | `P-MS` |
| ICS-15 | Uses `trusted_authorities` in DCQL | `P-TA` |
| ICS-16 | Optional checks: issuer registration (`providesAttestations`), CRL/OCSP of issuer certificates | |
| ICS-17 | Maximum accepted response size and decompressed status list size | |

## 5. Catalogue

Columns: **Objective** says what is verified. **Stimulus** is the mutation or input on top of the named scenario. **Expected** uses the codes from §2.5. **Var** lists the variants (cross product unless noted). **Rel** is the FCAF relevancy.

### 5.1 Class RP_WS: RP ↔ Wallet Solution

#### 5.1.1 Layer MS: message structure (requests the RP produces, `SCN-Q`)

##### RP_WS_MS_ProtocolMessages

| ID | Objective | Stimulus | Expected | References | Var | Rel |
| --- | --- | --- | --- | --- | --- | --- |
| `RP_WS_MS_ProtocolMessages_001` | Authorization Request is passed by reference: the invocation carries only `client_id` and `request_uri` (optionally `request_uri_method`), no unsigned request parameters. | Capture invocation URL | CONF | HAIP 5.1; RFC 9101 §5.2; OID4VP §5 | RD | G/R |
| `RP_WS_MS_ProtocolMessages_002` | Request Object payload: `response_type=vp_token`, `response_mode=direct_post.jwt`, https `response_uri`, no `redirect_uri`, `client_id` equal to the outer one, `nonce`, `dcql_query`, `aud` per OID4VP §5.8. | Capture request object | CONF | HAIP 5, 5.1; OID4VP §5.2, §5.8, §8.2, §8.3.1 | RD | G/R |
| `RP_WS_MS_ProtocolMessages_003` | `nonce` is at least 16 random bytes, base64url, and fresh per request. | 20 consecutive requests | CONF, no repeats | OID4VP §5.2, §13.3 | RD, DC | G/R |
| `RP_WS_MS_ProtocolMessages_004` | `state`, if used, is fresh and unguessable (≥ 128 bit). | 20 requests | CONF | OID4VP §13.3, §14.3.2 | RD | G/O |
| `RP_WS_MS_ProtocolMessages_005` | DC API request uses protocol `openid4vp-v1-signed` or `openid4vp-v1-multisigned`, `response_mode=dc_api.jwt`, `expected_origins` present, no `response_uri`. | Capture DC API request | CONF | OID4VP A.2, A.3.2; HAIP 5.2; OIA_08, OIA_08a | DC | G/R |
| `RP_WS_MS_ProtocolMessages_006` | 18013-7 Annex C request: DeviceRequest with ReaderAuth and registration certificate, EncryptionInfo with a fresh recipient key. | Capture request | CONF | OIA_08b; ISO/IEC 18013-7 Annex C; ETSI TS 119 472-2 | DCI | S/R |

##### RP_WS_MS_Metadata

| ID | Objective | Stimulus | Expected | References | Var | Rel |
| --- | --- | --- | --- | --- | --- | --- |
| `RP_WS_MS_Metadata_001` | `client_metadata.jwks` holds the response encryption key: EC P-256, `alg` ECDH-ES, `kid`, no private key members. | Capture request object | CONF | HAIP 5; OID4VP §8.3, §11.1 | RD, DC | G/R |
| `RP_WS_MS_Metadata_002` | `encrypted_response_enc_values_supported` lists both `A128GCM` and `A256GCM`. | Capture | CONF | HAIP 5 | RD, DC | G/R |
| `RP_WS_MS_Metadata_003` | The encryption key is ephemeral: a different key for every request. | 20 requests | CONF, all keys distinct | HAIP 5; OID4VP §8.3 | RD, DC | G/R |
| `RP_WS_MS_Metadata_004` | `vp_formats_supported` matches the requested formats and lists only ECCG-approved algorithms. | Capture | CONF | OID4VP §11.1, B.2.2, B.3.4; OIA_03 | SD, MD | S/R |

##### RP_WS_MS_CredentialFormats

| ID | Objective | Stimulus | Expected | References | Var | Rel |
| --- | --- | --- | --- | --- | --- | --- |
| `RP_WS_MS_CredentialFormats_001` | DCQL query is valid: unique ids, format `dc+sd-jwt` with `meta.vct_values` or `mso_mdoc` with `meta.doctype_value`, valid claims path pointers. | Capture | CONF | OID4VP §6, §7, B.2.3, B.3.5; HAIP 5.3.1, 5.3.2 | SD, MD | G/R |
| `RP_WS_MS_CredentialFormats_002` | Requested attributes are a subset of the attributes registered in the included registration certificate. | Compare DCQL with WRPRC | CONF | RPRC_19, RPRC_21; ETSI TS 119 475 | SD, MD | S/R |
| `RP_WS_MS_CredentialFormats_003` | `trusted_authorities`, if used, is of type `aki` and carries the key identifiers of anchors from the matching list. | Capture | CONF | HAIP 5; OID4VP §6.1.1.1 | SD, MD; `P-TA` | G/O |
| `RP_WS_MS_CredentialFormats_004` | PIDs are requested with holder binding (`require_cryptographic_holder_binding` not `false`). | Capture | CONF | OID4VP §6.1; ARF §6.6.3.8; OIA_17 | SD, MD | S/O |

#### 5.1.2 Layer IA: interaction

##### RP_WS_IA_Engagement

| ID | Objective | Stimulus | Expected | References | Var | Rel |
| --- | --- | --- | --- | --- | --- | --- |
| `RP_WS_IA_Engagement_001` | Same-device invocation uses `haip-vp://`, `openid4vp://` or a claimed https URL as declared. | Capture | CONF | HAIP 5.1; OID4VP §9 | RD | G/R |
| `RP_WS_IA_Engagement_002` | Cross-device QR code encodes the same authorization request as same-device. | Decode QR | CONF | OID4VP §5.7; OIA_08c | RD | G/O |
| `RP_WS_IA_Engagement_003` | DC API invocation calls the Digital Credentials API with the OpenID4VP protocol identifier. | Capture in browser | CONF | HAIP 5.2; OID4VP A.1 | DC | G/R |

##### RP_WS_IA_ProtocolFlow

| ID | Objective | Stimulus | Expected | References | Var | Rel |
| --- | --- | --- | --- | --- | --- | --- |
| `RP_WS_IA_ProtocolFlow_001` | `request_uri` returns the Request Object with `Content-Type: application/oauth-authz-req+jwt`. | GET `request_uri` | CONF | RFC 9101 §5.2; OID4VP §5.10.1 | RD | G/R |
| `RP_WS_IA_ProtocolFlow_002` | `request_uri` can be fetched more than once. | Second GET | CONF (OIDF `request-uri-fetched-twice`) | OID4VP §5 | RD | G/R |
| `RP_WS_IA_ProtocolFlow_003` | `request_uri_method=post` is handled: `wallet_nonce` echoed in the signed request object. | POST with `wallet_metadata`, `wallet_nonce` | CONF (OIDF `request-uri-method-post`) | OID4VP §5.10 | RD | G/O |
| `RP_WS_IA_ProtocolFlow_004_UF` | `request_uri` of an unknown, expired or completed transaction does not return a request object. | GET stale `request_uri` | 4xx, no request object | OID4VP §5.10.2 | RD | G/R |
| `RP_WS_IA_ProtocolFlow_005` | Same-device: `response_uri` answers 200 `application/json` with a `redirect_uri` containing a fresh response code (≥ 128 bit). | `SCN-R`, no mutation | CONF | OID4VP §8.2, §14.2; HAIP 5.1 | RD | G/R |
| `RP_WS_IA_ProtocolFlow_006_UF` | Same-device: the RP does not complete the transaction when the wallet does not follow the redirect back. | `SCN-F`: response posted, redirect not followed | REJ (session not completed, no attributes released to the front end) | HAIP 5.1 | RD | G/R |
| `RP_WS_IA_ProtocolFlow_007_UF` | Same-device: the RP rejects a redirect back that arrives in a different user session. | `SCN-F`: redirect followed in a fresh browser profile | REJ | HAIP 5.1; OID4VP §14.2 | RD | G/R |
| `RP_WS_IA_ProtocolFlow_008_UF` | A response code can be redeemed once only. | `SCN-F`: redeem the response code twice | Second redemption REJ | OID4VP §14.2 | RD | G/R |
| `RP_WS_IA_ProtocolFlow_009_UF` | A forged response code yields no result. | `SCN-F`: random response code | REJ | OID4VP §14.2 | RD | G/R |
| `RP_WS_IA_ProtocolFlow_010` | A wallet error response (`access_denied`, `invalid_request`), unencrypted as permitted, ends the transaction as failed and gets 200 `application/json`. | Error response | CONF, transaction failed | OID4VP §8.2, §8.3.1, §8.5 | RD | G/R |
| `RP_WS_IA_ProtocolFlow_011_UF` | A response arriving after the transaction lifetime is rejected. | `SCN-F`: send after `T_tx` | REJ | OID4VP §14.1; ICS-09 | RD, DC | G/R |
| `RP_WS_IA_ProtocolFlow_012_UF` | A second response for a completed transaction is rejected and does not change the first result. | `SCN-F`: resend the identical response | REJ, first result unchanged | OID4VP §14.1, §14.3.2 | RD | G/R |
| `RP_WS_IA_ProtocolFlow_013_UF` | A response with an unknown or missing `state` (when the RP sent one) is rejected. | `SCN-F` | REJ | OID4VP §14.3.2 | RD | G/O |
| `RP_WS_IA_ProtocolFlow_014` | DC API error object and cancelled request end the transaction as failed. | `{"error":"access_denied"}` / cancel | CONF | OID4VP A.4 | DC | G/R |

##### RP_WS_IA_MainInteraction (positive baseline; positive controls for the `_UF` tests)

| ID | Objective | Stimulus | Expected | References | Var | Rel |
| --- | --- | --- | --- | --- | --- | --- |
| `RP_WS_IA_MainInteraction_001` | PID presentation is accepted with exactly the requested attributes. | `SCN-R`, `CRED-PID` | ACC (OIDF `happy-flow`) | OIA_03b, OIA_03c, OIA_08, OIA_08a; OID4VP §8.6 | SD, MD × RD, DC; PX | S/R |
| `RP_WS_IA_MainInteraction_002` | QEAA presentation is accepted. | `CRED-Q` | ACC | OIA_13 | SD, MD × RD, DC; `P-Q` | S/R |
| `RP_WS_IA_MainInteraction_003` | PuB-EAA presentation is accepted. | `CRED-PB` | ACC | OIA_14 | SD, MD × RD, DC; `P-PB` | S/R |
| `RP_WS_IA_MainInteraction_004` | Non-qualified EAA presentation is accepted. | `CRED-E` | ACC | OIA_15 | SD, MD × RD, DC; `P-E` | S/R |
| `RP_WS_IA_MainInteraction_005` | Selective disclosure: only requested claims disclosed; undisclosed claims are absent from the result. | `CRED-PID`, request a subset | ACC, no other claims | OIA_07; RFC 9901 §7.1 | SD, MD | G/R |

#### 5.1.3 Layer SM: security mechanisms

##### RP_WS_SM_RpIntegrity (Relying Party authentication, `SCN-Q`)

| ID | Objective | Stimulus | Expected | References | Var | Rel |
| --- | --- | --- | --- | --- | --- | --- |
| `RP_WS_SM_RpIntegrity_001` | Request Object is a JWS with `typ` `oauth-authz-req+jwt` and an ECCG-approved `alg` (at least ES256); the signature verifies with the leaf in `x5c`. | Capture | CONF | HAIP 5, 7; RFC 9101 §10.8; OIA_03 | RD, DC | G/R |
| `RP_WS_SM_RpIntegrity_002` | `client_id` is `x509_hash:` plus the base64url SHA-256 of the DER leaf certificate. | Capture | CONF | HAIP 5; OID4VP §5.9.3; RPA_02 | RD, DC | G/R |
| `RP_WS_SM_RpIntegrity_003` | `x5c` holds leaf and intermediates, no trust anchor, leaf not self-signed, and validates to an anchor in `TL-AC`. | Capture | CONF | HAIP 5; RPA_02, RPA_04; Reg_10b | RD, DC | S/R |
| `RP_WS_SM_RpIntegrity_004` | The access certificate is valid at the time of the request and carries the entity identifier, service identifier and service trade name. | Capture | CONF | RPA_02; Reg_32, Reg_33, Reg_34; ETSI TS 119 411-8 | RD, DC, PX | S/R |
| `RP_WS_SM_RpIntegrity_005` | `verifier_info` carries exactly one registration certificate by value, valid and issued by `RC-A`, whose entity and service identifiers equal those of the access certificate. | Capture | CONF | RPRC_07a, RPRC_10, RPRC_19, RPRC_20; ETSI TS 119 475; ETSI TS 119 472-2 | RD, DC, PX | S/R |
| `RP_WS_SM_RpIntegrity_006` | The RP never sends an unauthenticated request: no unsigned redirect request, no unsigned DC API request. | Capture all request variants the RP offers | CONF | RPA_01, RPA_03; HAIP 5.1 | RD, DC | S/R |
| `RP_WS_SM_RpIntegrity_007` | DC API signed request: `expected_origins` contains the RP's own origin(s) only. | Capture | CONF | OID4VP A.3.2 | DC | G/R |
| `RP_WS_SM_RpIntegrity_008` | A multi-service RP uses the access and registration certificate of the service the request is for. | Trigger for `S1` and `S2` | CONF | RPA_06 note a; RPRC_10; Reg_10a | RD, DC; `P-MS` | S/R |
| `RP_WS_SM_RpIntegrity_009` | An intermediary includes its own access certificate (with the association to the intermediated RP) and the intermediated RP's registration certificate. | Capture | CONF | RPI_05, RPI_06; Reg_34a | RD, DC; `P-INT` | S/R |
| `RP_WS_SM_RpIntegrity_010` | Proximity: reader authentication is performed in every session with the access certificate, and the registration certificate is included per the ETSI TS 119 472-2 extension. | Capture DeviceRequest | CONF | RPA_03; ProxId_01a; RPRC_19, RPRC_20; ISO/IEC 18013-5 §9.1.4 | PX | S/R |
| `RP_WS_SM_RpIntegrity_011` | Proximity: the RP does not use server retrieval. | Capture engagement | CONF | ProxId_02 | PX | S/R |

##### RP_WS_SM_SessionEncryption (response encryption)

| ID | Objective | Stimulus | Expected | References | Var | Rel |
| --- | --- | --- | --- | --- | --- | --- |
| `RP_WS_SM_SessionEncryption_001` | Response encrypted with ECDH-ES (P-256) and A128GCM is accepted. | `SCN-R`, enc A128GCM | ACC | HAIP 5; OID4VP §8.3 | RD, DC | G/R |
| `RP_WS_SM_SessionEncryption_002` | Response encrypted with ECDH-ES (P-256) and A256GCM is accepted. | enc A256GCM | ACC | HAIP 5 | RD, DC | G/R |
| `RP_WS_SM_SessionEncryption_003_UF` | An unencrypted `vp_token` is rejected when `direct_post.jwt` was requested. | Plain `direct_post` with `vp_token` | REJ | HAIP 5.1; OID4VP §8.3.1 | RD | G/R |
| `RP_WS_SM_SessionEncryption_004_UF` | A response encrypted to a key the RP did not issue is rejected. | Encrypt to attacker key, copy RP `kid` | REJ | OID4VP §8.3 | RD, DC | G/R |
| `RP_WS_SM_SessionEncryption_005_UF` | A response encrypted to the ephemeral key of another, earlier transaction is rejected. | Encrypt to the key of transaction T1, send in T2 | REJ | HAIP 5; OID4VP §8.3 | RD, DC | G/R |
| `RP_WS_SM_SessionEncryption_006_UF` | JWE `alg` other than ECDH-ES is rejected. | `ECDH-ES+A256KW`, `RSA-OAEP-256`, `dir` | REJ | HAIP 5; OID4VP §8.3 | RD, DC | G/R |
| `RP_WS_SM_SessionEncryption_007_UF` | JWE `enc` not listed in the RP metadata is rejected. | `A128CBC-HS256` | REJ | OID4VP §8.3 | RD, DC | G/R |
| `RP_WS_SM_SessionEncryption_008_UF` | Tampered ciphertext or authentication tag is rejected. | Flip one bit in ciphertext; in tag | REJ | RFC 7516 §5.2 | RD, DC | G/R |
| `RP_WS_SM_SessionEncryption_009_UF` | An ephemeral public key `epk` not on P-256 or not a valid point is rejected (invalid curve attack). | `epk` off-curve; other curve | REJ | RFC 7518 §4.6; RFC 8725 §3.4 | RD, DC | G/R |
| `RP_WS_SM_SessionEncryption_010_UF` | A signed-only or `alg: none` response JWT is rejected. | JWS instead of JWE; unsecured JWT | REJ | OID4VP §8.3 | RD, DC | G/R |
| `RP_WS_SM_SessionEncryption_011_UF` | DC API: an unencrypted response is rejected. | `dc_api` response with plain `vp_token` | REJ | HAIP 5.2 | DC | G/R |
| `RP_WS_SM_SessionEncryption_012` | Unrecognised parameters in the decrypted payload are ignored. | Extra member `foo` | ACC | OID4VP §8.1 | RD, DC | G/R |

##### RP_WS_SM_SessionBinding (replay and audience)

| ID | Objective | Stimulus | Expected | References | Var | Rel |
| --- | --- | --- | --- | --- | --- | --- |
| `RP_WS_SM_SessionBinding_001_UF` | KB-JWT `nonce` different from the request `nonce` is rejected. | Other nonce | REJ (OIDF `invalid-kb-jwt-nonce`) | OID4VP §14.1.2, B.3.6; RFC 9901 §7.3 step 5f | SD × RD | G/R |
| `RP_WS_SM_SessionBinding_002_UF` | KB-JWT `aud` other than the full Client Identifier is rejected. | (a) other verifier's `client_id`; (b) `client_id` without the `x509_hash:` prefix | REJ (OIDF `invalid-kb-jwt-aud` covers a) | OID4VP §14.1.2, §14.8, B.3.6 | SD × RD | G/R |
| `RP_WS_SM_SessionBinding_003_UF` | KB-JWT `iat` older than `T_kb` is rejected. | `iat` = now − `T_kb` − 1 h | REJ (OIDF `kb-jwt-iat-in-past`) | RFC 9901 §7.3 step 5e | SD × RD, DC | G/R |
| `RP_WS_SM_SessionBinding_004_UF` | KB-JWT `iat` in the future beyond `T_skew` is rejected. | `iat` = now + `T_skew` + 1 h | REJ (OIDF `kb-jwt-iat-in-future`) | RFC 9901 §7.3 step 5e | SD × RD, DC | G/R |
| `RP_WS_SM_SessionBinding_005_UF` | A complete, valid presentation from an earlier transaction, re-encrypted for the current one, is rejected. | Replay T1 presentation into T2 | REJ | OID4VP §14.1 | SD, MD × RD, DC | G/R |
| `RP_WS_SM_SessionBinding_006_UF` | DC API: KB-JWT `aud` equal to the `client_id` instead of `origin:<origin>` is rejected. | `aud` = `x509_hash:…` | REJ | OID4VP A.4 | SD × DC | G/R |
| `RP_WS_SM_SessionBinding_007_UF` | DC API: KB-JWT `aud` naming another origin is rejected. | `aud` = `origin:https://other.example` | REJ | OID4VP A.4, A.5 | SD × DC | G/R |
| `RP_WS_SM_SessionBinding_008_UF` | mdoc: DeviceAuth over a SessionTranscript with a wrong OpenID4VPHandover element is rejected. | Wrong (a) nonce, (b) client_id, (c) response_uri, (d) jwkThumbprint | REJ (OIDF `invalid-session-transcript` covers one element) | OID4VP B.2.6.1; ISO/IEC 18013-5 §9.1.3 | MD × RD | G/R |
| `RP_WS_SM_SessionBinding_009_UF` | mdoc over DC API: handover with another origin or nonce is rejected. | Wrong (a) origin, (b) nonce | REJ | OID4VP B.2.6.2 | MD × DC | G/R |
| `RP_WS_SM_SessionBinding_010_UF` | Proximity: DeviceAuth computed over the SessionTranscript of another session is rejected. | Transcript with other DeviceEngagement / EReaderKey | REJ | ISO/IEC 18013-5 §9.1.3 | MD × PX | G/R |

##### RP_WS_SM_DeviceBinding (`P-DB`)

| ID | Objective | Stimulus | Expected | References | Var | Rel |
| --- | --- | --- | --- | --- | --- | --- |
| `RP_WS_SM_DeviceBinding_001_UF` | KB-JWT with an invalid signature is rejected. | Corrupt signature | REJ (OIDF `invalid-kb-jwt-signature`) | RFC 9901 §7.3 step 5c; OIA_17 | SD | G/R |
| `RP_WS_SM_DeviceBinding_002_UF` | KB-JWT validly signed with a key other than `cnf.jwk` is rejected. | Sign with fresh key | REJ | SD-JWT VC §2.4; RFC 9901 §7.3 step 5a | SD | G/R |
| `RP_WS_SM_DeviceBinding_003_UF` | Missing KB-JWT is rejected when the credential has `cnf` and holder binding was requested. | Present SD-JWT without KB-JWT | REJ | RFC 9901 §7.3 step 2; HAIP 6.1.1.1; OID4VP §8.6 | SD | G/R |
| `RP_WS_SM_DeviceBinding_004_UF` | KB-JWT `typ` other than `kb+jwt` is rejected. | `typ` missing; `JWT` | REJ | RFC 9901 §7.3 step 5d | SD | G/R |
| `RP_WS_SM_DeviceBinding_005_UF` | KB-JWT `sd_hash` not matching the presented SD-JWT is rejected. | Hash over different disclosures | REJ (OIDF `invalid-sd-hash`) | RFC 9901 §7.3 step 5g | SD | G/R |
| `RP_WS_SM_DeviceBinding_006_UF` | KB-JWT with `alg: none` or `HS256` keyed with the public key is rejected. | Algorithm confusion | REJ | RFC 9901 §7.3 step 5b; RFC 8725 §3.1, §3.2 | SD | G/R |
| `RP_WS_SM_DeviceBinding_007_UF` | A PID without `cnf` / device key is rejected. | PID issued without holder binding | REJ | OID4VP §6.1, §8.6; ARF §6.6.3.8 | SD, MD | S/R |
| `RP_WS_SM_DeviceBinding_008_UF` | mdoc DeviceSignature that does not verify is rejected. | Corrupt signature | REJ | ISO/IEC 18013-5 §9.1.3 | MD | G/R |
| `RP_WS_SM_DeviceBinding_009_UF` | mdoc DeviceSignature made with a key other than MSO `deviceKeyInfo.deviceKey` is rejected. | Sign with fresh key | REJ | ISO/IEC 18013-5 §9.1.3 | MD | G/R |
| `RP_WS_SM_DeviceBinding_010_UF` | mdoc without DeviceAuth is rejected. | Remove `deviceAuth` | REJ | ISO/IEC 18013-5 §9.1.3 | MD | G/R |
| `RP_WS_SM_DeviceBinding_011_UF` | Device-signed data elements are never taken as PID attributes. | PID with `family_name` in DeviceNameSpaces, not authorised by KeyAuthorizations | REJ, or element ignored and not released | ISO/IEC 18013-5 §9.1.3 (KeyAuthorizations); ARF §6.6.3.6 note | MD | S/R |
| `RP_WS_SM_DeviceBinding_012_UF` | Proximity: DeviceMac computed with the wrong reader key is rejected. | MAC with other EReaderKey | REJ | ISO/IEC 18013-5 §9.1.3 | MD × PX | G/O |
| `RP_WS_SM_DeviceBinding_013_UF` | Device authentication with an algorithm outside ECCG ACM is rejected. | ES256K | REJ | OIA_03; HAIP 7 | SD, MD | S/R |
| `RP_WS_SM_DeviceBinding_014` | A `cnf.jwk` carrying only the required JWK members is accepted. | Minimal `cnf.jwk` (`kty`, `crv`, `x`, `y`) | ACC (OIDF `minimal-cnf-jwk`) | RFC 7800 §3.2; SD-JWT VC §2.2.2.2; HAIP 6.1 | SD | G/R |

##### RP_WS_SM_IssuerIntegrity (authenticity of the credential)

SD-JWT VC:

| ID | Objective | Stimulus | Expected | References | Var | Rel |
| --- | --- | --- | --- | --- | --- | --- |
| `RP_WS_SM_IssuerIntegrity_001_UF` | Issuer-signed JWT with an invalid signature is rejected. | Corrupt signature | REJ (OIDF `invalid-credential-signature`) | RFC 9901 §7.1 step 2b | SD | G/R |
| `RP_WS_SM_IssuerIntegrity_002_UF` | Issuer-signed JWT with `alg: none` or `HS256` is rejected. | Algorithm confusion | REJ | RFC 9901 §7.1 step 2a | SD | G/R |
| `RP_WS_SM_IssuerIntegrity_003_UF` | Issuer signature with an algorithm outside ECCG ACM is rejected. | ES256K | REJ | OIA_03 | SD | S/R |
| `RP_WS_SM_IssuerIntegrity_004_UF` | SD-JWT VC without `x5c` is rejected. | Remove `x5c` | REJ | HAIP 6.1.1; SD-JWT VC §2.5 | SD | G/R |
| `RP_WS_SM_IssuerIntegrity_005_UF` | A chain that only validates to a root embedded in `x5c` is rejected. | `x5c` ends in self-signed `CA-X` | REJ | HAIP 6.1.1; SD-JWT VC §2.5; OIA_12 | SD | G/R |
| `RP_WS_SM_IssuerIntegrity_006_UF` | A self-signed signing certificate is rejected. | `x5c` = [self-signed leaf] | REJ | HAIP 6.1.1 | SD | G/R |
| `RP_WS_SM_IssuerIntegrity_007_UF` | `typ` other than `dc+sd-jwt` is rejected, including the legacy `vc+sd-jwt`. | `typ` missing; `JWT`; `vc+sd-jwt` | REJ | SD-JWT VC §2.2.1 (EUDI profile: no transition period, §8); HAIP 5.3.2 | SD | S/R |
| `RP_WS_SM_IssuerIntegrity_008_UF` | A disclosure whose digest is not in the payload is rejected. | (a) foreign disclosure added; (b) value of a disclosure modified | REJ | RFC 9901 §7.1 step 5 | SD | G/R |
| `RP_WS_SM_IssuerIntegrity_009_UF` | A digest occurring more than once is rejected. | Same disclosure twice; duplicate digest in `_sd` | REJ | RFC 9901 §7.1 step 4 | SD | G/R |
| `RP_WS_SM_IssuerIntegrity_010_UF` | Disclosure claim name `_sd` or `...`, or a name already present at that level, is rejected. | Issue such disclosures | REJ | RFC 9901 §7.1 step 3c | SD | G/R |
| `RP_WS_SM_IssuerIntegrity_011_UF` | A disclosure with the wrong number of elements is rejected. | 2-element disclosure for an object, 3 for an array | REJ | RFC 9901 §7.1 step 3c | SD | G/R |
| `RP_WS_SM_IssuerIntegrity_012_UF` | `_sd_alg` unknown or insecure is rejected. | `md5`, `sha-1` | REJ | RFC 9901 §7.1 step 2d; HAIP 8 | SD | G/R |
| `RP_WS_SM_IssuerIntegrity_013_UF` | `vct` not in the requested `vct_values` is rejected. | Other `vct` | REJ (OIDF `wrong-vct`) | OID4VP §8.6, §14.9, B.3.5 | SD | G/R |
| `RP_WS_SM_IssuerIntegrity_014` | Decoy digests are ignored. | Credential with decoys | ACC | RFC 9901 §4.2.5 | SD | G/R |
| `RP_WS_SM_IssuerIntegrity_015` | Recursive disclosures (structured objects such as address, place of birth) are resolved correctly. | Nested SD | ACC with correct values | RFC 9901 §4.2.6; PID rulebook | SD | G/R |

mdoc:

| ID | Objective | Stimulus | Expected | References | Var | Rel |
| --- | --- | --- | --- | --- | --- | --- |
| `RP_WS_SM_IssuerIntegrity_020_UF` | IssuerAuth with an invalid signature is rejected. | Corrupt COSE_Sign1 signature | REJ | ISO/IEC 18013-5 §9.1.2, §9.3.1 | MD | G/R |
| `RP_WS_SM_IssuerIntegrity_021_UF` | IssuerSignedItem whose digest does not match the MSO is rejected. | Change `elementValue` | REJ | ISO/IEC 18013-5 §9.3.1 | MD | G/R |
| `RP_WS_SM_IssuerIntegrity_022_UF` | IssuerSignedItem with a `digestID` not in `valueDigests` is rejected. | Add item with unknown digestID | REJ | ISO/IEC 18013-5 §9.3.1 | MD | G/R |
| `RP_WS_SM_IssuerIntegrity_023_UF` | MSO `docType` different from the Document `docType` is rejected. | Mismatch | REJ | ISO/IEC 18013-5 §9.3.1 | MD | G/R |
| `RP_WS_SM_IssuerIntegrity_024_UF` | Unsupported MSO `digestAlgorithm` is rejected. | `SHA-1` | REJ | HAIP 8 | MD | G/R |
| `RP_WS_SM_IssuerIntegrity_025_UF` | A `docType` not requested is rejected. | Other doctype | REJ | OID4VP §8.6, B.2.3 | MD | G/R |
| `RP_WS_SM_IssuerIntegrity_026_UF` | A chain that only validates to a root embedded in `x5chain` is rejected. | Self-signed IACA `CA-X` in chain | REJ | ISO/IEC 18013-5 §9.3.1; OIA_12 | MD | G/R |
| `RP_WS_SM_IssuerIntegrity_027_UF` | A document signer certificate without the mdoc DS extended key usage is rejected. | Remove EKU | REJ | ISO/IEC 18013-5 Annex B | MD | G/R |
| `RP_WS_SM_IssuerIntegrity_028_UF` | MSO `validityInfo.signed` outside the DS certificate validity is rejected. | `signed` after DS `notAfter` | REJ | ISO/IEC 18013-5 §9.3.1 | MD | G/R |

Certificate path, both formats:

| ID | Objective | Stimulus | Expected | References | Var | Rel |
| --- | --- | --- | --- | --- | --- | --- |
| `RP_WS_SM_IssuerIntegrity_030_UF` | Expired issuer signing certificate is rejected. | `notAfter` in the past | REJ | RFC 5280 §6.1.3; SD-JWT VC §2.5; ISO/IEC 18013-5 §9.3.1 | SD, MD | G/R |
| `RP_WS_SM_IssuerIntegrity_031_UF` | Not yet valid issuer signing certificate is rejected. | `notBefore` in the future | REJ | RFC 5280 §6.1.3 | SD, MD | G/R |
| `RP_WS_SM_IssuerIntegrity_032_UF` | Expired intermediate CA certificate is rejected. | Intermediate `notAfter` in the past | REJ | RFC 5280 §6.1.3 | SD, MD | G/R |
| `RP_WS_SM_IssuerIntegrity_033_UF` | Incomplete chain is rejected. | Intermediate missing | REJ | RFC 5280 §6.1 | SD, MD | G/R |
| `RP_WS_SM_IssuerIntegrity_034_UF` | Signing certificate issued by a non-CA certificate is rejected. | Issuer cert with `cA=false` | REJ | RFC 5280 §6.1.4 | SD, MD | G/R |
| `RP_WS_SM_IssuerIntegrity_035_UF` | Revoked issuer signing certificate is rejected. | CRL marks DS / signing cert revoked | REJ | RFC 5280 §6.3; ICS-16 | SD, MD | G/O |
| `RP_WS_SM_IssuerIntegrity_036_UF` | Key type or size outside ECCG ACM is rejected. | P-192, RSA-1024 | REJ | OIA_03 | SD, MD | S/R |
| `RP_WS_SM_IssuerIntegrity_037_UF` | Unknown critical extension in the signing certificate is rejected. | Critical private extension | REJ | RFC 5280 §4.2 | SD, MD | G/R |

##### RP_WS_SM_Validity (validity period of the credential)

| ID | Objective | Stimulus | Expected | References | Var | Rel |
| --- | --- | --- | --- | --- | --- | --- |
| `RP_WS_SM_Validity_001_UF` | Expired SD-JWT VC is rejected. | `exp` = now − `T_skew` − 1 h | REJ | RFC 9901 §7.1 step 6; RFC 7519 §4.1.4 | SD | G/R |
| `RP_WS_SM_Validity_002` | `exp` inside the clock tolerance is accepted. | `exp` = now − `T_skew`/2 | ACC | RFC 7519 §4.1.4; ICS-09 | SD | G/R |
| `RP_WS_SM_Validity_003_UF` | Not yet valid SD-JWT VC is rejected. | `nbf` = now + `T_skew` + 1 h | REJ | RFC 9901 §7.1 step 6; RFC 7519 §4.1.5 | SD | G/R |
| `RP_WS_SM_Validity_004` | Handling of an SD-JWT VC issued in the future is recorded. | `iat` = now + `T_skew` + 1 h | INFO | RFC 7519 §4.1.6 (no MUST, §8) | SD | G/U |
| `RP_WS_SM_Validity_005_UF` | Expired credential whose status is VALID is rejected, and the status list is not fetched. | Expired `CRED-PID`, status 0x00 | REJ, NOFETCH | Token Status List §7.1, §8.3 | SD, MD | G/R |
| `RP_WS_SM_Validity_006_UF` | A credential with an invalid issuer signature causes no status list fetch. | `IssuerIntegrity_001_UF` stimulus | REJ, NOFETCH | Token Status List §8.3 | SD, MD | G/R |
| `RP_WS_SM_Validity_010_UF` | Expired mdoc is rejected. | `validUntil` = now − `T_skew` − 1 h | REJ | ISO/IEC 18013-5 §9.3.1 | MD | G/R |
| `RP_WS_SM_Validity_011_UF` | Not yet valid mdoc is rejected. | `validFrom` = now + `T_skew` + 1 h | REJ | ISO/IEC 18013-5 §9.3.1 | MD | G/R |
| `RP_WS_SM_Validity_012` | Passed `expectedUpdate` alone does not cause rejection. | `expectedUpdate` past, `validUntil` future | ACC | ISO/IEC 18013-5 §9.1.2.4 | MD | G/R |
| `RP_WS_SM_Validity_020` | PID whose administrative expiry date has passed while the technical validity is fine is handled per declared policy, and the date is passed on. | PID rulebook expiry date in the past | POLICY | PID rulebook; ARF §5 (administrative vs technical validity) | SD, MD | S/U |

##### RP_WS_SM_TrustMechanisms (trust anchor and its category)

| ID | Objective | Stimulus | Expected | References | Var | Rel |
| --- | --- | --- | --- | --- | --- | --- |
| `RP_WS_SM_TrustMechanisms_001` | PID signed under a PID/Issuance anchor of `TL-PID` is accepted. | `CRED-PID` | ACC | OIA_12; PPNot_05 | SD, MD | S/R |
| `RP_WS_SM_TrustMechanisms_002_UF` | PID signed by a QTSP anchored only in `TL-QEAA` is rejected. | PID issued by `QP-A` | REJ | OIA_12; OIA_15 note | SD, MD | S/R |
| `RP_WS_SM_TrustMechanisms_003_UF` | PID signed under an anchor from another LoTE is rejected. | Anchor from (a) `TL-WP`, (b) `TL-AC`, (c) `TL-PUB` | REJ | OIA_12; OIA_15 note | SD, MD | S/R |
| `RP_WS_SM_TrustMechanisms_004_UF` | PID signed under an anchor published only for `PP-A`'s PID/Revocation service is rejected. | Sign with `PP-A` revocation CA | REJ | §3.2; PPNot_05; ETSI TS 119 602 service types | SD, MD | S/R |
| `RP_WS_SM_TrustMechanisms_005_UF` | Credential from an issuer on no list is rejected. | Issued by `CA-X` | REJ | OIA_12–OIA_15 | SD, MD × PID, Q, PB, E | S/R |
| `RP_WS_SM_TrustMechanisms_006_UF` | Credential from a provider whose entry is withdrawn is rejected. | Issued by `PP-W` | REJ | OIA_15a; ETSI TS 119 602 | SD, MD | S/R |
| `RP_WS_SM_TrustMechanisms_007_UF` | After an anchor is removed from the current list, credentials under it are rejected. | `SCN-T`: remove `PP-B` | REJ after refresh | OIA_15a | SD, MD | S/R |
| `RP_WS_SM_TrustMechanisms_008` | After an anchor is added to the current list, credentials under it are accepted. | `SCN-T`: add `PP-C` | ACC after refresh | OIA_15a | SD, MD | S/R |
| `RP_WS_SM_TrustMechanisms_009_UF` | Credential under an expired trust anchor is rejected. | Anchor `notAfter` in the past | REJ | OIA_15a; RFC 5280 §6.1 | SD, MD | S/R |
| `RP_WS_SM_TrustMechanisms_010` | QEAA under a granted qualified service in a Trusted List reached via the LOTL is accepted. | `CRED-Q` | ACC | OIA_13, OIA_15b; ETSI TS 119 612 | SD, MD; `P-Q` | S/R |
| `RP_WS_SM_TrustMechanisms_011_UF` | An attestation from a non-qualified or withdrawn TSP service is not accepted as QEAA. | Issued by `QP-N`; `QP-A` withdrawn | REJ | OIA_13; eIDAS Art. 32 | SD, MD; `P-Q` | S/R |
| `RP_WS_SM_TrustMechanisms_012` | PuB-EAA under a `TL-PUB` anchor is accepted. | `CRED-PB` | ACC | OIA_14; PuBPNot_06 | SD, MD; `P-PB` | S/R |
| `RP_WS_SM_TrustMechanisms_013_UF` | PuB-EAA signed under a PID Provider anchor is rejected. | `CRED-PB` issued by `PP-A` | REJ | OIA_14; OIA_15 note | SD, MD; `P-PB` | S/R |
| `RP_WS_SM_TrustMechanisms_014` | Non-qualified EAA under its rulebook anchor is accepted. | `CRED-E` | ACC | OIA_15 | SD, MD; `P-E` | S/R |
| `RP_WS_SM_TrustMechanisms_015_UF` | Non-qualified EAA under an anchor its rulebook does not name is rejected. | `CRED-E` issued by `PP-A` | REJ | OIA_15 | SD, MD; `P-E` | S/R |
| `RP_WS_SM_TrustMechanisms_016_UF` | The RP enforces its own `trusted_authorities`: a trusted issuer that does not match the requested `aki` is rejected. | Request names `PP-A`, wallet returns PID from `PP-B` | REJ | OID4VP §6.1.1.1, §14.9 | SD, MD; `P-TA` | G/R |
| `RP_WS_SM_TrustMechanisms_017_UF` | If the RP checks issuer registration: an attestation type missing from the issuer's registration certificate is rejected. | `providesAttestations` lacks the vct / doctype | REJ | ARF §6.6.3.6; ETSI TS 119 475; ICS-16 | SD, MD | S/O |

##### RP_WS_SM_Revocation (status reference in the credential, `P-REV`)

| ID | Objective | Stimulus | Expected | References | Var | Rel |
| --- | --- | --- | --- | --- | --- | --- |
| `RP_WS_SM_Revocation_001` | Credential with status VALID (0x00) is accepted. | `SCN-S`, status 0x00 | ACC | Token Status List §7.1, §8.3 | SD, MD × PID, Q, PB, E | S/R |
| `RP_WS_SM_Revocation_002_UF` | Revoked credential (0x01) is rejected. | Status 0x01 | REJ (OIDF `present-revoked-credential`) | Token Status List §7.1; VCR_13; SD-JWT VC §2.4 | SD, MD × PID, Q, PB, E | S/R |
| `RP_WS_SM_Revocation_003_UF` | Suspended credential (0x02) is rejected. | Status 0x02 | REJ | Token Status List §7.1 | SD, MD | S/R |
| `RP_WS_SM_Revocation_004` | Application-specific (0x03, 0x0C–0x0F) or unregistered status values are not treated as VALID unless the RP declared their meaning. | Status 0x03; 0x07 | REJ, unless the RP declared the value's meaning (then POLICY) | Token Status List §7.1 | SD, MD | G/U |
| `RP_WS_SM_Revocation_005_UF` | Malformed status reference is rejected. | (a) no `idx`; (b) no `uri`; (c) `idx` negative or not an integer; (d) `uri` not a URI | REJ | Token Status List §6.2, §8.3 step 1; HAIP 6.1 | SD, MD | G/R |
| `RP_WS_SM_Revocation_006_UF` | Index outside the list is rejected. | `idx` ≥ list size | REJ | Token Status List §8.3 step 6 | SD, MD | G/R |
| `RP_WS_SM_Revocation_007` | Credential without status and validity under 24 h is accepted. | `CRED-PID-SHORT` | ACC (OIDF `present-credential-without-status`) | VCR_01, VCR_01b; Token Status List §6.2 | SD, MD | S/R |
| `RP_WS_SM_Revocation_008_UF` | PID without status but with validity over 24 h is rejected: it carries no revocation information although VCR_01b requires it. | `CRED-PID` without status | NOSTAT (REJ for PID) | VCR_01b, VCR_14 | SD, MD | S/R |
| `RP_WS_SM_Revocation_009_UF` | mdoc revoked via identifier list is rejected. | Identifier listed in `IL-PP-A` | REJ (OIDF `present-credential-on-identifier-list`) | VCR_11, VCR_12; ISO/IEC 18013-5 second edition | MD | S/R |
| `RP_WS_SM_Revocation_010` | mdoc not on the identifier list is accepted. | Identifier not listed | ACC | VCR_11, VCR_12 | MD | S/R |
| `RP_WS_SM_Revocation_011` | An RP that checks mdoc revocation supports both mechanisms (status list and identifier list). | `_002_UF` (MD) and `_009_UF` both pass | CONF | VCR_12 | MD | S/R |

#### 5.1.4 Layer DM: data model

##### RP_WS_DM_IdentifyingData

| ID | Objective | Stimulus | Expected | References | Var | Rel |
| --- | --- | --- | --- | --- | --- | --- |
| `RP_WS_DM_IdentifyingData_001` | All mandatory PID attributes are mapped to the right values and types, including non-Latin-1 UTF-8 names. | `CRED-PID` with UTF-8 names | ACC, values exact | PID rulebook; CIR 2024/2977; ARB_06 | SD, MD | S/R |
| `RP_WS_DM_IdentifyingData_002` | Missing optional or conditional PID attributes that were not required do not cause failure. | PID without optional attributes | ACC | PID rulebook; ARB_09 | SD, MD | S/R |
| `RP_WS_DM_IdentifyingData_003_UF` | A requested, required claim that is not disclosed causes rejection. | Omit disclosure of `family_name` | REJ | OID4VP §6.4, §8.6 | SD, MD | G/R |
| `RP_WS_DM_IdentifyingData_004_UF` | Attribute values with the wrong data type are not accepted silently. | `birthdate` as integer; `nationalities` as string | REJ or attribute flagged invalid | PID rulebook; ISO 8601-1; OID4VP §8.6 | SD, MD | S/O |
| `RP_WS_DM_IdentifyingData_005` | Age-over attributes are processed as booleans. | `age_over_18` true / false | ACC with correct value | PID rulebook | SD, MD | S/R |
| `RP_WS_DM_IdentifyingData_006` | Structured address data is processed correctly. | Address object, partly disclosed | ACC with correct values | PID rulebook | SD, MD | S/R |
| `RP_WS_DM_IdentifyingData_007` | Unknown additional claims are ignored. | Extra private claim | ACC | SD-JWT VC §2.2.2.3 | SD, MD | G/R |

##### RP_WS_DM_CredentialMetadata

| ID | Objective | Stimulus | Expected | References | Var | Rel |
| --- | --- | --- | --- | --- | --- | --- |
| `RP_WS_DM_CredentialMetadata_001_UF` | Attributes disclosed but not requested are neither released nor retained. | Wallet discloses extra attributes | NOREL for the extra attributes; requested ones per ICS | OIA_16; OID4VP §15.4.2; GDPR Art. 5(1)(c) | SD, MD | S/O |
| `RP_WS_DM_CredentialMetadata_002_UF` | A claim value violating the query's `values` constraint is rejected. | Query `age_over_18` = true, credential false | REJ | OID4VP §6.3, §14.9, §15.4.1 | SD, MD | G/R |

#### 5.1.5 Layer UC: use cases

##### RP_WS_UC_Presentation

| ID | Objective | Stimulus | Expected | References | Var | Rel |
| --- | --- | --- | --- | --- | --- | --- |
| `RP_WS_UC_Presentation_001` | A request for PID and EAA, both satisfied, is accepted. | PID + `CRED-E` | ACC | OID4VP §6, §8.6 | SD, MD × RD, DC | G/R |
| `RP_WS_UC_Presentation_002_UF` | If one required presentation fails, the whole response is rejected and the valid part is not released as success. | PID valid, EAA revoked | REJ | OID4VP §8.6 | SD, MD | G/R |
| `RP_WS_UC_Presentation_003_UF` | A missing required credential query is rejected. | `vp_token` without the PID entry | REJ | OID4VP §6.4, §8.6 | SD, MD | G/R |
| `RP_WS_UC_Presentation_004_UF` | Nothing from a `vp_token` entry for an id not in the query is released as verified. | Extra key `x` with a valid presentation | REJ, or entry ignored with NOREL for its content | OID4VP §8.1 | SD, MD | G/R |
| `RP_WS_UC_Presentation_005_UF` | More than one presentation for a query without `multiple` is rejected. | Array of two | REJ | OID4VP §8.1 | SD, MD | G/R |
| `RP_WS_UC_Presentation_006` | `credential_sets`: a response satisfying an alternative option is accepted. | Option 2 of 2 | ACC | OID4VP §6.2, §6.4.2 | SD, MD | G/R |
| `RP_WS_UC_Presentation_007_UF` | `credential_sets`: a response satisfying no option is rejected. | Credentials from neither option | REJ | OID4VP §6.2, §6.4.2 | SD, MD | G/R |
| `RP_WS_UC_Presentation_008` | An optional credential query may be omitted. | Optional query not answered | ACC | OID4VP §8.1 | SD, MD | G/R |
| `RP_WS_UC_Presentation_009_UF` | Two mdocs in one DeviceResponse for two queries are handled per declared strictness. | Combined DeviceResponse | POLICY | HAIP 5.3.1 | MD | G/O |
| `RP_WS_UC_Presentation_010` | Combined presentation: PID and EAA with matching identifying attributes are accepted. | Same name and birth date | ACC | ARF §6.6.3.10 | SD, MD; `P-COMB` | S/O |
| `RP_WS_UC_Presentation_011_UF` | Combined presentation: PID and EAA of different persons are rejected when attribute-based binding is the declared method. | Different names / birth dates | REJ | ARF §6.6.3.10 | SD, MD; `P-COMB` | S/O |
| `RP_WS_UC_Presentation_012_UF` | Combined presentation spliced from two wallets (each part validly key-bound to a different device key) is handled per the declared binding method. | Splice two wallets' presentations | REJ if cryptographic binding is declared; POLICY otherwise | ARF §6.6.3.10; ACP_01–ACP_04 | SD, MD; `P-COMB` | S/U |
| `RP_WS_UC_Presentation_020` | An intermediary performs the checks agreed with the intermediated RP: the whole SM suite run through the intermediary gives the same verdicts. | Run SM tests via intermediary | Same verdicts as direct | RPI_09 | all; `P-INT` | S/R |
| `RP_WS_UC_Presentation_021` | An intermediated RP receives only the attributes of its own transaction. | Two concurrent intermediated RPs | CONF | RPI_05, RPI_06 | all; `P-INT` | S/R |

#### 5.1.6 Layer SH: robustness

##### RP_WS_SH_Encoding

| ID | Objective | Stimulus | Expected | References | Var | Rel |
| --- | --- | --- | --- | --- | --- | --- |
| `RP_WS_SH_Encoding_001_UF` | Malformed `response` is rejected cleanly. | Wrong segment count; invalid base64url | REJ, 4xx, no stack trace | RFC 7516 §9 | RD, DC | G/R |
| `RP_WS_SH_Encoding_002_UF` | Malformed SD-JWT is rejected. | No trailing `~`; empty segment; invalid JSON in a disclosure | REJ | RFC 9901 §4 | SD | G/R |
| `RP_WS_SH_Encoding_003_UF` | Malformed CBOR DeviceResponse is rejected. | Truncated; wrong major type; deep nesting; indefinite lengths | REJ | RFC 8949; ISO/IEC 18013-5 §8.3.2.1.2.2 | MD | G/R |
| `RP_WS_SH_Encoding_004_UF` | Oversized response is rejected without exhausting resources. | Response above ICS-17 limit | REJ, RP stays available | ICS-17 | RD, DC | G/R |
| `RP_WS_SH_Encoding_005_UF` | Duplicate member names in JOSE headers or JWT claims are rejected. | Duplicate `alg`; duplicate `nonce` | REJ | RFC 7515 §4; RFC 7519 §4; FCAF Shared_JSON | SD, RD, DC | G/R |
| `RP_WS_SH_Encoding_006_UF` | Excessive `x5c` / `x5chain` length is bounded. | 50 certificates | REJ, RP stays available | RFC 5280 §6.1 | SD, MD | G/R |
| `RP_WS_SH_Encoding_007` | Error responses to the wallet reveal no internal details. | Any `_UF` above | CONF | OID4VP §15.9 | RD | G/O |

### 5.2 Class RP_PP: RP ↔ PID Provider (status lists)

Every objective in this class also applies to class `RP_AP` with the same number for the categories `Q`, `PB` and `E` (`P-Q`, `P-PB`, `P-E`). Variant `SD` means the Status List Token in JWT format, `MD` the CWT format. All require `P-REV`. Which signers are trusted follows the suite's trust configuration in §3.2. When a status list cannot be used, the result is `NOSTAT`: reject for PIDs, declared policy for the other categories.

##### RP_PP_IA_Supportive (retrieval)

| ID | Objective | Stimulus | Expected | References | Var | Rel |
| --- | --- | --- | --- | --- | --- | --- |
| `RP_PP_IA_Supportive_001` | The RP fetches the status list with GET, `Accept: application/statuslist+jwt` or `+cwt`, without authentication and without data identifying the user or transaction. | `SCN-S`, inspect TSP log | CONF | Token Status List §8.1, §12.3; VCR_16 | SD, MD | G/R |
| `RP_PP_IA_Supportive_002` | Two presentations referencing the same list within `ttl` cause at most one fetch. | Two transactions | CONF | VCR_15; Token Status List §11.5, §13.7 | SD, MD; `P-CACHE` | S/O |
| `RP_PP_IA_Supportive_003` | After `ttl` or `exp` has passed, the RP fetches a fresh list before deciding; a revocation set in between is detected. | Revoke between transactions, wait `ttl` | First ACC, second REJ | Token Status List §8.3 step 4d | SD, MD; `P-CACHE` | G/R |
| `RP_PP_IA_Supportive_004_UF` | Status endpoint unreachable or failing gives no positive status statement, and the RP decides within its declared timeout. | Timeout; connection refused; 404; 500 | NOSTAT | Token Status List §8.3; VCR_14 | SD, MD | S/R |
| `RP_PP_IA_Supportive_005_UF` | Redirect loops and redirects to non-https or internal targets are bounded. | 3xx loop; 3xx to `http://127.0.0.1` | NOSTAT, RP stays available | Token Status List §11.4; RFC 9110 §15.4 | SD, MD | G/R |
| `RP_PP_IA_Supportive_006_UF` | A status `uri` pointing to a loopback, link-local or private address, or with a non-https scheme, is not fetched. | `uri` = `http://169.254.169.254/…` | REJ, no request to that address | Token Status List §6.2; OWASP SSRF | SD, MD | G/R |

##### RP_PP_SM_Revocation (Status List Token and identifier list validation)

| ID | Objective | Stimulus | Expected | References | Var | Rel |
| --- | --- | --- | --- | --- | --- | --- |
| `RP_PP_SM_Revocation_001` | A valid Status List Token (correct `typ`, `sub` = `uri`, `iat`, future `exp`, signed under the issuing entity's revocation anchor) yields the status. | `SCN-S`, valid token | ACC | Token Status List §5.1, §5.2, §8.3; HAIP 6.1; PPNot_05; §3.2 | SD, MD | G/R |
| `RP_PP_SM_Revocation_002_UF` | Token with an invalid signature gives no status statement. | Corrupt signature | NOSTAT | Token Status List §8.3 step 3a | SD, MD | G/R |
| `RP_PP_SM_Revocation_003_UF` | Unsigned token or a bare status list is not accepted. | `alg: none`; plain JSON | NOSTAT | Token Status List §5.1, §8.3 | SD, MD | G/R |
| `RP_PP_SM_Revocation_004_UF` | Expired token is not accepted. | `exp` = now − `T_skew` − 1 h | NOSTAT | Token Status List §8.3 step 4c | SD, MD | G/R |
| `RP_PP_SM_Revocation_005_UF` | Token whose `sub` differs from the credential's status `uri` is not accepted. | `sub` = other list URI | NOSTAT | Token Status List §8.3 step 4a | SD, MD | G/R |
| `RP_PP_SM_Revocation_006_UF` | Token with the wrong type is not accepted. | `typ` `JWT`; CWT type not `application/statuslist+cwt` | NOSTAT | Token Status List §5.1, §5.2, §8.3 step 3b | SD, MD | G/R |
| `RP_PP_SM_Revocation_007_UF` | Token missing a required claim is not accepted. | Without (a) `sub`, (b) `iat`, (c) `status_list`, (d) `bits`, (e) `lst` | NOSTAT | Token Status List §5.1, §5.2, §8.3 step 3b | SD, MD | G/R |
| `RP_PP_SM_Revocation_008_UF` | Token signed by an untrusted or self-signed certificate, or without `x5c`, is not accepted. | Signed by `CA-X`; no `x5c`; self-signed signer | NOSTAT | HAIP 6.1; Token Status List §11.3 | SD, MD | G/R |
| `RP_PP_SM_Revocation_009_UF` | Token signed under a trusted anchor of another entity or another list is not accepted. | Signed under (a) `PP-B`'s revocation anchor, (b) a `TL-WP` revocation anchor, (c) a `TL-AC` anchor | NOSTAT | §3.2; Token Status List §11.3; PPNot_05 | SD, MD | S/R |
| `RP_PP_SM_Revocation_010` | Token signed under the issuing entity's revocation anchor is accepted. | (a) `PP-A` list signed under `PP-A`'s revocation CA; (b) `PP-B` list signed with the credential's own key, whose CA `PP-B` lists under both services | ACC | §3.2; PPNot_05; ETSI TS 119 602; Token Status List §11.3 | SD, MD | S/R |
| `RP_PP_SM_Revocation_011_UF` | Token whose signer chains only to the entity's issuance anchor, which the list does not publish under its revocation service, is not accepted. | `PP-A` list signed (a) with the credential's own signing certificate, (b) with another certificate under `PP-A`'s issuance CA | NOSTAT | §3.2; PPNot_05 | SD, MD | S/R |
| `RP_PP_SM_Revocation_012_UF` | A token chain that only validates to a root embedded in `x5c` is not accepted. | `x5c` ends in self-signed root | NOSTAT | HAIP 6.1 | SD, MD | G/R |
| `RP_PP_SM_Revocation_013_UF` | Token signed by an expired or not yet valid certificate is not accepted. | Signer `notAfter` past; `notBefore` future | NOSTAT | RFC 5280 §6.1.3 | SD, MD | G/R |
| `RP_PP_SM_Revocation_014_UF` | Token `iat` in the future, or older than the declared freshness limit, is handled per policy. | `iat` future; `iat` old | POLICY | Token Status List §8.3 step 4b | SD, MD | G/O |
| `RP_PP_SM_Revocation_015_UF` | `lst` that is not valid base64url or not valid DEFLATE/ZLIB is rejected without failure. | Corrupt `lst` | NOSTAT, no crash | Token Status List §4.1, §8.3 step 5, §11.1 | SD, MD | G/R |
| `RP_PP_SM_Revocation_016_UF` | A decompression bomb is rejected without exhausting resources. | `lst` inflating beyond ICS-17 | NOSTAT, RP stays available | Token Status List §11.1; ICS-17 | SD, MD | G/R |
| `RP_PP_SM_Revocation_017_UF` | `bits` outside {1, 2, 4, 8} is rejected. | `bits` = 3 | NOSTAT | Token Status List §4.1 | SD, MD | G/R |
| `RP_PP_SM_Revocation_018` | Status values are read correctly for `bits` 1, 2, 4 and 8, including indices at byte boundaries. | Lists with each `bits`, indices 0, 7, 8, last | Correct status per index | Token Status List §4.1 | SD, MD | G/R |
| `RP_PP_SM_Revocation_019_UF` | Token signed with an algorithm outside ECCG ACM or with `HS256` is rejected. | ES256K; HS256 | NOSTAT | OIA_03; HAIP 7 | SD, MD | S/R |
| `RP_PP_SM_Revocation_030_UF` | Identifier list with an invalid signature, expired, or under an untrusted signer gives no status statement. | Each mutation | NOSTAT | VCR_11; ISO/IEC 18013-5 second edition | MD | S/R |
| `RP_PP_SM_Revocation_031` | When the MSO status element names a certificate, the identifier list or status list is validated against that certificate's chain. | Status element with Certificate | ACC | ISO/IEC 18013-5 second edition | MD | G/O |

### 5.3 Class RP_Inf: RP ↔ trust infrastructure

##### RP_Inf_SM_TrustMechanisms (LoTE and Trusted List processing)

| ID | Objective | Stimulus | Expected | References | Var | Rel |
| --- | --- | --- | --- | --- | --- | --- |
| `RP_Inf_SM_TrustMechanisms_001` | The RP loads the PID Provider LoTE, validates its JAdES seal against the configured scheme operator certificate, and uses its anchors. | `SCN-T`, valid list | ACC for `CRED-PID` | OIA_15a, OIA_15b; ETSI TS 119 602; TLPub_05, TLPub_07 | — | S/R |
| `RP_Inf_SM_TrustMechanisms_002_UF` | A LoTE with an invalid seal is not used. | Corrupt seal, list adds `PP-C` | `PP-C` credential REJ; the last valid list stays in use until its `NextUpdate` + `G` | OIA_15a; ETSI TS 119 602 | — | S/R |
| `RP_Inf_SM_TrustMechanisms_003_UF` | A LoTE sealed by a key other than the scheme operator's is not used. | Sealed by `CA-X` | As `_002_UF` | ETSI TS 119 602 | — | S/R |
| `RP_Inf_SM_TrustMechanisms_004` | Within the grace period after `NextUpdate`, a stale LoTE is still used and the RP signals it. | Serve the old list only; present at `NextUpdate` + `G`/2 | ACC, "trust list stale" signalled | ETSI TS 119 602; OIA_15a; ICS-11 | — | S/R |
| `RP_Inf_SM_TrustMechanisms_012_UF` | After the grace period, anchors from a stale LoTE are no longer used. | Serve the old list only; present at `NextUpdate` + `G` + 1 h | REJ | ETSI TS 119 602; OIA_15a; ICS-11 | — | S/R |
| `RP_Inf_SM_TrustMechanisms_005_UF` | A rollback to an older list version is ignored. | Lower `LoTESequenceNumber` / older `ListIssueDateTime`, re-adding `PP-W` | `PP-W` credential stays REJ | ETSI TS 119 602 | — | S/R |
| `RP_Inf_SM_TrustMechanisms_006_UF` | A list of the wrong LoTE type is not used for PID anchors. | Wallet Provider list served at the PID list location | PID from those anchors REJ | OIA_15 note; ETSI TS 119 602 (`LoTEType`) | — | S/R |
| `RP_Inf_SM_TrustMechanisms_007` | Lists are refreshed at least by `NextUpdate` or `T_refresh`, and changes reach every RP Instance. | Change list; observe each instance | CONF | OIA_15a | — | S/R |
| `RP_Inf_SM_TrustMechanisms_008` | The RP navigates LOTL → national Trusted List, validates the TL with the LOTL pointer certificate, and extracts QEAA service anchors with type and status. | `SCN-T` | ACC for `CRED-Q` | OIA_13, OIA_15b; ETSI TS 119 612 | `P-Q` | S/R |
| `RP_Inf_SM_TrustMechanisms_009_UF` | A national Trusted List signed with a certificate not in the LOTL pointer is not used. | Re-sign TL with `CA-X` | `CRED-Q` REJ | ETSI TS 119 612 | `P-Q` | S/R |
| `RP_Inf_SM_TrustMechanisms_010` | Anchors keep their category (PID, QEAA, PuB-EAA, EAA, Access CA, Registration CA, Wallet Provider). | Covered by `RP_WS_SM_TrustMechanisms_002_UF`, `_003_UF`, `_013_UF` | CONF | OIA_15 note | — | S/R |
| `RP_Inf_SM_TrustMechanisms_011` | Status list anchors (PID/Revocation service) are loaded and tied to their provider. | Covered by `RP_PP_SM_Revocation_009_UF`, `_010` | CONF | PPNot_05, PuBPNot_06 | — | S/R |

### 5.4 Class RP_TB: test book (inspection)

| ID | Objective | Method | References | Rel |
| --- | --- | --- | --- | --- |
| `RP_TB_001` | Unique elements (salts, digests, signatures, status index and URI, KB-JWT, timestamps) are discarded once no longer needed and not passed to the relying service or third parties. | Inspect what the RP forwards (API, webhooks, logs) and stores after a transaction. | OIA_16; ISSU_35 | S/R |
| `RP_TB_002` | The PID portrait is not retained or transferred without a legal basis. | Inspect storage and forwarding after a portrait request. | PID_03a; CIR 2024/2977 | S/R |
| `RP_TB_003` | If revocation is not checked, or accepted without reliable status, a risk analysis exists and matches ICS-05 / ICS-06. | Document review. | VCR_13, VCR_14 | S/R |
| `RP_TB_004` | Status lists are distributed to RP Instances instead of being fetched per presentation. | Architecture review, `RP_PP_IA_Supportive_002`. | VCR_15 | S/O |
| `RP_TB_005` | Cross-device redirect flows have documented and implemented mitigations. | Document review and walkthrough. | OIA_08d; ARF §4.4.3.1 | S/R |
| `RP_TB_006` | Configured algorithms are limited to ECCG ACM v2.0. | Configuration review. | OIA_03 | S/R |
| `RP_TB_007` | Data deletion requests arrive through the channel in the registration certificate, the requester is authenticated, and the TS7 interface is supported. | Walkthrough. | DATA_DLT_07, DATA_DLT_08; RPRC_11 | S/R |
| `RP_TB_008` | Registration data is kept current and registration certificates reach all RP Instances. | Process review. | Reg_08; RPRC_10 | S/R |
| `RP_TB_009` | Trust anchors are stored per category so they cannot be mixed up. | Configuration review; complements `RP_WS_SM_TrustMechanisms`. | OIA_15 note | S/R |
| `RP_TB_010` | Pseudonym verification (deferred until RP pseudonym support is in scope). | — | PA_10–PA_13, PA_15 | S/O |

### 5.5 Proximity (ISO/IEC 18013-5)

Following the FCAF approach for the wallet's mdoc tests: the mdoc reader test cases of ISO/IEC TS 18013-6 are adopted by reference through an RP ICS based on its Annex B, restricted to EUDI rules (server retrieval prohibited, reader authentication required, ECCG curves only). The objectives above marked `PX` add the EUDI-specific parts: access certificate as reader authentication certificate, registration certificate in the request, trust anchors from LoTEs, revocation through status list or identifier list, and offline status handling per VCR_14.

## 6. Traceability: ARF requirement → tests

| ARF HLR | Tests |
| --- | --- |
| OIA_03 (ECCG algorithms) | `MS_Metadata_004`, `SM_RpIntegrity_001`, `SM_DeviceBinding_013_UF`, `SM_IssuerIntegrity_003_UF`, `_036_UF`, `RP_PP_SM_Revocation_019_UF`, `RP_TB_006` |
| OIA_03b, OIA_03c, OIA_08, OIA_08a (HAIP profiles) | All `RD` and `DC` variants; `MS_ProtocolMessages`, `MS_Metadata`, `SM_SessionEncryption` |
| OIA_08b (18013-7 Annex C) | `MS_ProtocolMessages_006`, all `DCI` variants |
| OIA_08c, OIA_08d (cross-device) | `IA_Engagement_002`, `RP_TB_005` |
| OIA_12–OIA_15 (trust anchor per category) | `SM_TrustMechanisms_001`–`_015`, `SM_IssuerIntegrity_005_UF`, `_026_UF` |
| OIA_15a, OIA_15b (trust anchor management) | `SM_TrustMechanisms_006_UF`–`_009_UF`, `RP_Inf_SM_TrustMechanisms` |
| OIA_16, PID_03a (data minimisation) | `DM_CredentialMetadata_001_UF`, `RP_TB_001`, `RP_TB_002` |
| OIA_17 (device binding) | `SM_DeviceBinding`, `SM_SessionBinding` |
| RPA_01–RPA_04 (RP authentication) | `SM_RpIntegrity_001`–`_007`, `_010` |
| RPRC_07a, RPRC_10, RPRC_19–RPRC_21 (registration certificate) | `SM_RpIntegrity_005`, `_008`, `MS_CredentialFormats_002` |
| Reg_32–Reg_34 (access certificate content) | `SM_RpIntegrity_004` |
| VCR_01, VCR_01b, VCR_11–VCR_16 (revocation) | `SM_Revocation`, `RP_PP_*`, `RP_AP_*`, `RP_TB_003`, `RP_TB_004` |
| PPNot_05, PuBPNot_06 (list anchors incl. revocation anchors) | `SM_TrustMechanisms_004_UF`, `RP_PP_SM_Revocation_009_UF`, `_010` |
| ProxId_01a, ProxId_02 | `SM_RpIntegrity_010`, `_011`, §5.5 |
| RPI_05, RPI_06, RPI_09 (intermediaries) | `SM_RpIntegrity_009`, `UC_Presentation_020`, `_021` |
| ARF §6.6.3.6–§6.6.3.10 (RP verification steps) | `SM_IssuerIntegrity`, `SM_Revocation`, `SM_DeviceBinding`, `UC_Presentation_010`–`_012_UF` |
| DATA_DLT_07, DATA_DLT_08 | `RP_TB_007` |

## 7. Overlap with the OIDF verifier suite

These objectives can reuse the OIDF `vp1finalverifier` modules as execution vehicle; the catalogue adds the EUDI trust setup and the category variants.

| Objective | OIDF module |
| --- | --- |
| `RP_WS_IA_MainInteraction_001` | `oid4vp-1final-verifier-happy-flow` |
| `RP_WS_IA_ProtocolFlow_002` | `oid4vp-1final-verifier-request-uri-fetched-twice` |
| `RP_WS_IA_ProtocolFlow_003` | `oid4vp-1final-verifier-request-uri-method-post` |
| `RP_WS_SM_SessionBinding_001_UF` | `…-invalid-kb-jwt-nonce` |
| `RP_WS_SM_SessionBinding_002_UF` (a) | `…-invalid-kb-jwt-aud` |
| `RP_WS_SM_SessionBinding_003_UF` | `…-kb-jwt-iat-in-past` |
| `RP_WS_SM_SessionBinding_004_UF` | `…-kb-jwt-iat-in-future` |
| `RP_WS_SM_SessionBinding_008_UF` (one element) | `…-invalid-session-transcript` |
| `RP_WS_SM_DeviceBinding_001_UF` | `…-invalid-kb-jwt-signature` |
| `RP_WS_SM_DeviceBinding_005_UF` | `…-invalid-sd-hash` |
| `RP_WS_SM_DeviceBinding_014` | `…-minimal-cnf-jwk` |
| `RP_WS_SM_IssuerIntegrity_001_UF` | `…-invalid-credential-signature` |
| `RP_WS_SM_IssuerIntegrity_013_UF` | `…-wrong-vct` |
| `RP_WS_SM_Revocation_002_UF`, `_007`, `_009_UF` | `…-present-revoked-credential`, `…-present-credential-without-status`, `…-present-credential-on-identifier-list` |

## 8. Decisions and remaining notes

### 8.1 Decisions (2026-11-05)

| # | Question | Decision | Applied in |
| --- | --- | --- | --- |
| 1 | How is the RP's verdict read? OpenID4VP lets an RP answer 200 and verify later. | The RP exposes its verification result machine-readably (API or webhook). A 4xx at the `response_uri` also counts as reject. Manual screenshot runs end in REVIEW. For EUDIPLO: the session status. | §3.5, §3.6, ICS-10 |
| 2 | What if no reliable revocation status is available (VCR_14)? | PIDs are rejected. QEAA, PuB-EAA and non-qualified EAA follow the RP's declared policy and must be flagged "status unknown" when accepted. | `NOSTAT` in §2.5, ICS-06, `RP_PP_*`, `SM_Revocation_008_UF` |
| 3 | Who may sign a status list? | The suite defines every root of trust per purpose, so RPs know what is correct: a status list is trusted only under the revocation-service anchor of the same entity that issued the credential. Issuers that sign status lists with their issuance key list that CA under both services. | §3.2, `SM_TrustMechanisms_004_UF`, `RP_PP_SM_Revocation_009_UF`–`_011_UF` |
| 4 | Stale trust list (`NextUpdate` passed, no newer list)? | Keep using it for a declared grace period `G` and signal it; reject afterwards. | ICS-11, `RP_Inf_SM_TrustMechanisms_002_UF`, `_004`, `_012_UF` |
| 5 | Time windows | `T_skew` and `T_kb` each at most 5 minutes; RPs may declare tighter. A credential `iat` in the future is recorded only (`INFO`). | §3.4, ICS-09, `SM_Validity_004` |
| 6 | SD-JWT VC `typ` `vc+sd-jwt` | Rejected. The EUDI profile takes no transition period, which deviates from the SHOULD-accept note in SD-JWT VC draft-16 §2.2.1. | `SM_IssuerIntegrity_007_UF` |
| 7 | `vp_token` entry for an unknown query id | Rejecting the response and ignoring the entry both pass, as long as nothing from that entry is released as verified. | `UC_Presentation_004_UF` |
| 8 | Target | Aim for contribution to the FCAF (`eudi-doc-functional-conformance-assessment`) as the "Relying Party" SUT. Keep strict FCAF format and IDs. Contribution needs the EC's agreement first. | Whole document |

### 8.2 Remaining notes

- **Combined presentations.** No cryptographic binding scheme (ACP) is specified yet; `UC_Presentation_012_UF` stays a placeholder.
- **Spec versions.** HAIP pins SD-JWT VC draft-13 and Token Status List draft-14; the FCAF pins draft-16 and draft-20. The catalogue follows the FCAF.
- **ISO/IEC 18013-5 second edition** (status list and identifier list for mdoc) is not published; section references for `MD` revocation tests follow the draft.
- **Decision 6 conflicts with a SHOULD** in SD-JWT VC. For the upstream contribution this needs a reference the EC accepts, for example a HAIP or ETSI TS 119 472-2 profile statement.

## 9. Next steps

1. Done (2026-11-06): the baseline covers the `SM_Validity`, `SM_Revocation`, `RP_PP_SM_Revocation`, `SM_TrustMechanisms` and `SM_SessionEncryption` objectives plus the positive controls `RP_WS_IA_MainInteraction_001a` and `_001b`: 121 test cases in the FCAF format, one file per test case, in [fcaf-overlay](fcaf-overlay/README.md). The README lists the objectives left out and why.
2. Design the harness: draft in [harness-design.md](harness-design.md) (2026-11-06), with four decisions open in its §12.
3. Contact the FCAF maintainers about adding the Relying Party SUT before opening a pull request.
4. Write the remaining objectives as test cases, starting with `SM_SessionBinding`, `SM_DeviceBinding`, `SM_IssuerIntegrity` and `RP_Inf_SM_TrustMechanisms`.
