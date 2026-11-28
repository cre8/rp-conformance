# EUDIPLO issuer adapter

`IssuerAdapter` for EUDIPLO as the reference PID Provider of the issuer suite (issuer harness design sections 5.4 and
5.5, decision 2). Its ICS is [`ics.yaml`](ics.yaml), its known findings [`known-findings.yaml`](known-findings.yaml).

## Reference image

The suite is validated against a digest of EUDIPLO's main image, pinned in [`reference.env`](reference.env) (read by
`docker compose --env-file` and by `REFERENCE_EUDIPLO` in [`src/reference.ts`](src/reference.ts); change it there only):

`EUDIPLO_IMAGE` (the digest), `EUDIPLO_EXPECT_VERSION` (what `GET /api/version` reports: `10.0.0-main.7586139`
since 2026-11-23, `9.1.0-main.ae0792a` before) and `EUDIPLO_REVISION` (the source revision, which the CI job `eudiplo` compares with the image's
`org.opencontainers.image.revision` label).

It stays a digest of the main image until a release of EUDIPLO has the features below (decision of 2026-11-20). The
release 9.1.0 lacks too much of what the catalogue tests:

> **Why not 9.1.0.** EUDIPLO 9.1.0 (2026-10-10) cannot create a CSR for its keys (`GET /api/key-chain/{id}/csr` answers
> `404 Cannot GET`), so the Test Registrar had to generate them. It accepts a wallet attestation whose status list cannot
> be fetched and has no setting to reject it (`walletAttestationStatusCheckMode` came with EUDIPLO/eudiplo#1340). It
> checks no key attestation status at all and cannot revoke a PID with its wallet unit (`revokeWithWalletUnit` came with
> EUDIPLO/eudiplo#1468). It keeps using a trust list after its `NextUpdate` (EUDIPLO/eudiplo#1441). Against 9.1.0, a
> PID Provider would fail `ClientAttestation_013_UF`, `KeyAttestation_008_UF` and `_009_UF`, and could not run
> `SM_Revocation_006`, `_007` or `PP_TB_007` at all. The adapter still configures 9.1.0 (it leaves out what the instance
> does not know), so it can be run against later releases to decide when one can replace the digest.

## What the adapter configures

One tenant per namespace, as the RP adapter does (`adapters/eudiplo`):

| Hook | EUDIPLO calls |
| --- | --- |
| `enrol(namespace)` | Creates the tenant and four standalone key chains (`attestation` for SD-JWT VC, `attestation` for the mdoc document signer, `statusList`, `access`) and returns their CSRs (`GET /api/key-chain/{id}/csr`) with the profile of each credential signing key (`credentialSigningProfiles`). On an instance without the CSR route (9.1.0) it returns `undefined` and the Test Registrar generates the keys. |
| `setUp(env, namespace)` | Tenant with the roles `issuance:manage` and `issuance:offer` (one left from an earlier run is replaced). Key chains: the Registrar's certificates for the CSR key chains (`PUT /api/key-chain/{id}` `activeCertificate`), or else the Registrar's keys imported with their chains (`POST /api/key-chain/import`): credential signer under `PP-T`, status list signer under the revocation anchor of `PP-T`, access certificate from `AC-A`. Status list settings (`PUT /api/status-list-config`): 2 bits, 10 000 entries, `ttl` 60 s, `immediateUpdate`. The PID configuration `pid-sd-jwt-vc` (`dc+sd-jwt`, `vct` `urn:eudi:pid:1`, `keyBinding`, `statusManagement`, `keyAttestationsRequired` with the ICS levels, `revokeWithWalletUnit`, 30 days, and on every configuration the ARF Annex II reuse policy `credentialReusePolicy`: method A `once_only` with the batch size, then method B `limited_time`); with `P-MD` the PID in mdoc `pid-mso-mdoc` (`mso_mdoc`, docType and namespace `eu.europa.ec.eudi.pid.1`, signed by the document signer the Registrar issued); with `P-SHORT` the short-lived `pid-sd-jwt-vc-short` and `pid-mso-mdoc-short` (12 hours, no status reference). A second, identical configuration `pid-sd-jwt-vc-2` that no PID offer names, so `PP_WS_MS_CredentialEndpoint_004_UF` can request a configuration the access token was not issued for; `PP_WS_IA_PreAuthorized_004_UF` offers it on its own (`ICS-02.second`). The issuance configuration: built-in authorization server, `walletAttestationRequired`, `walletProviderTrustLists` = the harness's `TL-WP` pinned to its scheme operator certificate, `walletAttestationStatusCheckMode` `strict` (wallet attestations at the authorization server, key attestations at the credential endpoint), `batchSize` from the ICS, DPoP, notification endpoint, and the Registrar's registration certificate in `issuer_info`. |
| `createOffer` | `POST /api/issuer/offer` at the built-in authorization server, pre-authorized code or authorization code with `issuer_state` (issue 20), the subject's claims inline (`credentialClaims`) in the names of each configuration's format, with the age attributes and the issuance and expiry dates derived at issuance (`pidClaimsFor`), optionally a 6-digit `tx_code` (`txCode: true`). EUDIPLO offers by reference only; for `byReference: false` the adapter resolves the reference (once, it is single-use) and hands out `credential_offer` by value. |
| `authenticateSubject` | Opens the authorization request (`GET {authorization_endpoint}?client_id&request_uri`, no redirect following) and returns EUDIPLO's redirect to the wallet: `code`, `state`, `iss`, or `error`. Any other answer (EUDIPLO answers a request without a pushed `request_uri` with HTTP 409) is thrown as `AuthorizationEndpointError`. See below. |
| `createOffer` with `deferred: true` | Instead of inline claims, `credentialClaims` names a claims webhook the adapter serves on the host (`http://{harnessHost}:{port}/claims`, started on first use, stopped in `tearDown`). It answers every request with `{ "deferred": true, "interval": 1 }`, so EUDIPLO answers the credential request with HTTP 202, `transaction_id` and `interval` (inline claims never defer). |
| `completeDeferred` | `POST /api/issuer/deferred/{transactionId}/complete` with the subject's claims; the next poll of the deferred credential endpoint returns the PID. |
| `setStatus` | `POST /api/session/revoke` (`0` valid, `1` revoked, `2` suspended), then `GET /api/session/{id}/credential-status` must show the new status for every credential of the session. |
| `refreshTrust` | `DELETE /api/cache/trust-list` |
| `describe` | URL, version and revision (`GET /api/version`), tenant, enrolment method, the status check mode and revocation chaining as configured |
| `tearDown` | `DELETE /api/tenant/{id}` |

Revocation chaining is a poll: every `WALLET_UNIT_STATUS_CHECK_INTERVAL` seconds EUDIPLO reads the key attestation
status of every PID it follows and revokes the PIDs of a revoked wallet unit. The Compose file sets it to 30 s (default
3600 s), so `T_chain` is 30 s plus up to 300 s of reuse of `SL-WP-A` (its `ttl`) plus `T_rev`: PT7M in the ICS.

The values the adapter seeds for `SUBJ-1` and `SUBJ-2` are the suite's (`PID_TEST_SUBJECTS` of `@eudi-pcaf/core`),
in [`src/subjects.ts`](src/subjects.ts) (`PID_SUBJECTS`, `pidClaimsFor`): the Conformance Wallet compares the issued
claims with them (`pid-values`).

With CSR enrolment the adapter creates two attestation key chains, one for SD-JWT VC and one for the mdoc document
signer, and names their profiles in the enrolment request (`credentialSigningProfiles`); the Registrar certifies the
second in the document signer profile of ISO/IEC 18013-5 Annex B.

The mdoc fields `birth_date`, `issuance_date` and `expiry_date` of the PID (and `attribute_C` of `default_credential_A`)
declare `format` `date`, so EUDIPLO issues them as `full-date` (tag 1004) as the PID Rulebook v1.7 section 3.1.2
requires ([EUDIPLO/eudiplo#1635](https://github.com/EUDIPLO/eudiplo/pull/1635)), so `PP_WS_DM_PidMdoc_002` passes
against the reference image since 2026-11-23 ([EUDIPLO/eudiplo#1623](https://github.com/EUDIPLO/eudiplo/issues/1623)). A
release before it, such as the earlier reference image `ae0792a`, does not know the key: the adapter leaves it out and
the dates are text strings. The
portrait opt-out (`DM_Portrait_001`) is not offered: the PID configurations have no portrait, and inline JSON claims
cannot carry the empty byte string an mdoc needs (`ICS-17.portrait_opt_out` No).

The values the adapter seeds for `SUBJ-1` and `SUBJ-2` are in [`src/subjects.ts`](src/subjects.ts) (`PID_SUBJECTS`):
the Conformance Wallet compares the issued claims with them. `loadIssuerIcs` rejects an ICS whose declared durations
exceed the catalogue's caps (`T_rev`, `T_chain` 24 h; `T_proof`, `T_skew` 5 minutes) or with fewer than 10 000 status
list entries.

## Integration test

Not part of `pnpm test`, since it needs a running EUDIPLO:

```bash
EUDIPLO_PORT=3216 docker compose --env-file adapters/issuer-eudiplo/reference.env -p eudi-pcaf-i16 -f adapters/eudiplo/docker-compose.yml up -d --wait
```

```bash
EUDIPLO_PORT=3216 pnpm test:issuer-eudiplo
```

```bash
docker compose -p eudi-pcaf-i16 -f adapters/eudiplo/docker-compose.yml down -v
```

It enrols the SUT by CSR with the Test Registrar, publishes `TL-WP` (as the Test Wallet Provider builds it,
`publishTlWp`) and `TL-PID` on the Test Trust Infrastructure, and runs `setUp`. It then checks:

- that EUDIPLO stored the strict status check and `revokeWithWalletUnit`;
- the Credential Issuer metadata: the PID configuration, the key attestation levels, the batch size, the nonce and notification endpoints, and encryption;
- the authorization server metadata: `attest_jwt_client_auth` and DPoP;
- the signed metadata (`Accept: application/jwt`), whose `x5c` must be the Registrar's access certificate chain;
- offers by value and by reference, with and without `tx_code`, which it resolves;
- the status list settings, `setStatus` and `refreshTrust`;
- that `tearDown` removes the tenant.

`EUDIPLO_EXPECT_VERSION` (default: the version in `reference.env`) is the version the instance must report; the checks
of the reference's own features run only when it is the reference version.

`setStatus` cannot be shown without an issued credential: for a session that has issued none, EUDIPLO answers
`409 No status mapping found for session ... and credential configuration undefined`, and
`GET /api/session/{id}/credential-status` answers `[]`. The test asserts exactly that. Revocation of an issued PID is
exercised by the revocation test cases (issue 22): `PP_WS_SM_Revocation_003` and `PP_RP_SM_Revocation_008` revoke
through `setStatus` and see the published list change within `T_rev`.

## Status lists (issue 22)

The status list test cases (`PP_WS_SM_Revocation_001` to `_003`, `PP_RP_IA_Supportive_*`, `PP_RP_SM_Revocation_*`)
fetch the lists EUDIPLO publishes under `/issuers/{tenant}/status-management/status-list/{id}` anonymously, as a
Relying Party does. EUDIPLO answers `Accept: application/statuslist+cwt` with a CWT and anything else with a JWT
(`ICS-05.token_formats`). It re-signs a list on every change (`immediateUpdate`) and when a fetch finds it expired, so
every fetch returns a token that has not expired (`PP_RP_SM_Revocation_005`). It sets no cache headers on the status
list response, which Token Status List does not require of a Status Provider (`PP_RP_IA_Supportive_002` passes since the
spec review of 2026-11-20). It publishes no
identifier lists and the adapter configures no mdoc PID, so `PP_WS_SM_Revocation_002` and the `MD` variants of
`PP_RP_SM_Revocation_001` and `_007` are NOT APPLICABLE.

## Revocation chaining, trust lists, issuer integrity and unlinkability (issue 26)

- **Chaining** (`PP_WS_SM_Revocation_006`, `_007`): `revokeWithWalletUnit` is on for both PID configurations, and the
  Compose file polls wallet units every 30 s (`WALLET_UNIT_STATUS_CHECK_INTERVAL`). The test case serves `SL-WP-A`
  under a URL of its own, the WIA or KA of the issuance points there, and the Test Wallet Provider then revokes the
  entry in place. Both pass against the reference image since 2026-11-23; against `ae0792a` they failed (TS3 1.5,
  EUDI profile): EUDIPLO did not read the TS3 1.5 status claims, and `revokeWithWalletUnit` followed the KA only.
- **Suspension** (`_005`): status lists have 2 bits per entry; suspend, reinstate and revoke show within a second.
- **Change of subject data** (`_008`): EUDIPLO keeps no subject record, so `changeSubject` plays the back office. It
  revokes every session issued for the subject, and later offers carry the new data. The test case runs alone, last.
- **`TL-WP` versions** (`PP_Inf_SM_TrustMechanisms_*`): `refreshTrust` clears EUDIPLO's trust list cache (EUDIPLO has
  no refresh that keeps the cached list; after a version with a bad seal it uses no list, declared as
  `ICS-15.invalid_version: discard`, so `_004_UF` passes as `POLICY`). EUDIPLO keeps
  the highest accepted `LoTESequenceNumber` in its database, so the harness publishes the default list again under a
  higher number after each test case. A withdrawn Wallet Provider has no issuance service on the list, which EUDIPLO
  treats as untrusted.
- **Signed metadata** carries the access certificate (`PP_Inf_SM_TrustMechanisms_007`, `anchor-access`).

Findings against `ae0792a`, fixed in the reference image since 2026-11-23: a TS3 1.5 WIA or KA status was never read
([EUDIPLO/eudiplo#1620](https://github.com/EUDIPLO/eudiplo/issues/1620)) and `revokeWithWalletUnit` followed the KA only
([EUDIPLO/eudiplo#1621](https://github.com/EUDIPLO/eudiplo/issues/1621)), `PP_WS_SM_Revocation_006`, `_007`; array
elements of an SD-JWT VC were not disclosable one by one, PID_21
([EUDIPLO/eudiplo#1624](https://github.com/EUDIPLO/eudiplo/issues/1624)), `PP_WS_SM_IssuerIntegrity_005`.

SD-JWT VC salts have 64 bits, below the 128 bits RFC 9901 section 9.3 RECOMMENDS; `PP_WS_SM_IssuerIntegrity_006` records
it (suggestion in [`upstream-findings/suggestions/sd-jwt-salt-length.md`](upstream-findings/suggestions/sd-jwt-salt-length.md)).
A `TL-WP` with a bad seal leaves EUDIPLO without a list, which conforms (question in
[`upstream-findings/suggestions/trust-list-last-known-good.md`](upstream-findings/suggestions/trust-list-last-known-good.md)).

Concurrent credential requests of a fresh tenant sometimes fail with `credential_request_denied` "Could not allocate
status entry after maximum retries". The runner therefore issues one credential at a time, also for test cases that
wait in parallel.
## The authorization code flow (`P-AC`, issue 20)

EUDIPLO's built-in authorization server (PAR with PKCE `S256` required, `request_uri` single-use for 60 s, codes bound
to `client_id`, `redirect_uri` and the DPoP key, `iss` in the authorization response) issues authorization codes without
any login or consent step (docs `issuance/authorization-servers.md`). The adapter uses it rather than a `chained`
authorization server in front of a scripted test OpenID provider: the subject is the one whose claims the offer carries,
bound to the authorization request by `issuer_state`, so `authenticateSubject` only opens the authorization request
and returns the redirect. The ICS records the choice (`ICS-03.subject_authentication: none`). The authentication of the
User is outside the catalogue's scope (section 1); what the `AC` test cases test is the protocol: PAR, PKCE, the
`request_uri`, the code and its bindings, and the authorization response. A `chained` server with a scripted login
would test the same against EUDIPLO plus a test IdP, at the cost of a second service in the Compose setup.

## What the pinned image still lacks, and the test cases it leaves not validated

Checked against the running image and EUDIPLO's source at `ae0792a`. The full reference run against `7586139`
(2026-11-23) gives the same NOT APPLICABLE test cases.

| Gap | Effect | Test cases not validated against EUDIPLO |
| --- | --- | --- |
| No login at the built-in authorization server: it issues authorization codes without a login or consent step | `authenticateSubject` only follows the redirect (`ICS-03.subject_authentication: none`); the `AC` test cases test the protocol, not a login | none; a login would need the chained server below |
| No DPoP server nonce (no `DPoP-Nonce` or `use_dpop_nonce` in the source) | NOT APPLICABLE (`ICS-13.dpop_nonce` No; `P-DPN` stands for the nonce endpoint only) | `PP_WS_SM_TokenBinding_006_UF` |
| Identifier lists are read as verifier but never published by the issuer | `P-IL` No | `PP_RP_SM_Revocation_007` and the identifier list variants of `SCN-P` |
| A proof's `iat` is checked only against the future in the source; its age is bounded only by the `c_nonce`, which lives 10 minutes | `ICS-14.T_proof` "not bounded"; the test cases take the 5 minute cap | none: `PP_WS_SM_ProofOfPossession_006_UF` passes, the pinned image refuses `iat` − 1 h with `invalid_proof` (issue 19 run) |
| No subject record to change: the claims travel with each offer | The adapter plays the back office (issue 26): `changeSubject` revokes every session of the subject, and later offers for it carry the new data | none: `PP_WS_SM_Revocation_008` runs, alone, after every other test case |
| With `walletAttestationRequired`, the authorization server metadata still lists `none` next to `attest_jwt_client_auth` in `token_endpoint_auth_methods_supported` | A token request without WIA, or without PoP, is still refused with `invalid_client` | none: `PP_WS_SM_ClientAttestation_002_UF` passes |
| Shortest status list lifetime 60 s (`ttl` minimum, live) | `T_rev` PT1M with `immediateUpdate` | none: `REVOKED(T_rev)` test cases (`PP_WS_SM_Revocation_003`, `PP_RP_SM_Revocation_008`) poll for a minute, `PP_RP_SM_Revocation_005` across one `exp` |
| Revocation chaining is a poll, and a suspended wallet unit changes nothing | `T_chain` PT7M; a suspended WIA or KA is still rejected at issuance (strict), but suspension does not chain | none (the catalogue chains revocation only) |
| Pre-authorized codes live as long as the session (`SESSION_TTL` 24 h) | The expiry is tested one hour after it: 25 hours, above any reference run's `--max-wait`, so NOT APPLICABLE there | `PP_WS_IA_PreAuthorized_003_UF` |
| PAR `request_uri` lives 60 s | Its expiry half waits 61 minutes; NOT APPLICABLE in the reference run (default `--max-wait` 0), validated once with `--max-wait PT1H5M` | `PP_WS_IA_AuthorizationCode_004_UF` step 3 |

Known findings of the security mechanism test cases (issue 19) against `ae0792a`, all fixed in the reference image
since 2026-11-23 (the issues and their fixes are listed in [`upstream-findings/`](upstream-findings)): the status of a
TS3 1.5 WIA or KA (`client_status.status`, `key_storage_status.status`) was never read
(`PP_WS_SM_ClientAttestation_012_UF`, `_013_UF`, `PP_WS_SM_KeyAttestation_008_UF`, `_009_UF`), the PID's expiry was not
bounded by the WIA's revocation maintenance period (`PP_WS_SM_ClientAttestation_016_UF`), and a key proof with `alg`
`none` was rejected with `invalid_credential_request` instead of `invalid_proof` (`PP_WS_SM_ProofOfPossession_002_UF`).

Not findings since the spec review of 2026-11-20: WIA and KA under each other's anchor of the same Wallet Provider
(`PP_WS_SM_ClientAttestation_006_UF`, `PP_WS_SM_KeyAttestation_004_UF`: TS3 binds anchors per Wallet Provider, INFO),
the KA `nonce` in a `jwt` proof (`PP_WS_SM_KeyAttestation_007_UF`: F.4 checks the proof's nonce, INFO), and a replayed
PoP `jti` (`PP_WS_SM_ClientAttestation_009_UF`: replay detection is a SHOULD, INFO; a suggestion in
[`upstream-findings/suggestions/`](upstream-findings/suggestions)). With the maintenance period at the 31 days TS3
guarantees, `PP_WS_SM_ClientAttestation_015` and `PP_WS_SM_KeyAttestation_011` pass.

`PP_WS_SM_ProofOfPossession_009_UF`: EUDIPLO advertises `ES512` for `jwt` proofs, so its P-521 step is NOT APPLICABLE
and the test case is judged on the off-curve step. `PP_WS_SM_ProofOfPossession_007_UF` (`AC` only) runs since `P-AC`
(issue 20): EUDIPLO accepts a key proof whose `iss` is not the `client_id`, which Appendix F.4 does not require it to
check (INFO since the spec review).
`PP_WS_MS_CredentialEndpoint_006_UF` (`AC` only) is NOT APPLICABLE: EUDIPLO issues the configuration ID itself
(`pid-sd-jwt-vc`) as `credential_identifier` in every token response, so no identifier of another session exists.

Not configured by the adapter although EUDIPLO supports it; each can be added when the test cases need it:

| Feature | ICS | Test cases not validated until then |
| --- | --- | --- |
| PID in mdoc (`mso_mdoc`, `eu.europa.ec.eudi.pid.1`); a PID Provider must issue both formats (PID_02) | `ICS-02` SD-JWT VC only | `PP_WS_DM_PidMdoc_*`, `PP_WS_MS_Metadata_006`, `PP_WS_IA_MainInteraction_003` and every `MD` variant |
| Embedded disclosure policy | `P-EDP` No | `AP_WS_MS_Metadata_102`, `AP_WS_SM_Revocation_102` (Attestation Providers) |
| Short-lived configuration without status | `P-SHORT` No | `PP_WS_SM_Validity_002` |
| Portrait and its opt-out | `ICS-17.portrait_opt_out` No | `PP_WS_DM_Portrait_001` |

## DPoP, batch, re-issuance, deferred, notification and robustness (issue 25)

The test cases of `PP_WS_SM_TokenBinding`, `PP_WS_IA_Batch`, `_Reissuance`, `_Deferred`, `_Notification`,
`PP_WS_SH_Encoding` and `_Encryption` run against the pinned image and pass since 2026-11-23. Against `ae0792a`
four of them failed: HTTP 500 for a malformed `transaction_id` (`PP_WS_IA_Deferred_002_UF`, confirmed), and three on the
missing status check of a TS3 1.5 WIA or KA (EUDI profile). The others pass or record what the specifications leave open (INFO): `batch_size` exceeded with `jwt` proofs, refresh
after revocation, HTTP 201 at the notification endpoint (any 2xx is allowed), the error body for an unknown event, 413
without an OAuth error object, deeply nested JSON, and `jku`/`x5u` headers, which EUDIPLO does not fetch. The refresh
token is bound to the Wallet Unit's client authentication, as RFC 9449 section 5 allows for a confidential client:
`PP_WS_IA_Reissuance_002_UF` presents it as another Wallet Unit.

`PP_WS_IA_Reissuance_005_UF` and `PP_WS_SH_Encoding_005_UF` serve the revoked Wallet Instance and the decompression
bomb through issue 19's `wallet-event` step in a version of `SL-WP-A` under a URL of the test case; against `ae0792a`
they failed on the same missing status check, as EUDIPLO never requested it. `PP_WS_SM_TokenBinding_007_UF` waits out the access token: the adapter sets the built-in authorization
server's `token.lifetimeSeconds` to EUDIPLO's minimum of 60 s (ICS-14.access_token PT1M), and the step waits
`expires_in` plus the declared `T_skew` plus one minute (126 s).

`PP_WS_IA_Batch_006` runs in the authorization code flow (issue 20) and passes: one authorization gives the batch.
Not applicable against EUDIPLO: `PP_WS_SM_TokenBinding_006_UF` (no DPoP server nonce).

## EUDIPLO as Attestation Provider (issue 27)

The `categories` of [`ics.yaml`](ics.yaml) declare three more Provider instances of the same image, one tenant each, which
the runner sets up and tests in parallel with the PID Provider: a QEAA Provider (`Q`, enrolled as `QP-T` with a granted
qualified EAA service on `TL-QEAA`), a PuB-EAA Provider (`PB`, `PB-T` on `TL-PUB`) and a non-qualified EAA Provider
(`E`, `EP-T` under the rulebook anchor `CA-EP-T`). Each issues FCAF `default_credential_A`
(`vct` `urn:rp-conformance:credential_a:1`, doctype `test.rp-conformance.credential_a.1`) in the same configurations as
the PID (`ICS-02.SD`, `.MD`, `.second`, `ICS-05.short.*`), plus one SD-JWT VC configuration that is not device-bound
(`ICS-04.NDB.SD`, `keyBinding: false`). The device-bound ones require `iso_18045_moderate` or `iso_18045_high`
(ICS-04), so `AP_WS_SM_KeyAttestation_101_UF` runs with `basic`. The QEAA and PuB-EAA tenants chain revocation
(`revokeWithWalletUnit`, ICS-07 Yes), the non-qualified EAA tenant does not (ICS-07 No), so `AP_WS_SM_Revocation_100`
sees both answers of its `POLICY`. Every tenant rejects an unobtainable WIA or KA status (`strict`, ICS-18 reject). The
QEAA tenant publishes an embedded disclosure policy (`embeddedDisclosurePolicy`, ICS-19 `P-EDP`) on every
configuration. `AP_WS_SM_Revocation_102` issues from a configuration of its own (`ICS-19.EDP.SD`, `qeaa-sd-jwt-vc-edp`),
whose policy `changeDisclosurePolicy` changes with `PATCH /api/issuer/credentials/{id}?revokeOnDisclosurePolicyChange=true`
([EUDIPLO/eudiplo#1642](https://github.com/EUDIPLO/eudiplo/pull/1642)): EUDIPLO then revokes every attestation issued
under the old policy, which on a shared configuration would revoke those of the test cases running at the same time. A
release before it, such as the earlier reference image `ae0792a`, ignores the parameter.

The `AP_*` variants of `PP_*` test cases fail where the `PP_*` test case fails, for the same reason: EUDIPLO's behaviour
does not depend on the credential type. `AP_WS_SM_Revocation_101` uses the 31-day stimulus of
`PP_WS_SM_ClientAttestation_015`. Against `ae0792a` the `AP_*` variants of the `PP_*` findings failed, and two findings
were new (`basis: profile`): a configuration with `keyBinding: false` was published and handled as device-bound
([EUDIPLO/eudiplo#1625](https://github.com/EUDIPLO/eudiplo/issues/1625); `AP_WS_MS_Metadata_008`, `_100`, `_101`,
`AP_WS_SM_KeyAttestation_102`, `_103`), and changing the embedded disclosure policy left the attestations issued under the
old one valid, EDP_11 ([EUDIPLO/eudiplo#1626](https://github.com/EUDIPLO/eudiplo/issues/1626);
`AP_WS_SM_Revocation_102`). All of them pass against the reference image since 2026-11-23.

`AP_WS_SM_ClientAttestation_016_UF` is gone since 2026-11-23: the test case is PID only, as `_015`. EUDIPLO bounds the
expiry by the maintenance period of the WIA and KA only for configurations with `revokeWithWalletUnit`
([EUDIPLO/eudiplo#1634](https://github.com/EUDIPLO/eudiplo/pull/1634)), so its `E` variant (no chaining, ICS-07 No)
failed; TS3 1.5 section 2.4.3 (ISSU_12c) states the rule for the PID, and for an Attestation Provider that chains
`AP_WS_SM_Revocation_101` (ISSU_12d, `P-CHAIN`) tests it. [`known-findings.yaml`](known-findings.yaml) has no entry
against the reference image.

Not applicable against EUDIPLO, with the reason in the report: `AP_WS_MS_Metadata_102` and `AP_WS_SM_Revocation_102` in
`PB` and `E` (no embedded disclosure policy configured there, ICS-19), `AP_WS_SM_Revocation_101` in `E` (no chaining),
and the `AP_*` variants of the `PP_*` test cases that are not applicable to the PID Provider (`P-IL`, DPoP server nonce).

`POST /api/session/revoke` sometimes answers HTTP 503 "Could not generate current tokens for status list" when several
lifecycle test cases of one tenant change the same status list at once; the adapter's `setStatus` repeats the call, and
accepts a credential that already has the new status.

## Authorization code flow with a scripted login (option, not used)

Issue 20 chose the built-in authorization server (see "The authorization code flow" above). A chained server with a
scripted login remains possible, as follows:

EUDIPLO can run the authorization code flow with a real login through a **chained** authorization server
(docs `issuance/authorization-servers.md`, "Chained"). EUDIPLO is the authorization server towards the wallet: PAR,
PKCE `S256`, DPoP and wallet attestation stay EUDIPLO's. It delegates the login to an upstream OpenID provider:

1. The harness runs a small test OpenID provider on the host: discovery, `jwks_uri`, an authorization endpoint and a
   token endpoint. Its authorization endpoint logs in the test subject without a form: it answers at once with a
   redirect to EUDIPLO's callback carrying a `code`, for the subject the adapter named, and its ID token has
   `sub` = `SUBJ-1`. The Compose file already allows HTTP and private addresses for outbound calls
   (`OUTBOUND_URL_ALLOW_HTTP`, `OUTBOUND_URL_ALLOW_PRIVATE_NETWORK`), so EUDIPLO can reach it at
   `host.docker.internal`. The redirect URI to register is `{PUBLIC_URL}/issuers/{tenant}/chained-as/callback`.
2. `setUp` adds `{ "type": "chained", "id": "subject-login", "upstream": { "issuer": "<provider>", "clientId": "eudiplo" } }`
   to `authorizationServers`, after the built-in server, with `walletAttestationRequired` as for the built-in one. The
   built-in server must stay the first entry, since only it redeems pre-authorized codes.
3. `createOffer` with `grant: 'authorization_code'` posts `flow: authorization_code` and `authorization_server: subject-login`.
   The claims stay inline with the offer, so the subject's values do not depend on the provider.
4. `authenticateSubject(authorizationRequestUrl, subject)` makes the provider log in `subject` next. It then follows
   the redirects: EUDIPLO's `/chained-as/authorize`, the provider, EUDIPLO's `/chained-as/callback`. It returns the
   final redirect to the wallet's `redirect_uri` with `code`.

The `oid4vp` authorization server is the alternative: the "login" is a PID presentation, which the RP harness's
Conformance Wallet could answer. It ties the issuer suite to the RP side, though, so the chained server is the simpler
choice. The built-in server issues codes without any login, so a hook there would only follow the redirect, and would
not test that the User authenticates.
