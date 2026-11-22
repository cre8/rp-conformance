# RP conformance

Functional conformance tests for **Relying Parties** of the EUDI Wallet ecosystem: services that request and verify PIDs and attestations from Wallet Units.

Site: [rp-conformance.eudi-wallet.dev](https://rp-conformance.eudi-wallet.dev/), the **Peer Conformance Assessment Framework (PCAF)**: the Relying Party and the Provider test cases, the FCAF's framework pages rewritten for these SUTs (without the FCAF's Wallet Solution content) and the documents of both suites, as an unofficial preview (`scripts/site-build.sh`, deployed from `main` by `.github/workflows/pages.yml`). The overlays in `fcaf-overlay` and `fcaf-overlay-issuer` stay a diff against the FCAF; the site-only pages are in `website/pcaf`.

The EU [Functional Conformance Assessment Framework](https://conformance.eudi.dev) (FCAF) tests only the Wallet Solution, and the OIDF verifier suite mostly covers happy flows. This project defines and, later, executes the tests a Relying Party must pass, with the focus on what it must reject: expired credentials, revoked or suspended credentials, unusable status lists, wrong trust anchors, stale trust lists, faulty response encryption.

Status: specification, design, and Phases 1 to 4 of the harness: all 121 baseline test cases run unattended (PID, QEAA, PuB-EAA and non-qualified EAA in SD-JWT VC and mdoc format, Status List Tokens in JWT and CWT format, identifier lists, response encryption via redirects and via the W3C Digital Credentials API), each once per presentation flow the Relying Party supports. Phase 5 adds 97 test cases from the remaining catalogue areas: session binding (KB-JWT `nonce`, `aud` and `iat`, replay, the mdoc SessionTranscript), device binding (KB-JWT and device signature, `cnf`, device-signed elements, algorithms), issuer integrity (issuer signature, algorithm and key, `typ`, `vct` and `docType`, disclosures and value digests, the signer's certificate path), the trust lists themselves (`RP_Inf`: seal, signer, type, staleness and grace period, rollback, the Trusted List reached through the LOTL), and the requests the Relying Party sends (protocol messages, `client_metadata`, DCQL, access and registration certificate). Issue 29 adds 16 test cases for how the Relying Party invokes the wallet and handles the flow around the presentation (`IA_Engagement`, `IA_ProtocolFlow`: `request_uri`, the redirect and its response code, error, late and repeated responses, `state`). Issue 30 adds 24 test cases for the positive baseline of QEAA, PuB-EAA and non-qualified EAA, selective disclosure and the data model (the released PID attributes, their values and data types, missing and unrequested claims, `values` constraints). Issue 31 adds 21 test cases for combined presentations (`UC_Presentation`: a PID and an EAA in one response, `credential_sets`, entries left out, unknown or repeated, one DeviceResponse for two mdocs, attribute-based binding). Issue 32 adds 27 test cases: robustness against malformed and oversized input (`SH_Encoding`), how status lists are retrieved (`RP_PP_IA_Supportive`: the request, caching within `ttl`, failing endpoints, redirect loops, link-local URIs), and six single objectives on status list freshness, revocation mechanisms and validity policies. A nightly GitHub Actions job runs all 306 against EUDIPLO's main image.

## Contents

| Path | Content |
| --- | --- |
| [rp-test-catalogue.md](rp-test-catalogue.md) | All test objectives (222), traced to the ARF high-level requirements, with the decisions taken on the open questions (§8) |
| [issuer-test-catalogue.md](issuer-test-catalogue.md) | Draft: test objectives (182) for PID Providers and Attestation Providers as SUT, traced to the ARF high-level requirements, with the decisions taken on the open questions (§8). Executable in part (see Issuer suite) |
| [fcaf-overlay/](fcaf-overlay/README.md) | 121 baseline test cases and 185 further ones in the FCAF test case format, with the defaults, the Relying Party ICS and the navigation, as an overlay on the FCAF content branch `submitted` |
| [fcaf-overlay-issuer/](fcaf-overlay-issuer/README.md) | The PID Provider test cases of the issuer suite in the FCAF test case format, one page per test case with its variants, with the defaults, the Provider ICS and the navigation, as a second overlay laid over the first |
| [harness-design.md](harness-design.md) | Design of the test harness: conformance wallet, status and trust list servers, artifact forge with fault injection, RP adapters, verdicts, delivery phases |
| [issuer-harness-design.md](issuer-harness-design.md) | Draft addendum to the harness design for the issuer suite: what it reuses, the issuance client, Test Wallet Provider, Test Registrar, issuer adapter with EUDIPLO as the reference issuer, faults, expected results, delivery phases and the decisions taken (§12). Phase I0 implemented |
| [packages/](packages/) | The harness (TypeScript, pnpm workspace): `core` (adapter interface, test definition format, shared FCAF wording), `forge` (test PKI with IACA anchors and mdoc document signers, PID and `default_credential_A` in SD-JWT VC and mdoc format, Status List Tokens in JWT and CWT format, identifier lists, JAdES-sealed LoTE, the test LOTL and `TL-QEAA` as ETSI TS 119 612 Trusted Lists with XAdES signatures, registration certificate, and the fault layer), `wallet` (Conformance Wallet: KB-JWT, mdoc DeviceResponse with the OpenID4VP handover, via redirects and the DC API, with the presentation faults of the forge), `dc-api-shim` (Playwright replaces `navigator.credentials.get` on the Relying Party's page and hands the request to the Conformance Wallet), `status-provider`, `trust-infrastructure`, `validator` (reference validator with one named check per property, including the request-side and trust list checks, and the self-validation of every fault), `reference-rp`, `definitions` (the 279 test definitions, the source of the FCAF test cases), `fcaf-render` (renders the overlay from the definitions and the shared pages), `controller` (CLI, selection, gating, report, JUnit XML, known findings) |
| [scripts/fcaf-lint.sh](scripts/fcaf-lint.sh) | Runs the patched FCAF lint on the rendered test cases of both overlays, as CI does |
| [adapters/](adapters/) | RP adapters with their ICS: `reference` (the reference RP, in-process) and `eudiplo` (with a Docker Compose file for EUDIPLO and PostgreSQL, and its known findings) |
| [.github/workflows/nightly-eudiplo.yml](.github/workflows/nightly-eudiplo.yml) | Nightly run of every test case of both suites against `ghcr.io/eudiplo/eudiplo:main`, also started by hand (`workflow_dispatch`) |

## Approach

- **Structure**: the FCAF methodology, with the test classes it reserves for a Relying Party SUT (`RP_WS`, `RP_PP`, `RP_AP`, `RP_Inf`), so the test cases could be contributed upstream.
- **Sources**: ARF v3.0.0 (Annex 2), OpenID4VP 1.0, HAIP 1.0, SD-JWT (RFC 9901), SD-JWT VC, Token Status List, ISO/IEC 18013-5, ETSI TS 119 602, 119 612, 119 475 and 119 472-2.
- **Verdicts**: the Relying Party exposes its verification result; every negative test runs only after its positive control passed.

## Running the harness

Requires Node.js 22.12 or later and pnpm. The DC API flow runs in Playwright's Chromium (headless shell), installed once:

```bash
pnpm install
```

```bash
pnpm playwright:install
```

```bash
pnpm test
```

```bash
pnpm rp-conformance run --adapter reference
```

`pnpm test` includes the self-validation (harness design §7): every fault of the catalogue fails exactly its target check of the reference validator (the trust-list faults a check of the trust list, the request faults a request check), every step of every executable definition carries exactly one fault in each flow it runs in, the test LOTL and `TL-QEAA` that the forge signs are accepted by `@owf/eudi-tl`, and every executable test case passes against the reference RP in both flows. `--only` selects test cases by ID or pattern (`--only 'RP_PP_SM_Revocation_*'`); `--flows redirect` or `--flows dc-api` restricts the run to one flow; `--list` shows every definition and which are text only.

Every test case runs once per flow the ICS declares (RP.P.1 redirects, RP.P.2 DC API), and its positive control must have passed in the same flow. The `SessionEncryption` variants, the test cases on the audience and handover of one flow (`SessionBinding_002`, `_006` to `_009`) and the request-side test cases of one flow (`ProtocolMessages_001`, `_002`, `_004`, `_005`, `RpIntegrity_007`) name their flow in their profile and run only in it. The request-side test cases start presentations and check the requests the Conformance Wallet captures, without answering them; the `RP_Inf` test cases publish a new version of `TL-PID` or `TL-QEAA` and restore it afterwards. In the DC API flow the adapter returns a page of the Relying Party; the shim opens it in Chromium, answers its `navigator.credentials.get` call with the Conformance Wallet's `dc_api.jwt` response, keeping the page's real origin, and records the request in which the page forwards the response to its backend.

`--concurrency <n>` runs up to `n` test case runs at a time (default 1, one after another); most of a full run is the deliberate waits of a few test cases (the late response of `ProtocolFlow_011`, the `SessionEncryption` and `Encoding_001` waits), which then overlap. A test case waits for its positive control in the same flow. The test cases that publish trust list versions (`TrustMechanisms`) change the run's one namespace, which every other test case relies on, so they run after the others, one at a time (harness design §6). The report lists the results in definition order; the log lines come as the runs finish.

The report goes to `reports/<run>/report.json` with a `summary.md` and a `junit.xml`, and the artifacts of every step (credential, Status List Token as served and before its fault, request, presentation, response form or DC API `data`, the page's network log, the RP's verification result) next to it, per flow.

Against EUDIPLO (latest published image, PostgreSQL):

```bash
docker compose -f adapters/eudiplo/docker-compose.yml up -d --wait
```

```bash
pnpm rp-conformance run --adapter eudiplo
```

`EUDIPLO_IMAGE=ghcr.io/eudiplo/eudiplo:main` runs the unreleased main image instead.

`EUDIPLO_URL`, `EUDIPLO_CLIENT_ID`, `EUDIPLO_CLIENT_SECRET` and `HARNESS_HOST` override the defaults of the Compose file. The harness serves plain HTTP; the Compose file allows that with `OUTBOUND_URL_ALLOW_HTTP`.

EUDIPLO has no page of its own for the DC API, so the adapter serves a minimal relying-party page on `http://127.0.0.1:<port>` (`EUDIPLO_PAGE_PORT`, default a free port). It creates the offer with `response_type` `dc-api` and that origin as `expected_origin`, passes EUDIPLO's signed request object to `navigator.credentials.get`, and posts the returned `data` to the request's `response_uri`, as EUDIPLO's SDK does.

For QEAAs the adapter configures the test LOTL as an ETSI TS 119 612 Trusted List (`etsi_tl` with `format` `trusted-list`), pinned to its signing certificates; EUDIPLO follows its pointer to `TL-QEAA`. EUDIPLO reads Trusted Lists since [EUDIPLO/eudiplo#1513](https://github.com/EUDIPLO/eudiplo/pull/1513), which is on `main` but in no release yet: 9.1.0 rejects that configuration (HTTP 400 when the adapter sets up), so run 9.1.0 with an ICS that declares RP.G.3 (QEAAs) No (`--ics`), and its QEAA test cases are NOT APPLICABLE. For PuB-EAAs the adapter configures `TL-PUB`; for non-qualified EAAs it registers the rulebook anchor `CA-EP-A` in a trust list of the tenant, EUDIPLO's way of trusting an anchor that no list publishes.

`--known-findings adapters/eudiplo/known-findings.yaml` reports the FAILs listed there as known findings; the run then fails only on another FAIL, an INCONCLUSIVE or REVIEW result, or a harness error. The nightly job does this, uploads `reports/` as an artifact and adds the summary to the job summary. Its image is `ghcr.io/eudiplo/eudiplo:main`, or another one given when it is started by hand; PostgreSQL comes from Amazon ECR Public (`POSTGRES_IMAGE`), which has no anonymous pull limit like Docker Hub.

Everything on the host uses `127.0.0.1`, not `localhost`: Docker publishes EUDIPLO on `127.0.0.1` only, and Node.js may resolve `localhost` to `::1` first, where another process can hold the same port (an adapter login then fails with HTTP 401 and `request_uri` with 404). The adapter defaults to `http://127.0.0.1:3000`, EUDIPLO's `PUBLIC_URL` in the Compose file names `127.0.0.1`, and the CLI resolves host names IPv4 first. For a second EUDIPLO next to a running one, give it another project name and port; `EUDIPLO_PORT` sets the published port, the `PUBLIC_URL` and the adapter's default URL together:

```bash
EUDIPLO_PORT=3100 docker compose -p rp-conformance-eudiplo-2 -f adapters/eudiplo/docker-compose.yml up -d --wait
```

```bash
EUDIPLO_PORT=3100 pnpm rp-conformance run --adapter eudiplo
```

Decisions on the open points of [harness-design.md](harness-design.md) §12: the executable TypeScript definitions in `packages/definitions` are the source of truth, and `packages/fcaf-render` produces the FCAF markdown from them (§4.2); the reference RP is built on the reference validator; the OIDF bridge is optional and not implemented.

## Issuer suite

Status: phases I0 to I2 of [issuer-harness-design.md](issuer-harness-design.md) §10 in part. The PID Provider test cases of `packages/issuer-definitions` are executable, one definition per test case and variant: the positive controls and both grants (`PP_WS_IA_MainInteraction`, `_PreAuthorized`, `_AuthorizationCode`), batch, re-issuance, deferred issuance and notification (`PP_WS_IA_*`), message structure (`PP_WS_MS_Metadata`, `_Offer`, `_CredentialEndpoint`), client attestation, key attestation, proofs, DPoP, validity and revocation (`PP_WS_SM_*`), the PID Rulebook (`PP_WS_DM_*`), robustness and encryption (`PP_WS_SH_*`) and the published status lists (`PP_RP_*`). `pnpm rp-conformance issuer --list` lists them. They are rendered to the second FCAF overlay [fcaf-overlay-issuer/](fcaf-overlay-issuer/README.md) and published on the site next to the Relying Party test cases. Still to come: revocation chaining and `PP_Inf`, the rest of `PP_WS` (issuer integrity, unlinkability) and the Attestation Providers (`AP_*`).

What is not validated: the suite is proven against EUDIPLO only. Test cases EUDIPLO cannot run (no login at its built-in authorization server, so the `AC` variants run without user authentication; no identifier lists; no DPoP server nonce; no subject record to change) are NOT APPLICABLE against it and have not been seen to pass against any Provider, and test cases that FAIL against it with a known finding are not validated until EUDIPLO is fixed. [adapters/issuer-eudiplo/README.md](adapters/issuer-eudiplo/README.md) lists both, per test case.

```bash
pnpm rp-conformance issuer --list
```

```bash
docker compose --env-file adapters/issuer-eudiplo/reference.env -f adapters/eudiplo/docker-compose.yml up -d --wait
```

```bash
pnpm rp-conformance issuer run --adapter eudiplo --ics adapters/issuer-eudiplo/ics.yaml --known-findings adapters/issuer-eudiplo/known-findings.yaml
```

Per run the controller starts the Test Trust Infrastructure (`TL-WP`, `TL-PID`, `TL-AC`, `TL-RC`) and the Test Status Provider (`SL-WP-A`, `SL-WP-B`), creates the Test Wallet Provider with its Wallet Units, enrols the Provider through the Test Registrar (from its CSRs where the adapter returns them, otherwise with keys the Registrar generates) and sets the adapter up once. Each step of action `issuance` creates an offer through the adapter and runs the pre-authorized code flow with the issuance client of `packages/issuer-wallet` (WIA and PoP, DPoP, nonce, a proof that carries the KA). Every credential the Provider issues goes through the reference validator with the suite's trust configuration (`OBS-CRED`): format, `issuer-trust` to the enrolled `PP-T` on `TL-PID`, `issuer-signature`, `disclosures`, `validity`, `holder-binding` (bound to a proof key the KA attests, in place of `key-binding`) and `status-reference`, then the status list checks. `ISS` passes when every credential passes every check, `REJ` when the request at which the flow ended got a 4xx with an OAuth error object and nothing was issued; no answer may be a 5xx. The definitions are in `packages/issuer-definitions`, one per test case and variant; a step names its credential configuration by reference to the ICS (`ICS-02.SD`), which the adapter's `ics.yaml` maps to the Provider's configuration ID.

The report goes to `reports/<run>/` as for the RP suite (`report.json` with every request and response and the check results, `summary.md`, `junit.xml`, the credentials). `EUDIPLO_PORT` and `HARNESS_HOST` work as above. The CI job `Issuer reference run` runs the same command against the pinned image (`adapters/issuer-eudiplo/reference.env`, the one place that names it; see [adapters/issuer-eudiplo/README.md](adapters/issuer-eudiplo/README.md)) on every pull request that touches the issuer suite and uploads the report. The nightly job runs it against EUDIPLO's latest main image after the Relying Party suite, with its own report, JUnit XML and artifact (`issuer-conformance-eudiplo-<run>`): a FAIL there that is not a known finding is a regression of EUDIPLO's main to analyse, not a harness failure.

## Rendering the test cases

The test cases in `fcaf-overlay/docs/fcaf` are rendered from the definitions in `packages/definitions`, those in `fcaf-overlay-issuer/docs/fcaf` from `packages/issuer-definitions`; the shared pages come from `packages/fcaf-render/pages` and, for the four modified FCAF pages, from the base pages in `packages/fcaf-render/upstream`. Edit those, then:

```bash
pnpm fcaf:render
```

```bash
pnpm fcaf:render --check
```

```bash
scripts/fcaf-lint.sh
```

`--check` fails when a committed overlay differs from what the definitions render; `pnpm test` checks the same. `scripts/fcaf-lint.sh` fetches the FCAF repository at the pinned commits and runs its lint with [fcaf-overlay/fcaf_lint-rp.patch](fcaf-overlay/fcaf_lint-rp.patch) and [fcaf-overlay-issuer/fcaf_lint-issuer.patch](fcaf-overlay-issuer/fcaf_lint-issuer.patch) applied; any finding fails it, except the one check the issuer definitions do not satisfy yet ([fcaf-overlay-issuer/README.md](fcaf-overlay-issuer/README.md#lint)). CI runs all three.

## Licence

[EUPL-1.2](LICENSE), the licence of FCAF. The files under `fcaf-overlay/docs/fcaf/` and `fcaf-overlay-issuer/docs/fcaf/` that modify existing FCAF pages (`defaults.md`, `references.md`, `.nav.yml`, `suts/index.md`) and their unmodified originals in `packages/fcaf-render/upstream/` contain FCAF content, © European Union, under the same licence.
