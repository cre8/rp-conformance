# RP conformance

Functional conformance tests for **Relying Parties** of the EUDI Wallet ecosystem: services that request and verify PIDs and attestations from Wallet Units.

Site: [rp-conformance.eudi-wallet.dev](https://rp-conformance.eudi-wallet.dev/), the FCAF with the Relying Party test cases, as an unofficial preview (`scripts/site-build.sh`, deployed from `main` by `.github/workflows/pages.yml`).

The EU [Functional Conformance Assessment Framework](https://conformance.eudi.dev) (FCAF) tests only the Wallet Solution, and the OIDF verifier suite mostly covers happy flows. This project defines and, later, executes the tests a Relying Party must pass, with the focus on what it must reject: expired credentials, revoked or suspended credentials, unusable status lists, wrong trust anchors, stale trust lists, faulty response encryption.

Status: specification, design, and Phases 1 to 4 of the harness: all 121 baseline test cases run unattended (PID, QEAA, PuB-EAA and non-qualified EAA in SD-JWT VC and mdoc format, Status List Tokens in JWT and CWT format, identifier lists, response encryption via redirects and via the W3C Digital Credentials API), each once per presentation flow the Relying Party supports. A nightly GitHub Actions job runs them against EUDIPLO's main image.

## Contents

| Path | Content |
| --- | --- |
| [rp-test-catalogue.md](rp-test-catalogue.md) | All test objectives (222), traced to the ARF high-level requirements, with the decisions taken on the open questions (§8) |
| [fcaf-overlay/](fcaf-overlay/README.md) | 121 baseline test cases in the FCAF test case format, with the defaults, the Relying Party ICS and the navigation, as an overlay on the FCAF content branch `submitted` |
| [harness-design.md](harness-design.md) | Design of the test harness: conformance wallet, status and trust list servers, artifact forge with fault injection, RP adapters, verdicts, delivery phases |
| [packages/](packages/) | The harness (TypeScript, pnpm workspace): `core` (adapter interface, test definition format, shared FCAF wording), `forge` (test PKI with IACA anchors and mdoc document signers, PID and `default_credential_A` in SD-JWT VC and mdoc format, Status List Tokens in JWT and CWT format, identifier lists, JAdES-sealed LoTE, the test LOTL and `TL-QEAA` as ETSI TS 119 612 Trusted Lists with XAdES signatures, registration certificate, and the fault layer), `wallet` (Conformance Wallet: KB-JWT, mdoc DeviceResponse with the OpenID4VP handover, via redirects and the DC API), `dc-api-shim` (Playwright replaces `navigator.credentials.get` on the Relying Party's page and hands the request to the Conformance Wallet), `status-provider`, `trust-infrastructure`, `validator` (reference validator with one named check per property, and the self-validation of every fault), `reference-rp`, `definitions` (the 121 test definitions, the source of the FCAF test cases), `fcaf-render` (renders the overlay from the definitions and the shared pages), `controller` (CLI, selection, gating, report, JUnit XML, known findings) |
| [scripts/fcaf-lint.sh](scripts/fcaf-lint.sh) | Runs the patched FCAF lint on the rendered test cases, as CI does |
| [adapters/](adapters/) | RP adapters with their ICS: `reference` (the reference RP, in-process) and `eudiplo` (with a Docker Compose file for EUDIPLO and PostgreSQL, and its known findings) |
| [.github/workflows/nightly-eudiplo.yml](.github/workflows/nightly-eudiplo.yml) | Nightly run of every test case against `ghcr.io/eudiplo/eudiplo:main`, also started by hand (`workflow_dispatch`) |

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

`pnpm test` includes the self-validation (harness design §7): every fault of the catalogue fails exactly its target check of the reference validator, every step of every executable definition carries exactly one fault in each flow it runs in, the test LOTL and `TL-QEAA` that the forge signs are accepted by `@owf/eudi-tl`, and every executable test case passes against the reference RP in both flows. `--only` selects test cases by ID or pattern (`--only 'RP_PP_SM_Revocation_*'`); `--flows redirect` or `--flows dc-api` restricts the run to one flow; `--list` shows every definition and which are text only.

Every test case runs once per flow the ICS declares (RP.P.1 redirects, RP.P.2 DC API), and its positive control must have passed in the same flow. The `SessionEncryption` variants name their flow in their profile and run only in it. In the DC API flow the adapter returns a page of the Relying Party; the shim opens it in Chromium, answers its `navigator.credentials.get` call with the Conformance Wallet's `dc_api.jwt` response, keeping the page's real origin, and records the request in which the page forwards the response to its backend.

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

EUDIPLO reads trust lists only as LoTEs (ETSI TS 119 602), not as ETSI TS 119 612 Trusted Lists, so its ICS declares RP.G.3 (QEAAs) No and the QEAA test cases are NOT APPLICABLE. For PuB-EAAs the adapter configures `TL-PUB`; for non-qualified EAAs it registers the rulebook anchor `CA-EP-A` in a trust list of the tenant, EUDIPLO's way of trusting an anchor that no list publishes.

`--known-findings adapters/eudiplo/known-findings.yaml` reports the FAILs listed there as known findings; the run then fails only on another FAIL, an INCONCLUSIVE or REVIEW result, or a harness error. The nightly job does this, uploads `reports/` as an artifact and adds the summary to the job summary. Its image is `ghcr.io/eudiplo/eudiplo:main`, or another one given when it is started by hand; PostgreSQL comes from Amazon ECR Public (`POSTGRES_IMAGE`), which has no anonymous pull limit like Docker Hub.

Everything on the host uses `127.0.0.1`, not `localhost`: Docker publishes EUDIPLO on `127.0.0.1` only, and Node.js may resolve `localhost` to `::1` first, where another process can hold the same port (an adapter login then fails with HTTP 401 and `request_uri` with 404). The adapter defaults to `http://127.0.0.1:3000`, EUDIPLO's `PUBLIC_URL` in the Compose file names `127.0.0.1`, and the CLI resolves host names IPv4 first. For a second EUDIPLO next to a running one, give it another project name and port; `EUDIPLO_PORT` sets the published port, the `PUBLIC_URL` and the adapter's default URL together:

```bash
EUDIPLO_PORT=3100 docker compose -p rp-conformance-eudiplo-2 -f adapters/eudiplo/docker-compose.yml up -d --wait
```

```bash
EUDIPLO_PORT=3100 pnpm rp-conformance run --adapter eudiplo
```

Decisions on the open points of [harness-design.md](harness-design.md) §12: the executable TypeScript definitions in `packages/definitions` are the source of truth, and `packages/fcaf-render` produces the FCAF markdown from them (§4.2); the reference RP is built on the reference validator; the OIDF bridge is optional and not implemented.

## Rendering the baseline

The test cases in `fcaf-overlay/docs/fcaf` are rendered from the definitions in `packages/definitions`; the shared pages come from `packages/fcaf-render/pages` and, for the four modified FCAF pages, from the base pages in `packages/fcaf-render/upstream`. Edit those, then:

```bash
pnpm fcaf:render
```

```bash
pnpm fcaf:render --check
```

```bash
scripts/fcaf-lint.sh
```

`--check` fails when the committed overlay differs from what the definitions render; `pnpm test` checks the same. `scripts/fcaf-lint.sh` fetches the FCAF repository at the pinned commits and runs its lint with [fcaf-overlay/fcaf_lint-rp.patch](fcaf-overlay/fcaf_lint-rp.patch) applied; any finding fails it. CI runs all three.

## Licence

[EUPL-1.2](LICENSE), the licence of FCAF. The files under `fcaf-overlay/docs/fcaf/` that modify existing FCAF pages (`defaults.md`, `references.md`, `.nav.yml`, `suts/index.md`) and their unmodified originals in `packages/fcaf-render/upstream/` contain FCAF content, © European Union, under the same licence.
