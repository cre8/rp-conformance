# RP conformance

Functional conformance tests for **Relying Parties** of the EUDI Wallet ecosystem: services that request and verify PIDs and attestations from Wallet Units.

The EU [Functional Conformance Assessment Framework](https://conformance.eudi.dev) (FCAF) tests only the Wallet Solution, and the OIDF verifier suite mostly covers happy flows. This project defines and, later, executes the tests a Relying Party must pass, with the focus on what it must reject: expired credentials, revoked or suspended credentials, unusable status lists, wrong trust anchors, stale trust lists, faulty response encryption.

Status: specification, design, and Phase 1 of the harness: 53 of the 121 baseline test cases run unattended (SD-JWT VC, Status List Tokens in JWT format, response encryption via redirects); the others are rendered from text-only definitions until their phase.

## Contents

| Path | Content |
| --- | --- |
| [rp-test-catalogue.md](rp-test-catalogue.md) | All test objectives (222), traced to the ARF high-level requirements, with the decisions taken on the open questions (§8) |
| [fcaf-overlay/](fcaf-overlay/README.md) | 121 baseline test cases in the FCAF test case format, with the defaults, the Relying Party ICS and the navigation, as an overlay on the FCAF content branch `submitted` |
| [harness-design.md](harness-design.md) | Design of the test harness: conformance wallet, status and trust list servers, artifact forge with fault injection, RP adapters, verdicts, delivery phases |
| [packages/](packages/) | The harness (TypeScript, pnpm workspace): `core` (adapter interface, test definition format, shared FCAF wording), `forge` (test PKI, PID SD-JWT VC, Status List Token, JAdES-sealed LoTE, registration certificate, and the fault layer), `wallet` (Conformance Wallet), `status-provider`, `trust-infrastructure`, `validator` (reference validator with one named check per property, and the self-validation of every fault), `reference-rp`, `definitions` (the 121 test definitions, the source of the FCAF test cases), `fcaf-render` (renders the overlay from the definitions and the shared pages), `controller` (CLI, selection, gating, report) |
| [scripts/fcaf-lint.sh](scripts/fcaf-lint.sh) | Runs the patched FCAF lint on the rendered test cases, as CI does |
| [adapters/](adapters/) | RP adapters with their ICS: `reference` (the reference RP, in-process) and `eudiplo` (with a Docker Compose file for EUDIPLO and PostgreSQL) |

## Approach

- **Structure**: the FCAF methodology, with the test classes it reserves for a Relying Party SUT (`RP_WS`, `RP_PP`, `RP_AP`, `RP_Inf`), so the test cases could be contributed upstream.
- **Sources**: ARF v3.0.0 (Annex 2), OpenID4VP 1.0, HAIP 1.0, SD-JWT (RFC 9901), SD-JWT VC, Token Status List, ISO/IEC 18013-5, ETSI TS 119 602, 119 612, 119 475 and 119 472-2.
- **Verdicts**: the Relying Party exposes its verification result; every negative test runs only after its positive control passed.

## Running the harness

Requires Node.js 22.12 or later and pnpm.

```bash
pnpm install
```

```bash
pnpm test
```

```bash
pnpm rp-conformance run --adapter reference
```

`pnpm test` includes the self-validation (harness design §7): every fault of the catalogue fails exactly its target check of the reference validator, every step of every executable definition carries exactly one fault, and every executable test case passes against the reference RP. `--only` selects test cases by ID or pattern (`--only 'RP_PP_SM_Revocation_*'`); `--list` shows every definition and which are text only.

The report goes to `reports/<run>/report.json` with a `summary.md`, and the artifacts of every step (credential, Status List Token as served and before its fault, request, presentation, response form, the RP's verification result) next to it.

Against EUDIPLO (latest published image, PostgreSQL):

```bash
docker compose -f adapters/eudiplo/docker-compose.yml up -d --wait
```

```bash
pnpm rp-conformance run --adapter eudiplo
```

`EUDIPLO_IMAGE=ghcr.io/eudiplo/eudiplo:main` runs the unreleased main image instead.

`EUDIPLO_URL`, `EUDIPLO_CLIENT_ID`, `EUDIPLO_CLIENT_SECRET` and `HARNESS_HOST` override the defaults of the Compose file. The harness serves plain HTTP; the Compose file allows that with `OUTBOUND_URL_ALLOW_HTTP`.

Decisions on the open points of [harness-design.md](harness-design.md) §12: the executable TypeScript definitions in `packages/definitions` are the source of truth, and `packages/fcaf-render` produces the FCAF markdown from them (§4.2); the reference RP is built on the reference validator; the OIDF bridge is optional and not implemented yet.

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

Not chosen yet. The files under `fcaf-overlay/docs/fcaf/` that modify existing FCAF pages (`defaults.md`, `references.md`, `.nav.yml`, `suts/index.md`) and their unmodified originals in `packages/fcaf-render/upstream/` contain FCAF content, which is licensed under EUPL-1.2.
