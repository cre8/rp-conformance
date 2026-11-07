# RP conformance

Functional conformance tests for **Relying Parties** of the EUDI Wallet ecosystem: services that request and verify PIDs and attestations from Wallet Units.

The EU [Functional Conformance Assessment Framework](https://conformance.eudi.dev) (FCAF) tests only the Wallet Solution, and the OIDF verifier suite mostly covers happy flows. This project defines and, later, executes the tests a Relying Party must pass, with the focus on what it must reject: expired credentials, revoked or suspended credentials, unusable status lists, wrong trust anchors, stale trust lists, faulty response encryption.

Status: specification, design, and Phase 0 of the harness (positive control `RP_WS_IA_MainInteraction_001a` via redirects).

## Contents

| Path | Content |
| --- | --- |
| [rp-test-catalogue.md](rp-test-catalogue.md) | All test objectives (222), traced to the ARF high-level requirements, with the decisions taken on the open questions (§8) |
| [fcaf-overlay/](fcaf-overlay/README.md) | 121 baseline test cases in the FCAF test case format, with the defaults, the Relying Party ICS and the navigation, as an overlay on the FCAF content branch `submitted` |
| [generator/](generator/) | Python generator that renders the baseline test cases and shared pages; replaced by `packages/fcaf-render` in Phase 1 |
| [harness-design.md](harness-design.md) | Design of the test harness: conformance wallet, status and trust list servers, artifact forge with fault injection, RP adapters, verdicts, delivery phases |
| [packages/](packages/) | The harness (TypeScript, pnpm workspace): `core` (adapter interface, test definition format, shared FCAF wording), `forge` (test PKI, PID SD-JWT VC, Status List Token, JAdES-sealed LoTE, registration certificate), `wallet` (Conformance Wallet), `status-provider`, `trust-infrastructure`, `validator` (reference validator), `reference-rp`, `definitions` (executable test definitions), `fcaf-render` (FCAF markdown from the definitions), `controller` (CLI, selection, gating, report) |
| [adapters/](adapters/) | RP adapters with their ICS: `reference` (the reference RP, in-process) and `eudiplo` (with a Docker Compose file for EUDIPLO and PostgreSQL) |

## Approach

- **Structure**: the FCAF methodology, with the test classes it reserves for a Relying Party SUT (`RP_WS`, `RP_PP`, `RP_AP`, `RP_Inf`), so the test cases could be contributed upstream.
- **Sources**: ARF v3.0.0 (Annex 2), OpenID4VP 1.0, HAIP 1.0, SD-JWT (RFC 9901), SD-JWT VC, Token Status List, ISO/IEC 18013-5, ETSI TS 119 602, 119 612, 119 475 and 119 472-2.
- **Verdicts**: the Relying Party exposes its verification result; every negative test runs only after its positive control passed.

## Running the harness

Requires Node.js 22.12 or later and pnpm.

```bash
pnpm install
pnpm test
pnpm rp-conformance run --adapter reference --only RP_WS_IA_MainInteraction_001a
```

The report goes to `reports/<run>/report.json`, with the artifacts of every step (credential, Status List Token, request, presentation, encrypted response, the RP's verification result) next to it.

Against EUDIPLO (latest published image, PostgreSQL):

```bash
docker compose -f adapters/eudiplo/docker-compose.yml up -d --wait
pnpm rp-conformance run --adapter eudiplo --only RP_WS_IA_MainInteraction_001a
```

`EUDIPLO_URL`, `EUDIPLO_CLIENT_ID`, `EUDIPLO_CLIENT_SECRET` and `HARNESS_HOST` override the defaults of the Compose file. Phase 0 serves the harness over plain HTTP; the Compose file allows that with `OUTBOUND_URL_ALLOW_HTTP`.

Phase 0 decisions on the open points of [harness-design.md](harness-design.md) §12: the executable TypeScript definitions in `packages/definitions` are the source of truth, and a TypeScript renderer produces the FCAF markdown from them (complete in Phase 1, see §4.2); the reference RP is built on the reference validator; the OIDF bridge is optional and not part of Phase 0.

## Regenerating the baseline

```bash
python3 generator/render.py <fcaf-submitted-checkout>/docs/fcaf fcaf-overlay/docs/fcaf
```

Then run the FCAF lint with [fcaf-overlay/fcaf_lint-rp.patch](fcaf-overlay/fcaf_lint-rp.patch) applied; see the overlay README.

## Licence

Not chosen yet. The files under `fcaf-overlay/docs/fcaf/` that modify existing FCAF pages (`defaults.md`, `references.md`, `.nav.yml`, `suts/index.md`) contain FCAF content, which is licensed under EUPL-1.2.
