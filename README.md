# RP conformance

Functional conformance tests for **Relying Parties** of the EUDI Wallet ecosystem: services that request and verify PIDs and attestations from Wallet Units, and, as a draft, for the **PID Providers** and **Attestation Providers** that issue them.

The EU [Functional Conformance Assessment Framework](https://conformance.eudi.dev) (FCAF) tests only the Wallet Solution, and the OIDF verifier suite mostly covers happy flows. This project defines and executes the tests a Relying Party must pass, with the focus on what it must reject: expired credentials, revoked or suspended credentials, unusable status lists, wrong trust anchors, stale trust lists, faulty response encryption.

Site: [rp-conformance.eudi-wallet.dev](https://rp-conformance.eudi-wallet.dev/), the **Peer Conformance Assessment Framework (PCAF)**: the Relying Party and the Provider test cases in the FCAF format, the FCAF's framework pages rewritten for these SUTs and the documents of both suites, as an unofficial preview.

**Status.** All 470 test cases of the Relying Party suite run unattended, each once per presentation flow the Relying Party supports (redirects and the W3C Digital Credentials API): the 121 baseline test cases (PID, QEAA, PuB-EAA and non-qualified EAA in SD-JWT VC and mdoc format, Status List Tokens in JWT and CWT format, identifier lists, response encryption) and 199 further ones on session and device binding, issuer integrity, the trust lists, the requests the Relying Party sends, the protocol flow, the data model, combined presentations, robustness and the Polaris negative vectors (issue 10), and 150 in class `RP_AP`, the status list test cases of `RP_PP` for QEAAs, PuB-EAAs and non-qualified EAAs ([harness design §11](harness-design.md#11-delivery-phases)). The issuer suite is executable in part. A nightly GitHub Actions job runs both against EUDIPLO's main image.

## Contents

| Path | Content |
| --- | --- |
| [rp-test-catalogue.md](rp-test-catalogue.md) | All test objectives (236), traced to the ARF high-level requirements, with the decisions taken on the open questions (§8) |
| [issuer-test-catalogue.md](issuer-test-catalogue.md) | Draft: test objectives (182) for PID Providers and Attestation Providers as SUT, traced to the ARF high-level requirements, with the decisions taken on the open questions (§8). Executable in part (see [Issuer suite](#issuer-suite)) |
| [fcaf-overlay/](fcaf-overlay/README.md) | 121 baseline test cases and 349 further ones (150 of them in class `RP_AP`) in the FCAF test case format, with the defaults, the Relying Party ICS and the navigation, as an overlay on the FCAF content branch `submitted` |
| [fcaf-overlay-issuer/](fcaf-overlay-issuer/README.md) | The PID Provider test cases of the issuer suite in the FCAF test case format, one page per test case with its variants, with the defaults, the Provider ICS and the navigation, as a second overlay laid over the first |
| [harness-design.md](harness-design.md) | Design of the test harness: conformance wallet, status and trust list servers, artifact forge with fault injection, RP adapters, verdicts, delivery phases |
| [issuer-harness-design.md](issuer-harness-design.md) | Draft addendum to the harness design for the issuer suite: what it reuses, the issuance client, Test Wallet Provider, Test Registrar, issuer adapter with EUDIPLO as the reference issuer, faults, expected results, delivery phases and the decisions taken (§12). Phases I0 to I4 implemented |
| [packages/](packages/) | The harness (TypeScript, pnpm workspace): `core` (adapter interface, test definition format, shared FCAF wording), `forge` (test PKI with IACA anchors and mdoc document signers, PID and `default_credential_A` in SD-JWT VC and mdoc format, Status List Tokens in JWT and CWT format, identifier lists, JAdES-sealed LoTE, the test LOTL and `TL-QEAA` as ETSI TS 119 612 Trusted Lists with XAdES signatures, registration certificate, and the fault layer), `wallet` (Conformance Wallet: KB-JWT, mdoc DeviceResponse with the OpenID4VP handover, via redirects and the DC API, with the presentation faults of the forge), `dc-api-shim` (Playwright replaces `navigator.credentials.get` on the Relying Party's page and hands the request to the Conformance Wallet), `status-provider`, `trust-infrastructure`, `validator` (reference validator with one named check per property, including the request-side and trust list checks, and the self-validation of every fault), `reference-rp`, `definitions` (the 470 test definitions, the source of the FCAF test cases), `fcaf-render` (renders the overlay from the definitions and the shared pages), `controller` (CLI, selection, gating, report, JUnit XML, known findings) |
| [scripts/fcaf-lint.sh](scripts/fcaf-lint.sh) | Runs the patched FCAF lint on the rendered test cases of both overlays, as CI does |
| [adapter-guide.md](adapter-guide.md) | How to test your own Relying Party, PID Provider or Attestation Provider: writing an adapter from the templates, the ICS, networking, reading the report |
| [adapters/](adapters/) | RP adapters with their ICS: `reference` (the reference RP, in-process), [`eudiplo`](adapters/eudiplo/README.md) (with a Docker Compose file for EUDIPLO and PostgreSQL, and its known findings) and `template` (the starting point for an adapter of your own); issuer adapters: `issuer-eudiplo` and `issuer-template` |
| [running.md](running.md) | Running both suites: the CLI and its options, flows, the report, EUDIPLO, the Docker image, the GitHub Action and the CI jobs |
| [Dockerfile](Dockerfile), [action.yml](action.yml) | The harness image (`ghcr.io/cre8/rp-conformance`) and the GitHub Action that runs it, see [running.md](running.md#docker-image) |
| [.github/workflows/nightly-eudiplo.yml](.github/workflows/nightly-eudiplo.yml) | Nightly run of every test case of both suites against `ghcr.io/eudiplo/eudiplo:main`, also started by hand (`workflow_dispatch`) |
| [CONTRIBUTING.md](CONTRIBUTING.md) | Rendering the test cases into the overlays, the FCAF lint, building the site |

## Approach

- **Structure**: the FCAF methodology, with the test classes it reserves for a Relying Party SUT (`RP_WS`, `RP_PP`, `RP_AP`, `RP_Inf`), so the test cases could be contributed upstream.
- **Sources**: ARF v3.0.0 (Annex 2), OpenID4VP 1.0, HAIP 1.0, SD-JWT (RFC 9901), SD-JWT VC, Token Status List, ISO/IEC 18013-5, ETSI TS 119 602, 119 612, 119 475 and 119 472-2.
- **Verdicts**: the Relying Party exposes its verification result; every negative test runs only after its positive control passed.

## Quick start

Requires Node.js 22.12 or later and pnpm.

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

Against EUDIPLO:

```bash
docker compose -f adapters/eudiplo/docker-compose.yml up -d --wait
```

```bash
pnpm rp-conformance run --adapter eudiplo --known-findings adapters/eudiplo/known-findings.yaml
```

[running.md](running.md) explains the options, the flows and the report, and how to run the harness from its Docker image or with the GitHub Action. To test a Relying Party, PID Provider or Attestation Provider of your own, write an adapter for it: [adapter-guide.md](adapter-guide.md).

## Issuer suite

Status: [issuer-harness-design.md](issuer-harness-design.md) §10. The test cases of `packages/issuer-definitions` are executable, one definition per test case and variant: the PID Provider ones, and for Attestation Providers the same objectives in the category variants `Q`, `PB` and `E` with the objectives of their own. `pnpm rp-conformance issuer --list` lists them; they are rendered to the second FCAF overlay [fcaf-overlay-issuer/](fcaf-overlay-issuer/README.md) and published on the site next to the Relying Party test cases.

What is not validated: the suite is proven against EUDIPLO only. Test cases EUDIPLO cannot run are NOT APPLICABLE against it and have not been seen to pass against any Provider, and test cases that FAIL against it with a known finding are not validated until EUDIPLO is fixed. [adapters/issuer-eudiplo/README.md](adapters/issuer-eudiplo/README.md) lists both, per test case.

```bash
docker compose --env-file adapters/issuer-eudiplo/reference.env -f adapters/eudiplo/docker-compose.yml up -d --wait
```

```bash
pnpm rp-conformance issuer run --adapter eudiplo --ics adapters/issuer-eudiplo/ics.yaml --known-findings adapters/issuer-eudiplo/known-findings.yaml
```

## Licence

[EUPL-1.2](LICENSE), the licence of FCAF. The files under `fcaf-overlay/docs/fcaf/` and `fcaf-overlay-issuer/docs/fcaf/` that modify existing FCAF pages (`defaults.md`, `references.md`, `.nav.yml`, `suts/index.md`) and their unmodified originals in `packages/fcaf-render/upstream/` contain FCAF content, © European Union, under the same licence.
