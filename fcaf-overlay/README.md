# FCAF overlay: Relying Party baseline test cases

Draft of 2026-11-06. This overlay adds a **Relying Party** System Under Test to the EU Functional Conformance Assessment Framework (FCAF, [conformance.eudi.dev](https://conformance.eudi.dev)), with 121 baseline test cases written in the FCAF test case format. The objectives and the decisions behind them are in [rp-test-catalogue.md](../rp-test-catalogue.md).

## Base

The overlay is laid over the content branch `submitted` of `eu-digital-identity-wallet/eudi-doc-functional-conformance-assessment` at commit `0ed4ab1` (2026-10-16). Copy `docs/fcaf/` over the `docs/fcaf/` of that branch.

## Contents

New files:

| Path | Content |
| --- | --- |
| `docs/fcaf/suts/relying_party/index.md` | Relying Party SUT overview, test classes, decisions applied |
| `docs/fcaf/suts/relying_party/wallet_solution/` | Class `RP_WS`: overview, baseline list, test case page, 84 test cases |
| `docs/fcaf/suts/relying_party/pid_provider/` | Class `RP_PP`: overview, baseline list, test case page, 37 test cases |
| `docs/fcaf/ics-rp.md` | Relying Party ICS (capabilities, policies, time values, surrogate technology items) |

Modified copies of existing files (the base content plus additions):

| Path | Change |
| --- | --- |
| `docs/fcaf/defaults.md` | Appends the section "Relying Party testing": test roles, verification result, `default_configuration_rp_1`, `default_trust_configuration_rp`, the PID and attestation credentials and the default queries |
| `docs/fcaf/references.md` | Adds `[ARF]` (v3.0.0), `[ETSI TS 119 602]`, `[ISO/IEC 18013-5 ed2]`, `[RFC8392]`, `[RFC8725]` |
| `docs/fcaf/.nav.yml` | Adds the Relying Party SUT and the Relying Party ICS to the navigation |
| `docs/fcaf/suts/index.md` | Mentions the draft Relying Party SUT |

`fcaf_lint-rp.patch` changes the lint tool on the `site` branch (`tools/fcaf_lint.py`) so that it checks `RP_*` test case files and reads the ICS vocabulary from `ics-rp.md` as well. Without it the lint skips these files.

## Baseline

| Area | Test cases | Of which unhappy flow |
| --- | --- | --- |
| `RP_WS_IA_MainInteraction` (positive controls) | 2 | 0 |
| `RP_WS_SM_Validity` | 10 | 8 |
| `RP_WS_SM_Revocation` | 18 | 13 |
| `RP_WS_SM_TrustMechanisms` | 32 | 22 |
| `RP_WS_SM_SessionEncryption` | 22 | 16 |
| `RP_PP_SM_Revocation` | 37 | 31 |
| **Total** | **121** | **90** |

Variant letters: `a` is SD-JWT VC (with a Status List Token in JWT format in `RP_PP`), `b` is mdoc (CWT); in `SessionEncryption`, `a` is redirects with `direct_post.jwt` and `b` the W3C Digital Credentials API with `dc_api.jwt`. Where a catalogue objective has several stimuli, each stimulus is one test step with its own expected result.

Catalogue objectives in these areas that are not in the baseline: `RP_WS_SM_Validity_004` (informative only), `RP_WS_SM_Validity_020` (policy-dependent), `RP_WS_SM_Revocation_011` (aggregate of two other test cases), `RP_PP_SM_Revocation_014` and `_031` (optional checks), `RP_WS_SM_TrustMechanisms_017` (optional check).

## Rendering

The files are rendered; do not edit them here. The test cases come from the executable definitions in [../packages/definitions](../packages/definitions), the shared pages from [../packages/fcaf-render/pages](../packages/fcaf-render/pages), and the modified FCAF pages from their originals in [../packages/fcaf-render/upstream](../packages/fcaf-render/upstream) (`submitted` at `0ed4ab1`). From the repository root:

```bash
pnpm fcaf:render
```

CI fails when the committed files differ from the rendered ones, and runs the lint below through `scripts/fcaf-lint.sh`.

## Verification done

- The FCAF lint (`tools/fcaf_lint.py` from the `site` branch at `e2f076a`, with the patch above) reports 0 blocking findings and 0 warnings for the 121 files, including the advisory checks for ICS vocabulary, reference keys, `default_*` definitions, relative links and identifier markup. CI runs it with `--enforce-all`, so any finding fails the build.
- The lint over the whole corpus reports the same 3,779 warnings with and without the overlay, so the modified shared pages change nothing for the existing Wallet Solution test cases.
- The MkDocs build of the FCAF site (the `site` branch at `e2f076a` with the hooks of the FCAF repository) passes with `--strict`, with the overlay laid over `submitted`; the `include-markdown` pages render all 121 test cases. `scripts/site-build.sh` runs it, and `.github/workflows/pages.yml` publishes the result at [cre8.github.io/rp-conformance](https://cre8.github.io/rp-conformance/), under this project's name and colours instead of the Commission's.

## Open points before an upstream pull request

1. Agreement with the FCAF maintainers on adding a Relying Party SUT; the methodology already reserves the classes `RP_WS`, `RP_PP`, `RP_AP` and `RP_Inf`.
2. The lint patch goes to the `site` branch, the content to `submitted`.
3. The EUDI anchors: the test cases cite `[CIR 2024/2982 amended] Annex II` for presentation and `[CIR 2024/2979 amended] Annex II` for revocation (the latter following [ARF] Annex 2, VCR_11). Whether these Implementing Regulations bind Relying Parties directly, or only through the Wallet's profile, needs confirmation.
4. `[ISO/IEC 18013-5 ed2]` refers to a draft; its section numbers are left out.
5. SD-JWT VC `typ` `vc+sd-jwt` is rejected in the catalogue (decision 6), but no baseline test case covers it yet.
