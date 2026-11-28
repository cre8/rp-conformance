# FCAF overlay: PID Provider test cases

Draft. This overlay adds a **PID Provider** System Under Test to the EU Functional Conformance Assessment Framework (FCAF, [conformance.eudi.dev](https://conformance.eudi.dev)), with the test cases of the issuer suite written in the FCAF test case format. The objectives and the decisions behind them are in [issuer-test-catalogue.md](../issuer-test-catalogue.md), the harness that runs them in [issuer-harness-design.md](../issuer-harness-design.md). It is kept apart from the Relying Party overlay ([../fcaf-overlay](../fcaf-overlay/README.md)) because the FCAF methodology does not reserve test classes for Providers (issuer harness design, decision 1).

## Base

The overlay is laid over the content branch `submitted` of `eu-digital-identity-wallet/eudi-doc-functional-conformance-assessment` at commit `0ed4ab1` (2026-10-16) **with the Relying Party overlay**: copy `../fcaf-overlay/docs/fcaf/` and then `docs/fcaf/` over the `docs/fcaf/` of that branch. Its copies of the four modified FCAF pages contain the Relying Party additions too.

## Contents

New files:

| Path | Content |
| --- | --- |
| `docs/fcaf/suts/pid_provider/index.md` | PID Provider SUT overview, test classes, variants, decisions applied |
| `docs/fcaf/suts/pid_provider/wallet_solution/` | Class `PP_WS`: overview, test case page, the test cases by layer and area |
| `docs/fcaf/suts/pid_provider/relying_party/` | Class `PP_RP`: overview, test case page, the test cases by layer and area |
| `docs/fcaf/suts/pid_provider/infrastructure/` | Class `PP_Inf`: overview and test case page; its test cases come with revocation chaining and `PP_Inf` (issuer harness design section 10, I3) |
| `docs/fcaf/ics-issuer.md` | Provider ICS: the items ICS-01 to ICS-19 of the issuer catalogue section 4 with the profiles they select, and the surrogate technology items |

Modified copies of existing files (the Relying Party overlay's copy plus additions):

| Path | Change |
| --- | --- |
| `docs/fcaf/defaults.md` | Appends the section "PID Provider testing": test roles, trust configuration, Wallet Units `CW-1`, `CW-2`, `CW-B` and subjects `SUBJ-1`, `SUBJ-2`, `default_configuration_PP_1`, observation and expected result codes |
| `docs/fcaf/references.md` | Adds the reference keys the issuer test cases cite that the FCAF and the Relying Party overlay do not define |
| `docs/fcaf/.nav.yml` | Adds the PID Provider SUT and the Provider ICS to the navigation |
| `docs/fcaf/suts/index.md` | Mentions the draft PID Provider SUT |

`fcaf_lint-issuer.patch` changes the lint tool on the `site` branch (`tools/fcaf_lint.py`), on top of `../fcaf-overlay/fcaf_lint-rp.patch`, so that it checks `PP_*` (and later `AP_*`) test case files and reads the ICS vocabulary from `ics-issuer.md` as well.

## Variants

The issuer definitions have one definition per test case and variant (credential format `SD` or `MD`, grant `PA` or `AC`; issuer catalogue section 2.3), all with the same test case ID. The FCAF has one file per ID, so each page merges the variants of its test case: the references, relevancy and preconditions are the same for every variant (rendering fails otherwise), the profile applicability and technology are the union of the variants', and where the objective or a step differs, the page lists the text per variant. The comments end with the variants and the Provider profiles each one needs.

## Rendering

The files are rendered; do not edit them here. The test cases come from the executable definitions in [../packages/issuer-definitions](../packages/issuer-definitions), the ICS items from `ISSUER_ICS_ITEMS` of `@eudi-pcaf/core`, the hand-written pages from [../packages/fcaf-render/pages](../packages/fcaf-render/pages) (`pid-provider.md`, `pp_*.md`, `defaults-issuer.md`, `ics-issuer.md`, `references-issuer.md`), and the modified FCAF pages from the Relying Party overlay. From the repository root:

```bash
pnpm fcaf:render
```

renders both overlays; `pnpm fcaf:render --check` and `pnpm test` fail when the committed files differ. When `main` adds issuer definitions, render again instead of merging these files by hand. Rendering fails for an area, layer or technology line it has no title or ICS item for: add it to `packages/fcaf-render/src/issuer.ts` or `ISSUER_TECHNOLOGY` in `issuer-overlay.ts`.

## Lint

`scripts/fcaf-lint.sh` lays both overlays over `submitted`, applies both lint patches and lints every `RP_*` and `PP_*` test case. Every check blocks, except one that the issuer definitions do not satisfy yet and that is reported as a warning (`ISSUER_LINT_WARN`, default `FC100`), an advisory check of the FCAF lint, not in its default blocking set:

- `FC100`: most issuer test cases cite only [ARF] Annex 2, OpenID4VCI, HAIP and other specifications, and no `[CIR …]` or `[ETSI …]` item that anchors the test in the EUDI profile, as the Relying Party test cases do with `[CIR 2024/2982 amended]` and `[CIR 2024/2979 amended]`. Which Implementing Regulation anchors issuance needs deciding before the definitions can cite it.

Once the definitions cite such an anchor, remove the code from `ISSUER_LINT_WARN`.

## Open points before an upstream pull request

1. Agreement with the FCAF maintainers on adding a PID Provider SUT and its classes `PP_WS`, `PP_RP`, `PP_Inf` (issuer catalogue section 8.2).
2. The EUDI anchors of the issuer test cases (`FC100` above).
3. A variant format of the FCAF: the methodology knows variant letters in the ID, the issuer suite expands variants from one ID.
4. Attestation Providers (`AP_*`): a SUT of their own or a category variant of this one.
