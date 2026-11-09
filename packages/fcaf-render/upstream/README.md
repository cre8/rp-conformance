# FCAF base pages

The pages of the FCAF content that the overlay modifies, unchanged, so the renderer can produce the modified copies
without a checkout of the FCAF repository:

| File | Source |
| --- | --- |
| `defaults.md`, `references.md`, `.nav.yml`, `suts/index.md` | `docs/fcaf/` of [eu-digital-identity-wallet/eudi-doc-functional-conformance-assessment](https://github.com/eu-digital-identity-wallet/eudi-doc-functional-conformance-assessment), branch `submitted`, commit `0ed4ab1184851160cbbc3e76322b516ab3508d56` (2026-10-16) |

They are FCAF content, licensed under EUPL-1.2. CI checks that they equal the files at that commit. To move the
overlay to a newer FCAF commit, replace them, update the commit here and in `.github/workflows/ci.yml`, and render the
overlay again (`pnpm fcaf:render`).
