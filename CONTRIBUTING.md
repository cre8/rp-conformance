# Contributing

Run `pnpm test` before a pull request: it includes the self-validation of every fault and the reference run in both
flows ([running.md](running.md)). The executable definitions are the source of truth for the test cases; where
writing one shows that an objective cannot be executed as written, change its row in the catalogue
([rp-test-catalogue.md](rp-test-catalogue.md), [issuer-test-catalogue.md](issuer-test-catalogue.md)) in the same
commit, with the reason.

## Rendering the test cases

The test cases in `fcaf-overlay/docs/fcaf` are rendered from the definitions in `packages/definitions`, those in
`fcaf-overlay-issuer/docs/fcaf` from `packages/issuer-definitions`; the shared pages come from
`packages/fcaf-render/pages` and, for the four modified FCAF pages, from the base pages in
`packages/fcaf-render/upstream`. Edit those, never the overlays, then:

```bash
pnpm fcaf:render
```

```bash
pnpm fcaf:render --check
```

```bash
scripts/fcaf-lint.sh
```

`--check` fails when a committed overlay differs from what the definitions render; `pnpm test` checks the same.
`scripts/fcaf-lint.sh` fetches the FCAF repository at the pinned commits and runs its lint with
[fcaf-overlay/fcaf_lint-rp.patch](fcaf-overlay/fcaf_lint-rp.patch) and
[fcaf-overlay-issuer/fcaf_lint-issuer.patch](fcaf-overlay-issuer/fcaf_lint-issuer.patch) applied; any finding fails it,
except the one check the issuer definitions do not satisfy yet
([fcaf-overlay-issuer/README.md](fcaf-overlay-issuer/README.md#lint)). CI runs all three.

## The site

`scripts/site-build.sh` builds [pcaf.eudi-wallet.dev](https://pcaf.eudi-wallet.dev/) from both
overlays, the site-only pages in `website/` and the project documents that `scripts/site-project-pages.py` copies;
`SITE_SERVE=1` serves it locally. A new project document needs an entry there, in the navigation of
`website/mkdocs.yml` and in the path filter of `.github/workflows/pages.yml`. The overlays in `fcaf-overlay` and
`fcaf-overlay-issuer` stay a diff against the FCAF; the site-only pages are in `website/pcaf`.
