# The FCAF repository at the commits this project builds on, and how to fetch them. Sourced by fcaf-lint.sh and
# site-build.sh.
#  - SUBMITTED: the content branch `submitted`, which the overlay is laid over (and the base of the vendored pages in
#    packages/fcaf-render/upstream),
#  - SITE: the `site` branch with the lint tool and the MkDocs shell (configuration, theme, hooks).

REPO=https://github.com/eu-digital-identity-wallet/eudi-doc-functional-conformance-assessment.git
SUBMITTED=0ed4ab1184851160cbbc3e76322b516ab3508d56
SITE=e2f076adf2166a48d5c328d1933c6c552b494315

fetch() { # <dir> <commit>
  if [ ! -d "$1/.git" ]; then
    git init -q "$1"
    git -C "$1" remote add origin "$REPO"
  fi
  git -C "$1" fetch -q --depth 1 origin "$2"
  git -C "$1" -c advice.detachedHead=false checkout -q --force FETCH_HEAD
}
