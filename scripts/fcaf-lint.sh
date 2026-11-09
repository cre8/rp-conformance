#!/usr/bin/env bash
# Runs the FCAF lint on the rendered Relying Party test cases, as CI does:
#  1. fetches the FCAF repository at the pinned `submitted` (content) and `site` (lint tool) commits,
#  2. checks that the vendored base pages in packages/fcaf-render/upstream equal the `submitted` commit,
#  3. lays the overlay (fcaf-overlay/docs/fcaf, or OVERLAY_DIR) over the `submitted` content,
#  4. applies fcaf-overlay/fcaf_lint-rp.patch to tools/fcaf_lint.py and lints every RP_* test case; any finding fails.
#
#   scripts/fcaf-lint.sh [work-dir]
set -euo pipefail

REPO=https://github.com/eu-digital-identity-wallet/eudi-doc-functional-conformance-assessment.git
SUBMITTED=0ed4ab1184851160cbbc3e76322b516ab3508d56
SITE=e2f076adf2166a48d5c328d1933c6c552b494315

root=$(cd "$(dirname "$0")/.." && pwd)
work=${1:-$(mktemp -d)}
mkdir -p "$work"

fetch() { # <dir> <commit>
  if [ ! -d "$1/.git" ]; then
    git init -q "$1"
    git -C "$1" remote add origin "$REPO"
  fi
  git -C "$1" fetch -q --depth 1 origin "$2"
  git -C "$1" -c advice.detachedHead=false checkout -q --force FETCH_HEAD
}

fetch "$work/submitted" "$SUBMITTED"
fetch "$work/site" "$SITE"

for page in defaults.md references.md .nav.yml suts/index.md; do
  if ! cmp -s "$root/packages/fcaf-render/upstream/$page" "$work/submitted/docs/fcaf/$page"; then
    echo "packages/fcaf-render/upstream/$page differs from docs/fcaf/$page at $SUBMITTED" >&2
    exit 1
  fi
done

cp -R "${OVERLAY_DIR:-$root/fcaf-overlay/docs/fcaf}/." "$work/submitted/docs/fcaf/"
git -C "$work/site" apply "$root/fcaf-overlay/fcaf_lint-rp.patch"

cd "$work/submitted"
# The paths contain no spaces; bash 3 (macOS) has no mapfile.
files=($(find docs/fcaf/suts/relying_party -name 'RP_*.md' | sort))
echo "linting ${#files[@]} Relying Party test cases"
python3 "$work/site/tools/fcaf_lint.py" --root docs/fcaf --enforce-all --format "${FCAF_LINT_FORMAT:-text}" "${files[@]}"
