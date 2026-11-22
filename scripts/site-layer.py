"""Lays the site-only layer (website/pcaf) over the composed FCAF content (scripts/site-build.sh).

The overlays in fcaf-overlay and fcaf-overlay-issuer stay a clean diff against the FCAF, so they can be contributed
upstream. This site is the Peer Conformance Assessment Framework (PCAF) and presents only the Systems Under Test of
this project, the Relying Party, the PID Provider and the Attestation Provider, so this step
  1. removes the FCAF pages that concern the Wallet Solution or the FCAF project itself: the Wallet Solution SUT,
     the shared test cases (no test case here invokes them), the templates, the Wallet ICS, the changelog, the
     roadmap and "Using the FCAF", which using-pcaf.md replaces,
  2. copies the rewritten general pages of website/pcaf over docs/fcaf,
  3. replaces the Wallet Unit part at the top of defaults.md with website/pcaf/defaults-head.md, and keeps the
     generated sections from "## Relying Party testing" on,
  4. points the links to the Wallet ICS at the official FCAF,
  5. moves docs/fcaf to docs/pcaf, so the pages are served below /pcaf/,
  6. leaves a redirect page at every URL the site served before: a page that moved points to its new URL, a page of
     the FCAF that was removed points to the same page on the official FCAF.
Every rewrite fails loudly when the text it expects is gone, so a change upstream or in the renderer is noticed.

    python3 scripts/site-layer.py <repository root> <docs dir>
"""

import html
import pathlib
import shutil
import sys

FCAF_SITE = "https://conformance.eudi.dev/latest/"
FCAF_ICS = FCAF_SITE + "fcaf/ics/"
REMOVED = [
    "fcaf/suts/wallet_solution",
    "fcaf/suts/shared",
    "fcaf/templates",
    "fcaf/ics.md",
    "fcaf/CHANGELOG.md",
    "fcaf/using-fcaf.md",
    "fcaf/.nav.yml",
    "roadmap.md",
]
# Old page (below docs/) -> new page, for the pages that moved under another name.
RENAMED = {"fcaf/using-fcaf.md": "pcaf/using-pcaf.md"}
DEFAULTS_SPLIT = "## Relying Party testing\n"
ICS_LINK = "[Wallet ICS](ics.md)"


def url(page: str) -> str:
    """The directory URL MkDocs serves a page at, relative to the site root: a/b.md -> a/b/, a/index.md -> a/."""
    path = page.removesuffix(".md")
    if path == "index" or path.endswith("/index"):
        path = path.removesuffix("index")
    else:
        path += "/"
    return path


def pages(directory: pathlib.Path, docs: pathlib.Path) -> list[str]:
    if directory.is_file():
        return [directory.relative_to(docs).as_posix()] if directory.suffix == ".md" else []
    return sorted(p.relative_to(docs).as_posix() for p in directory.rglob("*.md"))


def redirect(docs: pathlib.Path, old: str, target: str) -> None:
    """A static page at the URL of `old` that sends the browser to `target` (absolute, or relative to the root)."""
    old_url = url(old)
    href = target if "://" in target else "../" * old_url.count("/") + target
    link = html.escape(href, quote=True)
    page = docs / old_url / "index.html"
    if page.exists():
        sys.exit(f"site-layer: {page} exists already")
    page.parent.mkdir(parents=True, exist_ok=True)
    page.write_text(
        '<!doctype html>\n<html lang="en">\n<head>\n<meta charset="utf-8">\n<title>Moved</title>\n'
        f'<link rel="canonical" href="{link}">\n<meta name="robots" content="noindex">\n'
        f'<meta http-equiv="refresh" content="0; url={link}">\n'
        f"<script>location.replace({href!r} + location.hash)</script>\n</head>\n"
        f'<body><p>This page has moved to <a href="{link}">{link}</a>.</p></body>\n</html>\n',
        encoding="utf-8",
    )


def main(root: pathlib.Path, docs: pathlib.Path) -> None:
    # Every page the site served below fcaf/, and where it is now.
    redirects = {}
    for name in REMOVED:
        path = docs / name
        if not path.exists():
            sys.exit(f"site-layer: {path} is missing; the FCAF content has changed")
        for page in pages(path, docs):
            redirects[page] = RENAMED.get(page, FCAF_SITE + url(page))
        shutil.rmtree(path) if path.is_dir() else path.unlink()
    # The pages that stay are served below pcaf/ under the same path.
    for page in pages(docs / "fcaf", docs):
        redirects[page] = "pcaf/" + page.removeprefix("fcaf/")

    layer = root / "website" / "pcaf"
    for source in sorted(layer.rglob("*.md")):
        if source.name == "defaults-head.md":
            continue
        target = docs / "fcaf" / source.relative_to(layer)
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target)

    defaults = docs / "fcaf" / "defaults.md"
    text = defaults.read_text(encoding="utf-8")
    if text.count(DEFAULTS_SPLIT) != 1:
        sys.exit(f"site-layer: {defaults} has no single {DEFAULTS_SPLIT.strip()!r} section")
    head = (layer / "defaults-head.md").read_text(encoding="utf-8")
    defaults.write_text(head.rstrip("\n") + "\n\n" + DEFAULTS_SPLIT + text.split(DEFAULTS_SPLIT, 1)[1], encoding="utf-8")

    for name in ("ics-rp.md", "ics-issuer.md"):
        page = docs / "fcaf" / name
        text = page.read_text(encoding="utf-8")
        if ICS_LINK not in text:
            sys.exit(f"site-layer: {page} has no link {ICS_LINK!r}")
        page.write_text(text.replace(ICS_LINK, f"[Wallet ICS of the FCAF]({FCAF_ICS})"), encoding="utf-8")

    if (docs / "pcaf").exists():
        sys.exit(f"site-layer: {docs / 'pcaf'} exists already")
    (docs / "fcaf").rename(docs / "pcaf")

    for old, new in sorted(redirects.items()):
        redirect(docs, old, new if "://" in new else url(new))


if __name__ == "__main__":
    main(pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2]))
