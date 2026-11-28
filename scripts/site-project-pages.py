"""Copies the project documents into the site (scripts/site-build.sh): below docs/harness/ the documents that cover
both suites (running the harness, writing an adapter), below docs/rp/ for the Relying Party suite and docs/issuer/ for
the issuer suite the test catalogue and the harness design, and the EUDIPLO adapter's README (where it has one), ICS,
known findings and upstream finding texts. YAML files become pages with the file in a code block. A relative link to a
document that is copied points to its copy; any other relative link points to the file on GitHub, so MkDocs finds no
broken link. The URLs the shared documents had before redirect to their pages.

    python3 scripts/site-project-pages.py <repository root> <docs dir>
"""

import importlib.util
import pathlib
import posixpath
import re
import sys

REPOSITORY = "https://github.com/cre8/eudi-pcaf"
BRANCH = "main"
LINK = re.compile(r"\]\((?!https?:|mailto:|#)([^)\s]+)\)")

# The documents that cover both suites -> their page below docs/.
SHARED = {
    "running.md": "harness/running.md",
    "adapter-guide.md": "harness/adapter-guide.md",
}
# Pages the shared documents were served at before -> where they are now.
MOVED = {
    "rp/running.md": "harness/running.md",
    "rp/adapter-guide.md": "harness/adapter-guide.md",
}

# Site directory -> the suite's documents and its EUDIPLO adapter. The two suites get the same pages.
SUITES = {
    "rp": {
        "documents": {
            "rp-test-catalogue.md": "rp-test-catalogue.md",
            "harness-design.md": "harness-design.md",
        },
        "adapter": "adapters/eudiplo",
        "role": "Relying Party",
        "suite": "Relying Party suite",
        "flags": "eudi-pcaf run --adapter eudiplo",
    },
    "issuer": {
        "documents": {
            "issuer-test-catalogue.md": "issuer-test-catalogue.md",
            "issuer-harness-design.md": "issuer-harness-design.md",
        },
        "adapter": "adapters/issuer-eudiplo",
        "role": "PID Provider and Attestation Provider",
        "suite": "issuer suite",
        "flags": "eudi-pcaf issuer run --adapter eudiplo",
    },
}


def pages(root: pathlib.Path) -> dict[str, str]:
    """Repository path -> site path below docs/, for every page copied."""
    out = dict(SHARED)
    for site, suite in SUITES.items():
        adapter = suite["adapter"]
        for source, target in suite["documents"].items():
            out[source] = f"{site}/{target}"
        if (root / adapter / "README.md").exists():
            out[f"{adapter}/README.md"] = f"{site}/eudiplo/index.md"
        out[f"{adapter}/ics.yaml"] = f"{site}/eudiplo/ics.md"
        out[f"{adapter}/known-findings.yaml"] = f"{site}/eudiplo/known-findings.md"
        # The directory, linked from the README, becomes its README or a generated list of its pages.
        out[f"{adapter}/upstream-findings"] = f"{site}/eudiplo/upstream-findings/index.md"
        findings = root / adapter / "upstream-findings"
        for finding in sorted([*findings.glob("*.md"), *findings.glob("suggestions/*.md")]):
            name = finding.relative_to(findings).as_posix()
            # The folder's README, where there is one, is its index page instead of the generated list.
            target = "index.md" if name == "README.md" else name
            out[f"{adapter}/upstream-findings/{name}"] = f"{site}/eudiplo/upstream-findings/{target}"
    return out


def yaml_titles() -> dict[str, tuple[str, str]]:
    """Repository path of a YAML file -> title and introduction of its page."""
    out = {}
    for suite in SUITES.values():
        adapter, role, name, flags = suite["adapter"], suite["role"], suite["suite"], suite["flags"]
        out[f"{adapter}/ics.yaml"] = (
            "EUDIPLO ICS",
            f"The Implementation Conformance Statement of EUDIPLO as {role}, as the adapter configures the reference "
            f"image: the file the {name} runs with (`{flags} --ics {adapter}/ics.yaml`).",
        )
        out[f"{adapter}/known-findings.yaml"] = (
            "EUDIPLO known findings",
            f"The FAILs of the {name} against EUDIPLO that are analysed and accepted as findings of EUDIPLO: the runs "
            f"against it report them as known findings (`--known-findings {adapter}/known-findings.yaml`).",
        )
    return out


YAML_TITLES = yaml_titles()


def rewrite_links(text: str, source: str, mapping: dict[str, str]) -> str:
    """Rewrites the relative links of `source` (a repository path) for its copy at `mapping[source]`."""
    here = posixpath.dirname(mapping[source])

    def replace(match: re.Match) -> str:
        target, _, fragment = match.group(1).partition("#")
        resolved = posixpath.normpath(posixpath.join(posixpath.dirname(source), target)).rstrip("/")
        anchor = f"#{fragment}" if fragment else ""
        if resolved in mapping:
            return f"]({posixpath.relpath(mapping[resolved], here)}{anchor})"
        kind = "blob" if posixpath.splitext(resolved)[1] else "tree"
        return f"]({REPOSITORY}/{kind}/{BRANCH}/{resolved}{anchor})"

    return LINK.sub(replace, text)


def main(root: pathlib.Path, docs: pathlib.Path) -> None:
    mapping = pages(root)
    for source, target in mapping.items():
        path = root / source
        if path.is_dir() and (path / "README.md").exists():
            continue
        if path.is_dir():
            items = [
                f"- [{p.read_text(encoding='utf-8').splitlines()[0].lstrip('# ').strip()}]({p.name})"
                for p in sorted(path.glob("*.md"))
            ]
            text = (
                "# EUDIPLO upstream findings\n\n"
                "Issue texts prepared for the known findings against EUDIPLO. They are not filed by this project; each "
                "names the test cases that show the finding.\n\n" + "\n".join(items) + "\n"
            )
        elif source in YAML_TITLES:
            title, intro = YAML_TITLES[source]
            link = f"{REPOSITORY}/blob/{BRANCH}/{source}"
            text = f"# {title}\n\n{intro} Source: [`{source}`]({link}).\n\n```yaml\n{path.read_text(encoding='utf-8').rstrip()}\n```\n"
        else:
            text = rewrite_links(path.read_text(encoding="utf-8"), source, mapping)
        out = docs / target
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(text, encoding="utf-8")

    # The redirect pages of scripts/site-layer.py, at the URLs the shared documents had before.
    spec = importlib.util.spec_from_file_location("site_layer", pathlib.Path(__file__).with_name("site-layer.py"))
    layer = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(layer)
    for old, new in MOVED.items():
        layer.redirect(docs, old, layer.url(new))


if __name__ == "__main__":
    main(pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2]))
