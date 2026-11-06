"""Render the Relying Party baseline as an overlay on the FCAF `submitted` content tree."""

import pathlib
import shutil
import sys

sys.path.insert(0, str(pathlib.Path(__file__).parent))
import pages  # noqa: E402
from tests import REL, TESTS  # noqa: E402

SRC = pathlib.Path(sys.argv[1])  # FCAF submitted checkout: .../submitted/docs/fcaf
OUT = pathlib.Path(sys.argv[2])  # overlay root: .../fcaf-overlay/docs/fcaf

CLASS_DIR = {"WS": "wallet_solution", "PP": "pid_provider"}
CLASS_TITLE = {"WS": "Relying Party - Wallet Solution", "PP": "Relying Party - PID Provider"}
LAYER_DIR = {"IA": "Interaction", "SM": "SecurityMechanisms"}
LAYER_TITLE = {"IA": "Interaction", "SM": "Security Mechanisms"}
AREA_TITLE = {
    "MainInteraction": "Main Interaction",
    "Validity": "Validity",
    "Revocation": "Revocation",
    "TrustMechanisms": "Trust Mechanisms",
    "SessionEncryption": "Session Encryption",
}


def write(path: pathlib.Path, text: str):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text.rstrip("\n") + "\n", encoding="utf-8")


def numbered(items):
    return "\n".join(f"{i}. {item}" for i, item in enumerate(items, 1))


def render(t):
    parts = [f"# {t['id']}", "## Objective", t["objective"], "## References", "\n".join(f"- {r}" for r in t["refs"])]
    parts += ["## Profile applicability", "\n".join(f"- {p}" for p in t["profile"]) if t["profile"] else "None"]
    parts += ["## EUDI-wallet relevancy", REL[t["rel"]]]
    if t["tech"]:
        parts += ["## Technology", "\n".join(f"- {x}" for x in t["tech"])]
    parts += ["## Preconditions", numbered(t["pre"]) if t["pre"] else "None"]
    assert len(t["steps"]) == len(t["expected"]), t["id"]
    parts += ["## Test Scenario", numbered(t["steps"]), "## Expected results", numbered(t["expected"])]
    if t["comments"]:
        parts += ["## Comments", "\n\n".join(t["comments"])]
    return "\n\n".join(parts)


def test_path(t):
    return OUT / "suts" / "relying_party" / CLASS_DIR[t["cls"]] / LAYER_DIR[t["layer"]] / t["area"] / f"{t['id']}.md"


def main():
    if OUT.exists():
        shutil.rmtree(OUT)
    ids = [t["id"] for t in TESTS]
    assert len(ids) == len(set(ids)), "duplicate test case IDs"

    for t in TESTS:
        write(test_path(t), render(t))

    # Overviews, area and layer indexes, test case pages and baseline lists.
    rp = OUT / "suts" / "relying_party"
    write(rp / "index.md", pages.SUT_INDEX)
    write(rp / "wallet_solution" / "rp_ws.md", pages.RP_WS)
    write(rp / "pid_provider" / "rp_pp.md", pages.RP_PP)
    for cls, cdir in CLASS_DIR.items():
        mine = [t for t in TESTS if t["cls"] == cls]
        write(rp / cdir / "test-cases.md", pages.TEST_CASES.format(title=CLASS_TITLE[cls]))
        lines = [
            f"# {CLASS_TITLE[cls]} baseline tests",
            f"The following {len(mine)} test cases form the baseline test set.",
            "\n".join(f"- [{t['id']}]({test_path(t).relative_to(rp / cdir).as_posix()})" for t in mine),
        ]
        write(rp / cdir / "baseline-tests.md", "\n\n".join(lines))
        for layer in sorted({t["layer"] for t in mine}):
            write(rp / cdir / LAYER_DIR[layer] / "index.md", pages.LAYER_INDEX.format(title=LAYER_TITLE[layer]))
            for area in sorted({t["area"] for t in mine if t["layer"] == layer}):
                write(rp / cdir / LAYER_DIR[layer] / area / "index.md",
                      pages.AREA_INDEX.format(layer=LAYER_TITLE[layer], area=AREA_TITLE[area]))

    # Relying Party ICS page.
    write(OUT / "ics-rp.md", pages.ICS_RP)

    # Modified copies of shared FCAF pages.
    defaults = (SRC / "defaults.md").read_text(encoding="utf-8").rstrip("\n")
    write(OUT / "defaults.md", defaults + "\n" + pages.DEFAULTS_RP)

    refs = (SRC / "references.md").read_text(encoding="utf-8").rstrip("\n")
    write(OUT / "references.md", refs + "\n" + "\n".join(pages.REFERENCES_ROWS))

    nav = (SRC / ".nav.yml").read_text(encoding="utf-8")
    anchor = "      - Shared: suts/shared/index.md\n"
    assert anchor in nav
    nav = nav.replace(anchor, pages.NAV_RP + anchor)
    ics_anchor = "  - ICS: ics.md\n"
    assert ics_anchor in nav
    nav = nav.replace(ics_anchor, ics_anchor + "  - ICS (Relying Party): ics-rp.md\n")
    write(OUT / ".nav.yml", nav)

    sut_index = (SRC / "suts" / "index.md").read_text(encoding="utf-8")
    old = "For the initial phase of the FCAF, the only SUT in scope is: **Wallet Solution**\n"
    assert old in sut_index
    sut_index = sut_index.replace(
        old,
        old + "\nA draft **Relying Party** SUT is defined in addition: see [Relying Party (SUT)](relying_party/index.md).\n",
    )
    write(OUT / "suts" / "index.md", sut_index)

    by_area = {}
    for t in TESTS:
        by_area.setdefault(f"RP_{t['cls']}_{t['layer']}_{t['area']}", []).append(t)
    for k, v in by_area.items():
        print(f"{k}: {len(v)}")
    print(f"total: {len(TESTS)}, unhappy flow: {sum(t['id'].endswith('_UF') for t in TESTS)}")


if __name__ == "__main__":
    main()
