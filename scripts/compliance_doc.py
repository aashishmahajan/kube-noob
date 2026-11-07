#!/usr/bin/env python3
"""Generate the rule and control tables in `docs/compliance.md` from the code.

Hand-keeping them went stale three ways at once: the heading said "The 78 audit rules" with 89 in the code,
seven controls that rules map to had no title row (every parenthesised enhancement -- a reader saw `IA-5(7)`
on a rule and had nowhere to look it up), and the only guard asserted every rule HAS a row and never that a
row still has a rule. Adding a rule meant hand-editing this table, two counts in the roadmap, the README and
the scorecard; this removes one of those and makes the rest checkable.

Only three regions are rewritten -- the heading's count, the rule table and the control-titles table. The
prose around them is left alone, and the structure is asserted rather than assumed, so a change to the
document's shape fails here instead of producing a mangled file.

    python scripts/compliance_doc.py --check    # exit 1 when the committed document is stale
    python scripts/compliance_doc.py            # rewrite the three regions
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
OUT = ROOT / "docs" / "compliance.md"

# Controls the document evidences through POSTURE rather than through an audit rule, so they are not in
# RULE_CONTROLS and generating from that alone would silently delete their title rows. SC-13 is cited by the
# `kube-noob doctor` row and by the FIPS guidance; its title is NIST's.
POSTURE_CONTROLS = {"SC-13": "Cryptographic Protection"}

_HEADING = re.compile(r"^## The \d+ audit rules and their controls$", re.M)
_RULE_TABLE = re.compile(
    r"^\| Rule \| What it checks \| NIST SP 800-53 Rev\. 5 controls \|\n\|---\|---\|---\|\n(?:\| KN-.*\n)+", re.M
)
_TITLE_TABLE = re.compile(r"^\| Control \| Title \|\n\|---\|---\|\n(?:\| [A-Z]{2}-.*\n)+", re.M)
_TITLE_ROW = re.compile(r"^\| ([A-Z]{2}-\d+(?:\(\d+\))?) \| (.+?) \|$", re.M)


def title_rows(doc: str) -> list[tuple[str, str]]:
    """The (control, title) pairs in the control-titles table, for a test to read back.

    The escaped pipe `_cell` writes is Markdown's, not part of the control's title, so it is undone here and
    a caller compares what it reads against `TITLES` directly.
    """
    block = _TITLE_TABLE.search(doc)
    if not block:
        return []
    return [(c, t.strip().replace(r"\|", "|")) for c, t in _TITLE_ROW.findall(block.group(0))]


def _cell(text: str) -> str:
    """A NIST enhancement title contains a literal `|` (`Least Privilege | Privileged Accounts`).

    Written raw into a Markdown cell it splits the row into three columns, which is how the committed table
    came to render wrong, and it also breaks line-oriented parsers that split on the pipe.
    """
    return text.replace("|", r"\|")


def _rule_table() -> str:
    from kube_noob.audit.engine import list_rules

    head = "| Rule | What it checks | NIST SP 800-53 Rev. 5 controls |\n|---|---|---|\n"
    rows = "".join(
        f"| {r['ruleId']} | {_cell(str(r['title']))} | {', '.join(r['controls'])} |\n"
        for r in sorted(list_rules(), key=lambda r: str(r["ruleId"]))
    )
    return head + rows


def _title_table() -> str:
    from kube_noob.audit.controls import RULE_CONTROLS, TITLES

    used = {c for cs in RULE_CONTROLS.values() for c in cs}
    titles = {c: TITLES[c] for c in used} | POSTURE_CONTROLS

    def key(control: str) -> tuple[str, int, int]:
        family, _, rest = control.partition("-")
        base, _, enh = rest.partition("(")
        return family, int(base), int(enh.rstrip(")") or 0)

    head = "| Control | Title |\n|---|---|\n"
    return head + "".join(f"| {c} | {_cell(titles[c])} |\n" for c in sorted(titles, key=key))


_RULE_ROW = re.compile(r"^\| KN-", re.M)
_ANY_ROW = re.compile(r"^\| ", re.M)


def _check_shape(doc: str) -> tuple[re.Match[str], re.Match[str]]:
    """Refuse unless each region covers every row it is responsible for.

    A blank line inside a table splits it: the pattern then matches only the first half, the rewrite
    regenerates that half, and the orphaned rows below are left in place -- a document listing 49 rules twice
    while the generator exits 0. That is the same absence-read-as-pass defect the rest of this tool exists to
    catch, so the regions are checked against the whole document rather than against themselves.
    """
    found: dict[str, re.Match[str]] = {}
    for name, pattern in (("heading", _HEADING), ("rule table", _RULE_TABLE), ("titles table", _TITLE_TABLE)):
        hits = list(pattern.finditer(doc))
        if len(hits) != 1:
            raise SystemExit(
                f"docs/compliance.md: expected exactly one {name}, found {len(hits)}; the document's shape changed"
            )
        found[name] = hits[0]
    rules, titles = found["rule table"], found["titles table"]
    outside = len(_RULE_ROW.findall(doc)) - len(_RULE_ROW.findall(rules.group(0)))
    if outside:
        raise SystemExit(
            f"docs/compliance.md: {outside} rule row(s) sit outside the rule table; the document's shape changed "
            "(a blank line inside the table splits it)"
        )
    # The titles table ends its section, so nothing between it and the next heading may be a table row. Control
    # ids do start lines in the posture table above, so this tail check is what a global count cannot give.
    tail = doc[titles.end() :].split("\n## ", 1)[0]
    if _ANY_ROW.search(tail):
        raise SystemExit("docs/compliance.md: table rows follow the control-titles table; the document's shape changed")
    return rules, titles


def render() -> str:
    from kube_noob.audit.engine import list_rules

    doc = OUT.read_text(encoding="utf-8")
    _check_shape(doc)
    doc = _HEADING.sub(f"## The {len(list_rules())} audit rules and their controls", doc, count=1)
    doc = _RULE_TABLE.sub(lambda _: _rule_table(), doc, count=1)
    return _TITLE_TABLE.sub(lambda _: _title_table(), doc, count=1)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--check", action="store_true", help="exit 1 when the committed document is stale")
    a = ap.parse_args(argv)
    text = render()
    if a.check:
        if OUT.read_text(encoding="utf-8") != text:
            print("docs/compliance.md is stale: run python scripts/compliance_doc.py", file=sys.stderr)
            return 1
        print(f"docs/compliance.md is current ({text.count('| KN-')} rule rows)")
        return 0
    OUT.write_text(text, encoding="utf-8")
    print(f"wrote docs/compliance.md ({text.count('| KN-')} rule rows)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
