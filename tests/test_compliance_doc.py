"""docs/compliance.md is generated from the code, because hand-keeping it went stale three ways (G206).

The heading said "The 78 audit rules" with 89 in the code; seven controls that rules map to had no title row,
so a reader saw `IA-5(7)` on a rule and had nowhere to look it up; and the only guard asserted every rule HAS
a row, never that a row still has a rule. SC-13 is deliberately in the titles table and not in RULE_CONTROLS:
it is a posture control, evidenced by `kube-noob doctor` rather than by an audit rule.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import compliance_doc as cd  # noqa: E402

from kube_noob.audit.controls import RULE_CONTROLS, TITLES  # noqa: E402
from kube_noob.audit.engine import list_rules  # noqa: E402

DOC = ROOT / "docs" / "compliance.md"


def test_the_committed_document_is_current() -> None:
    assert cd.main(["--check"]) == 0, "run: python scripts/compliance_doc.py"


def test_the_heading_states_the_real_rule_count() -> None:
    m = re.search(r"^## The (\d+) audit rules and their controls$", DOC.read_text(encoding="utf-8"), re.M)
    assert m, "the heading this document is generated around is gone"
    assert int(m.group(1)) == len(list_rules())


def test_every_rule_has_exactly_one_row_and_every_row_has_a_rule() -> None:
    rows = re.findall(r"^\| (KN-[A-Z]+\d+) \| ([^|]+?) \| ([^|]+?) \|$", DOC.read_text(encoding="utf-8"), re.M)
    ids = [r[0] for r in rows]
    assert len(ids) == len(set(ids)), "a rule is listed twice"
    assert set(ids) == {r["ruleId"] for r in list_rules()}, "the table and the rule set disagree"
    by_id = {r["ruleId"]: r for r in list_rules()}
    for rid, title, controls in rows:
        assert title.strip() == by_id[rid]["title"], rid
        assert controls.strip() == ", ".join(by_id[rid]["controls"]), rid


def test_every_control_a_rule_maps_to_has_a_title_row() -> None:
    """Seven did not, including every parenthesised enhancement, so they appeared with nowhere to look up."""
    titles = dict(cd.title_rows(DOC.read_text(encoding="utf-8")))
    used = {c for cs in RULE_CONTROLS.values() for c in cs}
    assert used <= set(titles), sorted(used - set(titles))
    for control in used:
        assert titles[control] == TITLES[control], control


def test_a_posture_control_is_kept_even_though_no_rule_maps_to_it() -> None:
    """SC-13 is evidenced by `kube-noob doctor`, not by a rule. Generating from RULE_CONTROLS alone drops it."""
    titles = dict(cd.title_rows(DOC.read_text(encoding="utf-8")))
    assert "SC-13" in titles and "SC-13" not in {c for cs in RULE_CONTROLS.values() for c in cs}
    assert titles["SC-13"] == "Cryptographic Protection"
    assert "SC-13" in cd.POSTURE_CONTROLS


def test_the_rows_are_sorted_so_a_new_rule_lands_in_one_place() -> None:
    rows = re.findall(r"^\| (KN-[A-Z]+\d+) \|", DOC.read_text(encoding="utf-8"), re.M)
    assert rows == sorted(rows), "the table is not sorted, so a generated row would move unrelated lines"


def _copy(tmp_path: Path, text: str) -> Path:
    out = tmp_path / "compliance.md"
    out.write_text(text, encoding="utf-8")
    return out


def test_a_damaged_table_fails_loudly_rather_than_being_rewritten_twice(tmp_path: Path, monkeypatch: object) -> None:
    """A blank line inside the table splits it, so a regex rewrite would regenerate one half and keep the other.

    The generator must not leave two tables behind. It either rewrites the whole region or refuses; what it
    must never do is exit 0 on a document that now lists some rules twice.
    """
    doc = DOC.read_text(encoding="utf-8")
    rows = [line for line in doc.splitlines(keepends=True) if line.startswith("| KN-")]
    damaged = doc.replace(rows[40], "\n" + rows[40], 1)
    broken = _copy(tmp_path, damaged)
    monkeypatch.setattr(cd, "OUT", broken)  # type: ignore[attr-defined]
    try:
        assert cd.main([]) == 0
    except SystemExit as exc:  # refusing is a correct outcome; silently duplicating is not
        assert "shape changed" in str(exc)
        return
    ids = re.findall(r"^\| (KN-[A-Z]+\d+) \|", broken.read_text(encoding="utf-8"), re.M)
    assert len(ids) == len(set(ids)), "the rewrite left a rule listed twice"
    assert set(ids) == {r["ruleId"] for r in list_rules()}


def test_a_renamed_heading_refuses_instead_of_reporting_the_document_current(
    tmp_path: Path, monkeypatch: object
) -> None:
    """The count lives in the heading. If the heading is reworded, a silent no-op would freeze the count."""
    doc = re.sub(
        r"^## The \d+ audit rules and their controls$",
        "## Audit rules",
        DOC.read_text(encoding="utf-8"),
        count=1,
        flags=re.M,
    )
    renamed = _copy(tmp_path, doc)
    monkeypatch.setattr(cd, "OUT", renamed)  # type: ignore[attr-defined]
    with pytest.raises(SystemExit, match="shape changed"):
        cd.main(["--check"])
