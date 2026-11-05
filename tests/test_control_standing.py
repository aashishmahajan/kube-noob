"""Per-control standing in the drift report, not just a count per namespace (roadmap N4).

`drift diff` grouped open findings by namespace, owner and rule. A platform team's question is the one a count
cannot answer: which controls are standing open, where, and which were checked and found nothing. The second half
is why this needs the coverage record (P1): without knowing which rules RAN, a control with no open finding is
indistinguishable from a control nothing ever evaluated, and reporting the first as if it were satisfied is the
defect this project keeps correcting (G191, G202, G210).

So a snapshot records what ran, the report says `clean` and `notEvaluated` only when it can, and a snapshot taken
before this change -- which carries no coverage record -- makes no standing claim at all.
"""

from __future__ import annotations

import datetime as dt
from pathlib import Path
from typing import Any

import yaml

from kube_noob import drift
from kube_noob.audit.controls import RULE_CONTROLS

FIX = Path(__file__).parent / "fixtures" / "drift"
T1 = dt.datetime(2026, 10, 27, 3, 0, tzinfo=dt.UTC)
T2 = dt.datetime(2026, 10, 28, 3, 0, tzinfo=dt.UTC)

# Hand-derived from the byRule rows of tests/test_drift.py::EXPECTED and the published rule-to-control map, before
# this code ran: KN-C016 (low, ops+shop), KN-S001 (critical, ops), KN-S002 (medium, ops), KN-S017 (low, shop).
BY_CONTROL: list[dict[str, Any]] = [
    {"control": "AC-6", "findings": 3, "critical": 1, "low": 1, "medium": 1, "namespaces": ["ops", "shop"]},
    {"control": "CM-7", "findings": 2, "critical": 1, "medium": 1, "namespaces": ["ops"]},
    {"control": "SC-5", "findings": 2, "low": 2, "namespaces": ["ops", "shop"]},
    {"control": "SC-6", "findings": 2, "low": 2, "namespaces": ["ops", "shop"]},
    {"control": "AC-3", "findings": 1, "low": 1, "namespaces": ["shop"]},
    {"control": "AC-5", "findings": 1, "low": 1, "namespaces": ["shop"]},
    {"control": "AC-6(10)", "findings": 1, "medium": 1, "namespaces": ["ops"]},
    {"control": "SC-39", "findings": 1, "critical": 1, "namespaces": ["ops"]},
]


def _docs(name: str) -> list[dict[str, Any]]:
    return [d for d in yaml.safe_load_all((FIX / name).read_text(encoding="utf-8")) if d]


def _snap(name: str, when: dt.datetime, **kw: Any) -> dict[str, Any]:
    return drift.snapshot(_docs(name), source="manifests", taken_at=when, **kw)


def _report(**kw: Any) -> dict[str, Any]:
    return drift.diff(_snap("day1.yaml", T1), _snap("day2.yaml", T2, **kw))


def test_open_findings_are_grouped_by_control() -> None:
    rows = _report()["violations"]["byControl"]
    assert [{k: v for k, v in r.items() if k != "title"} for r in rows] == BY_CONTROL


def test_each_row_carries_the_control_title() -> None:
    from kube_noob.audit.controls import TITLES

    for row in _report()["violations"]["byControl"]:
        assert row["title"] == TITLES[row["control"]]


def test_a_control_with_no_open_finding_is_absent_from_the_grouping() -> None:
    """This grouping counts open findings. It is not a coverage claim, and must not read as one."""
    rows = {r["control"] for r in _report()["violations"]["byControl"]}
    used = {c for cs in RULE_CONTROLS.values() for c in cs}
    assert rows < used and "SC-28" not in rows


def test_the_snapshot_records_what_ran() -> None:
    """Without it, a control with no finding and a control nothing evaluated are the same row."""
    snap = _snap("day2.yaml", T2)
    coverage = snap["coverage"]
    assert coverage["evaluatedRules"] == sorted(coverage["evaluatedRules"])
    assert "KN-S001" in coverage["evaluatedRules"]
    assert coverage["firedRules"] == sorted(coverage["firedRules"])
    assert set(coverage["firedRules"]) >= {"KN-C016", "KN-S001", "KN-S002", "KN-S017"}


def test_standing_separates_clean_from_never_evaluated() -> None:
    standing = _report()["controlStanding"]
    by_id = {c["id"]: c for c in standing["controls"]}
    assert by_id["AC-6"]["findings"] == 3
    clean = [c for c in standing["controls"] if c["findings"] == 0 and c["clean"]]
    assert clean, "a control whose rules ran and found nothing is reported, not omitted"
    for entry in standing["controls"]:
        assert entry["clean"] >= 0 and entry["notEvaluated"] >= 0
    assert "assessment" in standing["note"]


def test_a_snapshot_without_a_coverage_record_makes_no_standing_claim() -> None:
    """A snapshot written before this change has no coverage record. The diff must still work and must not
    invent one: counts yes, standing no."""
    old, new = _snap("day1.yaml", T1), _snap("day2.yaml", T2)
    del old["coverage"]
    del new["coverage"]
    report = drift.diff(old, new)
    assert report["violations"]["byControl"]  # the counts need no coverage record
    assert "controlStanding" not in report
    assert any("coverage" in n for n in report.get("notes", [])), report.get("notes")


def test_one_side_without_coverage_is_also_no_claim() -> None:
    old, new = _snap("day1.yaml", T1), _snap("day2.yaml", T2)
    del old["coverage"]
    assert "controlStanding" in drift.diff(old, new), "standing describes the NEW snapshot, which has coverage"


def test_the_markdown_report_shows_the_standing() -> None:
    text = drift.markdown(_report())
    assert "## Open findings by control" in text
    assert "AC-6" in text and "Least Privilege" in text


def test_the_namespaces_on_a_row_are_sorted_and_bounded() -> None:
    rows = _report()["violations"]["byControl"]
    for row in rows:
        assert row["namespaces"] == sorted(row["namespaces"])
        assert len(row["namespaces"]) <= drift.MAX_CONTROL_NAMESPACES


def test_a_rule_that_maps_to_no_control_does_not_vanish_silently() -> None:
    """Every rule maps to a control today, and a future one that does not must not disappear from the grouping
    without the report saying so."""
    unmapped = sorted(r for r in ("KN-C016", "KN-S001") if r not in RULE_CONTROLS)
    assert unmapped == []  # if this ever fails, the grouping needs an "unmapped" row before shipping
