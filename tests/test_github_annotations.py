"""Gate findings as GitHub annotations, which is where a developer actually looks (roadmap N12).

`gate --sarif` has always written SARIF, and `action.yml` has always run the gate, but nothing turned a finding
into an annotation -- so a finding landed in a log somebody had to go looking for. The constraint that shapes
this is GitHub's own: "10 warning annotations, 10 error annotations, and 10 notice annotations per step" and "50
annotations per job" (actions/toolkit, docs/problem-matchers.md, retrieved 2026-11-05). Emitting one per finding
would therefore drop the rest SILENTLY, and a developer who sees ten annotations and assumes that is all of them
has been misled by the tool -- the same defect as a count that stops being true.

So the last annotation of each kind is spent saying how many were not shown.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import pytest

from kube_noob import gate

ROOT = Path(__file__).resolve().parents[1]


def _finding(rule: str, severity: str, uri: str | None = "k8s/deploy.yaml", line: int | None = 7) -> dict[str, Any]:
    return {
        "ruleId": rule,
        "severity": severity,
        "title": f"{rule} title",
        "message": f"{rule} says something is wrong",
        "remediation": "do the thing",
        "resource": "Deployment/shop/web",
        "uri": uri,
        "line": line,
        "path": "spec.template.spec",
    }


def _report(findings: list[dict[str, Any]], fail_on: str = "high") -> dict[str, Any]:
    return {"findings": findings, "failOn": fail_on, "passed": False, "failures": ["x"]}


def test_a_finding_at_or_above_the_threshold_is_an_error_annotation() -> None:
    lines = gate.github_annotations(_report([_finding("KN-S001", "critical")]))
    assert len(lines) == 1
    assert lines[0].startswith("::error ")
    assert "file=k8s/deploy.yaml" in lines[0] and "line=7" in lines[0]
    assert "KN-S001" in lines[0]


def test_a_finding_below_the_threshold_is_a_warning() -> None:
    lines = gate.github_annotations(_report([_finding("KN-C001", "low")]))
    assert lines[0].startswith("::warning ")


def test_the_message_is_one_line_and_escaped() -> None:
    """A newline or a comma in a workflow command ends the annotation early, so the message must survive it."""
    bad = _finding("KN-S002", "high")
    bad["message"] = "first line\nsecond line, with a comma: and a colon%"
    line = gate.github_annotations(_report([bad]))[0]
    assert "\n" not in line
    assert "%0A" in line and "%25" in line
    # The shape is `::<level> <properties>::<message>`, so two `::` are correct and the properties must hold no
    # comma or colon pair of their own -- those end the property list.
    head, _, message = line.partition("::")[2].partition("::")
    assert head.startswith("error ") and "," in head
    assert "%0A" in message and ":" in message, "a colon in the MESSAGE is harmless and stays readable"


def test_a_finding_with_no_file_still_annotates() -> None:
    """A Containerfile finding or a scanner finding may have no manifest line. Dropping it would hide it."""
    line = gate.github_annotations(_report([_finding("KN-S003", "high", uri=None, line=None)]))[0]
    assert line.startswith("::error ") and "file=" not in line


def test_the_last_annotation_says_how_many_were_not_shown() -> None:
    """GitHub drops the eleventh silently. A tool that lets it is telling a developer there are ten problems."""
    findings = [_finding(f"KN-S{i:03d}", "critical") for i in range(25)]
    lines = gate.github_annotations(_report(findings))
    assert len(lines) == gate.MAX_ANNOTATIONS_PER_TYPE
    assert all(line.startswith("::error ") for line in lines)
    assert "16 more" in lines[-1] and "SARIF" in lines[-1]


def test_both_kinds_are_capped_independently() -> None:
    findings = [_finding(f"KN-S{i:03d}", "critical") for i in range(12)]
    findings += [_finding(f"KN-C{i:03d}", "low") for i in range(12)]
    lines = gate.github_annotations(_report(findings))
    errors = [x for x in lines if x.startswith("::error ")]
    warnings = [x for x in lines if x.startswith("::warning ")]
    assert len(errors) == len(warnings) == gate.MAX_ANNOTATIONS_PER_TYPE
    assert "3 more" in errors[-1] and "3 more" in warnings[-1]


def test_nothing_is_emitted_for_a_clean_report() -> None:
    assert gate.github_annotations({"findings": [], "failOn": "high", "passed": True, "failures": []}) == []


def test_the_worst_findings_come_first() -> None:
    lines = gate.github_annotations(_report([_finding("KN-A", "high"), _finding("KN-B", "critical")]))
    assert "KN-B" in lines[0] and "KN-A" in lines[1]


def test_never_as_a_threshold_makes_every_finding_a_warning() -> None:
    """`--fail-on never` means nothing fails, so nothing should be an error annotation either."""
    lines = gate.github_annotations(_report([_finding("KN-S001", "critical")], fail_on="never"))
    assert lines[0].startswith("::warning ")


def test_the_total_stays_under_githubs_per_job_cap() -> None:
    findings = [_finding(f"KN-S{i:03d}", "critical") for i in range(40)]
    findings += [_finding(f"KN-C{i:03d}", "low") for i in range(40)]
    assert len(gate.github_annotations(_report(findings))) <= 50


def test_the_cli_prints_them_and_keeps_the_exit_code() -> None:
    from kube_noob.cli import main

    fixtures = str(ROOT / "tests" / "fixtures" / "gate" / "bad")
    assert main(["gate", "-f", fixtures, "--platform", "kubernetes", "--fail-on", "high", "--github-annotations"]) == 1


def test_the_action_emits_them() -> None:
    """A feature the action does not call is a feature a user of the action does not have."""
    action = (ROOT / "action.yml").read_text(encoding="utf-8")
    assert "--github-annotations" in action
    assert re.search(r"annotations:\n\s+description:", action), "the behaviour is documented as an input"


def test_the_documented_limit_is_the_one_in_the_code() -> None:
    """If GitHub changes the cap, the number lives in one place and this test names where it came from."""
    assert gate.MAX_ANNOTATIONS_PER_TYPE == 10
    assert "problem-matchers" in (gate.github_annotations.__doc__ or "")


def test_a_json_report_is_unchanged_by_the_flag(capsys: pytest.CaptureFixture[str]) -> None:
    """Annotations go to stdout as workflow commands; the report must stay machine-readable beside them."""
    from kube_noob.cli import main

    fixtures = str(ROOT / "tests" / "fixtures" / "gate" / "bad")
    assert main(["--format", "json", "gate", "-f", fixtures, "--platform", "kubernetes", "--github-annotations"]) == 1
    out = capsys.readouterr().out
    body = "\n".join(line for line in out.splitlines() if not line.startswith("::"))
    assert json.loads(body)["findings"], "the JSON report survives beside the annotations"
