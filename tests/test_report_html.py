"""The self-contained HTML report (U1, G222).

The audience for per-control standing and the KSI crosswalk is a compliance reviewer, and until now what they got
was terminal text or JSON. These tests hold the two things that make an HTML report trustworthy rather than
merely prettier: every caveat the text view carries survives into it, and nothing from a manifest is ever
rendered as markup.
"""

from __future__ import annotations

import datetime as dt
import re
from html.parser import HTMLParser
from pathlib import Path
from typing import Any

import pytest
import yaml

from kube_noob import drift, gate, report_html

ROOT = Path(__file__).resolve().parents[1]
FIX = ROOT / "tests/fixtures/drift"


class _Sinks(HTMLParser):
    """Collect every attribute that makes the browser fetch something, and every script."""

    def __init__(self) -> None:
        super().__init__()
        self.loads: list[tuple[str, str]] = []
        self.scripts = 0
        self.events: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag in {"script", "iframe", "object", "embed"}:
            self.scripts += 1
        for name, value in attrs:
            if name.startswith("on"):
                self.events.append(f"{tag}@{name}")
            if name in {"src", "srcset", "data", "action", "poster", "background"} and value:
                self.loads.append((tag, value))
            if name == "href" and value and tag == "link":
                self.loads.append((tag, value))


def _parsed(html: str) -> _Sinks:
    p = _Sinks()
    p.feed(html)
    return p


def _gate_report(**kw: Any) -> dict[str, Any]:
    src = gate.Source("deploy/web.yaml", (ROOT / "examples/insecure-deployment.yaml").read_text())
    return gate.run([src], fail_on="high", **kw)


def _posture_report() -> dict[str, Any]:
    docs = [d for d in yaml.safe_load_all((FIX / "day2.yaml").read_text()) if d]
    snap = drift.snapshot(docs, source="manifests", taken_at=dt.datetime(2026, 10, 28, tzinfo=dt.UTC))
    return drift.first_report(snap)


def test_the_page_fetches_nothing_and_runs_nothing() -> None:
    """A report a reviewer opens from an email attachment, on a laptop with no network, in an air-gapped review
    room. One file: no stylesheet, no script, no font, no image, no inline handler."""
    for report in (_gate_report(), _posture_report()):
        page = report_html.render(report)
        sinks = _parsed(page)
        assert sinks.scripts == 0, "no script, iframe, object or embed"
        assert sinks.events == [], sinks.events
        assert sinks.loads == [], sinks.loads
        assert "<style" in page, "styling is inline or there is none"


def test_a_resource_name_is_never_rendered_as_markup() -> None:
    """Resource names, messages and paths come from someone else's manifests. This is the one place in the
    product where that text becomes a document another person opens."""
    hostile = (
        "apiVersion: apps/v1\nkind: Deployment\n"
        'metadata:\n  name: "<script>alert(1)</script>"\n  namespace: "x<img src=x onerror=alert(2)>"\n'
        "spec:\n  replicas: 1\n  selector: {matchLabels: {app: a}}\n"
        "  template:\n    metadata: {labels: {app: a}}\n"
        "    spec:\n      containers:\n      - name: c\n        image: nginx:latest\n"
        "        securityContext: {privileged: true}\n"
    )
    report = gate.run([gate.Source("evil.yaml", hostile)], fail_on="high")
    page = report_html.render(report)
    sinks = _parsed(page)
    assert sinks.scripts == 0
    assert sinks.events == []
    assert sinks.loads == []
    assert "<script>alert(1)</script>" not in page
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in page, "the name is shown, escaped, not dropped"


def test_every_caveat_the_text_view_carries_survives() -> None:
    """An HTML report that drops the caveats is the G221 defect in a third format. These are the four that
    change what a count means."""
    report = _gate_report()
    report["notCheckedBeyond"] = {"target": "1.40", "removalData": "1.37", "why": "read at 1.37, not 1.40"}
    report["assumptions"] = ["No Kubernetes version given; assumed 1.35."]
    report["unreadable"] = [{"path": "zz-bad.yaml", "why": "not readable as UTF-8 text"}]
    page = report_html.render(report)
    assert "read at 1.37, not 1.40" in page
    assert "assumed 1.35" in page
    assert "zz-bad.yaml" in page
    assert "not a complete" in page.lower(), "an incomplete read has to say the result is not clean"


def test_the_caveats_come_before_the_findings() -> None:
    """Position is the whole point: a reader who meets an empty findings table first has already concluded."""
    report = _gate_report()
    report["assumptions"] = ["No Kubernetes version given; assumed 1.35."]
    first = report["findings"][0]["ruleId"]
    page = report_html.render(report)
    assert page.index("assumed 1.35") < page.index(first)


def test_per_control_standing_keeps_its_five_buckets() -> None:
    report = _posture_report()
    page = report_html.render(report)
    assert "Control standing" in page
    for header in ("Findings", "Excepted", "Withheld", "Clean", "Not evaluated"):
        assert header in page, header


def test_a_withheld_standing_says_why_instead_of_showing_a_table() -> None:
    docs = [d for d in yaml.safe_load_all((FIX / "day2.yaml").read_text()) if d]
    docs = [d for d in docs if d["kind"] not in ("Role", "RoleBinding")]
    snap = drift.snapshot(
        docs,
        source="live",
        taken_at=dt.datetime(2026, 10, 28, tzinfo=dt.UTC),
        not_read=["roles in shop: forbidden"],
    )
    page = report_html.render(drift.first_report(snap))
    assert "forbidden" in page
    assert re.search(r"no standing|withheld entirely|cannot be trusted", page, re.I)


def test_the_ksi_view_carries_the_sentence_that_says_what_it_is_not() -> None:
    from kube_noob.audit import fedramp

    page = report_html.render(fedramp.summary([]))
    assert "never a compliance claim" in page
    assert "audited" in page.lower()
    assert fedramp.EVIDENCE["KSI-RPL-ABO"]["doesNotShow"][:40] in page
    assert "shared NIST control" in page, "the off-subject warning"


def test_an_unaudited_ksi_page_shows_no_counts() -> None:
    from kube_noob.audit import fedramp

    page = report_html.render(fedramp.summary([]))
    assert re.search(r"nothing (was )?audited|no audit", page, re.I)


def test_the_page_is_written_where_the_command_was_told() -> None:
    import subprocess
    import sys
    import tempfile

    with tempfile.TemporaryDirectory() as d:
        out = Path(d) / "report.html"
        r = subprocess.run(
            [
                sys.executable,
                "-m",
                "kube_noob.cli",
                "gate",
                "-f",
                "examples/insecure-deployment.yaml",
                "--fail-on",
                "never",
                "--html",
                str(out),
                "--format",
                "json",
            ],
            capture_output=True,
            text=True,
            cwd=ROOT,
            env={"PATH": "/usr/bin:/bin", "PYTHONPATH": str(ROOT / "src"), "HOME": d},
            check=False,
        )
        assert r.returncode == 0, r.stdout + r.stderr
        page = out.read_text()
    assert page.startswith("<!doctype html>")
    assert _parsed(page).loads == []


@pytest.mark.parametrize("report", [{}, {"findings": []}, {"indicators": []}])
def test_an_empty_report_still_renders_a_page(report: dict[str, Any]) -> None:
    page = report_html.render(report)
    assert page.startswith("<!doctype html>")
    assert page.rstrip().endswith("</html>")


def test_the_byline_never_borrows_another_version() -> None:
    """The KSI report carries `dataset.version`; using it as a fallback printed "by kube-noob 2026.11.02.01" in
    the first line of a document written for someone whose job is checking claims."""
    from kube_noob.audit import fedramp

    page = report_html.render(fedramp.summary([]))
    assert "by kube-noob 2026.11.02.01" not in page
    assert fedramp.DATASET_VERSION in page, "the dataset version still appears, where it belongs"
    assert "by kube-noob 0." in report_html.render({"version": "0.7.1", "findings": [], "passed": True})


def test_backticks_become_code_spans_and_hostile_text_stays_inert() -> None:
    """The curated prose is written with markdown backticks. Escaping happens first, so the only markup here is
    markup this code wrote; a name full of backticks and angle brackets is a code span of escaped text."""
    page = report_html.render({"assumptions": ["use `partial_bundle=false` for a whole namespace"]})
    assert "<code>partial_bundle=false</code>" in page
    hostile = report_html.render({"assumptions": ["`<script>alert(1)</script>`"]})
    assert "<script>" not in hostile
    assert "&lt;script&gt;" in hostile
    odd = report_html.render({"assumptions": ["one ` unpaired backtick"]})
    assert "<code>" not in odd


def test_a_row_with_no_counts_does_not_sit_under_the_findings_heading() -> None:
    """An indicator kube-noob cannot evidence has a note where the numbers go. Left as one cell, that note
    rendered in the Findings column -- the one column on the page a reader must not misread."""
    from kube_noob.audit import fedramp

    page = report_html.render(fedramp.summary([], evaluated_rule_ids=[]))
    assert 'colspan="4"' in page or 'colspan="5"' in page
