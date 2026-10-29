"""G3: the must-gather report and the support case draft. Golden files for both renderings (matchers stubbed so the
goldens do not move with the bundled indexes), the real known-issue and memory matchers, redaction, and the CLI.

Regenerate the goldens after an intended change: KN_UPDATE_GOLDEN=1 pytest tests/test_mustgather_report.py"""

from __future__ import annotations

import io
import json
import os
import re
import tarfile
from pathlib import Path
from typing import Any

import pytest

from kube_noob.cli import main
from kube_noob.mustgather import analyse, ingest, report, sample

GOLDEN = Path(__file__).resolve().parent / "fixtures" / "must-gather" / "golden"


@pytest.fixture(scope="module")
def bundle(tmp_path_factory: pytest.TempPathFactory) -> tuple[ingest.Bundle, analyse.Analysis]:
    b = ingest.open_bundle(sample.write(tmp_path_factory.mktemp("mgr")))
    return b, analyse.analyse(b)


def _known(text: str, platform: str, version: str | None) -> dict[str, Any]:
    matches = []
    if "leader" in text:
        matches.append(
            {
                "id": "OCPBUGS-1",
                "url": "https://example.invalid/OCPBUGS-1",
                "kind": "fixed",
                "fixedIn": "4.20.13",
                "status": f"Fixed in 4.20.13; you run {version}",
                "summary": "etcd leader elections under catalog sync I/O",
            }
        )
    return {"knowledge": {"knownIssuesAsOf": "2026-10-27", "openshiftReleases": ["4.20"]}, "matches": matches}


def _memory(text: str, version: str | None, platform: str | None, operators: list[str]) -> dict[str, Any]:
    if "CrashLoopBackOff" not in text:
        return {"matches": [], "notes": []}
    return {"matches": [{"id": "MEM-7", "symptom": "web crashes when the database is not up yet"}], "notes": []}


def _golden(name: str, text: str) -> None:
    path = GOLDEN / name
    if os.environ.get("KN_UPDATE_GOLDEN"):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    assert text == path.read_text(encoding="utf-8"), f"{name} differs from its golden file"


def test_report_and_case_draft_match_the_goldens(bundle: tuple[ingest.Bundle, analyse.Analysis]) -> None:
    b, a = bundle
    r = report.build(b, a, match_known=_known, match_memory=_memory, generated_by="kube-noob TEST")
    assert [m["id"] for m in r["knownIssues"]] == ["OCPBUGS-1"] and r["knownIssues"][0]["findings"] == [14, 16]
    assert r["memory"][0]["id"] == "MEM-7" and r["memory"][0]["findings"] == [10]
    assert r["collected"] == "2026-10-28 10:00:05.1 +0000 UTC"  # Go's monotonic " m=+0.03" dropped
    _golden("report.md", report.markdown(r))
    _golden("case-draft.md", report.case_draft(r))


def test_case_draft_invents_nothing(bundle: tuple[ingest.Bundle, analyse.Analysis]) -> None:
    b, a = bundle
    r = report.build(b, a, match_known=_known, generated_by="kube-noob TEST")
    draft = report.case_draft(r)
    for placeholder in (
        "what is not working",
        "when it started",
        "what changed before it started",
        "constant, intermittent or once",
        "who is affected",
        "the case severity you choose",
        "what you tried",
    ):
        assert f"[FILL IN: {placeholder}" in draft
    for h in ("Problem statement", "Environment", "Timeline", "Frequency", "Business impact", "Evidence"):
        assert f"## {h}" in draft
    assert "## Matched known issues and bugs" in draft and "## Steps already taken" in draft
    versions = {"4.20.3", "4.20.4", "4.20.13"}  # the cluster's, its update's, the matched fix's
    assert set(re.findall(r"\b4\.\d+\.\d+\b", draft)) <= versions
    assert "```bash" in draft and "#" not in draft.split("```bash", 1)[1].split("```", 1)[0]


def test_real_matchers(bundle: tuple[ingest.Bundle, analyse.Analysis], tmp_path: Path) -> None:
    from kube_noob.memory import dump_entry, repo

    b, a = bundle
    root = tmp_path / "team-memory"
    repo.init_repo(root)
    path, entry = repo.add_entry(
        root,
        {
            "kind": "fix",
            "signals": [{"kind": "alert", "name": "KubePodCrashLooping"}],
            "symptom": "web crash-loops when its database is not reachable",
            "platform": "openshift",
            "cause": "The database Service had no endpoints after a node went NotReady.",
            "fix": {"text": "Wait for the database pod; add a readiness gate on the database."},
            "owners": ["shop-team"],
        },
    )
    path.write_text(dump_entry(entry.model_copy(update={"status": "approved"})), encoding="utf-8")
    r = report.build(b, a, data_dir=tmp_path / "data", memory_dirs=[root])
    assert r["knowledge"]["knownIssuesAsOf"] and r["knowledge"]["openshiftReleases"]
    assert all(m["id"] and m["findings"] for m in r["knownIssues"])
    crash = next(f for f in r["findings"] if f.get("reason") == "CrashLoopBackOff")
    assert entry.id in crash.get("memory", []), r["memory"]
    assert r["nextSteps"][0] == {"command": "oc adm upgrade", "label": "read-only", "for": 1}


def test_redacted_and_untrusted(tmp_path: Path) -> None:
    secret = "tok" + "en=" + "s3cr3t-" + "v" * 12
    co = (
        "apiVersion: config.openshift.io/v1\nkind: ClusterOperator\nmetadata:\n  name: dns\nstatus:\n  conditions:\n"
        f'  - type: Degraded\n    status: "True"\n    message: "| pipe `tick` <b>x</b> {secret}"\n'
    )
    path = tmp_path / "mg.tgz"
    with tarfile.open(path, "w:gz") as tf:
        data = co.encode()
        info = tarfile.TarInfo("mg/img/cluster-scoped-resources/config.openshift.io/clusteroperators/dns.yaml")
        info.size = len(data)
        tf.addfile(info, io.BytesIO(data))
    b = ingest.open_bundle(path)
    r = report.build(b, analyse.analyse(b), match_known=_known)
    md = report.markdown(r) + report.case_draft(r)
    assert "s3cr3t" not in md and "<b>" not in md and "\\| pipe 'tick'" in md
    assert r["source"] == "mg.tgz" and str(tmp_path) not in json.dumps(r)


def test_cli(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    tgz = sample.write(tmp_path / "in")
    assert main(["must-gather", "analyze", str(tgz), "--case-draft"]) == 2
    out_dir = tmp_path / "out"
    assert main(["must-gather", "analyze", str(tgz), "--report", str(out_dir), "--case-draft"]) == 0
    text = capsys.readouterr().out
    assert f"wrote {out_dir / 'case-draft.md'}" in text
    assert {p.name for p in out_dir.iterdir()} == {"report.md", "report.json", "case-draft.md"}
    saved = json.loads((out_dir / "report.json").read_text())
    assert saved["cluster"]["version"] == "4.20.3" and saved["findings"][0]["rank"] == 1
    (tmp_path / "file").write_text("x")
    assert main(["must-gather", "analyze", str(tgz), "--report", str(tmp_path / "file")]) == 2
    assert main(["--format", "json", "must-gather", "analyze", str(tgz)]) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["kind"] == "tar" and "knownIssues" in out and "nextSteps" in out
