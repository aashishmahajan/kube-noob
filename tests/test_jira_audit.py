"""J2: `kube-noob corpus jira-audit` reports what the local Jira copy holds and checks that no people are left."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from kube_noob import jira_audit
from kube_noob.cli import main
from kube_noob.sources.jira import sync_projects
from tests.test_jira_full_text import CommentJira, _long_ticket
from tests.test_tickets import BASE, MIRROR, NOW, OVN, ROUTER, ROUTER_DUP, SENSOR, _client


def _copy(tmp_path: Path) -> Path:
    issue, comments = _long_ticket()
    fake = CommentJira(
        {"OCPBUGS": [ROUTER, MIRROR, OVN, ROUTER_DUP, issue], "ROX": [SENSOR]}, {"OCPBUGS-500": comments}
    )
    sync_projects(_client(fake, []), ["OCPBUGS", "ROX"], tmp_path, BASE, NOW)
    return tmp_path


def test_the_report_counts_what_the_copy_holds(tmp_path: Path) -> None:
    rep = jira_audit.audit(_copy(tmp_path))
    assert rep["available"] and rep["tickets"] == 6 and rep["baseUrl"] == BASE
    ocp = rep["projects"]["OCPBUGS"]
    assert ocp["tickets"] == 5 and ocp["keyRange"] == [101, 500] and ocp["keyCoverage"] == round(5 / 400, 3)
    assert ocp["byVerdict"]["duplicate"] == 1 and ocp["byVerdict"]["not-a-bug"] == 1
    assert ocp["commentsKept"] == ocp["commentsReported"] and ocp["ticketsMissingComments"] == 0
    assert ocp["olderFormat"] == 0 and ocp["textCut"] == 0 and ocp["sync"]["complete"] is True
    assert ocp["sync"]["textVersion"] == 2 and ocp["withComments"] >= 3
    assert rep["commentCompleteness"] == 1.0
    assert rep["anonymiser"]["commenter labels"] >= 3 and rep["anonymiser"]["<phone>"] == 1
    assert rep["selfCheck"] == {"personShapedFindings": 0, "examples": []}


def test_missing_comments_older_format_and_leaks_are_reported(tmp_path: Path) -> None:
    data = _copy(tmp_path)
    shard = data / "corpus" / "jira-ocpbugs.jsonl"
    lines = shard.read_text().splitlines()
    recs = [json.loads(line) for line in lines]
    recs[0]["comments"], recs[0]["commentsTotal"] = 3, 10
    del recs[1]["commentsTotal"]
    recs[2]["text"] += " contact jane.doe@example.com https://redhat.atlassian.net/jira/people/5b10a2844c20165700ede21f"
    shard.write_text("\n".join(json.dumps(r) for r in recs) + "\nnot json\n")
    ocp = jira_audit.audit(data, "ocpbugs")["projects"]["OCPBUGS"]
    assert ocp["ticketsMissingComments"] == 1 and ocp["mostMissing"][0].endswith("(7 missing)")
    assert ocp["olderFormat"] == 1 and ocp["malformedLines"] == 1
    check = jira_audit.audit(data)["selfCheck"]
    assert check["personShapedFindings"] == 3
    assert {e.split(": ")[1] for e in check["examples"]} == {"email", "account id", "profile link"}


def test_cli_text_json_and_no_copy(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("KUBE_NOOB_DATA_DIR", str(_copy(tmp_path / "a")))
    monkeypatch.setenv("KUBE_NOOB_OFFLINE", "1")  # local only: works under the offline lock
    assert main(["corpus", "jira-audit"]) == 0
    out = capsys.readouterr().out
    assert out.startswith("Jira copy: 6 tickets") and "OCPBUGS" in out and "self-check: no person-shaped text" in out
    assert main(["corpus", "jira-audit", "--project", "ROX", "--format", "json"]) == 0
    assert list(json.loads(capsys.readouterr().out)["projects"]) == ["ROX"]
    monkeypatch.setenv("KUBE_NOOB_DATA_DIR", str(tmp_path / "empty"))
    assert main(["corpus", "jira-audit"]) == 1
    assert "No local Jira copy" in capsys.readouterr().out


def test_hostile_shards_are_bounded(tmp_path: Path) -> None:
    corpus = tmp_path / "corpus"
    corpus.mkdir()
    (corpus / "jira-x.jsonl").write_text(
        "x" * (jira_audit.MAX_LINE + 10)
        + "\n"
        + json.dumps({"id": "jira-X-1", "sourceId": "jira:X", "text": 5})
        + "\n"
        + json.dumps([1, 2])
        + "\n"
        + json.dumps({"id": "jira-X-2", "sourceId": "other"})
        + "\n"
    )
    rep = jira_audit.audit(tmp_path)
    x = rep["projects"]["X"]
    assert x["tickets"] == 1 and x["malformedLines"] == 1 and x["olderFormat"] == 1
