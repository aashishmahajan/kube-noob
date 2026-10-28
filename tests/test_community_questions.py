"""QA1: what the eval over 25,292 community questions (scripts/eval_questions.py, the owner's CSV, not in the repo)
changed, each as a test on text written for this file. Before: an OpenShift release-note bug topped 6,177 answers to
questions about other platforms; OpenShift and ROSA playbooks answered Docker and EKS questions; documents that
shared one incidental word were offered as answers."""

from __future__ import annotations

import csv
import importlib.util
import json
import sys
import time
from pathlib import Path

import pytest

from kube_noob import known_issues as ki
from kube_noob import toolkit as tk
from kube_noob.config import load_settings
from kube_noob.debug.diagnose import diagnose
from kube_noob.insight import recognise

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(scope="module")
def kit(tmp_path_factory: pytest.TempPathFactory) -> tk.Toolkit:
    return tk.Toolkit(
        load_settings(overrides={"dataDir": str(tmp_path_factory.mktemp("qa1")), "learningEnabled": False})
    )


def _ids(text: str, platform: str | None = None) -> list[str]:
    return [d["id"] for d in diagnose(text, platform=platform).as_dict()["diagnoses"]]


def test_release_notes_need_openshift_context_when_no_platform_is_given(kit: tk.Toolkit) -> None:
    post = (
        "Agent pod fails when deployed with the audit plugin\n"
        "Following the docs, the registry mirrors are replaced and the signature check causes the pod to fail."
    )
    out = kit.diagnose(tk.DiagnoseIn(text=post))
    assert out["knownIssues"] == []
    gated = ki.match(post, None, None, 3, require_context=True)
    assert gated["matches"] == [] and "does not say it is about OpenShift" in gated["note"]
    assert ki.openshift_context("oc adm release mirror to a disconnected registry") is True
    assert ki.openshift_context("pods in openshift-etcd restart") is True
    assert ki.openshift_context("my k3s cluster on a Raspberry Pi") is False


def test_everyday_words_are_not_evidence() -> None:
    for word, base in (("deployed", "deploy"), ("following", "follow"), ("causes", "cause"), ("mirrors", "mirror")):
        assert base in ki._forms(word) and base in ki.EVERYDAY_WORDS
    text = "deployed following plugin mirrors causes replaced"
    assert ki.match(text, "openshift", None, 3)["matches"] == []


def test_openshift_playbooks_need_openshift_words(kit: tk.Toolkit) -> None:
    assert "DBG-ARBITRARY-UID" not in _ids("docker compose: /docker-entrypoint.sh: Permission denied")
    assert _ids('[emerg] mkdir() "/var/cache/nginx/client_temp" failed (13: Permission denied)')[0] == (
        "DBG-ARBITRARY-UID"
    )  # the specific nginx line still names it
    assert "DBG-ARBITRARY-UID" in _ids("Permission denied writing /data on OpenShift")
    eks = "Karpenter NodeClaim stuck, nodes NotReady, the VPC endpoint for the node pool is missing"
    assert "DBG-ROSA-HCP-NODES" not in _ids(eks)
    assert "DBG-ROSA-HCP-NODES" in _ids("ROSA HCP machine pool nodes NotReady after the VPC endpoint change")


def test_new_trigger_phrases() -> None:
    assert _ids("PVC creation stuck with the ceph-csi rbd driver on k3s")[0] == "DBG-PVC-PENDING"
    assert _ids("weird DNS issues on k3s: pods time out")[0] == "DBG-DNS"
    row = "etcd 4.17.37 True False True 352d RevisionControllerDegraded: unable to ApplyStatus"
    assert "DBG-CLUSTEROPERATOR" in _ids(f"oc get co during the upgrade\n{row}")
    assert "DBG-CLUSTEROPERATOR" in _ids(row, platform="openshift")


def test_documents_must_share_more_than_an_incidental_word(kit: tk.Toolkit) -> None:
    post = "How to share my web app between two laptops\nI built a small app and want my friend to run it too?"
    out = kit.insight(tk.InsightIn(text=post))
    assert not [f for f in out["findings"] if f["source"] == "doc"]
    typed = kit.insight(tk.InsightIn(text="why does my pod stay Pending?", platform="kubernetes"))
    docs = [f for f in typed["findings"] if f["source"] == "doc"]
    assert docs and all(f["sharedTerms"] for f in docs)
    unknown = kit.insight(tk.InsightIn(text="Talos 1.12 cannot upgrade kubernetes"))
    assert not [f for f in unknown["findings"] if f["source"] == "doc"]


def test_a_forum_post_that_asks_is_a_question() -> None:
    post = (
        "Kubectl command to list only some pods\n"
        "Is there a way to use kubectl to list only the pods of one deployment? Today I grep the whole list."
    )
    assert "question" in [k.kind for k in recognise(post)]


def test_context_detection_is_linear_on_hostile_text() -> None:
    start = time.perf_counter()
    for text in ("a-" * 199_000, "a." * 199_000, "x" * 400_000):
        ki.openshift_context(text)
    assert time.perf_counter() - start < 3


def test_the_eval_script_runs_on_a_small_csv(tmp_path: Path) -> None:
    path = tmp_path / "q.csv"
    cols = ["id", "question", "body_excerpt", "topic_category", "platform_tags", "source", "url", "item_type"]
    with path.open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=cols)
        w.writeheader()
        w.writerow(
            {
                "id": "1",
                "question": "Pod stuck in CrashLoopBackOff",
                "body_excerpt": "Back-off restarting failed container web",
                "topic_category": "workloads-debugging",
                "platform_tags": "kubernetes",
                "source": "stackexchange:stackoverflow",
                "url": "https://stackoverflow.com/questions/1",
                "item_type": "question",
            }
        )
        w.writerow(
            {
                "id": "2",
                "question": "etcd leader changes on masters",
                "body_excerpt": "etcdserver: leader changed during the upgrade",
                "topic_category": "etcd-control-plane",
                "platform_tags": "openshift",
                "source": "redhat-jira:OCPBUGS",
                "url": "https://redhat.atlassian.net/browse/OCPBUGS-1",
                "item_type": "bug-report",
            }
        )
    spec = importlib.util.spec_from_file_location("eval_questions", ROOT / "scripts" / "eval_questions.py")
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules["eval_questions"] = mod
    spec.loader.exec_module(mod)
    out = tmp_path / "out"
    assert mod.main([str(path), "--out", str(out), "--sample-review", "2"]) == 0
    rows = list(csv.DictReader((out / "results.csv").open()))
    assert rows[0]["answer"] == "playbook" and rows[0]["topicAgree"] == "True"
    assert rows[1]["expectedKey"] == "OCPBUGS-1" and rows[1]["keyIndexed"] == "False"
    assert "question" not in rows[0]  # results never carry the question text
    review = list(csv.DictReader((out / "review.csv").open()))
    assert len(review) == 2 and review[0]["verdict"] == ""

    # Grades carry over while the answer is unchanged; a moved answer is listed for re-grading.
    grades = tmp_path / "grades.csv"
    with grades.open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(mod.GRADE_COLUMNS))
        w.writeheader()
        w.writerow({"id": "1", "answer": rows[0]["answer"], "top": rows[0]["topId"], "verdict": "correct"})
        w.writerow({"id": "2", "answer": "docs", "top": "kn:somewhere#0", "verdict": "wrong"})
        w.writerow({"id": "9", "answer": "none", "top": "", "verdict": "out-of-scope"})
    out2 = tmp_path / "out2"
    assert mod.main([str(path), "--out", str(out2), "--sample-review", "2", "--grades", str(grades)]) == 0
    graded = json.loads((out2 / "summary.json").read_text())["graded"]
    assert graded["unchanged"] == 1 and graded["notRun"] == 1 and graded["verdicts"]["correct"] == 1
    assert graded["helpfulWhenAnswered"] == 100.0
    assert [c["id"] for c in graded["changed"]] == ["2"] and graded["changed"][0]["was"] == "docs kn:somewhere#0"
    by_id = {r["id"]: r for r in csv.DictReader((out2 / "review.csv").open())}
    assert by_id["1"]["verdict"] == "correct" and by_id["2"]["verdict"] == ""
    assert by_id["2"]["previousVerdict"] == "wrong"
    results = {r["id"]: r for r in csv.DictReader((out2 / "results.csv").open())}
    assert results["1"]["verdict"] == "correct" and results["2"]["previousVerdict"] == "wrong"


@pytest.mark.parametrize(
    ("body", "message"),
    [
        ("id,answer,top\n1,none,\n", "missing column(s) verdict"),
        ("id,answer,top,verdict\n1,none,,great\n", "is not one of"),
        ("id,answer,top,verdict\n1,none,,wrong\n1,none,,wrong\n", "graded twice"),
        ("id,answer,top,verdict\n,none,,wrong\n", "empty id"),
        ("id,answer,top,verdict,note\n1,none,,wrong," + "x" * 301 + "\n", "note longer"),
    ],
)
def test_a_malformed_grades_file_stops_the_eval(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], body: str, message: str
) -> None:
    spec = importlib.util.spec_from_file_location("eval_questions_g", ROOT / "scripts" / "eval_questions.py")
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules["eval_questions_g"] = mod
    spec.loader.exec_module(mod)
    grades = tmp_path / "grades.csv"
    grades.write_text(body)
    (tmp_path / "q.csv").write_text("id,question,body_excerpt\n1,a,b\n")
    assert mod.main([str(tmp_path / "q.csv"), "--out", str(tmp_path / "o"), "--grades", str(grades)]) == 2
    assert message in capsys.readouterr().err
    assert not (tmp_path / "o").exists()  # nothing was scored against a bad file


def test_the_committed_grades_file_is_well_formed() -> None:
    spec = importlib.util.spec_from_file_location("eval_questions_c", ROOT / "scripts" / "eval_questions.py")
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules["eval_questions_c"] = mod
    spec.loader.exec_module(mod)
    path = ROOT / "docs" / "evals" / "community-questions-grades.csv"
    grades = mod.load_grades(path)
    assert len(grades) == 76
    header = path.read_text(encoding="utf-8").splitlines()[0]
    assert header == ",".join(mod.GRADE_COLUMNS)  # ids and verdicts only: no question text in the repo
