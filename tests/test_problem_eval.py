"""PB1: your own problems as a test (`kube-noob selftest --cases`): every file format, expectations of each kind,
unlabelled cases reported with what kube-noob said, the gate, the report files, and hostile input."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from kube_noob.cli import main
from kube_noob.config import load_settings
from kube_noob.evals import problems

QUESTION = "ImagePullBackOff when the pull secret sits in a different namespace from the pod"
EVENTS = (
    "Warning FailedToRetrieveImagePullSecret kubelet Unable to retrieve some image pull secrets (regcred); "
    "attempting to pull the image may not succeed.\nWarning Failed kubelet Error: ImagePullBackOff"
)
BAD_DEPLOY = """\
apiVersion: apps/v1
kind: Deployment
metadata: {name: web, namespace: shop}
spec:
  selector: {matchLabels: {app: web}}
  template:
    metadata: {labels: {app: web}}
    spec:
      containers: [{name: web, image: "nginx:latest", securityContext: {privileged: true}}]
"""
EVENTS_YAML = EVENTS.replace(chr(10), "\\n")
YAML_CASES = f"""\
cases:
  - id: linkedin-pull-secret
    source: launch post comment
    input: "{QUESTION}"
    expect: {{playbook: DBG-PULLSECRET, mention: [system:image-puller], notMention: ["-n from"]}}
  - id: events-pull-secret
    input: "{EVENTS_YAML}"
    expect: {{playbook: [DBG-PULLSECRET], mention: [regcred]}}
  - id: helm-lock
    input: "helm upgrade failed: another operation (install/upgrade/rollback) is in progress"
    expect: {{playbook: DBG-HELM-LOCK, docs: [helm-troubleshooting]}}
  - id: wrong-on-purpose
    input: "route returns 503 application is not available"
    expect: {{playbook: DBG-OOM}}
  - id: just-asking
    input: "etcd leader changed frequently, apiserver timeouts after upgrade"
"""


@pytest.fixture
def settings(tmp_path: Path):  # type: ignore[no-untyped-def]
    return load_settings(overrides={"dataDir": str(tmp_path / "data")})


def test_yaml_cases_pass_fail_and_unlabelled(settings) -> None:  # type: ignore[no-untyped-def]
    rep = problems.run_cases(settings, problems.parse(YAML_CASES, "p.yaml"))
    status = {r["id"]: r["status"] for r in rep["results"]}
    assert status == {
        "linkedin-pull-secret": "pass",
        "events-pull-secret": "pass",
        "helm-lock": "pass",
        "wrong-on-purpose": "fail",
        "just-asking": "unlabelled",
    }
    assert rep["labelled"] == 4 and rep["passed"] == 3 and rep["passRate"] == 0.75 and rep["unlabelled"] == 1
    wrong = next(r for r in rep["results"] if r["id"] == "wrong-on-purpose")
    assert wrong["misses"] == ["expected playbook DBG-OOM in the top 1, got DBG-ROUTE-503"]
    asking = next(r for r in rep["results"] if r["id"] == "just-asking")
    assert asking["said"]["diagnoses"][0]["id"] == "DBG-ETCD" and asking["said"]["issues"]
    md = problems.markdown(rep)
    assert "| Passed | 3 of 4 (75%) |" in md and "### wrong-on-purpose" in md and "### just-asking" in md
    assert "- miss: expected playbook DBG-OOM" in md and "linkedin-pull-secret" not in md  # passes are not listed


def test_audit_cases_check_rules_both_ways(settings) -> None:  # type: ignore[no-untyped-def]
    cases = [
        problems.Case(id="a1", input=BAD_DEPLOY, expect=problems.Expect(rules=["KN-S001"])),
        problems.Case(id="a2", input=BAD_DEPLOY, expect=problems.Expect(not_rules=["KN-S001"])),
        problems.Case(id="a3", input=BAD_DEPLOY, platform="openshift", expect=problems.Expect(rules=["KN-C013"])),
    ]
    rep = problems.run_cases(settings, cases)
    status = {r["id"]: (r["status"], r["misses"]) for r in rep["results"]}
    assert status["a1"] == ("pass", [])
    assert status["a2"] == ("fail", ["rules fired that should not: KN-S001"])
    assert status["a3"] == ("fail", ["rules did not fire: KN-C013"])
    assert rep["results"][0]["said"]["kinds"] == ["audit"]


@pytest.mark.parametrize(
    ("name", "text", "ids"),
    [
        ("q.txt", f"{QUESTION}\n# a comment line\nwhy is my pod Pending\n", ["P0001", "P0002"]),
        ("q.txt", f"{EVENTS}\n---\n{QUESTION}\n", ["P0001", "P0002"]),
        (
            "q.jsonl",
            json.dumps({"id": "j1", "input": QUESTION, "expect": {"playbook": "DBG-PULLSECRET"}}) + "\n\n",
            ["j1"],
        ),
        (
            "q.csv",
            "id,input,playbook,mention\nc1," + f'"{QUESTION}"' + ",DBG-PULLSECRET;DBG-IMAGEPULL,regcred;secret\n",
            ["c1"],
        ),
        ("q.yaml", f"- input: {QUESTION}\n- {{id: two, input: why is my pod Pending}}\n", ["P0001", "two"]),
    ],
)
def test_every_file_format(name: str, text: str, ids: list[str]) -> None:
    cases = problems.parse(text, name)
    assert [c.id for c in cases] == ids
    if name.endswith(".csv"):
        assert cases[0].expect.playbook == ["DBG-PULLSECRET", "DBG-IMAGEPULL"]
        assert cases[0].expect.mention == ["regcred", "secret"]
    if "---" in text:
        assert cases[0].input == EVENTS


@pytest.mark.parametrize(
    ("name", "text", "error"),
    [
        ("p.yaml", "cases: []", "holds no cases"),
        ("p.yaml", "cases: [1, 2]", "case 1: expected a mapping"),
        ("p.yaml", "- {id: x, input: abc}\n- {id: x, input: def}", "unique"),
        ("p.yaml", "- {input: abc, expect: {rules: [S001]}}", "not rule ids"),
        ("p.yaml", "- {input: abc, expect: {playbok: DBG-OOM}}", "playbok"),
        ("p.yaml", "- {input: abc, platform: windows}", "platform"),
        ("p.yaml", "- {id: 'bad id; rm', input: abc}", "case bad id; rm: id"),
        ("p.yaml", "- {input: 'a'}", "input"),
        ("p.jsonl", '{"input": "abc"}\n[1]\n', "expected a mapping"),
    ],
)
def test_bad_files_are_refused_with_the_case_named(name: str, text: str, error: str) -> None:
    with pytest.raises(ValueError, match="(?s).*" + __import__("re").escape(error)):
        problems.parse(text, name)


def test_limits() -> None:
    many = "\n".join(f"question number {i}" for i in range(problems.MAX_CASES + 1))
    with pytest.raises(ValueError, match="at most 2000"):
        problems.parse(many, "q.txt")
    with pytest.raises(ValueError, match="larger than"):
        problems.parse("x" * (problems.MAX_FILE + 1), "q.txt")


def test_cli_scorecard_gate_and_report_files(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    f = tmp_path / "problems.yaml"
    f.write_text(YAML_CASES, encoding="utf-8")
    out = tmp_path / "report"
    assert main(["selftest", "--cases", str(f), "--out", str(out)]) == 1  # one case fails
    text = capsys.readouterr().out
    assert "# kube-noob problem eval" in text and (out / "report.md").read_text() == text
    assert json.loads((out / "report.json").read_text())["passRate"] == 0.75
    assert main(["selftest", "--cases", str(f), "--gate", "0.7"]) == 0
    capsys.readouterr()
    assert main(["selftest", "--cases", str(f), "--gate", "0.8", "--format", "json"]) == 1
    assert json.loads(capsys.readouterr().out)["gate"] == {"threshold": 0.8, "passed": False}
    assert main(["selftest", "--cases", str(f), "--gate", "8"]) == 2
    assert main(["selftest", "--cases", str(tmp_path / "missing.yaml")]) == 2
    raw = tmp_path / "raw.txt"
    raw.write_text(QUESTION + "\n", encoding="utf-8")
    assert main(["selftest", "--cases", str(raw)]) == 0  # unlabelled only: answered, nothing failed
    assert "DBG-PULLSECRET" in capsys.readouterr().out


def test_the_eval_never_reaches_the_network_or_a_cluster(tmp_path: Path) -> None:
    s = load_settings(overrides={"dataDir": str(tmp_path), "webEnabled": True, "cluster": {"enabled": True}})
    rep = problems.run_cases(s, problems.parse(QUESTION, "q.txt"))
    assert rep["results"][0]["status"] == "unlabelled"
    assert rep["results"][0]["said"]["kinds"] == ["diagnose", "known-issues", "search"]


def test_the_shipped_example_passes(settings) -> None:  # type: ignore[no-untyped-def]
    rep = problems.run_cases(
        settings, problems.load(Path(__file__).resolve().parents[1] / "examples" / "problems.yaml")
    )
    assert rep["labelled"] == 4 and rep["passed"] == 4 and rep["unlabelled"] == 1
