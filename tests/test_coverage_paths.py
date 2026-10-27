"""Exercise the remaining public surfaces: toolkit, CLI subcommands, history, judge/runner, providers, in-cluster."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import httpx
import pytest

from kube_noob import toolkit as tk
from kube_noob.agent import providers
from kube_noob.cli import main
from kube_noob.config import load_settings
from kube_noob.debug import cluster
from kube_noob.evals import runner
from kube_noob.evals.judge import LLMJudge, NoJudge, build_judge
from kube_noob.sources.history import minor_timeline, timeline_record
from tests.conftest import FIXTURES

BAD = (FIXTURES / "bad-bundle.yaml").read_text()


def test_toolkit_all_offline_tools(tmp_path: Path) -> None:
    kit = tk.Toolkit(load_settings())
    assert kit.validate(tk.ManifestsIn(manifests=BAD))["summary"]["counts"]["critical"] >= 1
    assert kit.red_team(tk.ManifestsIn(manifests=BAD))["scenarios"]
    fixed = kit.fix(tk.FixIn(manifests=BAD, platform="openshift", version="4.22"))
    assert fixed["changes"] and "route.openshift.io/v1" in fixed["manifests"]
    assert kit.clarify(tk.ClarifyIn(blueprint={"name": "BAD NAME"}))["ready"] is False
    ok = kit.clarify(tk.ClarifyIn(blueprint={"name": "a", "namespace": "b", "image": "c:1"}))
    assert ok["ready"] and ok["assumptions"]
    bp = tk.BlueprintIn.model_validate(
        {
            "blueprint": {
                "name": "a",
                "namespace": "b",
                "image": "c:1",
                "platform": "kubernetes",
                "exposure": {"type": "route"},
            }
        }
    )
    assert kit.generate(bp)["status"] == "needs-clarification"
    assert kit.helm_chart(bp)["status"] == "needs-clarification"
    good = tk.BlueprintIn.model_validate({"blueprint": {"name": "a", "namespace": "b", "image": "c:1.0"}})
    chart = kit.helm_chart(good)
    assert chart["status"] == "ok" and "Chart.yaml" in chart["files"]
    assert kit.get_chunk(tk.ChunkIn(id="kn:ocp-scc#0"))["text"]
    assert kit.get_chunk(tk.ChunkIn(id="ocp-scc"))["chunks"]
    with pytest.raises(KeyError):
        kit.get_chunk(tk.ChunkIn(id="kn:nope#0"))
    with pytest.raises(KeyError):
        kit.get_chunk(tk.ChunkIn(id="nope"))
    hist = kit.api_history(tk.ApiHistoryIn(kind="PodDisruptionBudget", platform="openshift", version="4.12"))
    assert hist["kubernetesVersion"] == "1.25" and hist["removedInTarget"]
    assert kit.explain(tk.RuleIn(rule_id="KN-S001"))["stackroxPolicies"] == ["Privileged Container"]
    assert len(kit.rules(tk.EmptyIn())["rules"]) >= 45
    assert kit.tracks(tk.LearnerIn(learner="t"))["tracks"]
    assert kit.lesson(tk.LessonIn(lesson_id="k8s-104-storage"))["content"]
    assert kit.exercise(tk.ExerciseIn(exercise_id="k8s-ex-migrate-removed-apis"))["starter"]
    assert kit.quiz(tk.QuizIn(question_id="k8s-q-exit137"))["choices"]
    assert kit.quiz(tk.QuizIn(question_id="k8s-q-exit137", choice=0))["correct"] is False
    assert kit.progress(tk.LearnerIn(learner="t"))["credits"] == 0
    g = kit.grade(tk.GradeIn(completion="helm history then rollback the pending release", task_id="bench-qa-helm-lock"))
    assert g["components"]["task"] == 1.0
    inline = kit.grade(tk.GradeIn(completion="x", task={"id": "t", "type": "qa", "mustMention": ["x"]}))
    assert inline["components"]["task"] == 1.0
    with pytest.raises(ValueError):
        kit.grade(tk.GradeIn(completion="x"))
    assert kit.config_status(tk.EmptyIn())["config"]["webEnabled"] is False


def test_toolkit_web_fetch_strips_html(monkeypatch: pytest.MonkeyPatch) -> None:
    s = load_settings(overrides={"webEnabled": True})
    kit = tk.Toolkit(s)
    real = tk.http_client

    def fake(settings: Any, purpose: Any, **kw: Any) -> httpx.Client:
        def handler(req: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200,
                headers={"content-type": "text/html"},
                text="<html><script>evil()</script><p>Hello &amp; welcome</p></html>",
            )

        return real(settings, purpose, transport=httpx.MockTransport(handler))

    monkeypatch.setattr(tk, "http_client", fake)
    out = kit.web_fetch(tk.WebFetchIn(url="https://kubernetes.io/docs/"))
    assert "Hello & welcome" in out["text"] and "evil" not in out["text"]


def test_cli_misc_commands(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    bad = tmp_path / "bad.yaml"
    bad.write_text(BAD)
    for argv in (
        ["search", "restricted-v2", "--format", "json"],
        ["rules"],
        ["explain", "KN-V002"],
        ["learn", "tracks"],
        ["learn", "lesson", "k8s-101-objects"],
        ["learn", "exercise", "rosa-ex-rwx"],
        ["learn", "quiz", "rosa-q-cp"],
        ["learn", "quiz", "rosa-q-cp", "--choice", "1"],
        ["train", "tasks"],
        ["config"],
        ["corpus", "stats"],
        ["corpus", "verify"],
        ["redteam", "-f", str(bad)],
        ["validate", "-f", str(bad), "--format", "json"],
    ):
        rc = main(argv)
        assert rc in (0, 1), argv
    capsys.readouterr()
    assert main(["protocol", "Review for OpenShift 4.22", "-f", str(bad)]) in (0, 1)
    out = capsys.readouterr().out
    assert "## Audit & Validation Brief" in out and "## Red Team Findings & Safeguards" in out
    bp = tmp_path / "bp.yaml"
    bp.write_text(
        "name: api\nnamespace: shop\nimage: quay.io/a/api:1.0.0\nplatform: rosa-hcp\nexposure: {type: route}\n"
    )
    assert main(["protocol", "build it", "--blueprint", str(bp), "--format", "json"]) == 0
    assert json.loads(capsys.readouterr().out)["status"] == "ready"
    assert main(["helm-chart", "--blueprint", str(bp), "-o", str(tmp_path / "charts")]) == 0
    assert (tmp_path / "charts" / "api" / "Chart.yaml").is_file()
    comp = tmp_path / "c.txt"
    comp.write_text("helm history shows pending-upgrade; rollback to the previous revision")
    assert main(["train", "grade", "--task", "bench-qa-helm-lock", "-f", str(comp)]) == 0
    assert main(["train", "export", "--out", str(tmp_path / "ds"), "--synthetic-limit", "2"]) == 0
    assert (tmp_path / "ds" / "sft.jsonl").stat().st_size > 0
    assert main(["explain", "KN-NOPE1"]) == 4  # rejected by the RuleIn pattern
    import shutil

    expected = {0, 1} if shutil.which("helm") else {4}  # rendering needs the helm binary (present in CI)
    assert main(["helm-audit", str(tmp_path / "charts" / "api")]) in expected


def test_history_timeline() -> None:
    tags = [
        ("v4.0.0", "2025-11-12"),
        ("v4.0.1", "2025-12-01"),
        ("v3.19.0", "2025-09-11"),
        ("v4.1.0-rc.1", "2026-01-01"),
        ("v4.1.0", "2026-01-21"),
    ]
    tl = minor_timeline(tags)
    assert [t["minor"] for t in tl] == ["3.19", "4.0", "4.1"]
    assert tl[1]["ga"] == "2025-11-12" and tl[1]["latestTag"] == "v4.0.1"
    rec = timeline_record("helm", "helm/helm", tl)
    assert "| 4.0 | v4.0.0 | 2025-11-12 | v4.0.1 | 2025-12-01 |" in rec["text"] and rec["redistributable"]


class FakeProvider:
    name = "fake"
    model = "fake-1"

    def turn(self, system: str, messages: list[dict[str, Any]], tools: list[dict[str, Any]]) -> providers.Turn:
        return providers.Turn(
            "helm history, then rollback the pending release [kn:helm-troubleshooting#0]",
            [],
            "end_turn",
            self.model,
            {"role": "assistant", "content": "x"},
        )

    def tool_results_message(self, results: Any) -> list[dict[str, Any]]:
        return []

    def user_message(self, text: str) -> dict[str, Any]:
        return {"role": "user", "content": text}

    def complete_text(self, prompt: str, max_tokens: int = 1024) -> str:
        return 'Sure: {"score": 0.8, "rationale": "fine"}'


def test_runner_and_judges(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        runner,
        "Agent",
        lambda s: __import__("kube_noob.agent.loop", fromlist=["Agent"]).Agent(s, provider=FakeProvider()),
    )
    rep = runner.run_benchmark(load_settings(), ["bench-qa-helm-lock"])
    assert rep["tasks"] == 1 and rep["passRate"] == 1.0
    assert isinstance(build_judge(load_settings()), NoJudge)
    monkeypatch.setattr(providers, "build_provider", lambda llm, s: FakeProvider())
    judge = LLMJudge(load_settings(overrides={"judge": {"provider": "openai-compatible"}}))
    assert judge.judge({"prompt": "p"}, "a", {"components": {}}) == {
        "score": 0.8,
        "rationale": "fine",
        "labelSource": "llm-judge",
        "judge": judge.name,
    }


def test_openai_compatible_provider(monkeypatch: pytest.MonkeyPatch) -> None:
    s = load_settings(
        overrides={"llm": {"provider": "openai-compatible", "baseUrl": "http://llm.local/v1", "model": "kube-noob-sft"}}
    )
    seen: list[dict[str, Any]] = []

    def handler(req: httpx.Request) -> httpx.Response:
        body = json.loads(req.content)
        seen.append(body)
        return httpx.Response(
            200,
            json={
                "model": "kube-noob-sft",
                "choices": [
                    {
                        "finish_reason": "tool_calls",
                        "message": {
                            "content": None,
                            "tool_calls": [
                                {
                                    "id": "c1",
                                    "type": "function",
                                    "function": {"name": "diagnose", "arguments": '{"text": "OOMKilled"}'},
                                }
                            ],
                        },
                    }
                ],
            },
        )

    real = providers.http_client
    monkeypatch.setattr(
        providers,
        "http_client",
        lambda settings, purpose, **kw: real(
            settings,
            purpose,
            timeout=kw.get("timeout"),
            extra_headers=kw.get("extra_headers"),
            transport=httpx.MockTransport(handler),
        ),
    )
    p = providers.build_provider(s.llm, s)
    turn = p.turn("sys", [p.user_message("hi")], [{"name": "diagnose", "description": "d", "input_schema": {}}])
    assert turn.tool_calls[0].name == "diagnose" and turn.tool_calls[0].arguments == {"text": "OOMKilled"}
    assert seen[0]["messages"][0] == {"role": "system", "content": "sys"}
    assert p.tool_results_message([(turn.tool_calls[0], "out", False)])[0]["role"] == "tool"
    with pytest.raises(Exception, match="baseUrl"):
        providers.build_provider(load_settings(overrides={"llm": {"provider": "openai-compatible"}}).llm, s)
    with pytest.raises(Exception, match="none"):
        providers.build_provider(load_settings(overrides={"llm": {"provider": "none"}}).llm, s)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    with pytest.raises(Exception, match="ANTHROPIC_API_KEY"):
        providers.build_provider(load_settings().llm, s)


def test_in_cluster_backend(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    sa = tmp_path / "sa"
    sa.mkdir()
    (sa / "token").write_text("tkn")
    (sa / "ca.crt").write_text("ca")
    monkeypatch.setattr(cluster, "SA_DIR", sa)
    monkeypatch.setenv("KUBERNETES_SERVICE_HOST", "10.0.0.1")
    paths: list[str] = []

    def handler(req: httpx.Request) -> httpx.Response:
        paths.append(f"{req.url.path}?{req.url.query.decode()}")
        assert req.headers["Authorization"] == "Bearer tkn"
        if req.url.path.endswith("/log"):
            return httpx.Response(200, text="token=abc123 boom")
        if "forbidden" in req.url.path:
            return httpx.Response(403, text="no")
        return httpx.Response(
            200, json={"kind": "ConfigMap", "data": {"k": "secret-ish"}, "metadata": {"managedFields": [1]}}
        )

    monkeypatch.setattr(
        cluster,
        "cluster_client",
        lambda base, token, ca, timeout: httpx.Client(
            base_url=base, transport=httpx.MockTransport(handler), headers={"Authorization": f"Bearer {token}"}
        ),
    )
    s = load_settings(overrides={"cluster": {"enabled": True}})
    b = cluster.get_backend(s)
    assert b.name == "in-cluster"
    cm = b.get("cm", name="app", namespace="ns")
    assert cm["data"]["k"].startswith("<redacted") and "managedFields" not in cm["metadata"]
    assert b.get("routes", namespace="ns", selector="app=x")
    assert "abc123" not in b.logs("ns", "pod-1", "c", 10, previous=True)
    assert paths[0] == "/api/v1/namespaces/ns/configmaps/app?"
    assert paths[1].startswith("/apis/route.openshift.io/v1/namespaces/ns/routes?labelSelector=app")
    with pytest.raises(cluster.ClusterAccessError, match="Forbidden"):
        b.get("pods", name="forbidden", namespace="ns")
