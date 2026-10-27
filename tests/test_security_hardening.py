"""Regression tests for the security/runtime findings of the red-team review."""

from __future__ import annotations

import hashlib
import json
import os
import random
from pathlib import Path
from typing import Any

import httpx
import pytest

from kube_noob import toolkit as tk
from kube_noob.config import load_settings
from kube_noob.debug import cluster
from kube_noob.errors import ConfigError, ManifestError
from kube_noob.sources.corpus import import_corpus
from kube_noob.sources.jira import MAX_RETRY_AFTER, JiraClient, JiraError
from kube_noob.yamlio import load_documents

ROOT = Path(__file__).resolve().parents[1]


def test_config_in_working_directory_is_not_trusted(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    (tmp_path / "kube-noob.yaml").write_text(
        "webEnabled: true\ncluster: {enabled: true}\nllm: {baseUrl: 'https://attacker.example/v1'}\n"
    )
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("KUBE_NOOB_CONFIG", raising=False)
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "xdg"))
    s = load_settings()
    assert not s.web_enabled and not s.cluster.enabled and s.llm.base_url is None and s.source_path is None
    explicit = load_settings(tmp_path / "kube-noob.yaml")  # explicit --config still works
    assert explicit.web_enabled


@pytest.mark.parametrize(
    "override",
    [
        {"llm": {"apiKeyEnv": "AWS_SECRET_ACCESS_KEY"}},
        {"llm": {"apiKeyEnv": "GITHUB_TOKEN"}},
        {"judge": {"apiKeyEnv": "HOME"}},
        {"llm": {"baseUrl": "http://attacker.example/v1"}},
        {"llm": {"baseUrl": "https://user:pw@llm.example/v1"}},
        {"llm": {"baseUrl": "file:///etc/passwd"}},
        {"web": {"allowedDomains": ["*"]}},
    ],
)
def test_unsafe_llm_and_web_settings_are_rejected(override: dict[str, Any]) -> None:
    with pytest.raises(ConfigError):
        load_settings(overrides=override)


def test_safe_llm_endpoints_are_accepted() -> None:
    assert load_settings(overrides={"llm": {"baseUrl": "http://vllm.ai.svc:8000/v1", "apiKeyEnv": "VLLM_API_KEY"}})
    assert load_settings(overrides={"llm": {"baseUrl": "http://127.0.0.1:11434/v1"}})
    assert load_settings(overrides={"llm": {"baseUrl": "http://10.0.0.5:8000/v1", "allowInsecureBaseUrl": True}})
    assert load_settings(overrides={"web": {"allowedDomains": ["*.example.com"]}}).web.allowed_domains == [
        "example.com"
    ]


def test_cluster_redaction_covers_values_args_and_list_wrappers() -> None:
    pods = {
        "kind": "List",
        "items": [
            {
                "metadata": {
                    "name": "a",
                    "annotations": {"vault.hashicorp.com/token": "hvs.CAESIJabcdefghijklmnopqrstuv"},
                },
                "spec": {
                    "containers": [
                        {
                            "name": "c",
                            "args": ["--db-password=hunter2", "--token", "abc123"],
                            "env": [{"name": "DATABASE_URL", "value": "postgres://app:hunter2@db/app"}],
                        }
                    ]
                },
            }
        ],
    }
    out = json.dumps(cluster._redact_obj(pods, cluster._list_hint(pods, "pods")))
    assert "hunter2" not in out and "abc123" not in out and "hvs.CAES" not in out
    cms = {"kind": "List", "items": [{"metadata": {"name": "x"}, "data": {"pw": "hunter2"}}]}
    assert "hunter2" not in json.dumps(cluster._redact_obj(cms, cluster._list_hint(cms, "configmaps")))


def test_yaml_depth_and_duplicate_keys() -> None:
    with pytest.raises(ManifestError, match="too deep"):
        load_documents("a: " + "[" * 600 + "]" * 600 + "\n")
    docs = load_documents("kind: Pod\nmetadata: {name: a}\nspec: {x: 1}\nspec: {y: 2}\n")
    assert docs[0].duplicate_keys == [(("spec",), 4)]


def test_web_fetch_stops_at_max_bytes(monkeypatch: pytest.MonkeyPatch) -> None:
    s = load_settings(overrides={"webEnabled": True, "web": {"maxBytes": 1000}})
    kit = tk.Toolkit(s)
    real = tk.http_client
    served = {"bytes": 0}

    def stream() -> Any:
        for _ in range(10_000):  # ~10 MB if fully read
            served["bytes"] += 1024
            yield b"a" * 1024

    def fake(settings: Any, purpose: Any, **kw: Any) -> httpx.Client:
        def handler(req: httpx.Request) -> httpx.Response:
            return httpx.Response(200, headers={"content-type": "text/plain"}, content=stream())

        return real(settings, purpose, transport=httpx.MockTransport(handler))

    monkeypatch.setattr(tk, "http_client", fake)
    out = kit.web_fetch(tk.WebFetchIn(url="https://kubernetes.io/big"))
    assert out["truncated"] is True and len(out["text"]) <= 1000 and served["bytes"] < 100_000


def test_jira_retry_after_is_capped_and_auth_requires_https() -> None:
    sleeps: list[float] = []
    state = {"n": 0}

    def handler(req: httpx.Request) -> httpx.Response:
        state["n"] += 1
        if state["n"] == 1:
            return httpx.Response(429, headers={"Retry-After": "86400"})
        assert req.headers["Authorization"].startswith("Basic ")
        return httpx.Response(200, json=[])

    client = JiraClient(
        httpx.Client(transport=httpx.MockTransport(handler)),
        "https://jira.example",
        sleep=sleeps.append,
        rng=random.Random(0),
        auth=("me@example.com", "tok"),
    )
    assert client.versions("ROX") == []
    assert sleeps and max(sleeps) <= MAX_RETRY_AFTER
    with pytest.raises(JiraError, match="https"):
        JiraClient(httpx.Client(), "http://jira.example", auth=("a", "b"))


def test_corpus_import_rejects_malformed_records(tmp_path: Path) -> None:
    src = tmp_path / "src"
    src.mkdir()
    shard = src / "bad.jsonl"
    shard.write_text(json.dumps({"title": "no id", "text": "x"}) + "\n")
    digest = hashlib.sha256(shard.read_bytes()).hexdigest()
    (src / "MANIFEST.json").write_text(json.dumps({"shards": {"bad": {"file": "bad.jsonl", "sha256": digest}}}))
    with pytest.raises(ValueError, match="missing"):
        import_corpus(src, tmp_path / "dest")


def test_chart_and_image_do_not_pin_web_enabled() -> None:
    containerfile = (ROOT / "Containerfile").read_text()
    assert "KUBE_NOOB_WEB_ENABLED=" not in containerfile
    deployment = (ROOT / "deploy/helm/kube-noob/templates/deployment.yaml").read_text()
    assert "KUBE_NOOB_WEB_ENABLED" in deployment and ".Values.config.webEnabled | quote" in deployment
    netpol = (ROOT / "deploy/helm/kube-noob/templates/networkpolicy.yaml").read_text()
    assert "fail" in netpol and "at least one allowed source" in netpol
    assert os.path.exists(ROOT / "deploy/helm/kube-noob/values.yaml")
