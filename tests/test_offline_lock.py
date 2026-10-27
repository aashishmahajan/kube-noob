"""Admin offline lock: nothing leaves the network or cluster, whatever else is configured."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import httpx
import pytest

from kube_noob import toolkit as tk
from kube_noob.agent.providers import build_provider
from kube_noob.cli import main
from kube_noob.config import load_settings
from kube_noob.errors import ProviderError, WebContentRejectedError, WebDisabledError
from kube_noob.net import Purpose, http_client

_REAL_HTTP_CLIENT = tk.http_client


def test_lock_beats_web_enabled_everywhere(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("KUBE_NOOB_OFFLINE", "1")
    s = load_settings(overrides={"webEnabled": True})
    assert s.offline and not s.web_enabled and s.web_locked
    assert "web_fetch" not in [spec.name for spec in tk.Toolkit(s).specs()]
    for purpose, kw in ((Purpose.WEB, {}), (Purpose.SOURCES, {"allow_sources": True})):
        with pytest.raises(WebDisabledError, match="offline"):
            http_client(s, purpose, **kw)
    assert main(["corpus", "build", "--online", "--sources", "helm-docs"]) != 0


def test_lock_allows_only_local_models(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("KUBE_NOOB_OFFLINE", "1")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "x")
    s = load_settings(overrides={"llm": {"provider": "anthropic"}})
    with pytest.raises(ProviderError, match="offline"):
        build_provider(s.llm, s)
    local = load_settings(overrides={"llm": {"provider": "openai-compatible", "baseUrl": "http://127.0.0.1:8000/v1"}})
    assert build_provider(local.llm, local).name == "openai-compatible"
    remote = load_settings(
        overrides={"llm": {"provider": "openai-compatible", "baseUrl": "https://api.example.com/v1"}}
    )
    with pytest.raises(ProviderError, match="offline"):
        build_provider(remote.llm, remote)


def test_lock_only_tightens(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    from kube_noob import config

    user = tmp_path / "user.yaml"
    user.write_text("offline: true\n")
    monkeypatch.setenv("KUBE_NOOB_OFFLINE", "0")
    assert load_settings(user, overrides={"offline": False}).offline
    system = tmp_path / "system.yaml"
    system.write_text("offline: true\n")
    monkeypatch.setattr(config, "SYSTEM_CONFIG", system)
    other = tmp_path / "other.yaml"
    other.write_text("webEnabled: true\n")
    s = load_settings(other)
    assert s.offline and not s.web_enabled


def _fetch(
    monkeypatch: pytest.MonkeyPatch,
    content_type: str,
    body: bytes,
    method_check: list[str],
    extra: dict[str, str] | None = None,
    max_bytes: int = 2_000_000,
) -> Any:
    s = load_settings(overrides={"webEnabled": True, "web": {"maxBytes": max_bytes}})
    kit = tk.Toolkit(s)
    real = _REAL_HTTP_CLIENT

    def fake(settings: Any, purpose: Any, **kw: Any) -> httpx.Client:
        def handler(req: httpx.Request) -> httpx.Response:
            method_check.append(req.method)
            chunks = [body[i : i + 65536] for i in range(0, len(body), 65536)] or [b""]
            return httpx.Response(200, headers={"content-type": content_type, **(extra or {})}, content=iter(chunks))

        return real(settings, purpose, transport=httpx.MockTransport(handler))

    monkeypatch.setattr(tk, "http_client", fake)
    return kit.web_fetch(tk.WebFetchIn(url="https://kubernetes.io/docs/x"))


def test_web_reads_text_only_and_only_with_get(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    methods: list[str] = []
    assert _fetch(monkeypatch, "text/markdown; charset=utf-8", b"# hi", methods)["text"] == "# hi"
    for ctype in ("application/octet-stream", "application/zip", "application/x-sh", "image/png", ""):
        with pytest.raises(WebContentRejectedError):
            _fetch(monkeypatch, ctype, b"PK\x03\x04", methods)
    assert set(methods) == {"GET"}
    s = load_settings(overrides={"webEnabled": True})
    transport = httpx.MockTransport(lambda r: httpx.Response(200))
    with http_client(s, Purpose.WEB, transport=transport) as c, pytest.raises(WebDisabledError, match="GET"):
        c.post("https://kubernetes.io/x", content=b"{}")


def test_doctor_reports_posture_and_flags_conflicts(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    assert main(["doctor", "--format", "json"]) == 0
    posture = json.loads(capsys.readouterr().out)
    assert posture["network"]["web"] == "off" and posture["cluster"]["enabled"] is False
    monkeypatch.setenv("KUBE_NOOB_OFFLINE", "1")
    monkeypatch.setenv("KUBE_NOOB_WEB_ENABLED", "true")
    assert main(["doctor", "--format", "json"]) == 1
    locked = json.loads(capsys.readouterr().out)
    assert locked["offlineLock"] is True and locked["conflicts"]


def test_web_fetch_bounds_compressed_bodies_and_odd_charsets(monkeypatch: pytest.MonkeyPatch) -> None:
    import gzip

    methods: list[str] = []
    bomb = gzip.compress(b"a" * 50_000_000)
    out = _fetch(monkeypatch, "text/plain", bomb, methods, {"content-encoding": "gzip"}, max_bytes=10_000)
    assert out["truncated"] is True and len(out["text"]) <= 10_000
    with pytest.raises(WebContentRejectedError, match="encoding"):
        _fetch(monkeypatch, "text/plain", b"x", methods, {"content-encoding": "br"})
    for charset in ("hex", "base64", "rot13", "zlib", "no-such-codec"):
        assert _fetch(monkeypatch, f"text/plain; charset={charset}", b"plain", methods)["text"] == "plain"
