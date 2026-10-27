from __future__ import annotations

from pathlib import Path

import httpx
import pytest

from kube_noob.config import load_settings
from kube_noob.errors import ConfigError, DomainNotAllowedError, WebDisabledError
from kube_noob.net import Purpose, host_allowed, http_client


def test_defaults_are_offline() -> None:
    s = load_settings()
    assert s.web_enabled is False and s.cluster.enabled is False and s.llm.model == "claude-fable-5-1"


def test_config_file_and_env_precedence(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    cfg = tmp_path / "kube-noob.yaml"
    cfg.write_text("webEnabled: True\ncluster: {enabled: true, backend: oc}\nllm: {model: claude-opus-5-5}\n")
    s = load_settings(cfg)
    assert s.web_enabled and s.cluster.backend == "oc" and s.llm.model == "claude-opus-5-5"
    monkeypatch.setenv("KUBE_NOOB_WEB_ENABLED", "false")
    assert load_settings(cfg).web_enabled is False
    monkeypatch.setenv("KUBE_NOOB_WEB_ENABLED", "maybe")
    with pytest.raises(ConfigError):
        load_settings(cfg)


def test_config_rejects_unknown_keys(tmp_path: Path) -> None:
    cfg = tmp_path / "c.yaml"
    cfg.write_text("webEnable: true\n")
    with pytest.raises(ConfigError):
        load_settings(cfg)
    with pytest.raises(ConfigError):
        load_settings(tmp_path / "missing.yaml")


def test_web_blocked_when_disabled() -> None:
    with pytest.raises(WebDisabledError):
        http_client(load_settings(), Purpose.WEB)
    with pytest.raises(WebDisabledError):
        http_client(load_settings(), Purpose.SOURCES)
    http_client(load_settings(), Purpose.SOURCES, allow_sources=True).close()


def test_domain_allowlist_applies_to_redirects() -> None:
    s = load_settings(overrides={"webEnabled": True, "web": {"allowedDomains": ["kubernetes.io"]}})

    def handler(req: httpx.Request) -> httpx.Response:
        if req.url.host == "kubernetes.io":
            return httpx.Response(302, headers={"Location": "https://evil.example.com/x"})
        return httpx.Response(200, text="pwned")

    client = http_client(s, Purpose.WEB, transport=httpx.MockTransport(handler))
    with pytest.raises(DomainNotAllowedError):
        client.get("https://kubernetes.io/docs/")
    with pytest.raises(DomainNotAllowedError):
        client.get("http://kubernetes.io/docs/")
    assert host_allowed("docs.kubernetes.io", ["kubernetes.io"])
    assert not host_allowed("kubernetes.io.evil.com", ["kubernetes.io"])
