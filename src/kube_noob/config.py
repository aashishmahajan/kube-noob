"""Configuration.

Precedence (lowest -> highest): built-in defaults < config file < environment variables < explicit
overrides passed by the CLI.

Config file lookup order: ``$KUBE_NOOB_CONFIG``, ``./kube-noob.yaml``, ``$XDG_CONFIG_HOME/kube-noob/config.yaml``
(``~/.config/kube-noob/config.yaml``), ``/etc/kube-noob/config.yaml`` (the path the Helm chart mounts).

Keys are camelCase in YAML (``webEnabled: true``) and snake_case in Python.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator
from pydantic.alias_generators import to_camel

from kube_noob.errors import ConfigError

DEFAULT_ALLOWED_DOMAINS: tuple[str, ...] = (
    "kubernetes.io",
    "helm.sh",
    "docs.redhat.com",
    "docs.openshift.com",
    "access.redhat.com",
    "cloud.redhat.com",
    "developers.redhat.com",
    "redhat.atlassian.net",
    "docs.aws.amazon.com",
    "github.com",
    "raw.githubusercontent.com",
    "stackrox.io",
    "www.stackrox.io",
    "gateway-api.sigs.k8s.io",
    "kind.sigs.k8s.io",
)

DEFAULT_MODEL = "claude-fable-5-1"


class _Base(BaseModel):
    model_config = ConfigDict(alias_generator=to_camel, populate_by_name=True, extra="forbid")


class WebSettings(_Base):
    allowed_domains: list[str] = Field(default_factory=lambda: list(DEFAULT_ALLOWED_DOMAINS))
    timeout_seconds: float = Field(default=20.0, gt=0, le=120)
    max_bytes: int = Field(default=2_000_000, gt=0, le=20_000_000)

    @field_validator("allowed_domains")
    @classmethod
    def _lower(cls, v: list[str]) -> list[str]:
        cleaned = [d.strip().lower().lstrip(".") for d in v if d.strip()]
        for d in cleaned:
            if "/" in d or ":" in d or " " in d:
                raise ValueError(f"allowedDomains entries must be bare host names, got {d!r}")
        return cleaned


class ClusterSettings(_Base):
    enabled: bool = False
    backend: Literal["auto", "in-cluster", "kubectl", "oc"] = "auto"
    context: str | None = None
    timeout_seconds: float = Field(default=20.0, gt=0, le=120)
    max_log_lines: int = Field(default=200, ge=1, le=5000)


class LLMSettings(_Base):
    provider: Literal["anthropic", "openai-compatible", "none"] = "anthropic"
    model: str = DEFAULT_MODEL
    base_url: str | None = None
    api_key_env: str = "ANTHROPIC_API_KEY"
    max_tokens: int = Field(default=4096, ge=256, le=64000)
    max_tool_rounds: int = Field(default=12, ge=1, le=50)
    timeout_seconds: float = Field(default=120.0, gt=0, le=900)


class JudgeSettings(_Base):
    """Optional LLM judge. Eval-only: judge outputs are never exported as training labels by default."""

    provider: Literal["none", "anthropic", "openai-compatible"] = "none"
    model: str = DEFAULT_MODEL
    base_url: str | None = None
    api_key_env: str = "ANTHROPIC_API_KEY"


class ServerSettings(_Base):
    host: str = "127.0.0.1"
    port: int = Field(default=8080, ge=1, le=65535)
    path: str = "/mcp"
    auth_token_env: str = "KUBE_NOOB_HTTP_TOKEN"  # noqa: S105 - env var *name*, not a secret
    allowed_hosts: list[str] = Field(default_factory=list)
    allowed_origins: list[str] = Field(default_factory=list)


def _default_data_dir() -> Path:
    env = os.environ.get("KUBE_NOOB_DATA_DIR")
    if env:
        return Path(env)
    xdg = os.environ.get("XDG_DATA_HOME")
    base = Path(xdg) if xdg else Path.home() / ".local" / "share"
    return base / "kube-noob"


class Settings(_Base):
    web_enabled: bool = False
    web: WebSettings = Field(default_factory=WebSettings)
    cluster: ClusterSettings = Field(default_factory=ClusterSettings)
    llm: LLMSettings = Field(default_factory=LLMSettings)
    judge: JudgeSettings = Field(default_factory=JudgeSettings)
    server: ServerSettings = Field(default_factory=ServerSettings)
    data_dir: Path = Field(default_factory=_default_data_dir)
    default_platform: Literal["kubernetes", "openshift", "rosa-classic", "rosa-hcp"] = "kubernetes"
    source_path: Path | None = Field(default=None, exclude=True)

    def public_view(self) -> dict[str, Any]:
        """Config safe to display (no secrets are ever stored in Settings, only env var names)."""
        out = self.model_dump(by_alias=True, mode="json")
        out["configFile"] = str(self.source_path) if self.source_path else None
        return out


def _candidate_files() -> list[Path]:
    env = os.environ.get("KUBE_NOOB_CONFIG")
    if env:
        return [Path(env)]
    xdg = os.environ.get("XDG_CONFIG_HOME")
    cfg_home = Path(xdg) if xdg else Path.home() / ".config"
    return [Path.cwd() / "kube-noob.yaml", cfg_home / "kube-noob" / "config.yaml", Path("/etc/kube-noob/config.yaml")]


_TRUE = {"1", "true", "yes", "on"}
_FALSE = {"0", "false", "no", "off"}


def _env_bool(name: str) -> bool | None:
    raw = os.environ.get(name)
    if raw is None:
        return None
    v = raw.strip().lower()
    if v in _TRUE:
        return True
    if v in _FALSE:
        return False
    raise ConfigError(f"{name} must be one of true/false/1/0/yes/no/on/off, got {raw!r}")


def _deep_merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    out = dict(base)
    for k, v in override.items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _deep_merge(out[k], v)
        else:
            out[k] = v
    return out


def _env_overrides() -> dict[str, Any]:
    o: dict[str, Any] = {}
    web = _env_bool("KUBE_NOOB_WEB_ENABLED")
    if web is not None:
        o["webEnabled"] = web
    cluster = _env_bool("KUBE_NOOB_CLUSTER_ENABLED")
    if cluster is not None:
        o.setdefault("cluster", {})["enabled"] = cluster
    for env, path in (
        ("KUBE_NOOB_LLM_PROVIDER", ("llm", "provider")),
        ("KUBE_NOOB_LLM_MODEL", ("llm", "model")),
        ("KUBE_NOOB_LLM_BASE_URL", ("llm", "baseUrl")),
        ("KUBE_NOOB_CLUSTER_BACKEND", ("cluster", "backend")),
        ("KUBE_NOOB_DEFAULT_PLATFORM", ("defaultPlatform",)),
        ("KUBE_NOOB_SERVER_HOST", ("server", "host")),
    ):
        val = os.environ.get(env)
        if val:
            cur = o
            for part in path[:-1]:
                cur = cur.setdefault(part, {})
            cur[path[-1]] = val
    port = os.environ.get("KUBE_NOOB_SERVER_PORT")
    if port:
        try:
            o.setdefault("server", {})["port"] = int(port)
        except ValueError as exc:
            raise ConfigError(f"KUBE_NOOB_SERVER_PORT must be an integer, got {port!r}") from exc
    return o


def load_settings(path: str | Path | None = None, overrides: dict[str, Any] | None = None) -> Settings:
    """Load settings. ``overrides`` use the camelCase keys of the YAML file."""
    data: dict[str, Any] = {}
    source: Path | None = None
    candidates = [Path(path)] if path else _candidate_files()
    for cand in candidates:
        if cand.is_file():
            try:
                raw = yaml.safe_load(cand.read_text(encoding="utf-8")) or {}
            except yaml.YAMLError as exc:
                raise ConfigError(f"Config file {cand} is not valid YAML: {exc}") from exc
            if not isinstance(raw, dict):
                raise ConfigError(f"Config file {cand} must contain a mapping at the top level")
            data = raw
            source = cand
            break
        if path:  # an explicit path that does not exist is an error, not a silent fallback
            raise ConfigError(f"Config file {cand} does not exist")
    data = _deep_merge(data, _env_overrides())
    if overrides:
        data = _deep_merge(data, overrides)
    try:
        settings = Settings.model_validate(data)
    except ValidationError as exc:
        raise ConfigError(f"Invalid kube-noob configuration: {exc}") from exc
    settings.source_path = source
    return settings


_settings: Settings | None = None


def get_settings() -> Settings:
    global _settings  # noqa: PLW0603 - process-wide cached settings
    if _settings is None:
        _settings = load_settings()
    return _settings


def set_settings(settings: Settings) -> None:
    global _settings  # noqa: PLW0603
    _settings = settings
