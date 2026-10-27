"""Configuration.

Precedence (lowest -> highest): built-in defaults < config file < environment variables < explicit
overrides passed by the CLI.

Config file lookup order: ``--config``, ``$KUBE_NOOB_CONFIG``, ``$XDG_CONFIG_HOME/kube-noob/config.yaml``
(``~/.config/kube-noob/config.yaml``), ``/etc/kube-noob/config.yaml`` (the path the Helm chart mounts).

The current directory is deliberately NOT searched: a ``kube-noob.yaml`` inside a cloned repository could otherwise
enable web/cluster access or point the agent's API key at an attacker's endpoint. Pass ``--config ./kube-noob.yaml``
to use a project file explicitly.

Keys are camelCase in YAML (``webEnabled: true``) and snake_case in Python.

``offline: true`` (or ``KUBE_NOOB_OFFLINE=1``) is an admin lock, not a default: it overrides ``webEnabled``, blocks
corpus downloads and allows only local model endpoints, and no later source in the chain can lift it.
"""

from __future__ import annotations

import ipaddress
import os
import re
from pathlib import Path
from typing import Any, Literal
from urllib.parse import urlsplit

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator
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
        cleaned = []
        for raw in v:
            d = raw.strip().lower()
            if not d:
                continue
            # Entries already match their subdomains, so '*.example.com' means 'example.com'.
            d = d.removeprefix("*.").lstrip(".")
            if "/" in d or ":" in d or " " in d or "*" in d or "." not in d:
                raise ValueError(f"allowedDomains entries must be bare host names like 'docs.redhat.com', got {raw!r}")
            cleaned.append(d)
        return cleaned


class ClusterSettings(_Base):
    enabled: bool = False
    backend: Literal["auto", "in-cluster", "kubectl", "oc"] = "auto"
    context: str | None = None
    timeout_seconds: float = Field(default=20.0, gt=0, le=120)
    max_log_lines: int = Field(default=200, ge=1, le=5000)


# The API key is sent to base_url, so only variables that are plainly LLM API keys may be named here: never
# AWS_SECRET_ACCESS_KEY, GITHUB_TOKEN or similar.
_API_KEY_ENV = re.compile(r"^(?:[A-Z][A-Z0-9_]*_API_KEY|KUBE_NOOB_[A-Z0-9_]+)$")
_CLUSTER_LOCAL_SUFFIXES = (".svc", ".svc.cluster.local", ".local", ".internal")


def is_local_url(url: str | None) -> bool:
    """Loopback or cluster-local host (``*.svc``, ``*.svc.cluster.local``, ``*.local``, ``*.internal``)."""
    if not url:
        return False
    host = (urlsplit(url).hostname or "").lower()
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return host == "localhost" or host.endswith(_CLUSTER_LOCAL_SUFFIXES)


def _check_endpoint(base_url: str | None, allow_insecure: bool, what: str) -> None:
    if base_url is None:
        return
    parts = urlsplit(base_url)
    if parts.scheme not in {"https", "http"} or not parts.hostname:
        raise ValueError(f"{what}.baseUrl must be an http(s) URL with a host, got {base_url!r}")
    if parts.username or parts.password:
        raise ValueError(f"{what}.baseUrl must not embed credentials; use apiKeyEnv")
    if parts.scheme == "http" and not allow_insecure:
        host = parts.hostname.lower()
        try:
            local = ipaddress.ip_address(host).is_loopback
        except ValueError:
            local = host == "localhost" or host.endswith(_CLUSTER_LOCAL_SUFFIXES)
        if not local:
            raise ValueError(
                f"{what}.baseUrl {base_url!r} uses plain http to a non-local host: the API key would travel in "
                "clear text. Use https, a loopback / cluster-local (*.svc) endpoint, or set "
                f"{what}.allowInsecureBaseUrl: true."
            )


class _LLMEndpoint(_Base):
    base_url: str | None = None
    api_key_env: str = "ANTHROPIC_API_KEY"
    allow_insecure_base_url: bool = False

    @field_validator("api_key_env")
    @classmethod
    def _key_env(cls, v: str) -> str:
        if not _API_KEY_ENV.match(v):
            raise ValueError(
                f"apiKeyEnv {v!r} must name an LLM API key variable (*_API_KEY or KUBE_NOOB_*); its value is sent to "
                "the configured endpoint"
            )
        return v


class LLMSettings(_LLMEndpoint):
    provider: Literal["anthropic", "openai-compatible", "none"] = "anthropic"
    model: str = DEFAULT_MODEL
    max_tokens: int = Field(default=4096, ge=256, le=64000)
    max_tool_rounds: int = Field(default=12, ge=1, le=50)
    timeout_seconds: float = Field(default=120.0, gt=0, le=900)

    @model_validator(mode="after")
    def _endpoint(self) -> LLMSettings:
        _check_endpoint(self.base_url, self.allow_insecure_base_url, "llm")
        return self


class JudgeSettings(_LLMEndpoint):
    """Optional LLM judge. Eval-only: judge outputs are never exported as training labels by default."""

    provider: Literal["none", "anthropic", "openai-compatible"] = "none"
    model: str = DEFAULT_MODEL

    @model_validator(mode="after")
    def _endpoint(self) -> JudgeSettings:
        _check_endpoint(self.base_url, self.allow_insecure_base_url, "judge")
        return self


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
    offline: bool = False  # admin lock: no web, no corpus downloads, only local model endpoints
    learning_enabled: bool = True  # local learning.json: confirmed notes, profile, pattern counters
    web_enabled: bool = False
    web: WebSettings = Field(default_factory=WebSettings)
    cluster: ClusterSettings = Field(default_factory=ClusterSettings)
    llm: LLMSettings = Field(default_factory=LLMSettings)
    judge: JudgeSettings = Field(default_factory=JudgeSettings)
    server: ServerSettings = Field(default_factory=ServerSettings)
    data_dir: Path = Field(default_factory=_default_data_dir)
    default_platform: Literal["kubernetes", "openshift", "rosa-classic", "rosa-hcp"] = "kubernetes"
    source_path: Path | None = Field(default=None, exclude=True)
    web_locked: bool = Field(default=False, exclude=True)

    @model_validator(mode="after")
    def _offline_lock(self) -> Settings:
        if self.offline and self.web_enabled:
            self.web_enabled = False
            self.web_locked = True
        return self

    def llm_endpoint_is_local(self) -> bool:
        """True when the configured model endpoint stays inside the machine or cluster."""
        return self.llm.provider == "openai-compatible" and is_local_url(self.llm.base_url)

    def public_view(self) -> dict[str, Any]:
        """Config safe to display (no secrets are ever stored in Settings, only env var names)."""
        out = self.model_dump(by_alias=True, mode="json")
        out["configFile"] = str(self.source_path) if self.source_path else None
        return out


SYSTEM_CONFIG = Path("/etc/kube-noob/config.yaml")


def _system_lock() -> bool:
    """``offline: true`` in the system config is an admin lock that applies even when a user config file wins."""
    try:
        raw = yaml.safe_load(SYSTEM_CONFIG.read_text(encoding="utf-8")) if SYSTEM_CONFIG.is_file() else None
    except (OSError, yaml.YAMLError):
        return False
    return isinstance(raw, dict) and raw.get("offline") is True


def _candidate_files() -> list[Path]:
    env = os.environ.get("KUBE_NOOB_CONFIG")
    if env:
        return [Path(env)]
    xdg = os.environ.get("XDG_CONFIG_HOME")
    cfg_home = Path(xdg) if xdg else Path.home() / ".config"
    return [cfg_home / "kube-noob" / "config.yaml", SYSTEM_CONFIG]


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
    offline = _env_bool("KUBE_NOOB_OFFLINE")
    if offline is not None:
        o["offline"] = offline
    learning = _env_bool("KUBE_NOOB_LEARNING_ENABLED")
    if learning is not None:
        o["learningEnabled"] = learning
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
    # The offline lock only ever tightens: any of the system config, the chosen config file or KUBE_NOOB_OFFLINE can
    # switch it on, and nothing later in the chain (environment "0", CLI flags, tool overrides) can switch it off.
    locked = data.get("offline") is True or _system_lock()
    data = _deep_merge(data, _env_overrides())
    locked = locked or data.get("offline") is True
    if overrides:
        data = _deep_merge(data, overrides)
    if locked:
        data["offline"] = True
    try:
        settings = Settings.model_validate(data)
    except ValidationError as exc:
        raise ConfigError(f"Invalid kube-noob configuration: {exc}") from exc
    settings.source_path = source
    return settings
