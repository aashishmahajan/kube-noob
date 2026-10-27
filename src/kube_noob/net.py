"""Single choke point for outbound HTTP.

* ``Purpose.WEB``     - answering questions from the web. Requires ``webEnabled: true`` and every request
                        (including redirects) must target an allowlisted domain.
* ``Purpose.SOURCES`` - maintainer-run corpus builds (git/Jira ingestion). Requires ``webEnabled: true`` or an
                        explicit ``allow_sources=True`` from a CLI command the operator ran on purpose.
* ``Purpose.LLM``     - the configured model provider endpoint. Not web browsing; always permitted when an
                        LLM provider is configured. Under the offline lock every request (and no redirect, no proxy
                        from the environment) must target loopback or an in-cluster ``*.svc`` host.

No other module may construct an ``httpx`` client directly, except the in-cluster API client in
``kube_noob.debug.backends`` (ServiceAccount token, cluster CA, no redirects, no proxy), which is used only when cluster
access is enabled.
"""

from __future__ import annotations

import enum

import httpx

from kube_noob import __version__
from kube_noob.config import Settings, is_local_url
from kube_noob.errors import DomainNotAllowedError, WebDisabledError

USER_AGENT = f"kube-noob/{__version__} (+https://github.com/aashishmahajan/kube-noob)"


class Purpose(enum.Enum):
    WEB = "web"
    SOURCES = "sources"
    LLM = "llm"


def host_allowed(host: str, allowed: list[str]) -> bool:
    host = host.lower().rstrip(".")
    return any(host == d or host.endswith("." + d) for d in allowed)


def http_client(
    settings: Settings,
    purpose: Purpose,
    *,
    allow_sources: bool = False,
    timeout: float | None = None,
    extra_headers: dict[str, str] | None = None,
    transport: httpx.BaseTransport | None = None,
) -> httpx.Client:
    if settings.offline and purpose in (Purpose.WEB, Purpose.SOURCES):
        raise WebDisabledError(
            purpose.value,
            f"Outbound access for '{purpose.value}' is blocked by the offline lock (offline: true / "
            "KUBE_NOOB_OFFLINE). kube-noob answers from local knowledge only.",
        )
    if purpose is Purpose.WEB and not settings.web_enabled:
        raise WebDisabledError("web lookup")
    if purpose is Purpose.SOURCES and not (settings.web_enabled or allow_sources):
        raise WebDisabledError("source ingestion")

    hooks: dict[str, list] = {"request": []}  # type: ignore[type-arg]
    if purpose is Purpose.WEB:
        allowed = list(settings.web.allowed_domains)

        def _guard(request: httpx.Request) -> None:
            if request.method != "GET":
                raise WebDisabledError("web lookup", f"Web access is read-only: {request.method} is not allowed (GET).")
            if request.url.scheme != "https":
                raise DomainNotAllowedError(f"{request.url.host} (non-https scheme {request.url.scheme})")
            if not host_allowed(request.url.host, allowed):
                raise DomainNotAllowedError(request.url.host)

        hooks["request"].append(_guard)

    locked_llm = settings.offline and purpose is Purpose.LLM
    if locked_llm:

        def _local_only(request: httpx.Request) -> None:
            if not is_local_url(str(request.url)):
                raise WebDisabledError(
                    "llm",
                    f"The offline lock only allows model endpoints on loopback or inside the cluster (*.svc); "
                    f"refused {request.url.host}.",
                )

        hooks["request"].append(_local_only)

    headers = {"User-Agent": USER_AGENT}
    if extra_headers:
        headers.update(extra_headers)
    return httpx.Client(
        timeout=timeout if timeout is not None else settings.web.timeout_seconds,
        follow_redirects=not locked_llm,
        max_redirects=5,
        headers=headers,
        event_hooks=hooks,
        transport=transport,
        trust_env=not locked_llm,
    )
