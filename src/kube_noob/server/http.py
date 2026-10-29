"""Serve the MCP server over streamable HTTP: the OpenShift sidecar and the in-cluster service.

Kept apart from ``mcp_app`` because it reads the bearer token from the environment; the Claude plugin serves over stdio
only and ships without this module.
"""

from __future__ import annotations

import hmac
import os
from typing import Any

from mcp.server.transport_security import TransportSecuritySettings
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Receive, Scope, Send

from kube_noob.config import Settings
from kube_noob.server.mcp_app import build_server

PUBLIC_PATHS = frozenset({"/healthz", "/readyz"})
DEFAULT_TOKEN_ENV = "KUBE_NOOB_HTTP_TOKEN"  # noqa: S105 - the variable's name, not a secret
MAX_BODY_BYTES = 8 * 1024 * 1024  # manifests are capped at 5 MB; JSON-RPC framing needs some headroom


class BodyLimit:
    """Reject request bodies above ``limit`` bytes with 413 before the MCP app sees them.

    Bodies are read up front (JSON-RPC requests are small and the server answers with plain JSON), so a declared
    Content-Length or a chunked upload that exceeds the limit never reaches the application.
    """

    def __init__(self, app: ASGIApp, limit: int = MAX_BODY_BYTES) -> None:
        self.app = app
        self.limit = limit

    async def _reject(self, scope: Scope, receive: Receive, send: Send) -> None:
        await JSONResponse({"error": "request body too large", "limitBytes": self.limit}, status_code=413)(
            scope, receive, send
        )

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or scope.get("method") not in {"POST", "PUT", "PATCH"}:
            await self.app(scope, receive, send)
            return
        declared = dict(scope.get("headers") or []).get(b"content-length")
        if declared is not None and declared.isdigit() and int(declared) > self.limit:
            await self._reject(scope, receive, send)
            return
        body = bytearray()
        while True:
            message = await receive()
            if message["type"] == "http.disconnect":
                return
            body.extend(message.get("body", b""))
            if len(body) > self.limit:
                await self._reject(scope, receive, send)
                return
            if not message.get("more_body", False):
                break
        replayed = False

        async def replay() -> Any:
            nonlocal replayed
            if not replayed:
                replayed = True
                return {"type": "http.request", "body": bytes(body), "more_body": False}
            return await receive()

        await self.app(scope, replay, send)


class BearerAuth:
    """Constant-time static bearer token check for HTTP mode (health endpoints stay public for probes)."""

    def __init__(self, app: ASGIApp, token: str | None) -> None:
        self.app = app
        self.token = token.encode() if token else None

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] == "http" and self.token is not None and scope.get("path") not in PUBLIC_PATHS:
            headers = dict(scope.get("headers") or [])
            auth = headers.get(b"authorization", b"")
            expected = b"Bearer " + self.token
            if not hmac.compare_digest(auth, expected):
                resp = JSONResponse({"error": "unauthorized"}, status_code=401, headers={"WWW-Authenticate": "Bearer"})
                await resp(scope, receive, send)
                return
        await self.app(scope, receive, send)


def http_app(settings: Settings, *, allow_unauthenticated: bool = False) -> ASGIApp:
    srv = settings.server
    token_env = srv.auth_token_env or DEFAULT_TOKEN_ENV
    token = os.environ.get(token_env) or None
    loopback = srv.host in {"127.0.0.1", "::1", "localhost"}
    if token is None and not loopback and not allow_unauthenticated:
        raise RuntimeError(
            f"Refusing to serve MCP over HTTP on {srv.host} without authentication. Set {token_env}, bind "
            "to 127.0.0.1 (sidecar mode), or pass --allow-unauthenticated if a mesh/proxy authenticates callers."
        )
    if token is not None and not loopback and not srv.allowed_hosts:
        # Remote service with bearer auth and no Host allowlist configured (e.g. `docker run` with the image's default
        # command): a DNS-rebinding page cannot attach the bearer token, so Host/Origin checks would only turn every
        # request addressed by a DNS name into a 421. Configure server.allowedHosts to re-enable them.
        security = TransportSecuritySettings(enable_dns_rebinding_protection=False)
    else:
        allowed_hosts = srv.allowed_hosts or ["127.0.0.1", "localhost", "127.0.0.1:*", "localhost:*", "[::1]:*"]
        security = TransportSecuritySettings(
            enable_dns_rebinding_protection=True, allowed_hosts=allowed_hosts, allowed_origins=srv.allowed_origins
        )
    # Over HTTP many callers share one learning file, so the tools that write it are not offered (add team notes
    # with `kube-noob learning note` in the pod instead).
    mcp = build_server(settings, shared=True, rest=security)
    app = mcp.streamable_http_app(
        streamable_http_path=srv.path,
        transport_security=security,
        host=srv.host,
        stateless_http=True,
        json_response=True,
    )
    # Authenticate before reading any body, so a caller without the token cannot make the server buffer requests.
    return BearerAuth(BodyLimit(app), token)
