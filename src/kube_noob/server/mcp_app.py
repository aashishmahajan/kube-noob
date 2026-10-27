"""MCP server (``kube_noob_mcp``): stdio for local clients, streamable HTTP for the OpenShift sidecar / service.

Tools are generated from the shared Toolkit so the MCP surface, the standalone agent and the CLI never drift.
"""

from __future__ import annotations

import base64
import hmac
import inspect
import os
from importlib import resources
from typing import Annotated, Any, cast

import anyio
from mcp.server import MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from mcp.server.transport_security import TransportSecuritySettings
from mcp_types import Icon, ToolAnnotations
from pydantic import Field, ValidationError
from pydantic_core import PydanticUndefined
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.types import ASGIApp, Receive, Scope, Send

from kube_noob import __version__
from kube_noob.agent.loop import system_prompt
from kube_noob.audit.engine import list_rules
from kube_noob.config import Settings
from kube_noob.errors import KubeNoobError
from kube_noob.knowledge.store import get_store
from kube_noob.learn.tutor import curriculum
from kube_noob.toolkit import Toolkit, ToolSpec

TOOL_PREFIX = "kubenoob_"
PUBLIC_PATHS = frozenset({"/healthz", "/readyz"})
MAX_ERROR_CHARS = 2000


def _icons() -> list[Icon]:
    try:
        svg = resources.files("kube_noob").joinpath("data", "brand", "kube-noob-icon.svg").read_bytes()
    except FileNotFoundError:
        return []
    uri = "data:image/svg+xml;base64," + base64.b64encode(svg).decode()
    return [Icon(src=uri, mime_type="image/svg+xml", sizes=["any"])]


def _instructions(settings: Settings) -> str:
    return (
        "kube-noob: offline-first Kubernetes / Helm / OpenShift / ROSA HCP / RHACS (StackRox) learning, audit and "
        "debugging tools. Start design or review requests with kubenoob_run_protocol (7 steps: Clarify, Validate, "
        "Research, Audit, Calibrate, Generate, Red Team). Ground answers with kubenoob_search_knowledge and cite "
        "chunk ids as [kn:<doc>#<n>]. Debug with kubenoob_diagnose"
        + (" and the read-only kubenoob_cluster_* tools." if settings.cluster.enabled else ".")
        + (
            " Web access is ENABLED (kubenoob_web_fetch, allowlisted domains)."
            if settings.web_enabled
            else " Web access is DISABLED (webEnabled: false): rely on local knowledge only."
        )
        + " Learning: kubenoob_learn_*. Training enforcer: kubenoob_grade_answer."
    )


def _wrapper(spec: ToolSpec) -> Any:
    """Build an async function whose signature mirrors the tool's Pydantic model (flat MCP arguments)."""
    model = spec.model
    params: list[inspect.Parameter] = []
    annotations: dict[str, Any] = {}
    for name, f in model.model_fields.items():
        arg = f.alias or name
        ann = cast(Any, Annotated)[(f.annotation, *f.metadata, Field(description=f.description))]
        if f.is_required():
            default: Any = inspect.Parameter.empty
        else:
            default = f.get_default(call_default_factory=True)
            if default is PydanticUndefined:
                default = None
        params.append(inspect.Parameter(arg, inspect.Parameter.KEYWORD_ONLY, default=default, annotation=ann))
        annotations[arg] = ann

    async def tool(**kwargs: Any) -> dict[str, Any]:
        # Anticipated failures (guards, bad input, disabled features) become ToolError so the calling model sees the
        # actionable message; anything else stays an opaque crash whose details remain in the server log.
        try:
            validated = model.model_validate(kwargs)
            result: dict[str, Any] = await anyio.to_thread.run_sync(spec.fn, validated)
        except ValidationError as exc:
            raise ToolError(f"invalid arguments: {str(exc)[:MAX_ERROR_CHARS]}") from exc
        except (KubeNoobError, ValueError) as exc:
            raise ToolError(str(exc)[:MAX_ERROR_CHARS]) from exc
        except KeyError as exc:  # unknown task / chunk / lesson ids
            raise ToolError(str(exc.args[0] if exc.args else exc)[:MAX_ERROR_CHARS]) from exc
        return result

    tool.__name__ = TOOL_PREFIX + spec.name
    tool.__doc__ = spec.description
    tool.__signature__ = inspect.Signature(params, return_annotation=dict[str, Any])  # type: ignore[attr-defined]
    annotations["return"] = dict[str, Any]
    tool.__annotations__ = annotations
    return tool


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


def build_server(settings: Settings) -> MCPServer:
    toolkit = Toolkit(settings)
    mcp = MCPServer(
        name="kube_noob_mcp",
        title="kube-noob",
        version=__version__,
        instructions=_instructions(settings),
        website_url="https://github.com/aashishmahajan/kube-noob",
        icons=_icons(),
    )
    for spec in toolkit.specs():
        mcp.tool(
            name=TOOL_PREFIX + spec.name,
            title=spec.title,
            description=spec.description,
            annotations=ToolAnnotations(
                title=spec.title,
                read_only_hint=spec.read_only,
                destructive_hint=False,
                idempotent_hint=spec.read_only,
                open_world_hint=spec.open_world,
            ),
        )(_wrapper(spec))

    @mcp.prompt(
        name="master_controller",
        title="7-step engineering protocol",
        description="Run a request through Clarify, Validate, Research, Audit, Calibrate, Generate, Red Team.",
    )
    def master_controller(request: str, platform: str = "", manifests: str = "") -> str:
        parts = [system_prompt(settings), f"\nRequest: {request}"]
        if platform:
            parts.append(f"Target platform: {platform}")
        if manifests:
            parts.append(f"Manifests to review:\n```yaml\n{manifests}\n```")
        parts.append(
            "Start by calling kubenoob_run_protocol, then explain the brief, manifest and red-team findings "
            "with [kn:...] citations."
        )
        return "\n".join(parts)

    @mcp.prompt(
        name="debug_session",
        title="Guided debugging",
        description="Diagnose a failing workload from pasted events/logs (and live cluster if enabled).",
    )
    def debug_session(symptoms: str, namespace: str = "", workload: str = "") -> str:
        live = (
            f" Then call kubenoob_cluster_debug_workload for {workload} in {namespace}."
            if settings.cluster.enabled and workload and namespace
            else ""
        )
        return (
            f"Diagnose this problem. Call kubenoob_diagnose with the text below first.{live} Explain the most "
            f"likely root cause, the read-only checks to confirm it and the fix, citing [kn:...] chunks.\n\n"
            f"{symptoms}"
        )

    @mcp.prompt(
        name="tutor",
        title="Learning session",
        description="Start or continue a learning track with lessons, exercises and quizzes.",
    )
    def tutor(track: str = "kubernetes", learner: str = "local") -> str:
        return (
            f"Act as a patient tutor for the '{track}' track for learner '{learner}'. Use kubenoob_learn_tracks, "
            "kubenoob_learn_lesson, kubenoob_learn_exercise / kubenoob_learn_submit and kubenoob_learn_quiz. "
            "Teach one concept at a time, ask the learner to try the exercise, and explain feedback with "
            "citations."
        )

    @mcp.resource(
        "kubenoob://knowledge/{doc_id}",
        name="knowledge",
        title="Knowledge document",
        description="Full text of a built-in or ingested knowledge document.",
        mime_type="text/markdown",
    )
    def knowledge_doc(doc_id: str) -> str:
        chunks = get_store(settings.data_dir).doc(doc_id)
        if not chunks:
            raise ValueError(f"unknown knowledge document {doc_id!r}")
        head = f"# {chunks[0].title}\n\nSource: {chunks[0].url or 'built-in'} ({chunks[0].license})\n\n"
        return head + "\n\n".join(f"## {c.heading}\n\n{c.text}" for c in chunks)

    @mcp.resource("kubenoob://rules", name="rules", title="Audit rules", mime_type="application/json")
    def rules_resource() -> list[dict[str, object]]:
        return list_rules()

    @mcp.resource("kubenoob://curriculum", name="curriculum", title="Learning curriculum", mime_type="application/json")
    def curriculum_resource() -> dict[str, Any]:
        return {
            "tracks": [
                {"id": t["id"], "title": t["title"], "summary": t.get("summary", "")} for t in curriculum()["tracks"]
            ]
        }

    @mcp.custom_route("/healthz", methods=["GET"])
    async def healthz(_: Request) -> Response:
        return JSONResponse({"status": "ok", "version": __version__})

    @mcp.custom_route("/readyz", methods=["GET"])
    async def readyz(_: Request) -> Response:
        try:
            stats = await anyio.to_thread.run_sync(lambda: get_store(settings.data_dir).stats())
        except Exception as exc:  # noqa: BLE001 - readiness must report, not crash
            return JSONResponse({"status": "not-ready", "error": type(exc).__name__}, status_code=503)
        return JSONResponse(
            {
                "status": "ready",
                "knowledgeChunks": stats["chunks"],
                "webEnabled": settings.web_enabled,
                "clusterEnabled": settings.cluster.enabled,
            }
        )

    return mcp


def http_app(settings: Settings, *, allow_unauthenticated: bool = False) -> ASGIApp:
    srv = settings.server
    token = os.environ.get(srv.auth_token_env) or None
    loopback = srv.host in {"127.0.0.1", "::1", "localhost"}
    if token is None and not loopback and not allow_unauthenticated:
        raise RuntimeError(
            f"Refusing to serve MCP over HTTP on {srv.host} without authentication. Set {srv.auth_token_env}, bind "
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
    mcp = build_server(settings)
    app = mcp.streamable_http_app(
        streamable_http_path=srv.path,
        transport_security=security,
        host=srv.host,
        stateless_http=True,
        json_response=True,
    )
    return BearerAuth(app, token)
