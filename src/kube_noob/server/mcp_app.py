"""MCP server (``kube_noob_mcp``): the tools, prompts and resources, served over stdio or HTTP.

Tools are generated from the shared Toolkit so the MCP surface, the standalone agent and the CLI never drift.
stdio serving is in ``kube_noob.server.stdio``; HTTP serving (bearer token, body limit) is in ``kube_noob.server.http``.
"""

from __future__ import annotations

import base64
import inspect
import logging
import time
import traceback
from importlib import resources
from typing import Annotated, Any, cast

import anyio
from mcp.server import MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from mcp_types import Icon, ToolAnnotations
from pydantic import ConfigDict, Field, ValidationError
from pydantic_core import PydanticUndefined
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from kube_noob import __version__
from kube_noob.audit.engine import list_rules
from kube_noob.config import Settings
from kube_noob.errors import KubeNoobError
from kube_noob.knowledge.store import get_store
from kube_noob.knowledge_status import line as knowledge_line
from kube_noob.learn.tutor import curriculum
from kube_noob.prompts import system_prompt
from kube_noob.toolkit import Toolkit, ToolSpec

TOOL_PREFIX = "kubenoob_"
MAX_ERROR_CHARS = 2000
_audit = logging.getLogger("kube_noob.audit")


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
        + " For 'is this a known bug?' or any OpenShift error, check kubenoob_known_issues (reported issues from the "
        "release notes, with the fix version) and give the issue link. Every result carries knowledgeAsOf: say how "
        "current kube-noob's knowledge is when the answer depends on versions or recent changes."
        + (
            " Web access is ENABLED (kubenoob_web_fetch, allowlisted domains)."
            if settings.web_enabled
            else " Web access is DISABLED (webEnabled: false): rely on local knowledge only."
        )
        + " Learning: kubenoob_learn_*. Training enforcer: kubenoob_grade_answer."
    )


def _wrapper(spec: ToolSpec, knowledge: str) -> Any:
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
        started = time.monotonic()
        outcome = "ok"
        try:
            validated = model.model_validate(kwargs)
            result: dict[str, Any] = await anyio.to_thread.run_sync(spec.fn, validated)
            if isinstance(result, dict):
                # Every answer says how current kube-noob's knowledge is, so the model can tell the user.
                result.setdefault("knowledgeAsOf", knowledge)
        except ValidationError as exc:
            outcome = "invalid-arguments"
            raise ToolError(f"invalid arguments: {str(exc)[:MAX_ERROR_CHARS]}") from exc
        except (KubeNoobError, ValueError) as exc:
            outcome = type(exc).__name__
            raise ToolError(str(exc)[:MAX_ERROR_CHARS]) from exc
        except KeyError as exc:  # unknown task / chunk / lesson ids
            outcome = "not-found"
            raise ToolError(str(exc.args[0] if exc.args else exc)[:MAX_ERROR_CHARS]) from exc
        except Exception as exc:  # noqa: BLE001 - every unexpected failure becomes an opaque error
            # Log the failure without its message (which can quote the caller's data) and hand the client an
            # opaque error; the stack shows where it failed.
            outcome = "crash"
            _audit.error(
                "tool=%s crashed: %s\n%s",
                TOOL_PREFIX + spec.name,
                type(exc).__name__,
                "".join(traceback.format_tb(exc.__traceback__)),
            )
            raise ToolError(f"internal error ({type(exc).__name__}); see the server log") from None
        finally:
            # Audit trail without content: which tool, argument names and sizes, outcome, duration.
            _audit.info(
                "tool=%s args=%s outcome=%s ms=%d",
                TOOL_PREFIX + spec.name,
                {k: len(v) if isinstance(v, str | list | dict) else type(v).__name__ for k, v in kwargs.items()},
                outcome,
                (time.monotonic() - started) * 1000,
            )
        return result

    tool.__name__ = TOOL_PREFIX + spec.name
    tool.__doc__ = spec.description
    tool.__signature__ = inspect.Signature(params, return_annotation=dict[str, Any])  # type: ignore[attr-defined]
    annotations["return"] = dict[str, Any]
    tool.__annotations__ = annotations
    return tool


def _forbid_unknown_arguments(mcp: MCPServer, name: str) -> None:
    """Reject misspelled arguments (e.g. 'taskId' for 'task_id') instead of silently dropping them.

    The SDK builds a lenient argument model from the function signature; swap in a subclass with extra='forbid' and
    advertise additionalProperties: false. Covered by a test, so an SDK change that breaks this fails CI.
    """
    tool = mcp._tool_manager.get_tool(name)
    if tool is None:
        raise RuntimeError(f"tool {name} was not registered")
    base = tool.fn_metadata.arg_model
    strict = type(base.__name__, (base,), {"model_config": ConfigDict(arbitrary_types_allowed=True, extra="forbid")})
    tool.fn_metadata.arg_model = strict
    tool.parameters["additionalProperties"] = False


def build_server(settings: Settings, *, shared: bool = False) -> MCPServer:
    toolkit = Toolkit(settings, shared=shared)
    mcp = MCPServer(
        name="kube_noob_mcp",
        title="kube-noob",
        version=__version__,
        instructions=_instructions(settings),
        website_url="https://github.com/aashishmahajan/kube-noob",
        icons=_icons(),
    )
    # The SDK logs each failed call's message at INFO, and messages can quote the caller's input (a YAML error shows
    # the offending line). Our own audit line (tool, argument sizes, outcome) is the record; keep the SDK quiet.
    logging.getLogger("mcp.server.mcpserver.server").setLevel(logging.WARNING)
    knowledge = knowledge_line(settings.data_dir)
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
        )(_wrapper(spec, knowledge))
        _forbid_unknown_arguments(mcp, TOOL_PREFIX + spec.name)

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
            f"Diagnose this problem. Call kubenoob_diagnose with the text below first.{live} Diagnose before "
            f"change: give the likely root cause and its readOnlyNextSteps (get, describe, logs, events, or "
            f"`kube-noob bundle`) first; list diagnosticCommands and proposedChanges only after that, each marked "
            f"as requiring the user's approval. Cite [kn:...] chunks. If the user confirms the fix worked, offer "
            f"to remember it with kubenoob_learning_note_add.\n\n{symptoms}"
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

    @mcp.prompt(
        name="getting_started",
        title="Getting started with kube-noob",
        description="A short, role-based tour: what kube-noob can do offline and the first three things to try.",
    )
    def getting_started(role: str = "", platform: str = "") -> str:
        who = role or "not stated yet (ask: learner, developer, SRE/on-call, platform admin or security)"
        where = platform or "not stated yet (ask: Kubernetes, OpenShift, ROSA Classic or ROSA HCP, and the version)"
        return (
            "Give the user a two-minute tour of kube-noob. It works offline by default: no web and no cluster "
            "access unless enabled, and it never changes the cluster.\n"
            f"User role: {who}. Platform: {where}.\n"
            "1. Call kubenoob_learning_summary. If the profile is empty and the user states a platform or version, "
            "offer to save it with kubenoob_learning_profile_set.\n"
            "2. Suggest the three most useful first steps for the role, each as one sentence plus the tool to use:\n"
            "   - learner/trainer: kubenoob_learn_tracks, then kubenoob_learn_lesson and kubenoob_learn_submit;\n"
            "   - developer: kubenoob_audit_manifests or kubenoob_run_protocol on their YAML or a blueprint;\n"
            "   - SRE/on-call: kubenoob_diagnose on pasted events or logs, read-only steps first;\n"
            "   - platform admin/security: kubenoob_config_status to show the posture (offline lock, web, cluster), "
            "then kubenoob_audit_manifests against their charts.\n"
            "3. Mention that `kube-noob demo --list` in a terminal shows offline walkthroughs for each use case.\n"
            "Keep it under 150 words and cite [kn:...] chunks only for factual claims."
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
