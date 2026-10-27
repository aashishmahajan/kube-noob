"""End-to-end check of the Claude plugin's MCP server, started exactly as plugin/kube-noob/.mcp.json says.

Usage: python scripts/e2e_plugin.py
Needs `uv` on PATH. Expands ${CLAUDE_PLUGIN_ROOT} and ${CLAUDE_PLUGIN_DATA} the way Claude Code does, starts the
server over stdio with a throwaway data dir and config dir, and checks that:
- the server runs the bundled source under plugin/kube-noob/server with the locked dependencies, and no LLM SDK;
- web and cluster tools are off and the posture reports no model;
- audit, diagnose and cited search answer from local data.
Exits non-zero on the first broken guarantee.
"""

from __future__ import annotations

import asyncio
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

ROOT = Path(__file__).resolve().parents[1]
PLUGIN = ROOT / "plugin" / "kube-noob"
_VAR = re.compile(r"\$\{(CLAUDE_PLUGIN_ROOT|CLAUDE_PLUGIN_DATA)\}")


def check(ok: object, message: str) -> None:
    if not ok:
        raise SystemExit(f"plugin e2e FAILED: {message}")


def _json(result: Any) -> dict[str, Any]:
    check(not result.is_error, f"tool call failed: {result.content[0].text if result.content else result}")
    return json.loads(result.content[0].text)  # type: ignore[no-any-return]


def _expand(value: str, variables: dict[str, str]) -> str:
    return _VAR.sub(lambda m: variables[m.group(1)], value)


def server_params(data_dir: Path, plugin_data: Path) -> StdioServerParameters:
    spec = json.loads((PLUGIN / ".mcp.json").read_text())["mcpServers"]["kube-noob"]
    variables = {"CLAUDE_PLUGIN_ROOT": str(PLUGIN), "CLAUDE_PLUGIN_DATA": str(plugin_data)}
    env = {k: v for k, v in os.environ.items() if not k.startswith(("KUBE_NOOB_", "UV_PROJECT_", "VIRTUAL_ENV"))}
    env.update({k: _expand(v, variables) for k, v in spec.get("env", {}).items()})
    env.update({"KUBE_NOOB_DATA_DIR": str(data_dir), "XDG_CONFIG_HOME": str(data_dir)})
    return StdioServerParameters(
        command=_expand(spec["command"], variables),
        args=[_expand(a, variables) for a in spec["args"]],
        env=env,
    )


def check_environment(params: StdioServerParameters) -> None:
    """The plugin environment holds the locked dependencies and no LLM SDK."""
    probe = (
        "import importlib.util, json, sys; "
        "print(json.dumps({'anthropic': importlib.util.find_spec('anthropic') is not None, "
        "'openai': importlib.util.find_spec('openai') is not None, "
        "'mcp': importlib.util.find_spec('mcp') is not None}))"
    )
    args = list(params.args)
    python_at = args.index("python")
    cmd = [params.command, *args[:python_at], "python", "-c", probe]
    out = subprocess.run(cmd, env=params.env, capture_output=True, text=True, check=False, timeout=600)
    check(out.returncode == 0, f"the locked environment did not build: {out.stderr.strip()[-800:]}")
    found = json.loads(out.stdout.strip().splitlines()[-1])
    check(found["mcp"], "mcp is missing from the plugin environment")
    check(not found["anthropic"] and not found["openai"], f"an LLM SDK is installed in the plugin environment: {found}")


async def main() -> None:
    check(shutil.which("uv"), "uv is not on PATH")
    data = Path(tempfile.mkdtemp(prefix="kn-plugin-e2e-"))
    plugin_data = Path(tempfile.mkdtemp(prefix="kn-plugin-data-"))
    params = server_params(data, plugin_data)
    check_environment(params)
    check(not (PLUGIN / ".venv").exists(), "uv wrote a virtual environment into the plugin root")

    manifest = (ROOT / "examples" / "insecure-deployment.yaml").read_text()
    events = (ROOT / "examples" / "events-scc.txt").read_text()
    async with stdio_client(params) as (r, w), ClientSession(r, w) as s:
        init = await s.initialize()
        version = re.search(r'__version__ = "([^"]+)"', (PLUGIN / "server/kube_noob/__init__.py").read_text())
        check(version and init.server_info.version == version.group(1), f"server reports {init.server_info}")
        tools = {t.name for t in (await s.list_tools()).tools}
        check({"kubenoob_audit_manifests", "kubenoob_diagnose", "kubenoob_search_knowledge"} <= tools, "core tools")
        check(not any(t.startswith(("kubenoob_web", "kubenoob_cluster")) for t in tools), "web/cluster tools are on")

        status = _json(await s.call_tool("kubenoob_config_status", {}))
        posture = status["posture"]
        check(posture["network"]["web"] in {"off", "locked-off"}, f"web is reachable: {posture['network']}")
        check(posture["model"]["provider"] == "none", f"the plugin server reports a model: {posture['model']}")

        audit = _json(
            await s.call_tool(
                "kubenoob_audit_manifests", {"manifests": manifest, "platform": "openshift", "version": "4.22"}
            )
        )
        check(audit["summary"]["counts"]["high"] >= 1 and audit["summary"]["score"] < 100, "audit found nothing")

        dx = _json(await s.call_tool("kubenoob_diagnose", {"text": events, "platform": "openshift"}))
        top = dx["diagnoses"][0]
        check(top["readOnlyNextSteps"], f"diagnosis {top['id']} has no read-only first steps")

        hits = _json(await s.call_tool("kubenoob_search_knowledge", {"query": "restricted-v2 SCC runAsUser range"}))
        check(hits["results"] and hits["results"][0]["chunkId"].startswith("kn:"), "search returned no citation")

    shutil.rmtree(data, ignore_errors=True)
    shutil.rmtree(plugin_data, ignore_errors=True)
    print(
        f"plugin e2e OK: server {init.server_info.name} {init.server_info.version}, {len(tools)} tools, "
        f"audit score {audit['summary']['score']}, top diagnosis {top['id']}, "
        f"first citation {hits['results'][0]['chunkId']}"
    )


if __name__ == "__main__":
    if len(sys.argv) != 1:
        print(__doc__)
        raise SystemExit(2)
    asyncio.run(main())
