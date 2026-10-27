"""End-to-end check of the installed MCP server over stdio under the admin offline lock.

Usage: python scripts/e2e_mcp_offline.py <path-to-kube-noob-executable>
Exits non-zero on the first broken guarantee. Runs with a throwaway data dir and no network access needed.
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
import tempfile

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


def check(ok: object, message: str) -> None:
    if not ok:
        raise SystemExit(f"MCP offline e2e FAILED: {message}")


def _json(result: object) -> dict:  # type: ignore[type-arg]
    return json.loads(result.content[0].text)  # type: ignore[attr-defined]


async def main(exe: str) -> None:
    data = tempfile.mkdtemp(prefix="kn-e2e-")
    env = {
        **os.environ,
        "KUBE_NOOB_OFFLINE": "1",
        "KUBE_NOOB_WEB_ENABLED": "true",
        "KUBE_NOOB_DATA_DIR": data,
        "XDG_CONFIG_HOME": data,
    }
    async with (
        stdio_client(StdioServerParameters(command=exe, args=["mcp"], env=env)) as (r, w),
        ClientSession(r, w) as s,
    ):
        await s.initialize()
        tools = {t.name for t in (await s.list_tools()).tools}
        check("kubenoob_web_fetch" not in tools, "web tool registered under the offline lock")
        check(
            {"kubenoob_learning_summary", "kubenoob_learning_note_add", "kubenoob_learning_profile_set"} <= tools,
            "learning tools are missing",
        )

        posture = _json(await s.call_tool("kubenoob_config_status", {}))["posture"]
        check(
            posture["offlineLock"] and posture["network"]["web"] == "locked-off" and posture["conflicts"],
            "posture does not report the lock and the webEnabled conflict",
        )

        note = {"symptom": "orders-api pods rejected by restricted-v2 SCC", "cause": "chart hard-codes runAsUser 1000"}
        secret = await s.call_tool(
            "kubenoob_learning_note_add", {**note, "fix": "token: abc123def456", "confirmed_by_user": True}
        )
        check(secret.is_error, "a note carrying a credential was stored")
        unconfirmed = await s.call_tool(
            "kubenoob_learning_note_add", {**note, "fix": "drop runAsUser", "confirmed_by_user": False}
        )
        check(unconfirmed.is_error, "an unconfirmed note was stored")
        extra = await s.call_tool(
            "kubenoob_learning_note_add", {**note, "fix": "drop runAsUser", "confirmed_by_user": True, "sneaky": 1}
        )
        check(extra.is_error, "unknown arguments were accepted")
        saved = _json(
            await s.call_tool(
                "kubenoob_learning_note_add",
                {**note, "fix": "drop runAsUser on OpenShift", "platform": "openshift", "confirmed_by_user": True},
            )
        )
        chunk = saved["citation"].strip("[]")
        hits = _json(
            await s.call_tool("kubenoob_search_knowledge", {"query": "orders-api restricted-v2 runAsUser chart"})
        )
        check(any(h["chunkId"] == chunk for h in hits["results"]), "confirmed note is not searchable")

        dx = _json(
            await s.call_tool(
                "kubenoob_diagnose", {"text": "Reason: OOMKilled\nExit Code: 137\nReason: CrashLoopBackOff"}
            )
        )
        top = dx["diagnoses"][0]
        check(
            top["id"] == "DBG-OOM" and "#" not in top["readOnlyNextSteps"][0].get("command", ""),
            "OOM is not ranked first or its first step carries a shell comment",
        )

        prompts = {p.name for p in (await s.list_prompts()).prompts}
        check(
            {"getting_started", "debug_session", "tutor", "master_controller"} <= prompts,
            "MCP prompts are missing",
        )
    mode = os.stat(os.path.join(data, "learning.json")).st_mode & 0o777
    check(mode == 0o600, f"learning.json mode is {oct(mode)}, expected 0o600")
    print(
        f"MCP offline e2e OK: {len(tools)} tools, posture={posture['status']}, note {chunk} searchable, top={top['id']}"
    )


if __name__ == "__main__":
    asyncio.run(main(sys.argv[1]))
