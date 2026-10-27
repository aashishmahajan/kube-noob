"""Measure kube-noob's memory: the stdio MCP server (Claude plugin, local MCP clients) and the HTTP service (sidecar,
OpenShift service), idle and after a realistic workload.

Usage: python scripts/measure_footprint.py [--kube-noob PATH] [--corpus DOCS_DIR] [--json]
Linux only (reads /proc). Starts each server with a throwaway data dir, web and cluster off, then reports resident
memory (RSS) after start-up and the peak (VmHWM) after: listing tools, a knowledge search (builds the index), an audit,
a diagnosis and a full 7-step protocol run. With --corpus, a folder of Markdown is indexed first (as
`kube-noob corpus add-docs` does for team runbooks), to size a server that carries a large corpus. Use the peak plus
headroom to size requests and limits.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

import httpx
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = (ROOT / "examples" / "insecure-deployment.yaml").read_text()
EVENTS = (ROOT / "examples" / "events-scc.txt").read_text()
BLUEPRINT = {
    "name": "orders-api",
    "namespace": "shop",
    "image": "quay.io/acme/orders@sha256:" + "a" * 64,
    "platform": "rosa-hcp",
    "platformVersion": "4.22",
    "storage": {"size": "20Gi", "accessMode": "ReadWriteMany"},
    "exposure": {"type": "route", "host": "orders.apps.example.com"},
}
CALLS: list[tuple[str, dict[str, Any]]] = [
    ("kubenoob_search_knowledge", {"query": "restricted-v2 SCC runAsUser range"}),
    ("kubenoob_audit_manifests", {"manifests": MANIFEST, "platform": "openshift", "version": "4.22"}),
    ("kubenoob_diagnose", {"text": EVENTS, "platform": "openshift"}),
    ("kubenoob_run_protocol", {"request": "Deploy orders-api on ROSA HCP", "blueprint": BLUEPRINT}),
]


def _mib(pid: int, field: str) -> float:
    for line in Path(f"/proc/{pid}/status").read_text().splitlines():
        if line.startswith(field + ":"):
            return int(line.split()[1]) / 1024
    raise RuntimeError(f"{field} missing for pid {pid}")


def _find(pattern: str) -> int:
    me = os.getpid()
    for d in Path("/proc").iterdir():
        if not d.name.isdigit() or int(d.name) == me:
            continue
        try:
            cmd = (d / "cmdline").read_bytes().replace(b"\0", b" ").decode()
        except OSError:
            continue
        if pattern in cmd and "measure_footprint" not in cmd:
            return int(d.name)
    raise RuntimeError(f"no process matching {pattern!r}")


CORPUS: str | None = None
EXE = "kube-noob"


def _new_data_dir() -> str:
    data = tempfile.mkdtemp(prefix="kn-mem-")
    if CORPUS:
        subprocess.run(
            [EXE, "corpus", "add-docs", CORPUS, "--source", "sizing"],
            env=_env(data),
            check=True,
            stdout=subprocess.DEVNULL,
        )
    return data


def _env(data: str) -> dict[str, str]:
    env = {k: v for k, v in os.environ.items() if not k.startswith("KUBE_NOOB_")}
    env.update(
        {
            "KUBE_NOOB_DATA_DIR": data,
            "XDG_CONFIG_HOME": data,
            "KUBE_NOOB_WEB_ENABLED": "false",
            "KUBE_NOOB_CLUSTER_ENABLED": "false",
            "KUBE_NOOB_LLM_PROVIDER": "none",
        }
    )
    return env


async def stdio(exe: str) -> dict[str, float]:
    data = _new_data_dir()
    params = StdioServerParameters(command=exe, args=["mcp"], env=_env(data))
    async with stdio_client(params) as (r, w), ClientSession(r, w) as s:
        await s.initialize()
        pid = _find(f"{exe} mcp")
        idle = _mib(pid, "VmRSS")
        await s.list_tools()
        for name, args in CALLS:
            res = await s.call_tool(name, args)
            if res.is_error:
                raise SystemExit(f"{name} failed: {res.content[0].text}")
        out = {"rssIdleMiB": idle, "rssAfterMiB": _mib(pid, "VmRSS"), "peakMiB": _mib(pid, "VmHWM")}
    shutil.rmtree(data, ignore_errors=True)
    return out


def http(exe: str) -> dict[str, float]:
    data = _new_data_dir()
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    env = {**_env(data), "KUBE_NOOB_HTTP_TOKEN": "measure-token"}
    proc = subprocess.Popen(
        [exe, "serve", "--host", "127.0.0.1", "--port", str(port)],
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    url = f"http://127.0.0.1:{port}/mcp"
    headers = {
        "Accept": "application/json, text/event-stream",
        "Content-Type": "application/json",
        "MCP-Protocol-Version": "2025-06-18",
        "Authorization": "Bearer measure-token",
    }
    try:
        with httpx.Client(timeout=120) as client:
            for _ in range(100):
                try:
                    client.get(f"http://127.0.0.1:{port}/healthz")
                    break
                except httpx.TransportError:
                    time.sleep(0.1)
            idle = _mib(proc.pid, "VmRSS")

            def rpc(n: int, method: str, params: dict[str, Any]) -> None:
                body = {"jsonrpc": "2.0", "id": n, "method": method, "params": params}
                resp = client.post(url, json=body, headers=headers)
                if resp.status_code != 200:
                    raise SystemExit(f"{method}: HTTP {resp.status_code} {resp.text[:300]}")

            rpc(
                1,
                "initialize",
                {
                    "protocolVersion": "2025-06-18",
                    "capabilities": {},
                    "clientInfo": {"name": "measure", "version": "1"},
                },
            )
            rpc(2, "tools/list", {})
            for i, (name, args) in enumerate(CALLS, start=3):
                rpc(i, "tools/call", {"name": name, "arguments": args})
            return {"rssIdleMiB": idle, "rssAfterMiB": _mib(proc.pid, "VmRSS"), "peakMiB": _mib(proc.pid, "VmHWM")}
    finally:
        proc.terminate()
        proc.wait(timeout=10)
        shutil.rmtree(data, ignore_errors=True)


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--kube-noob", default=shutil.which("kube-noob") or "kube-noob")
    ap.add_argument("--corpus", help="a folder of Markdown/AsciiDoc/text to index before measuring")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args()
    global CORPUS, EXE
    CORPUS, EXE = a.corpus, a.kube_noob
    if not Path("/proc/self/status").exists():
        raise SystemExit("Linux only: needs /proc")
    results = {
        "stdio (plugin, local MCP)": asyncio.run(stdio(a.kube_noob)),
        "http (sidecar, service)": http(a.kube_noob),
    }
    if a.json:
        print(json.dumps(results, indent=2))
        return
    print(f"{'mode':28} {'idle MiB':>9} {'after MiB':>10} {'peak MiB':>9}")
    for mode, r in results.items():
        print(f"{mode:28} {r['rssIdleMiB']:9.0f} {r['rssAfterMiB']:10.0f} {r['peakMiB']:9.0f}")
    print(f"python {sys.version.split()[0]}")


if __name__ == "__main__":
    main()
