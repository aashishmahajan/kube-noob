#!/usr/bin/env python3
"""End-to-end check of a running kube-noob MCP server over streamable HTTP (JSON-RPC).

Usage: python scripts/e2e_mcp_http.py --url http://127.0.0.1:8080/mcp --token TOKEN [--cluster-namespace demo
       --cluster-deployment crasher]
Exits non-zero on the first failed expectation. Used by CI against a kind cluster.
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Any

import httpx

PROTOCOL = "2025-06-18"


class Rpc:
    def __init__(self, url: str, token: str | None) -> None:
        self.url = url
        self.headers = {
            "Accept": "application/json, text/event-stream",
            "Content-Type": "application/json",
            "MCP-Protocol-Version": PROTOCOL,
        }
        if token:
            self.headers["Authorization"] = f"Bearer {token}"
        self.n = 0
        self.http = httpx.Client(timeout=120)

    def call(self, method: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        self.n += 1
        body = {"jsonrpc": "2.0", "id": self.n, "method": method, "params": params or {}}
        r = self.http.post(self.url, json=body, headers=self.headers)
        if r.status_code != 200:
            raise SystemExit(f"{method}: HTTP {r.status_code} {r.text[:500]}")
        data = r.json()
        if "error" in data:
            raise SystemExit(f"{method}: {data['error']}")
        return data["result"]  # type: ignore[no-any-return]

    def tool(self, name: str, args: dict[str, Any]) -> dict[str, Any]:
        res = self.call("tools/call", {"name": name, "arguments": args})
        if res.get("isError"):
            raise SystemExit(f"{name} failed: {res['content'][0]['text'][:500]}")
        return res.get("structuredContent") or json.loads(res["content"][0]["text"])


def expect(cond: bool, msg: str) -> None:
    print(("PASS " if cond else "FAIL ") + msg)
    if not cond:
        sys.exit(1)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", required=True)
    ap.add_argument("--token")
    ap.add_argument("--cluster-namespace")
    ap.add_argument("--cluster-deployment")
    a = ap.parse_args()

    if a.token:
        unauth = httpx.post(
            a.url,
            json={"jsonrpc": "2.0", "id": 0, "method": "tools/list"},
            headers={"Content-Type": "application/json"},
            timeout=30,
        )
        expect(unauth.status_code == 401, "request without token is rejected (401)")

    rpc = Rpc(a.url, a.token)
    init = rpc.call(
        "initialize",
        {"protocolVersion": PROTOCOL, "capabilities": {}, "clientInfo": {"name": "kube-noob-e2e", "version": "1"}},
    )
    expect(init["serverInfo"]["name"] == "kube_noob_mcp", "initialize returns kube_noob_mcp")
    tools = {t["name"] for t in rpc.call("tools/list")["tools"]}
    expect({"kubenoob_run_protocol", "kubenoob_audit_manifests", "kubenoob_diagnose"} <= tools, "core tools listed")
    expect("kubenoob_web_fetch" not in tools, "web tool absent (webEnabled: false)")

    bad = (
        "apiVersion: apps.openshift.io/v1\nkind: Route\nmetadata: {name: r, namespace: a}\n"
        "spec: {to: {kind: Service, name: s}}\n"
    )
    audit = rpc.tool("kubenoob_audit_manifests", {"manifests": bad, "platform": "openshift"})
    expect(any(f["ruleId"] == "KN-V002" for f in audit["findings"]), "audit catches wrong Route apiVersion")

    if a.cluster_namespace and a.cluster_deployment:
        expect("kubenoob_cluster_debug_workload" in tools, "cluster tools listed (cluster.enabled)")
        dbg = rpc.tool(
            "kubenoob_cluster_debug_workload",
            {"namespace": a.cluster_namespace, "kind": "deployment", "name": a.cluster_deployment},
        )
        ids = [d["id"] for d in dbg["diagnoses"]]
        print(json.dumps({"diagnoses": ids, "evidence": dbg["evidence"][:6]}, indent=1))
        expect(bool(ids) and ids[0] in {"DBG-CRASHLOOP", "DBG-PROBE", "DBG-OOM"}, "live debug diagnoses crash loop")
        pods = rpc.tool("kubenoob_cluster_get", {"resource": "pods", "namespace": a.cluster_namespace})
        expect(len(pods.get("items", [])) >= 1, "cluster_get lists pods")
        res = rpc.call(
            "tools/call",
            {"name": "kubenoob_cluster_get", "arguments": {"resource": "secrets", "namespace": a.cluster_namespace}},
        )
        expect(bool(res.get("isError")) and "not permitted" in res["content"][0]["text"], "secrets are refused")
    print("e2e OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
