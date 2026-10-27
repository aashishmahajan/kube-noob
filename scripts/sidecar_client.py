"""What an app container does with the kube-noob sidecar: call its MCP tools on 127.0.0.1 over HTTP (JSON-RPC).

Usage (inside the app container of the pod): python sidecar_client.py [--url http://127.0.0.1:8080/mcp]
Standard library only, so it runs in any Python container. Prints each step; exits 1 if a step fails.
"""

from __future__ import annotations

import argparse
import json
import sys
import urllib.request
from typing import Any

MANIFEST = """\
apiVersion: apps/v1
kind: Deployment
metadata: {name: api, namespace: shop}
spec:
  selector: {matchLabels: {app: api}}
  template:
    metadata: {labels: {app: api}}
    spec:
      containers:
        - name: api
          image: quay.io/acme/api:latest
          securityContext: {runAsUser: 1000, allowPrivilegeEscalation: true}
          env: [{name: DB_PASSWORD, value: hunter2}]
"""
EVENTS = """\
Last State:     Terminated
  Reason:       OOMKilled
  Exit Code:    137
Warning  BackOff  kubelet  Back-off restarting failed container api in pod api-7d9f
"""


class Mcp:
    def __init__(self, url: str) -> None:
        self.url, self.n = url, 0

    def call(self, method: str, params: dict[str, Any]) -> dict[str, Any]:
        self.n += 1
        body = json.dumps({"jsonrpc": "2.0", "id": self.n, "method": method, "params": params}).encode()
        req = urllib.request.Request(  # noqa: S310 - loopback URL given by the operator
            self.url,
            data=body,
            headers={
                "Content-Type": "application/json",
                "Accept": "application/json, text/event-stream",
                "MCP-Protocol-Version": "2025-06-18",
            },
        )
        with urllib.request.urlopen(req, timeout=60) as resp:  # noqa: S310
            data = json.load(resp)
        if "error" in data:
            raise SystemExit(f"{method}: {data['error']}")
        return data["result"]  # type: ignore[no-any-return]

    def tool(self, name: str, args: dict[str, Any]) -> dict[str, Any]:
        res = self.call("tools/call", {"name": name, "arguments": args})
        if res.get("isError"):
            raise SystemExit(f"{name}: {res['content'][0]['text'][:300]}")
        return res.get("structuredContent") or json.loads(res["content"][0]["text"])


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", default="http://127.0.0.1:8080/mcp")
    url = ap.parse_args().url
    mcp = Mcp(url)
    info = mcp.call(
        "initialize",
        {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "app", "version": "1"}},
    )["serverInfo"]
    tools = [t["name"] for t in mcp.call("tools/list", {})["tools"]]
    print(f"connected to {info['name']} {info['version']} at {url}: {len(tools)} tools")

    audit = mcp.tool("kubenoob_audit_manifests", {"manifests": MANIFEST, "platform": "openshift", "version": "4.22"})
    counts = audit["summary"]["counts"]
    print(f"audit: score {audit['summary']['score']}/100, high={counts['high']} medium={counts['medium']}")
    for f in [f for f in audit["findings"] if f["severity"] in {"critical", "high"}][:3]:
        print(f"  [{f['severity'].upper()}] {f['ruleId']}: {f['message']}")

    dx = mcp.tool("kubenoob_diagnose", {"text": EVENTS, "platform": "openshift"})["diagnoses"][0]
    print(f"diagnose: {dx['id']} - {dx['title']}")
    for step in dx["readOnlyNextSteps"][:2]:
        print(f"  read-only first: {step.get('command') or step.get('instruction')}")

    hits = mcp.tool("kubenoob_search_knowledge", {"query": "restricted-v2 SCC runAsUser range", "limit": 2})
    for r in hits["results"]:
        print(f"cited: [{r['chunkId']}] {r['title']}")
    posture = mcp.tool("kubenoob_config_status", {})["posture"]
    print(
        f"posture: web {posture['network']['web']}, cluster {'on' if posture['cluster']['enabled'] else 'off'}, "
        f"model {posture['model']['provider']}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
