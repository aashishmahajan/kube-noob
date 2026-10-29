"""In-cluster check of kube-noob-admission (CI job admission-kind, requirements R3.3).

1. Fuzz: ``--fuzz`` AdmissionReviews built from mutated workloads (wrong types, missing fields, odd operations,
   deep nesting, long and non-ASCII strings) are sent to the webhook. In warn mode every one must be admitted, and
   every response must be a well-formed AdmissionReview v1 for the same uid, with no patch and bounded warnings.
2. Load: a steady ``--rate`` requests per second for ``--seconds`` seconds of a workload with findings; every request
   must succeed and the 99th percentile latency, measured by the client, must stay under ``--p99-ms``.

It reads no cluster objects and needs only the webhook's Service URL and the CA that signed its certificate.
Usage: python admission_kind_load.py https://<service>.<namespace>.svc/validate ca.crt [--rate 50] [--seconds 30]
"""

from __future__ import annotations

import argparse
import copy
import json
import random
import sys
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from typing import Any

import httpx

API_VERSION = "admission.k8s.io/v1"
WARNING_CHARS = 256

BASE: dict[str, Any] = {
    "apiVersion": "apps/v1",
    "kind": "Deployment",
    "metadata": {"name": "web", "namespace": "shop", "labels": {"app": "web"}},
    "spec": {
        "replicas": 2,
        "selector": {"matchLabels": {"app": "web"}},
        "template": {
            "metadata": {"labels": {"app": "web"}},
            "spec": {
                "containers": [
                    {
                        "name": "web",
                        "image": "registry.example.com/web:1.0",
                        "securityContext": {"privileged": True},
                        "ports": [{"containerPort": 8080}],
                    }
                ]
            },
        },
    },
}
KINDS = ["Deployment", "StatefulSet", "DaemonSet", "Pod", "Service", "Job", "CronJob", "Ingress", "Role", "Thing"]
ODD = [
    None,
    True,
    0,
    -1,
    1e308,
    "",
    "x" * 5000,
    "".join(map(chr, (0x202E, 0x0, 0xD7FF))),
    [],
    {},
    [[[[]]]],
    {"a": {"b": {"c": {}}}},
]
OPERATIONS = ["CREATE", "UPDATE", "DELETE", "CONNECT", "PATCH", "", None]


def _paths(obj: Any, prefix: tuple[Any, ...] = ()) -> list[tuple[Any, ...]]:
    out = [prefix]
    if isinstance(obj, dict):
        for k, v in obj.items():
            out += _paths(v, (*prefix, k))
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            out += _paths(v, (*prefix, i))
    return out


def _set(obj: Any, path: tuple[Any, ...], value: Any) -> Any:
    if not path:
        return value
    cur = obj
    for p in path[:-1]:
        cur = cur[p]
    cur[path[-1]] = value
    return obj


def mutate(rng: random.Random) -> dict[str, Any]:
    obj: Any = copy.deepcopy(BASE)
    if rng.random() < 0.5:
        obj["kind"] = rng.choice(KINDS)
    for _ in range(rng.randint(0, 6)):
        path = rng.choice(_paths(obj))
        try:
            obj = _set(obj, path, copy.deepcopy(rng.choice(ODD)))
        except (TypeError, KeyError, IndexError):
            continue
    return obj if isinstance(obj, dict) else {"value": obj}


def review(obj: Any, rng: random.Random) -> dict[str, Any]:
    request: dict[str, Any] = {
        "uid": str(uuid.UUID(int=rng.getrandbits(128))),
        "kind": {"group": "apps", "version": "v1", "kind": obj.get("kind") if isinstance(obj, dict) else "x"},
        "resource": {"group": "apps", "version": "v1", "resource": "deployments"},
        "namespace": rng.choice(["shop", "payments", "", "kube-system", "openshift-monitoring"]),
        "operation": rng.choice(OPERATIONS),
        "userInfo": {"username": "fuzz"},
        "object": obj,
    }
    if request["operation"] == "UPDATE" or rng.random() < 0.1:
        request["oldObject"] = mutate(rng)
    if rng.random() < 0.05:
        request["subResource"] = rng.choice(["status", "scale", "exec"])
    return {"apiVersion": API_VERSION, "kind": "AdmissionReview", "request": request}


def check(sent: dict[str, Any], resp: httpx.Response, max_warnings: int) -> str | None:
    if resp.status_code != 200:
        return f"HTTP {resp.status_code}"
    try:
        out = resp.json()
    except ValueError:
        return "not JSON"
    r = out.get("response") if isinstance(out, dict) else None
    if out.get("apiVersion") != API_VERSION or out.get("kind") != "AdmissionReview" or not isinstance(r, dict):
        return f"not an AdmissionReview v1: {str(out)[:200]}"
    if r.get("uid") != sent["request"]["uid"]:
        return "uid differs"
    if "patch" in r or "patchType" in r:
        return "a patch: the webhook must never mutate"
    if r.get("allowed") is not True:
        return f"denied in warn mode: {r.get('status')}"
    warnings = r.get("warnings") or []
    if len(warnings) > max_warnings + 1 or any(len(w) > WARNING_CHARS for w in warnings):
        return f"warnings out of bounds: {len(warnings)}"
    return None


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("url")
    ap.add_argument("ca")
    ap.add_argument("--fuzz", type=int, default=500)
    ap.add_argument("--rate", type=float, default=50.0)
    ap.add_argument("--seconds", type=float, default=30.0)
    ap.add_argument("--p99-ms", type=float, default=50.0)
    ap.add_argument("--max-warnings", type=int, default=10)
    ap.add_argument("--seed", type=int, default=20261028)
    a = ap.parse_args(argv)
    rng = random.Random(a.seed)  # noqa: S311 - reproducible fuzz cases, not crypto
    failures: list[str] = []
    with httpx.Client(verify=a.ca, timeout=10.0) as client:
        for i in range(a.fuzz):
            sent = review(mutate(rng), rng)
            try:
                why = check(sent, client.post(a.url, content=json.dumps(sent)), a.max_warnings)
            except httpx.HTTPError as exc:
                why = f"{type(exc).__name__}: {exc}"
            if why:
                failures.append(f"fuzz case {i}: {why}")
                if len(failures) >= 20:
                    break
    local = threading.local()

    def one(body: bytes, uid: str) -> tuple[float, str | None]:
        if not hasattr(local, "client"):
            local.client = httpx.Client(verify=a.ca, timeout=10.0)
        start = time.perf_counter()
        try:
            resp = local.client.post(a.url, content=body)
        except httpx.HTTPError as exc:
            return time.perf_counter() - start, f"{type(exc).__name__}"
        took = time.perf_counter() - start
        sent = {"request": {"uid": uid}}
        return took, check(sent, resp, a.max_warnings)

    total = int(a.rate * a.seconds)
    futures = []
    with ThreadPoolExecutor(max_workers=16) as pool:
        begin = time.perf_counter()
        for i in range(total):
            delay = begin + i / a.rate - time.perf_counter()
            if delay > 0:
                time.sleep(delay)
            sent = review(copy.deepcopy(BASE), rng)
            sent["request"]["operation"], sent["request"]["namespace"] = "CREATE", "shop"
            futures.append(pool.submit(one, json.dumps(sent).encode(), sent["request"]["uid"]))
        results = [f.result() for f in futures]
        elapsed = time.perf_counter() - begin
    latencies = sorted(t for t, _ in results)
    errors = [w for _, w in results if w]
    p99 = latencies[max(0, int(len(latencies) * 0.99) - 1)] * 1000 if latencies else float("inf")
    p50 = latencies[len(latencies) // 2] * 1000 if latencies else float("inf")
    summary = {
        "fuzzCases": a.fuzz,
        "fuzzFailures": len(failures),
        "requests": total,
        "seconds": round(elapsed, 1),
        "ratePerSecond": round(total / elapsed, 1) if elapsed else 0,
        "p50ms": round(p50, 2),
        "p99ms": round(p99, 2),
        "maxms": round(latencies[-1] * 1000, 2) if latencies else None,
        "errors": len(errors),
    }
    print(json.dumps(summary))
    for f in [*failures[:10], *errors[:10]]:
        print(f, file=sys.stderr)
    if failures or errors or p99 >= a.p99_ms:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
