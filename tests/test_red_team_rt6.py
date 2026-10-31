"""Red team RT6: connection-slot starvation, and the numbers that have to stay consistent with it.

Measured on the real server: 70 TCP connections that send nothing make every request answer 503, including the
kubelet's probes, and nothing reclaims them -- ``timeout_keep_alive`` applies between requests on a keep-alive
connection, not to a connection that never made one. That is a property of uvicorn's connection accounting, not
something kube-noob can close in process, so what kube-noob owes here is: a concurrency limit chosen against the
body limit rather than left at a number from when bodies were six times larger, probes that shed traffic instead of
restarting the pod under overload, and a security policy that says so out loud.
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
CLI = (ROOT / "src" / "kube_noob" / "cli.py").read_text(encoding="utf-8")
DEPLOYMENT = (ROOT / "deploy" / "helm" / "kube-noob" / "templates" / "deployment.yaml").read_text(encoding="utf-8")
VALUES = yaml.safe_load((ROOT / "deploy" / "helm" / "kube-noob" / "values.yaml").read_text(encoding="utf-8"))


def _limit_concurrency() -> int:
    m = re.search(r"limit_concurrency=(\d+)", CLI)
    assert m, "serve no longer sets limit_concurrency"
    return int(m.group(1))


def _mib(value: str) -> int:
    assert value.endswith("Mi"), value
    return int(value[:-2])


def test_the_concurrency_limit_and_the_body_limit_stay_consistent() -> None:
    """The two numbers are one decision: the limit exists so requests get 503 instead of piling up in memory, and
    what each one can hold is the body limit. They were set apart -- 64 slots against an 8 MiB body, so 512 MiB of
    buffered body against a 512Mi container limit, exactly the ceiling the kernel kills at. Whatever either number
    becomes, their product has to leave the process room to run."""
    from kube_noob.server.http import MAX_BODY_BYTES

    slots = _limit_concurrency()
    container_limit = _mib(VALUES["resources"]["limits"]["memory"]) * 1024 * 1024
    worst_case_bodies = slots * MAX_BODY_BYTES
    assert worst_case_bodies <= container_limit * 0.75, (
        f"{slots} slots x {MAX_BODY_BYTES} bytes = {worst_case_bodies / 1024 / 1024:.0f} MiB of buffered body "
        f"against a {container_limit / 1024 / 1024:.0f} MiB container limit"
    )


def test_overload_sheds_traffic_rather_than_restarting_the_pod() -> None:
    """Under slot starvation every request answers 503, the probes included. A readiness failure is right -- stop
    sending this pod traffic. A liveness failure restarts it, which does not free the connections and drops the
    work in flight, so liveness must be the slower and more forgiving of the two."""
    probes = yaml.safe_load(re.search(r"(?s)( +readinessProbe:.*?)\n( +resources:)", DEPLOYMENT).group(1))
    ready, live = probes["readinessProbe"], probes["livenessProbe"]
    ready_budget = ready["periodSeconds"] * ready["failureThreshold"]
    live_budget = live["periodSeconds"] * live["failureThreshold"]
    assert live_budget >= ready_budget * 3, (
        f"liveness gives up after {live_budget}s and readiness after {ready_budget}s: a pod under overload is "
        "restarted about as fast as it is taken out of the endpoints, and the restart does not help"
    )
    assert live_budget >= 120, f"liveness gives up after {live_budget}s, which a burst of traffic can outlast"


def test_the_security_policy_states_the_limitation() -> None:
    """A denial of service nobody can close in process is one an operator has to know about before they expose the
    port, so it belongs in the policy rather than in a commit message."""
    policy = (ROOT / "SECURITY.md").read_text(encoding="utf-8")
    assert "idle connection" in policy.lower() or "slow" in policy.lower()
    assert re.search(r"(?i)(reverse proxy|ingress|service mesh|gateway)", policy)
