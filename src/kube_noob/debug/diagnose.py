"""Debugging: match symptoms (events, describe output, logs, CLI errors, status JSON) to playbooks.

Offline by default. ``debug_workload`` additionally collects live, read-only evidence when cluster access is enabled.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any

from kube_noob.debug.cluster import Backend, redact_text
from kube_noob.debug.playbooks import EXIT_CODES, PLAYBOOKS, Playbook
from kube_noob.debug.steps import classify_step, split_comment
from kube_noob.errors import ClusterAccessError

MAX_INPUT = 400_000

_COMPILED: dict[str, list[re.Pattern[str]]] = {
    p.pid: [re.compile(s, re.IGNORECASE) for s in p.signals] for p in PLAYBOOKS
}

_NS_PATTERNS = (
    re.compile(r"(?:-n|--namespace)[ =]([a-z0-9][-a-z0-9]{0,62})"),
    re.compile(r"\bNamespace:\s+([a-z0-9][-a-z0-9]{0,62})"),
    re.compile(r"\"namespace\":\s*\"([a-z0-9][-a-z0-9]{0,62})\""),
    re.compile(r"namespace \"?([a-z0-9][-a-z0-9]{0,62})\"?"),
)
_POD_PATTERNS = (
    re.compile(r"\bpod[/ ]\"?([a-z0-9][-a-z0-9.]{0,252})\"?"),
    re.compile(r"^Name:\s+([a-z0-9][-a-z0-9.]{0,252})$", re.MULTILINE),
)
_PVC_PATTERN = re.compile(r"(?:persistentvolumeclaim|pvc)[/ ]\"?([a-z0-9][-a-z0-9.]{0,252})\"?", re.IGNORECASE)
_SA_PATTERN = re.compile(r"system:serviceaccount:[a-z0-9-]+:([a-z0-9][-a-z0-9]{0,62})")
_EXIT_PATTERN = re.compile(r"(?:exit ?code|exitCode)[\"':\s]+(\d{1,3})", re.IGNORECASE)


@dataclass
class Diagnosis:
    playbook: Playbook
    score: float
    evidence: list[str]
    checks: list[str]

    def as_dict(self) -> dict[str, Any]:
        p = self.playbook
        return {
            "id": p.pid,
            "title": p.title,
            "confidence": round(min(1.0, self.score / 3.0), 2),
            "evidence": self.evidence,
            "rootCauses": list(p.root_causes),
            # Diagnose before change: read-only evidence first; anything that executes or mutates needs approval.
            "readOnlyNextSteps": [_step(c) for c in self.checks if classify_step(c) == "read"],
            "diagnosticCommands": [
                {**_step(c), "requiresApproval": True} for c in self.checks if classify_step(c) == "exec"
            ],
            "proposedChanges": [{"change": f, "requiresApproval": True} for f in p.fixes],
            "relatedRules": list(p.related_rules),
            "knowledge": list(p.knowledge),
        }


def _step(check: str) -> dict[str, str]:
    """A copy-paste-safe step: the bare command plus why it helps, or a plain instruction for prose guidance."""
    cmd, why = split_comment(check)
    if re.match(r"^[a-z][\w.-]*\s", cmd + " ") is None:
        return {"instruction": check.strip()}
    return {"command": cmd, **({"why": why} if why else {})}


def _step_line(step: dict[str, str]) -> str:
    if "command" not in step:
        return f"- {step['instruction']}"
    return f"- `{step['command']}`" + (f": {step['why']}" if step.get("why") else "")


@dataclass
class DiagnoseResult:
    diagnoses: list[Diagnosis]
    context: dict[str, str]
    exit_codes: dict[int, str] = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "approach": (
                "Run the read-only steps first (get, describe, logs, events). Commands that execute in a container or "
                "change the cluster are listed separately and require explicit approval."
            ),
            "context": self.context,
            "exitCodes": {str(k): v for k, v in self.exit_codes.items()},
            "diagnoses": [d.as_dict() for d in self.diagnoses],
            "notes": self.notes,
        }


def _first(patterns: tuple[re.Pattern[str], ...], text: str) -> str | None:
    for p in patterns:
        m = p.search(text)
        if m:
            return m.group(1)
    return None


def extract_context(text: str) -> dict[str, str]:
    ctx: dict[str, str] = {}
    ns = _first(_NS_PATTERNS, text)
    if ns:
        ctx["ns"] = ns
    pod = _first(_POD_PATTERNS, text)
    if pod:
        ctx["pod"] = pod
        ctx.setdefault("name", pod)
    m = _PVC_PATTERN.search(text)
    if m:
        ctx["pvc"] = m.group(1)
    m = _SA_PATTERN.search(text)
    if m:
        ctx["sa"] = m.group(1)
    return ctx


def _fill(cmd: str, ctx: dict[str, str]) -> str:
    out = cmd
    defaults = {"ns": "<namespace>", "pod": "<pod>", "name": "<name>", "pvc": "<pvc>", "sa": "default"}
    for key, default in defaults.items():
        out = out.replace("{" + key + "}", ctx.get(key, default))
    return out.replace("{{", "{").replace("}}", "}")


def diagnose(text: str, platform: str | None = None, limit: int = 5) -> DiagnoseResult:
    if len(text) > MAX_INPUT:
        text = text[-MAX_INPUT:]
    text = redact_text(text)
    ctx = extract_context(text)
    lines = text.splitlines()
    results: list[Diagnosis] = []
    for p in PLAYBOOKS:
        if platform and platform not in p.platforms:
            continue
        evidence: list[str] = []
        hits = 0
        for pat in _COMPILED[p.pid]:
            matched_line = next((ln.strip() for ln in lines if pat.search(ln)), None)
            if matched_line is None and pat.search(text):
                matched_line = pat.pattern
            if matched_line is not None:
                hits += 1
                clipped = matched_line[:300]
                if clipped not in evidence:
                    evidence.append(clipped)
        if hits:
            score = hits * p.weight
            results.append(Diagnosis(p, score, evidence[:5], [_fill(c, ctx) for c in p.checks]))
    results.sort(key=lambda d: (-d.score, d.playbook.pid))
    codes = {int(c) for c in _EXIT_PATTERN.findall(text)}
    exit_info = {c: EXIT_CODES[c] for c in sorted(codes) if c in EXIT_CODES}
    notes: list[str] = []
    if not results:
        notes.append(
            "No playbook matched. Paste `oc describe pod`, `oc get events --sort-by=.lastTimestamp` and "
            "`oc logs --previous` output for a better diagnosis."
        )
    return DiagnoseResult(results[:limit], ctx, exit_info, notes)


# --- live collection ---------------------------------------------------------------------------------------

WORKLOAD_RESOURCES = {
    "deployment": "deployments",
    "deployments": "deployments",
    "statefulset": "statefulsets",
    "statefulsets": "statefulsets",
    "daemonset": "daemonsets",
    "daemonsets": "daemonsets",
    "job": "jobs",
    "jobs": "jobs",
    "pod": "pods",
    "pods": "pods",
}


def _selector_string(sel: dict[str, Any]) -> str:
    return ",".join(f"{k}={v}" for k, v in sorted((sel.get("matchLabels") or {}).items()))


def _pod_summary(pod: dict[str, Any]) -> list[str]:
    out: list[str] = []
    name = pod.get("metadata", {}).get("name")
    status = pod.get("status", {})
    out.append(f"pod/{name} phase={status.get('phase')} node={pod.get('spec', {}).get('nodeName')}")
    for cond in status.get("conditions") or []:
        if cond.get("status") != "True":
            out.append(
                f"  condition {cond.get('type')}={cond.get('status')} {cond.get('reason', '')} "
                f"{cond.get('message', '')}"
            )
    for cs in (status.get("initContainerStatuses") or []) + (status.get("containerStatuses") or []):
        state, last = cs.get("state") or {}, cs.get("lastState") or {}
        for k, v in state.items():
            if k != "running":
                out.append(
                    f"  container {cs.get('name')} {k}: {v.get('reason', '')} {v.get('message', '')} "
                    f"exitCode: {v.get('exitCode', '')}"
                )
        if "terminated" in last:
            t = last["terminated"]
            out.append(
                f"  container {cs.get('name')} lastState terminated: {t.get('reason')} exitCode: {t.get('exitCode')}"
            )
        out.append(f"  container {cs.get('name')} ready={cs.get('ready')} restartCount: {cs.get('restartCount')}")
    return out


def collect_evidence(backend: Backend, namespace: str, kind: str, name: str, log_lines: int = 100) -> dict[str, Any]:
    resource = WORKLOAD_RESOURCES.get(kind.lower())
    if resource is None:
        raise ClusterAccessError(f"Unsupported workload kind {kind!r}; use one of {sorted(set(WORKLOAD_RESOURCES))}")
    lines: list[str] = []
    obj = backend.get(resource, name=name, namespace=namespace)
    pods: list[dict[str, Any]]
    if resource == "pods":
        pods = [obj]
    else:
        st = obj.get("status") or {}
        lines.append(
            f"{kind}/{name} status: "
            + json.dumps(
                {
                    k: st.get(k)
                    for k in (
                        "replicas",
                        "readyReplicas",
                        "availableReplicas",
                        "updatedReplicas",
                        "unavailableReplicas",
                        "failed",
                        "succeeded",
                    )
                    if k in st
                }
            )
        )
        for cond in st.get("conditions") or []:
            lines.append(
                f"  condition {cond.get('type')}={cond.get('status')} {cond.get('reason', '')}: "
                f"{cond.get('message', '')}"
            )
        sel = (obj.get("spec") or {}).get("selector") or {}
        sel_str = _selector_string(sel) if resource != "jobs" else f"job-name={name}"
        pods = backend.get("pods", namespace=namespace, selector=sel_str or None).get("items", []) if sel_str else []
    for pod in pods[:10]:
        lines.extend(_pod_summary(pod))
    events = backend.get("events", namespace=namespace).get("items", [])
    names = {name} | {p.get("metadata", {}).get("name") for p in pods}
    rel = [
        e
        for e in events
        if (e.get("involvedObject") or {}).get("name") in names
        or str((e.get("involvedObject") or {}).get("name", "")).startswith(name)
    ]
    rel.sort(key=lambda e: e.get("lastTimestamp") or e.get("eventTime") or "")
    for e in rel[-40:]:
        io = e.get("involvedObject") or {}
        lines.append(f"event {e.get('type')} {e.get('reason')} {io.get('kind')}/{io.get('name')}: {e.get('message')}")
    logs: dict[str, str] = {}
    for pod in pods[:3]:
        pname = pod.get("metadata", {}).get("name")
        for cs in (pod.get("status") or {}).get("containerStatuses") or []:
            crashed = bool((cs.get("lastState") or {}).get("terminated")) or cs.get("restartCount", 0) > 0
            try:
                logs[f"{pname}/{cs.get('name')}"] = backend.logs(
                    namespace, pname, cs.get("name"), log_lines, previous=crashed
                )
            except ClusterAccessError as exc:
                logs[f"{pname}/{cs.get('name')}"] = f"<logs unavailable: {exc}>"
    return {"summary": lines, "logs": logs, "object": obj}


def debug_workload(
    backend: Backend, namespace: str, kind: str, name: str, platform: str | None = None, log_lines: int = 100
) -> dict[str, Any]:
    ev = collect_evidence(backend, namespace, kind, name, log_lines)
    blob = "\n".join(ev["summary"]) + "\n" + "\n".join(ev["logs"].values())
    blob += f"\nNamespace: {namespace}\n"
    result = diagnose(blob, platform=platform)
    if "pod" not in result.context:
        result.context["name"] = name
    return {
        "backend": backend.name,
        "target": f"{kind}/{namespace}/{name}",
        "evidence": ev["summary"],
        "logs": {k: v[-6000:] for k, v in ev["logs"].items()},
        **result.as_dict(),
    }


def bundle_markdown(result: dict[str, Any]) -> str:
    """Human-readable diagnostic bundle: evidence first, then read-only steps, then gated commands and changes."""
    lines = [
        f"# Diagnostic bundle: {result['target']}",
        "",
        f"Collected read-only via `{result['backend']}`. Secrets were not read; sensitive values are redacted.",
        "",
        "## Evidence",
        *(f"- {e}" for e in result.get("evidence", [])),
    ]
    for d in result.get("diagnoses", []):
        lines += ["", f"## {d['id']}: {d['title']} (confidence {d['confidence']})", "", "Likely causes:"]
        lines += [f"- {c}" for c in d["rootCauses"]]
        lines += ["", "Read-only next steps:", *(_step_line(s) for s in d["readOnlyNextSteps"])]
        if d["diagnosticCommands"]:
            lines += ["", "Diagnostic commands that execute in a container (require approval):"]
            lines += [_step_line(c) for c in d["diagnosticCommands"]]
        lines += ["", "Proposed changes (require approval):"]
        lines += [f"- {c['change']}" for c in d["proposedChanges"]]
    if result.get("logs"):
        lines += ["", "## Recent logs (redacted)"]
        for name, text in result["logs"].items():
            lines += ["", f"### {name}", "```", text[-3000:], "```"]
    return "\n".join(lines) + "\n"
