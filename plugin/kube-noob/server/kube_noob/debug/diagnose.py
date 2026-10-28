"""Debugging: match symptoms (events, describe output, logs, CLI errors, status JSON) to playbooks.

Offline by default. ``debug_workload`` additionally collects live, read-only evidence when cluster access is enabled.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from kube_noob.debug.cluster import Backend, redact_text
from kube_noob.debug.playbooks import EXIT_CODES, PLAYBOOKS, Playbook
from kube_noob.debug.steps import classify_step, split_comment
from kube_noob.errors import ClusterAccessError
from kube_noob.signals import Signal, for_text, playbooks_for

MAX_INPUT = 400_000
SIGNAL_WEIGHT = 1.0  # a playbook that catalogued signals point at gains this much, once: CrashLoopBackOff and
# BackOff name one symptom, so two symptom signals must not outrank the specific cause (OOMKilled) they share
MAX_SIGNALS_SHOWN = 50

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
_SA_PATTERN = re.compile(r"system:serviceaccount:(?P<ns>[a-z0-9][-a-z0-9]{0,62}):([a-z0-9][-a-z0-9]{0,62})")
_SA_SPEC = re.compile(r"\bserviceAccountName[=:]\s*\"?([a-z0-9][-a-z0-9.]{0,252})")
_FORBIDDEN = re.compile(
    r"User \"(?P<subject>[A-Za-z0-9@._:/=+#%-]{1,253})\" cannot (?P<verb>[a-z]+) resource "
    r"\"(?P<resource>[a-z0-9./-]{1,253})\""
    r"(?: in API group \"(?P<group>[a-z0-9.-]*)\")?"
)
_EXIT_PATTERN = re.compile(r"(?:exit ?code|exitCode)[\"':\s]+(\d{1,3})", re.IGNORECASE)


@dataclass
class Diagnosis:
    playbook: Playbook
    score: float
    evidence: list[str]
    checks: list[str]
    fixes: list[str] | None = None  # the playbook's fixes with the names from the input filled in
    causes: list[str] | None = None  # the same for its root causes

    def as_dict(self) -> dict[str, Any]:
        p = self.playbook
        return {
            "id": p.pid,
            "title": p.title,
            "confidence": round(min(1.0, self.score / 3.0), 2),
            "evidence": self.evidence,
            "rootCauses": list(p.root_causes if self.causes is None else self.causes),
            # Diagnose before change: read-only evidence first; anything that executes or mutates needs approval.
            "readOnlyNextSteps": [_step(c) for c in self.checks if classify_step(c) == "read"],
            "diagnosticCommands": [
                {**_step(c), "requiresApproval": True} for c in self.checks if classify_step(c) == "exec"
            ],
            "proposedChanges": [
                {"change": f, "requiresApproval": True} for f in (p.fixes if self.fixes is None else self.fixes)
            ],
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
    signals: list[Signal] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "approach": (
                "Run the read-only steps first (get, describe, logs, events). Commands that execute in a container or "
                "change the cluster are listed separately and require explicit approval."
            ),
            "context": self.context,
            "signals": [x.as_dict() for x in self.signals[:MAX_SIGNALS_SHOWN]],
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


# English words that follow "namespace" in a sentence ("a different namespace from the pod") and are not its name.
_NOT_A_NAMESPACE = frozenset(
    {
        "a", "an", "and", "another", "are", "as", "at", "but", "by", "different", "does", "for", "from", "has", "in",
        "into", "is", "it", "its", "level", "of", "on", "or", "other", "same", "scoped", "than", "that", "the", "then",
        "this", "to", "was", "which", "while", "with", "without",
    }
)  # fmt: skip
# kube-scheduler's Scheduled event: "Successfully assigned <namespace>/<pod> to <node>" (pkg/scheduler/schedule_one.go)
_ASSIGNED = re.compile(r"Successfully assigned ([a-z0-9][-a-z0-9]{0,62})/([a-z0-9][-a-z0-9.]{0,252}) to ")
_PULL_SECRETS = re.compile(r"Unable to retrieve some image pull secrets \(([a-z0-9][-a-z0-9.]{0,252})")


def _namespace(text: str) -> str | None:
    for p in _NS_PATTERNS:
        for m in p.finditer(text):
            if m.group(1) not in _NOT_A_NAMESPACE:
                return m.group(1)
    return None


def extract_context(text: str) -> dict[str, str]:
    ctx: dict[str, str] = {}
    ns = _namespace(text)
    assigned = _ASSIGNED.search(text)
    if ns:
        ctx["ns"] = ns
    elif assigned:
        ctx["ns"] = assigned.group(1)
    m = _PULL_SECRETS.search(text)
    if m:
        ctx["secret"] = m.group(1)
    pod = _first(_POD_PATTERNS, text) or (assigned.group(2) if assigned else None)
    if pod:
        ctx["pod"] = pod
        ctx.setdefault("name", pod)
    m = _PVC_PATTERN.search(text)
    if m:
        ctx["pvc"] = m.group(1)
    m = _SA_PATTERN.search(text)
    if m:
        ctx["sa"], ctx["sa_ns"] = m.group(2), m.group("ns")
    elif m := _SA_SPEC.search(text):
        ctx["sa"] = m.group(1)
    m = _FORBIDDEN.search(text)
    if m:
        ctx["subject"], ctx["verb"] = m.group("subject"), m.group("verb")
        group = m.group("group")
        ctx["resource"] = f"{m.group('resource')}.{group}" if group else m.group("resource")
    return ctx


_SAFE_VALUE = re.compile(r"^[A-Za-z0-9@._:/=+#%-]{1,253}$")  # nothing a shell treats specially, no spaces


def _fill(cmd: str, ctx: dict[str, str]) -> str:
    """``cmd`` with the names found in the input. A value that could do anything in a shell (quotes, $, `, ;, |, &,
    spaces, newlines...) is never pasted into a command: its placeholder stays, so a copied step only ever reads."""
    ctx = {k: v for k, v in ctx.items() if isinstance(v, str) and _SAFE_VALUE.match(v)}
    out = cmd
    sa_ns = ctx.get("sa_ns") or ctx.get("ns", "<namespace>")
    sa_subject = f"system:serviceaccount:{sa_ns}:{ctx.get('sa', 'default')}"
    defaults = {
        "ns": "<namespace>",
        "pod": "<pod>",
        "name": "<name>",
        "pvc": "<pvc>",
        "secret": "<secret>",
        "sa": "default",
        "subject": sa_subject if "sa" in ctx else "<user-or-serviceaccount>",
        "verb": "<verb>",
        "resource": "<resource>",
    }
    for key, default in defaults.items():
        out = out.replace("{" + key + "}", ctx.get(key, default))
    return out.replace("{{", "{").replace("}}", "}")


_OPENSHIFT_ONLY = re.compile(
    r"#\s*\[(OCP|ROSA)\]|\boc (get|describe) (route|scc|securitycontextconstraints)\b|\boc adm (?!top)"
)
_KUBERNETES_ONLY = re.compile(r"#\s*\[K8S\]")  # e.g. kubeadm's static pods in kube-system


def _for_platform(cmd: str, platform: str | None) -> str | None:
    """Commands as the user's platform spells them: plain Kubernetes gets kubectl and no OpenShift-only steps;
    OpenShift and ROSA get no steps marked [K8S]. With no platform, both are shown."""
    if platform and platform != "kubernetes" and _KUBERNETES_ONLY.search(cmd):
        return None
    if platform != "kubernetes" or not cmd.startswith(("oc ", "openssl", "kubectl")):
        return cmd
    if _OPENSHIFT_ONLY.search(cmd):
        return None
    cmd = re.sub(r"^oc adm top ", "kubectl top ", cmd)
    rsh = re.match(r"^oc rsh (-n \S+ )?(\S+) (.+)$", cmd)
    if rsh:
        return f"kubectl exec {rsh.group(1) or ''}{rsh.group(2)} -- {rsh.group(3)}"
    return re.sub(r"^oc ", "kubectl ", cmd)


def _fix_applies(fix: str, platform: str | None) -> bool:
    """Fixes marked [OCP] or [ROSA] are for OpenShift; [K8S] for plain Kubernetes. With no platform, all apply."""
    if platform == "kubernetes":
        return not fix.startswith(("[OCP]", "[ROSA]"))
    if platform:
        return not fix.startswith("[K8S]")
    return True


_ROSA_CONTEXT = re.compile(r"(?i)\b(?:rosa|hypershift|hosted control planes?|hcp)\b")
# Patterns too common to name an OpenShift playbook when the text does not say it is OpenShift: a bare "Permission
# denied" is a Docker entrypoint without +x as often as an arbitrary UID. The playbook's specific patterns (nginx's
# "mkdir() ... failed (13: Permission denied)") still name it.
_WEAK_WITHOUT_CONTEXT: dict[str, frozenset[str]] = {
    "DBG-ARBITRARY-UID": frozenset({"EACCES", "Permission denied"}),
    "DBG-CLUSTEROPERATOR": frozenset({r"Degraded\s+True", r"Available\s+False"}),
}


def diagnose(
    text: str, platform: str | None = None, limit: int = 5, signals: list[Signal] | None = None
) -> DiagnoseResult:
    """Rank playbooks for ``text``: one point per matching pattern plus ``SIGNAL_WEIGHT`` when catalogued signals point
    at the playbook (``kube_noob.signals``: an alert name, a container or event reason, a phrase such as "leader
    changed"), times the playbook's weight. ``signals`` overrides the signals read from ``text``, e.g. the ones read
    from an Alertmanager payload."""
    if len(text) > MAX_INPUT:
        text = text[-MAX_INPUT:]
    text = redact_text(text)
    ctx = extract_context(text)
    if signals is None:
        signals = for_text(text)
    linked = playbooks_for(signals)
    lines = text.splitlines()
    results: list[Diagnosis] = []
    openshift = rosa = False
    if not platform:
        from kube_noob.known_issues import openshift_context

        openshift = openshift_context(text)
        rosa = bool(_ROSA_CONTEXT.search(text))
    for p in PLAYBOOKS:
        if platform and platform not in p.platforms:
            continue
        # No platform given: an OpenShift playbook needs the text to say it is OpenShift (a bare "Permission denied"
        # is not the arbitrary-UID problem on Docker), and a ROSA playbook needs ROSA or hosted control planes.
        weak: frozenset[str] = frozenset()
        if not platform and "kubernetes" not in p.platforms:
            if set(p.platforms) <= {"rosa-hcp", "rosa-classic"} and not rosa:
                continue  # a ROSA playbook needs ROSA or hosted control planes in the text
            if not openshift:
                if p.pid not in _WEAK_WITHOUT_CONTEXT:
                    continue  # an OpenShift playbook needs the text to say it is OpenShift
                weak = _WEAK_WITHOUT_CONTEXT[p.pid]  # without it, only the playbook's specific patterns count
        evidence: list[str] = [f"signal {x.kind} {x.name}" for x in linked.get(p.pid, [])]
        hits = 0
        for pat in _COMPILED[p.pid]:
            if pat.pattern in weak or not pat.search(text):  # one scan; the line is looked up only for matches
                continue
            matched_line = next((ln.strip() for ln in lines if pat.search(ln)), pat.pattern)
            if matched_line is not None:
                hits += 1
                clipped = matched_line[:300]
                if clipped not in evidence:
                    evidence.append(clipped)
        boost = SIGNAL_WEIGHT if p.pid in linked else 0.0
        if hits or boost:
            score = (hits + boost) * p.weight
            checks = [_for_platform(_fill(c, ctx), platform) for c in p.checks]
            fixes = [_fill(f, ctx) for f in p.fixes if _fix_applies(f, platform)]
            causes = [_fill(c, ctx) for c in p.root_causes if _fix_applies(c, platform)]
            results.append(Diagnosis(p, score, evidence[:5], [c for c in checks if c], fixes, causes))
    results.sort(key=lambda d: (-d.score, d.playbook.pid))
    codes = {int(c) for c in _EXIT_PATTERN.findall(text)}
    exit_info = {c: EXIT_CODES[c] for c in sorted(codes) if c in EXIT_CODES}
    notes: list[str] = []
    if not results:
        notes.append(
            "No playbook matched. Paste `oc describe pod`, `oc get events --sort-by=.lastTimestamp` and "
            "`oc logs --previous` output for a better diagnosis."
        )
    return DiagnoseResult(results[:limit], ctx, exit_info, notes, signals)


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
    spec = pod.get("spec") or {}
    out.append(f"pod/{name} phase={status.get('phase')} node={spec.get('nodeName')}")
    pull = [str(s.get("name")) for s in spec.get("imagePullSecrets") or [] if isinstance(s, dict) and s.get("name")]
    if pull or spec.get("serviceAccountName"):  # names only: kube-noob never reads a Secret
        out.append(f"  spec serviceAccountName={spec.get('serviceAccountName') or 'default'} imagePullSecrets={pull}")
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


_PULL_REASONS = frozenset({"ErrImagePull", "ImagePullBackOff"})


def _service_account_pull_secrets(backend: Backend, namespace: str, pods: list[dict[str, Any]]) -> list[str]:
    """For pods stuck pulling: the pull secret names their ServiceAccounts link (names only, never a Secret)."""
    accounts: list[str] = []
    for pod in pods:
        statuses = (pod.get("status") or {}).get("containerStatuses") or []
        if any(((cs.get("state") or {}).get("waiting") or {}).get("reason") in _PULL_REASONS for cs in statuses):
            sa = (pod.get("spec") or {}).get("serviceAccountName") or "default"
            if sa not in accounts:
                accounts.append(sa)
    out: list[str] = []
    for sa in accounts[:3]:
        try:
            obj = backend.get("serviceaccounts", name=sa, namespace=namespace)
        except ClusterAccessError:
            continue  # the ServiceAccount is a bonus; the events already name the missing secret
        names = [str(s.get("name")) for s in obj.get("imagePullSecrets") or [] if isinstance(s, dict)]
        out.append(f"serviceaccount/{sa} imagePullSecrets={names}")
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
    lines.extend(_service_account_pull_secrets(backend, namespace, pods[:10]))
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
    backend: Backend,
    namespace: str,
    kind: str,
    name: str,
    platform: str | None = None,
    log_lines: int = 100,
    data_dir: Path | None = None,
) -> dict[str, Any]:
    from kube_noob.debug.cluster import cluster_info
    from kube_noob.debug.policy import explain as explain_denials
    from kube_noob.known_issues import match as known_issue_match

    ev = collect_evidence(backend, namespace, kind, name, log_lines)
    blob = "\n".join(ev["summary"]) + "\n" + "\n".join(ev["logs"].values())
    blob += f"\nNamespace: {namespace}\n"
    try:
        info: dict[str, Any] = cluster_info(backend)
    except Exception:  # noqa: BLE001 - the version is a bonus; the diagnosis must not depend on it
        info = {}
    platform = platform or ("openshift" if info.get("openshift") else None)
    result = diagnose(blob, platform=platform)
    if "pod" not in result.context:
        result.context["name"] = name
    reported = known_issue_match(blob, platform, info.get("openshift"), 3, data_dir)
    denials = explain_denials(blob, platform)["denials"]
    return {
        "backend": backend.name,
        "target": f"{kind}/{namespace}/{name}",
        "cluster": {k: info.get(k) for k in ("kubernetes", "openshift", "newerThanKnowledge", "warnings") if k in info},
        "evidence": ev["summary"],
        "logs": {k: v[-6000:] for k, v in ev["logs"].items()},
        **result.as_dict(),
        "knownIssues": reported["matches"],
        **({"policyDenials": denials} if denials else {}),
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
    if result.get("signals"):
        lines += ["", "## Signals", ""]
        lines += [
            f"- {x['kind']} {x['name']}" + (f" ({x['detail']})" if x.get("detail") else "") for x in result["signals"]
        ]
    for m in result.get("memory", []):
        state_label = {
            "fix": "fix",
            "runbook": "runbook",
            "retired": "retired",
            "tried, did not work": "tried, did not work",
        }
        lines += ["", f"## Team memory {m['citation']}: {state_label[m['state']]}", "", m["symptom"], ""]
        lines += [f"- Cause: {m['cause']}", f"- Fix: {m['fix']['text']}", f"- {m['outcomes']['summary']}"]
        lines += [f"- Note: {m['note']}"] if m.get("note") else []
    for m in result.get("knownIssues", []):
        lines += ["", f"## Reported issue {m['id']}", "", m["status"], "", m["summary"], "", f"- Issue: {m['url']}"]
        lines += [f"- Workaround: {m['workaround']}"] if m.get("workaround") else []
        lines += [f"- Release notes: {m['source']}"]
    for p in result.get("policyDenials", []):
        title = f"{p['engineName']} {p.get('policy') or ''}".strip() + (f" / {p['rule']}" if p.get("rule") else "")
        lines += ["", f"## Denied by {title}", "", p["meaning"], "", "Read-only next steps:"]
        lines += [_step_line(s) for s in p.get("readOnlyNextSteps", [])]
        lines += ["", "Proposed changes (require approval):"]
        lines += [f"- {c['change']}" for c in p.get("proposedChanges", [])]
        if p.get("patch"):
            lines += ["", "```yaml", p["patch"].rstrip(), "```"]
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
