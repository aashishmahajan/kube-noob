"""RHACS (StackRox) policies next to kube-noob's rules (requirements R3.7): where they overlap and where they differ.

Input: a policy export (the RHACS portal's Export policy to JSON, or ``POST /v1/policies/export``:
``{"policies": [...]}``), a list of policies, or one policy. Reading them from Central (``rhacs.enabled``) is
``kube_noob.rhacs_central``, which the Claude plugin does not ship.

Every policy gets one outcome, with the reason:

- ``overlap``: kube-noob has a rule for the same thing, found by the policy's name (the default RHACS policies each
  rule cites) or by its criteria (``policySections[].policyGroups[].fieldName``). Severity and scope differences are
  stated (``RHACS high, kube-noob medium``; RHACS checks the image's USER where kube-noob checks the pod spec).
- ``related``: the same risk seen another way: RHACS records who did it (an exec, a Secret read) where kube-noob
  checks who may (KN-S017); RHACS also needs image data for part of it.
- ``gap``: a deploy-time setting kube-noob has no rule for (AppArmor, mount propagation, an exposed port 22, an egress
  NetworkPolicy, CPU limits). Named so a rule can be added.
- ``outside``: what a static manifest check cannot see: image contents and vulnerabilities (RHACS scans images),
  runtime processes, network flows and files (RHACS's collector), Kubernetes API events, or label and annotation
  conventions of the organisation.
- ``unexplained``: criteria kube-noob does not know (a newer RHACS field). The acceptance test requires none.

``kubeNoobOnly`` lists the rules no imported policy covers (storage, OpenShift Routes, EgressFirewall order...).
"""

from __future__ import annotations

import json
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any

from kube_noob.audit.rules import RULES

MAX_POLICIES = 2000
MAX_BYTES = 20_000_000
SEVERITY = {
    "LOW_SEVERITY": "low",
    "MEDIUM_SEVERITY": "medium",
    "HIGH_SEVERITY": "high",
    "CRITICAL_SEVERITY": "critical",
}
OUTCOMES = ("overlap", "related", "gap", "outside", "unexplained")

# fieldName -> kube-noob rules (deploy-time manifest criteria kube-noob also checks).
OVERLAP_FIELDS: dict[str, tuple[str, ...]] = {
    "Privileged Container": ("KN-S001",),
    "Allow Privilege Escalation": ("KN-S002",),
    "Image User": ("KN-S003",),
    "Add Capabilities": ("KN-S005",),
    "Drop Capabilities": ("KN-S006",),
    "Read-Only Root Filesystem": ("KN-S007",),
    "Seccomp Profile Type": ("KN-S008",),
    "Host Network": ("KN-S009",),
    "Host PID": ("KN-S009",),
    "Host IPC": ("KN-S009",),
    "Volume Source": ("KN-S010",),
    "Volume Type": ("KN-S010",),
    "Writable Host Mount": ("KN-S010",),
    "Exposed Node Port": ("KN-S011", "KN-N005"),
    "Image Tag": ("KN-S012",),
    "Environment Variable": ("KN-S013",),
    "Automount Service Account Token": ("KN-S014",),
    "Minimum RBAC Permissions": ("KN-S016", "KN-S017"),
    "Has Ingress Network Policy": ("KN-N001",),
    "Port Exposure Method": ("KN-N002", "KN-N004", "KN-N005", "KN-S011"),
    "Container CPU Request": ("KN-C004",),
    "Container Memory Request": ("KN-C004",),
    "Container Memory Limit": ("KN-C005",),
    "Liveness Probe Defined": ("KN-C002",),
    "Readiness Probe Defined": ("KN-C001",),
    "Replicas": ("KN-C007",),
}
# How kube-noob's view differs for a field, said once per policy that uses it.
FIELD_NOTES: dict[str, str] = {
    "Image User": "RHACS reads the image's USER; kube-noob reads the pod's runAsNonRoot/runAsUser",
    "Exposed Node Port": "RHACS looks at the node port number (privileged ports); kube-noob flags hostPort and "
    "NodePort",
    "Port Exposure Method": "RHACS flags the exposure itself; kube-noob flags Routes without TLS, load balancers open "
    "to the internet, NodePorts and hostPorts",
    "Minimum RBAC Permissions": "RHACS grades the deployment's ServiceAccount; kube-noob reads the Role and binding "
    "objects",
}
# Deploy-time settings kube-noob has no rule for.
GAP_FIELDS: dict[str, str] = {
    "AppArmor Profile": "an AppArmor profile",
    "Mount Propagation": "mount propagation",
    "Has Egress Network Policy": "an egress NetworkPolicy per deployment",
    "Container CPU Limit": "CPU limits (kube-noob asks for CPU requests and a memory limit, not a CPU limit)",
    "Exposed Port": "specific container ports (such as 22)",
    "Exposed Port Protocol": "the protocol of an exposed port",
    "Runtime Class": "the runtime class",
    "Writable Mounted Volume": "writable non-host volumes",
    "Volume Name": "volume names",
    "Volume Destination": "volume mount paths",
}
# What a static manifest check does not see, by category.
OUTSIDE: dict[str, tuple[str, frozenset[str]]] = {
    "image": (
        "image contents and vulnerabilities: RHACS scans images; kube-noob reads manifests, not images",
        frozenset(
            {
                "CVE",
                "CVSS",
                "NVD CVSS",
                "EPSS",
                "CISA KEV",
                "Severity",
                "Fixable",
                "Fixed By",
                "Days Since CVE Was Published",
                "Days Since CVE Fix Was Available",
                "Days Since CVE Was First Discovered In Image",
                "Days Since CVE Was First Discovered In System",
                "Image Component",
                "Image Age",
                "Image Scan Age",
                "Unscanned Image",
                "Image Registry",
                "Image Remote",
                "Image OS",
                "Image Signature Verified By",
                "Required Image Label",
                "Disallowed Image Label",
                "Dockerfile Line",
            }
        ),
    ),
    "runtime": (
        "runtime behaviour: RHACS's collector watches processes, network flows and files in running pods; kube-noob "
        "is a static, read-only check",
        frozenset(
            {
                "Process Name",
                "Process Arguments",
                "Process Ancestor",
                "Process UID",
                "Unexpected Process Executed",
                "Unexpected Network Flow Detected",
                "File Operation",
                "File Path",
            }
        ),
    ),
    "events": (
        "Kubernetes API events: RHACS records who did something (exec, attach, port-forward, a Secret read); "
        "kube-noob checks who is allowed to (KN-S017)",
        frozenset(
            {
                "Kubernetes Resource",
                "Kubernetes API Verb",
                "Kubernetes Resource Name",
                "Kubernetes User Name",
                "Kubernetes User Groups",
                "Is Impersonated User",
                "User Agent",
                "Source IP Address",
            }
        ),
    ),
    "labels": (
        "the organisation's label and annotation conventions: kube-noob does not require labels (the drift report "
        "reads owner and team labels)",
        frozenset({"Required Label", "Required Annotation", "Disallowed Annotation"}),
    ),
}
# Port Exposure Method values -> the rule for that exposure (INTERNAL and UNSET have none).
EXPOSURE_RULES = {"ROUTE": "KN-N002", "EXTERNAL": "KN-N004", "NODE": "KN-N005", "HOST": "KN-S011"}
SCOPE_FIELDS = frozenset({"Namespace", "Service Account", "Container Name"})
EVENT_RULES = ("KN-S017",)
KNOWN_FIELDS: frozenset[str] = frozenset(OVERLAP_FIELDS).union(
    GAP_FIELDS, SCOPE_FIELDS, *(members for _, members in OUTSIDE.values())
)


class RhacsError(ValueError):
    """Not a policy export, too large, or Central refused."""


@dataclass(frozen=True)
class Compared:
    name: str
    policy_id: str
    severity: str | None
    disabled: bool
    lifecycle: tuple[str, ...]
    outcome: str
    rules: tuple[str, ...]
    reason: str
    notes: tuple[str, ...]
    disagrees: bool = False

    def as_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "name": self.name,
            "id": self.policy_id,
            "severity": self.severity,
            "disabled": self.disabled,
            "lifecycle": list(self.lifecycle),
            "outcome": self.outcome,
            "rules": list(self.rules),
            "reason": self.reason,
        }
        if self.notes:
            out["notes"] = list(self.notes)
        if self.disagrees:
            out["disagrees"] = True
        return out


def _by_name() -> dict[str, tuple[str, ...]]:
    out: dict[str, list[str]] = {}
    for rid, rule in RULES.items():
        for name in rule.stackrox_policies:
            out.setdefault(name, []).append(rid)
    return {k: tuple(sorted(v)) for k, v in out.items()}


def policies_from(data: Any) -> list[dict[str, Any]]:
    """The policies in an export, a list, or one policy."""
    if isinstance(data, dict) and isinstance(data.get("policies"), list):
        items = data["policies"]
    elif isinstance(data, list):
        items = data
    elif isinstance(data, dict) and "policySections" in data:
        items = [data]
    else:
        raise RhacsError('not an RHACS policy export: expected {"policies": [...]}, a list of policies or one policy')
    if len(items) > MAX_POLICIES:
        raise RhacsError(f"more than {MAX_POLICIES} policies")
    out = [p for p in items if isinstance(p, dict) and isinstance(p.get("name"), str)]
    if not out:
        raise RhacsError("no policy with a name in the input")
    return out


def load(text: str) -> list[dict[str, Any]]:
    if len(text.encode("utf-8")) > MAX_BYTES:
        raise RhacsError(f"larger than {MAX_BYTES} bytes")
    try:
        data = json.loads(text)
    except (ValueError, RecursionError) as exc:
        raise RhacsError(f"not JSON: {str(exc)[:120]}") from exc
    return policies_from(data)


def _fields(policy: dict[str, Any]) -> dict[str, list[str]]:
    """fieldName -> its values, over every section and group (malformed parts are skipped)."""
    out: dict[str, list[str]] = {}
    sections = policy.get("policySections")
    for section in sections if isinstance(sections, list) else []:
        groups = section.get("policyGroups") if isinstance(section, dict) else None
        for group in groups if isinstance(groups, list) else []:
            if not (isinstance(group, dict) and isinstance(group.get("fieldName"), str)):
                continue
            vals = out.setdefault(group["fieldName"][:100], [])
            raw = group.get("values")
            for v in raw if isinstance(raw, list) else []:
                if isinstance(v, dict) and isinstance(v.get("value"), str):
                    vals.append(v["value"][:500])
    return out


def _severity_note(severity: str | None, rules: Iterable[str]) -> str | None:
    if severity is None:
        return None
    differing = [f"{r} {RULES[r].severity.name.lower()}" for r in rules if RULES[r].severity.name.lower() != severity]
    return f"severity: RHACS {severity}, kube-noob {', '.join(differing)}" if differing else None


def _rules_for(field: str, values: list[str]) -> set[str]:
    if field == "Port Exposure Method" and values:
        return {EXPOSURE_RULES[v] for v in values if v in EXPOSURE_RULES}
    return set(OVERLAP_FIELDS.get(field, ()))


def _check_verb(rules: Iterable[str]) -> str:
    rs = sorted(rules)
    return "kube-noob " + ", ".join(rs) + (" checks" if len(rs) == 1 else " check")


def compare_one(policy: dict[str, Any], by_name: dict[str, tuple[str, ...]] | None = None) -> Compared:
    """One policy's outcome. A default policy is matched by name (each rule cites the defaults it mirrors) and every
    policy by its criteria."""
    by_name = by_name if by_name is not None else _by_name()
    name = str(policy.get("name"))[:300]
    fields = _fields(policy)
    names = set(fields)
    criteria = names - SCOPE_FIELDS or names
    rules = set(by_name.get(name, ()))
    notes: list[str] = []
    for f in sorted(criteria):
        rules |= _rules_for(f, fields[f])
        if f in FIELD_NOTES:
            notes.append(FIELD_NOTES[f])
    disagrees = any(v.startswith("SECRET_KEY=") for v in fields.get("Environment Variable", []))
    if disagrees:
        notes.append(
            "RHACS and kube-noob disagree: RHACS flags Secrets passed as environment variables (secretKeyRef) and "
            "prefers mounted files; kube-noob KN-S013 flags literal values and suggests secretKeyRef"
        )
    if names & SCOPE_FIELDS and criteria != names:
        notes.append(f"RHACS scopes it by {', '.join(sorted(names & SCOPE_FIELDS))}; kube-noob checks every object")
    gaps = sorted(GAP_FIELDS[f] for f in criteria if f in GAP_FIELDS)
    outside = [cat for cat, (_, members) in OUTSIDE.items() if criteria & members]
    unknown = sorted(criteria - KNOWN_FIELDS)
    severity = SEVERITY.get(str(policy.get("severity")))
    note = _severity_note(severity, sorted(rules))
    if note:
        notes.append(note)
    actions = policy.get("enforcementActions")
    if isinstance(actions, list) and actions:
        notes.append("RHACS enforces it (" + ", ".join(str(a)[:60] for a in actions[:10]) + ")")
    if unknown:
        outcome, reason = "unexplained", f"criteria kube-noob does not know: {', '.join(unknown[:20])}"
    elif rules and outside:
        static = sorted(criteria & (set(OVERLAP_FIELDS) | set(GAP_FIELDS)))
        part = f"{_check_verb(rules)} the deploy-time part ({', '.join(static)})" if static else _check_verb(rules)
        outcome, reason = "related", part + "; the rest needs " + "; ".join(OUTSIDE[c][0] for c in outside)
    elif rules:
        outcome, reason = "overlap", _check_verb(rules) + " the same setting"
        if gaps:
            reason += "; no kube-noob rule for " + ", ".join(gaps)
    elif "events" in outside and not gaps:
        outcome, reason, rules = "related", OUTSIDE["events"][0], set(EVENT_RULES)
    elif gaps:
        outcome, reason = "gap", "no kube-noob rule for " + ", ".join(gaps)
    elif outside:
        outcome, reason = "outside", "; ".join(OUTSIDE[c][0] for c in outside)
    else:
        outcome, reason = "unexplained", "the policy has no criteria kube-noob can read"
    lifecycle = policy.get("lifecycleStages")
    return Compared(
        name=name,
        policy_id=str(policy.get("id") or "")[:100],
        severity=severity,
        disabled=bool(policy.get("disabled")),
        lifecycle=tuple(str(x)[:30] for x in lifecycle[:5]) if isinstance(lifecycle, list) else (),
        outcome=outcome,
        rules=tuple(sorted(rules)),
        reason=reason,
        notes=tuple(notes),
        disagrees=disagrees,
    )


def compare(policies: list[dict[str, Any]]) -> dict[str, Any]:
    by_name = _by_name()
    rows = [compare_one(p, by_name) for p in policies]
    covered = {r for row in rows if row.outcome in {"overlap", "related"} for r in row.rules}
    counts = {o: sum(1 for r in rows if r.outcome == o) for o in OUTCOMES}
    disabled_overlap = sorted(r.name for r in rows if r.disabled and r.outcome == "overlap")
    return {
        "policies": [r.as_dict() for r in sorted(rows, key=lambda x: (x.outcome, x.name))],
        "counts": counts,
        "total": len(rows),
        "unexplained": [r.name for r in rows if r.outcome == "unexplained"],
        "disabledButCheckedByKubeNoob": disabled_overlap,
        "disagreements": sorted(r.name for r in rows if r.disagrees),
        "kubeNoobOnly": sorted(set(RULES) - covered),
    }
