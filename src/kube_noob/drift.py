"""Daily drift and policy report (requirements R3.4): what changed since the last snapshot, read-only.

A snapshot records, for every watched object, a hash of its desired state and a short hash per field (no values: a
snapshot file holds names and hashes, never configuration), plus the audit findings at low severity or above with
the owner of each object. Two snapshots give the report: objects added, removed and changed (with the fields that
changed), findings new and fixed since the earlier one, and today's open findings by namespace, by owner and by rule.

What counts as a change: the object without ``status``, server-set metadata (uid, resourceVersion, generation,
creation time, managed fields), ``kubectl.kubernetes.io/last-applied-configuration``, ``deployment.kubernetes.io/
revision`` and ``kubectl.kubernetes.io/restartedAt``, and without ``spec.replicas`` of scalable workloads (scaling is
not drift). Objects a controller owns (ReplicaSets, Jobs and pods it made) are not watched: their parent is.

The owner of an object is its ``owner``, ``team``, ``app.kubernetes.io/owner`` or ``app.kubernetes.io/team`` label (or
a ``kube-noob.io/owner`` or ``owner`` annotation), else its namespace's, else ``unowned``.

Live snapshots read through the read-only allowlist: never Secrets, and ConfigMap values arrive redacted (a change
that keeps a value's length is not seen). ``kube-noob posture report`` keeps the snapshots and reports in a folder
(``<dataDir>/posture`` by default) and ``kube-noob serve`` with ``posture.reportEnabled`` writes one a day.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import json
from collections import Counter
from collections.abc import Iterable
from pathlib import Path
from typing import Any

import yaml

from kube_noob.attack_paths import LIVE_RESOURCES

FORMAT = "kube-noob-snapshot/1"
REPORT_FORMAT = "kube-noob-drift/1"
MAX_OBJECTS = 50_000
MAX_FIELDS = 400
MAX_CHANGED_FIELDS = 20
MAX_SNAPSHOT_BYTES = 200_000_000
MAX_NOT_READ = 200  # entries kept in a snapshot; the reason strings are bounded by collect_live
MAX_CONTROL_NAMESPACES = 20  # named on a byControl row; the count is exact, the list is a sample
WATCHED = frozenset(
    {
        "Deployment",
        "StatefulSet",
        "DaemonSet",
        "CronJob",
        "Pod",
        "DeploymentConfig",
        "Service",
        "Route",
        "Ingress",
        "NetworkPolicy",
        "EgressFirewall",
        "ServiceAccount",
        "Role",
        "RoleBinding",
        "ClusterRole",
        "ClusterRoleBinding",
        "SecurityContextConstraints",
        "PodDisruptionBudget",
        "HorizontalPodAutoscaler",
        "ConfigMap",
        "StorageClass",
        "PersistentVolumeClaim",
        "Namespace",
    }
)
EXTRA_LIVE: dict[str, str] = {
    "networkpolicies": "NetworkPolicy",
    "egressfirewalls": "EgressFirewall",
    "poddisruptionbudgets": "PodDisruptionBudget",
    "horizontalpodautoscalers": "HorizontalPodAutoscaler",
    "configmaps": "ConfigMap",
    "storageclasses": "StorageClass",
    "persistentvolumeclaims": "PersistentVolumeClaim",
    "namespaces": "Namespace",
}
CLUSTER_SCOPED_LIVE = frozenset(
    {"clusterroles", "clusterrolebindings", "securitycontextconstraints", "storageclasses", "namespaces"}
)
_SCALABLE = frozenset({"Deployment", "StatefulSet", "DeploymentConfig", "ReplicaSet"})
_SERVER_META = frozenset(
    {"uid", "resourceVersion", "generation", "creationTimestamp", "managedFields", "selfLink", "ownerReferences"}
)
_VOLATILE_ANNOTATIONS = frozenset(
    {
        "kubectl.kubernetes.io/last-applied-configuration",
        "deployment.kubernetes.io/revision",
        "kubectl.kubernetes.io/restartedAt",
    }
)
OWNER_LABELS = ("owner", "team", "app.kubernetes.io/owner", "app.kubernetes.io/team")
OWNER_ANNOTATIONS = ("kube-noob.io/owner", "owner")


class DriftError(ValueError):
    """A snapshot that is not one, or too large."""


def _kind_of(ref: str) -> str:
    """The Kind from a ``_ref``-shaped key (``Kind/namespace/name`` or ``Kind/name``)."""
    return ref.split("/", 1)[0]


def _ref(obj: dict[str, Any]) -> str:
    meta = obj.get("metadata") or {}
    ns = meta.get("namespace")
    return f"{obj.get('kind')}/{ns}/{meta.get('name')}" if ns else f"{obj.get('kind')}/{meta.get('name')}"


def _owned(obj: dict[str, Any]) -> bool:
    refs = (obj.get("metadata") or {}).get("ownerReferences") or []
    return any(isinstance(r, dict) and r.get("controller") is True for r in refs if isinstance(refs, list))


def _strip_template_meta(meta: Any) -> Any:
    if not isinstance(meta, dict):
        return meta
    out = {k: v for k, v in meta.items() if k not in _SERVER_META}
    ann = out.get("annotations")
    if isinstance(ann, dict):
        kept = {k: v for k, v in ann.items() if k not in _VOLATILE_ANNOTATIONS}
        if kept:
            out["annotations"] = kept
        else:
            out.pop("annotations")
    return out


def normalise(obj: dict[str, Any]) -> dict[str, Any]:
    """The object's desired state: what the report compares (see the module docstring)."""
    out = {k: v for k, v in obj.items() if k != "status"}
    out["metadata"] = _strip_template_meta(obj.get("metadata") or {})
    spec = out.get("spec")
    if isinstance(spec, dict):
        spec = dict(spec)
        if obj.get("kind") in _SCALABLE:
            spec.pop("replicas", None)
        tpl = spec.get("template")
        if isinstance(tpl, dict) and "metadata" in tpl:
            spec["template"] = {**tpl, "metadata": _strip_template_meta(tpl["metadata"])}
        out["spec"] = spec
    return out


def _digest(value: Any, length: int = 64) -> str:
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()[:length]


def _leaves(value: Any, path: str = "") -> Iterable[tuple[str, Any]]:
    if isinstance(value, dict) and value:
        for k in sorted(value):
            yield from _leaves(value[k], f"{path}.{k}" if path else str(k))
    elif isinstance(value, list) and value:
        for i, v in enumerate(value):
            yield from _leaves(v, f"{path}[{i}]")
    else:
        yield path, value


def _fields(obj: dict[str, Any]) -> dict[str, str]:
    out: dict[str, str] = {}
    rest: list[Any] = []
    for i, (path, value) in enumerate(_leaves(obj)):
        if i < MAX_FIELDS:
            out[path] = _digest(value, 12)
        else:
            rest.append((path, value))
    if rest:
        out["<more fields>"] = _digest(rest, 12)
    return out


def _owner(obj: dict[str, Any], namespaces: dict[str, str]) -> str:
    meta = obj.get("metadata") or {}
    raw_labels, raw_ann = meta.get("labels"), meta.get("annotations")
    labels: dict[str, Any] = raw_labels if isinstance(raw_labels, dict) else {}
    ann: dict[str, Any] = raw_ann if isinstance(raw_ann, dict) else {}
    for key in OWNER_LABELS:
        if labels.get(key):
            return str(labels[key])
    for key in OWNER_ANNOTATIONS:
        if ann.get(key):
            return str(ann[key])
    ns = meta.get("namespace")
    return namespaces.get(str(ns), "unowned") if ns else "unowned"


def _namespace_owners(objects: list[dict[str, Any]]) -> dict[str, str]:
    out: dict[str, str] = {}
    for o in objects:
        if o.get("kind") in {"Namespace", "Project"}:
            name = str((o.get("metadata") or {}).get("name") or "")
            owner = _owner({"metadata": {k: v for k, v in (o.get("metadata") or {}).items() if k != "namespace"}}, {})
            if name and owner != "unowned":
                out[name] = owner
    return out


def watched(objects: Iterable[Any]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for o in objects:
        if isinstance(o, dict) and o.get("kind") == "List":
            out += watched(o.get("items") or [])
        elif isinstance(o, dict) and o.get("kind") in WATCHED and not _owned(o):
            out.append(o)
        if len(out) > MAX_OBJECTS:
            raise DriftError(f"more than {MAX_OBJECTS} objects; snapshot fewer namespaces")
    return out


def snapshot(
    objects: Iterable[Any],
    *,
    source: str,
    platform: str = "kubernetes",
    version: str | None = None,
    exceptions: Any = None,
    taken_at: dt.datetime | None = None,
    not_read: Iterable[str] = (),
) -> dict[str, Any]:
    """A snapshot of ``objects`` (dicts read from manifests or the cluster); ``exceptions``: an exceptions Review.

    ``not_read``: the entries ``collect_live`` could not read, verbatim. They are kept because a resource the
    backend refused is not a resource with no objects in it: without the record, the next ``diff`` cannot tell an
    object that was deleted from one it was no longer allowed to see, and reports the second as the first.
    """
    from kube_noob.audit.engine import analyze
    from kube_noob.audit.exceptions import match
    from kube_noob.audit.model import Severity, Stage
    from kube_noob.yamlio import load_documents

    # Materialised once: `objects` is an Iterable, and the audit below needs it again. Taking it twice read
    # an exhausted generator and silently produced a snapshot with zero findings -- which the CLI test
    # caught, and which would otherwise have looked like a clean cluster.
    raw = [o for o in objects if isinstance(o, dict) and o.get("kind")]
    objs = watched(raw)
    ns_owner = _namespace_owners(objs)
    items: dict[str, dict[str, Any]] = {}
    owners: dict[str, str] = {}
    for o in objs:
        key = _ref(o)
        norm = normalise(o)
        meta = o.get("metadata") or {}
        owners[key] = _owner(o, ns_owner)
        items[key] = {
            "kind": o.get("kind"),
            "namespace": meta.get("namespace"),
            "name": meta.get("name"),
            "owner": owners[key],
            "hash": _digest(norm),
            "fields": _fields(norm),
        }
    # Audited over EVERY object collected, not the watched subset. `watched()` decides what is TRACKED for drift
    # (hashes per object), which is a different question from what the rules may look at -- and feeding them the
    # subset made two wrong answers: KN-C016 reported "no ResourceQuota in this namespace" for a bundle holding
    # one, because ResourceQuota is not a watched kind, and a rule whose subject kind was filtered out ran
    # against nothing, found nothing, and was recorded as evaluated. With N4 that second one became a per-control
    # `clean`, which is the absence-read-as-pass this project exists to catch.
    docs = load_documents(yaml.safe_dump_all([{k: v for k, v in o.items() if k != "status"} for o in raw]))
    # A resource the cluster would not show is exactly "you did not pass it": the rules that fire because another
    # object is absent cannot tell that from a real gap, so they decline to decide and land in `notEvaluated`
    # rather than `clean` (G186, G202). Without this, a forbidden `roles` read left AC-6 reading "16 clean".
    partial = bool(list(not_read))
    report = analyze(
        docs,
        platform,
        version,
        stages={Stage.VALIDATE, Stage.AUDIT, Stage.CALIBRATE},
        schema=False,
        partial_bundle=partial,
    )
    findings: list[dict[str, Any]] = []
    seen: set[str] = set()
    for f in report.findings:
        if f.severity < Severity.LOW:
            continue
        fid = f"{f.rule_id} {f.resource} {f.path}"
        if fid in seen:
            continue
        seen.add(fid)
        hit = match(exceptions, f.rule_id, f.resource) if exceptions is not None else None
        ns = items.get(f.resource, {}).get("namespace")
        findings.append(
            {
                "id": fid,
                "ruleId": f.rule_id,
                "resource": f.resource,
                "severity": f.severity.name.lower(),
                "namespace": ns,
                "owner": owners.get(f.resource, ns_owner.get(str(ns), "unowned") if ns else "unowned"),
                "excepted": hit.id if hit else None,
            }
        )
    when = (taken_at or dt.datetime.now(dt.UTC)).replace(microsecond=0)
    unread = sorted(dict.fromkeys(str(x) for x in not_read))
    return {
        "format": FORMAT,
        "takenAt": when.isoformat().replace("+00:00", "Z"),
        "source": source,
        "platform": platform,
        "objects": dict(sorted(items.items())),
        "findings": sorted(findings, key=lambda x: str(x["id"])),
        # What RAN, not just what fired. Without it a control with no open finding and a control nothing ever
        # evaluated are the same empty row, and reporting the first as satisfied is the defect G191, G202 and
        # G210 each fixed somewhere else. Sorted, so two snapshots of the same cluster are byte-identical.
        "coverage": {
            "evaluatedRules": sorted(report.evaluated_rules),
            "firedRules": sorted(report.fired_rules),
        },
        "notRead": unread[:MAX_NOT_READ],
        "notReadKinds": sorted(_kinds_not_read(unread)),
    }


def _kinds_not_read(not_read: Iterable[str]) -> set[str]:
    """The kinds behind ``collect_live``'s messages, so a diff can tell "deleted" from "not allowed to look".

    ``collect_live`` writes ``"<resource>[ in <namespace>]: <reason>"``, so the resource is the first token, and
    the live maps turn it into the kind that would have been stored under it.
    """
    resources = {**LIVE_RESOURCES, **EXTRA_LIVE}
    kinds: set[str] = set()
    for entry in not_read:
        token = entry.split(":", 1)[0].split(" in ", 1)[0].strip()
        kind = resources.get(token)
        if kind:
            kinds.add(kind)
    return kinds


def _counts(rows: list[dict[str, Any]], key: str) -> list[dict[str, Any]]:
    by: dict[str, Counter[str]] = {}
    for r in rows:
        by.setdefault(str(r.get(key) or "-"), Counter())[str(r["severity"])] += 1
    out = [{key: k, "findings": sum(c.values()), **dict(sorted(c.items()))} for k, c in by.items()]
    return sorted(out, key=lambda x: (-int(x["findings"]), str(x[key])))


def _by_control(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Open findings grouped by the controls their rules map to, most findings first.

    A finding counts once for each control its rule names, so the column does not sum to the finding total -- a
    rule that is evidence about three controls is evidence about three controls. This is a COUNT of open findings
    and nothing more: a control with none is absent, which is why it cannot be read as a coverage claim. The
    standing view below is where clean and never-evaluated are separated.
    """
    from kube_noob.audit.controls import RULE_CONTROLS, TITLES

    by: dict[str, Counter[str]] = {}
    where: dict[str, set[str]] = {}
    for r in rows:
        for control in RULE_CONTROLS.get(str(r.get("ruleId")), ()):
            by.setdefault(control, Counter())[str(r["severity"])] += 1
            # A finding on a cluster-scoped object has no namespace. Named rather than left as a bare "-",
            # which read as a namespace called "-" and took one of the listed slots without saying what it was.
            where.setdefault(control, set()).add(str(r.get("namespace") or "(cluster-scoped)"))
    out = []
    for control, counts in by.items():
        names = sorted(where[control])
        row: dict[str, Any] = {
            "control": control,
            "title": TITLES[control],
            "findings": sum(counts.values()),
            **dict(sorted(counts.items())),
            "namespaces": names[:MAX_CONTROL_NAMESPACES],
        }
        # A silent slice makes the row claim fewer namespaces than there are. The count of the rest is part of
        # the answer, the same way a `changed` row carries `more`.
        if len(names) > MAX_CONTROL_NAMESPACES:
            row["moreNamespaces"] = len(names) - MAX_CONTROL_NAMESPACES
        out.append(row)
    return sorted(out, key=lambda x: (-int(x["findings"]), str(x["control"])))


def _standing(new: dict[str, Any], open_rows: list[dict[str, Any]]) -> tuple[dict[str, Any] | None, str]:
    """Per-control standing from the new snapshot's coverage record, or nothing and a reason.

    The record says which rules ran, which is the only way `clean` means anything. A snapshot written before the
    record existed has none, and then this returns no standing at all rather than a list in which every control
    with no finding looks satisfied. The OLD snapshot's record is not needed: standing describes where the cluster
    is now, not what changed.
    """
    from kube_noob.audit.controls import summary as control_summary

    unread = [str(x) for x in new.get("notRead") or ()]
    if unread:
        # A rule whose SUBJECT kind was refused runs against nothing, finds nothing, and would be reported
        # `clean`. The engine knows which rules fire on another object's absence (they decline to decide on a
        # partial bundle) but not which kind each rule reads, so no `clean` on this snapshot can be trusted and
        # none is offered. Counts still stand: a finding that was reported was reported.
        return None, (
            f"{len(unread)} resource(s) could not be read in this snapshot, so no per-control standing is "
            "reported: a rule whose subject kind was refused finds nothing and would look clean. The open "
            "findings per control below are still what was found. First: " + "; ".join(unread[:3])
        )
    coverage = new.get("coverage")
    if not isinstance(coverage, dict) or not isinstance(coverage.get("evaluatedRules"), list):
        return None, (
            "this snapshot carries no coverage record, so the report counts open findings per control and makes "
            "no statement about the controls without one: a control with no open finding here may simply not "
            "have been evaluated. Take a new snapshot to get per-control standing."
        )
    excepted = [str(f["ruleId"]) for f in new["findings"] if f.get("excepted") and f.get("ruleId")]
    return (
        control_summary(
            [str(r["ruleId"]) for r in open_rows],
            excepted,
            [str(x) for x in coverage.get("evaluatedRules") or ()],
            [str(x) for x in coverage.get("firedRules") or ()],
        ),
        "",
    )


def diff(old: dict[str, Any], new: dict[str, Any]) -> dict[str, Any]:
    """The report from ``old`` to ``new``."""
    for snap in (old, new):
        if not isinstance(snap, dict) or snap.get("format") != FORMAT:
            raise DriftError(f"not a {FORMAT} snapshot")
    a, b = old["objects"], new["objects"]
    changed = []
    for key in sorted(set(a) & set(b)):
        if a[key]["hash"] != b[key]["hash"]:
            fa, fb = a[key].get("fields", {}), b[key].get("fields", {})
            paths = sorted(p for p in set(fa) | set(fb) if fa.get(p) != fb.get(p))
            row: dict[str, Any] = {"object": key, "owner": b[key].get("owner"), "fields": paths[:MAX_CHANGED_FIELDS]}
            if len(paths) > MAX_CHANGED_FIELDS:
                row["more"] = len(paths) - MAX_CHANGED_FIELDS
            changed.append(row)
    old_f = {f["id"]: f for f in old["findings"] if not f.get("excepted")}
    new_f = {f["id"]: f for f in new["findings"] if not f.get("excepted")}
    open_rows = list(new_f.values())

    def brief(f: dict[str, Any]) -> dict[str, Any]:
        return {k: f[k] for k in ("ruleId", "resource", "severity", "namespace", "owner")}

    # A kind the new snapshot was refused cannot be said to have lost objects or had findings fixed: kube-noob
    # stopped being able to look, which is not the same event and must not be published as the good one.
    blind = set(new.get("notReadKinds") or ())
    gone = sorted(set(a) - set(b))
    removed = [k for k in gone if _kind_of(k) not in blind]
    undetermined = [k for k in gone if _kind_of(k) in blind]
    was_fixed = [old_f[i] for i in sorted(set(old_f) - set(new_f))]
    fixed = [brief(f) for f in was_fixed if _kind_of(str(f["resource"])) not in blind]
    undetermined_findings = [brief(f) for f in was_fixed if _kind_of(str(f["resource"])) in blind]
    out: dict[str, Any] = {
        "format": REPORT_FORMAT,
        "from": old["takenAt"],
        "to": new["takenAt"],
        "notRead": list(new.get("notRead") or ()),
        "objects": {
            "added": sorted(set(b) - set(a)),
            "removed": removed,
            "undetermined": undetermined,
            "changed": changed,
            "unchanged": sum(1 for k in set(a) & set(b) if a[k]["hash"] == b[k]["hash"]),
        },
        "findings": {
            "new": [brief(new_f[i]) for i in sorted(set(new_f) - set(old_f))],
            "fixed": fixed,
            "undetermined": undetermined_findings,
            "open": len(open_rows),
            "excepted": sum(1 for f in new["findings"] if f.get("excepted")),
        },
        "violations": {
            "byNamespace": _counts(open_rows, "namespace"),
            "byOwner": _counts(open_rows, "owner"),
            "byRule": _counts(open_rows, "ruleId"),
            "byControl": _by_control(open_rows),
        },
    }
    standing, note = _standing(new, open_rows)
    if standing is not None:
        out["controlStanding"] = standing
    if note:
        out.setdefault("notes", []).append(note)
    return out


def first_report(new: dict[str, Any]) -> dict[str, Any]:
    """A report with no earlier snapshot: everything is new."""
    empty = {**new, "objects": {}, "findings": [], "takenAt": new["takenAt"]}
    out = diff(empty, new)
    out["from"] = None
    return out


def markdown(report: dict[str, Any]) -> str:
    o, f = report["objects"], report["findings"]
    since = report["from"] or "the first snapshot"
    lines = [
        f"# Drift and policy report, {report['to']}",
        "",
        f"Since {since}: {len(o['added'])} added, {len(o['removed'])} removed, {len(o['changed'])} changed, "
        f"{o['unchanged']} unchanged. Findings: {len(f['new'])} new, {len(f['fixed'])} fixed, {f['open']} open"
        + (f", {f['excepted']} excepted" if f["excepted"] else "")
        + ".",
        "",
    ]
    # The record goes in the summary, before any count, because every count below it is over what could be read.
    not_read = list(report.get("notRead") or ())
    if not_read:
        undet_o = len(o.get("undetermined") or ())
        undet_f = len(f.get("undetermined") or ())
        lines += [
            f"**{len(not_read)} resource(s) could not be read, so this report is not a full picture.** "
            f"{undet_o} object(s) and {undet_f} finding(s) are undetermined: they were in the previous snapshot "
            "and are absent from this one, which here means kube-noob was not allowed to look, not that they "
            "went away.",
            "",
            "| Could not be read |",
            "| --- |",
            *[f"| {entry} |" for entry in not_read[:20]],
            "",
        ]
        if len(not_read) > 20:
            lines += [f"...and {len(not_read) - 20} more.", ""]
    if o["changed"]:
        lines += ["## Changed", "", "| Object | Owner | Fields |", "| --- | --- | --- |"]
        for c in o["changed"]:
            more = f" +{c['more']}" if c.get("more") else ""
            lines.append(f"| {c['object']} | {c['owner']} | {', '.join(c['fields'])}{more} |")
        lines.append("")
    for title, keys in (
        ("Added", o["added"]),
        ("Removed", o["removed"]),
        ("Undetermined: present before, not readable now", list(o.get("undetermined") or ())),
    ):
        if keys:
            lines += [f"## {title}", "", *[f"- {k}" for k in keys], ""]
    for title, rows in (
        ("New findings", f["new"]),
        ("Fixed findings", f["fixed"]),
        ("Undetermined findings: not fixed, not readable", list(f.get("undetermined") or ())),
    ):
        if rows:
            lines += [f"## {title}", "", "| Rule | Object | Severity | Owner |", "| --- | --- | --- | --- |"]
            lines += [f"| {r['ruleId']} | {r['resource']} | {r['severity']} | {r['owner']} |" for r in rows]
            lines.append("")
    for title, key in (("By namespace", "namespace"), ("By owner", "owner")):
        rows = report["violations"]["byNamespace" if key == "namespace" else "byOwner"]
        if rows:
            lines += [
                f"## Open findings {title.lower()}",
                "",
                f"| {key.title()} | Findings | Critical | High |",
                "| --- | --- | --- | --- |",
            ]
            lines += [f"| {r[key]} | {r['findings']} | {r.get('critical', 0)} | {r.get('high', 0)} |" for r in rows]
            lines.append("")
    controls = report["violations"].get("byControl") or []
    if controls:
        lines += [
            "## Open findings by control",
            "",
            "| Control | Title | Findings | Critical | High | Namespaces |",
            "| --- | --- | --- | --- | --- | --- |",
        ]
        lines += [
            f"| {r['control']} | {r['title']} | {r['findings']} | {r.get('critical', 0)} | "
            f"{r.get('high', 0)} | {', '.join(r['namespaces'])}"
            + (f", +{r['moreNamespaces']} more" if r.get("moreNamespaces") else "")
            + " |"
            for r in controls
        ]
        lines.append("")
    standing = report.get("controlStanding")
    if standing:
        # The point of this table is the two columns a count cannot have: a control whose rules ran and found
        # nothing, and one nothing evaluated. Reported together so neither can be read as the other.
        # Every bucket, because the note under this table explains `excepted` and `withheld` and the first
        # version of the table did not have those columns: a CRITICAL finding somebody accepted, and one a
        # severity filter removed, both rendered as a row of zeros beside a `Clean` count.
        lines += [
            "## Control standing",
            "",
            "| Control | Findings | Excepted | Withheld | Clean | Not evaluated |",
            "| --- | --- | --- | --- | --- | --- |",
        ]
        lines += [
            f"| {c['id']} | {c['findings']} | {c.get('excepted', 0)} | {c.get('withheld', 0)} | "
            f"{c.get('clean', 0)} | {c.get('notEvaluated', 0)} |"
            for c in standing["controls"]
        ]
        lines += ["", standing["note"], ""]
    for note in report.get("notes") or []:
        lines += [f"> {note}", ""]
    return "\n".join(lines)


def load(path: Path) -> dict[str, Any]:
    if path.stat().st_size > MAX_SNAPSHOT_BYTES:
        raise DriftError(f"{path} is larger than {MAX_SNAPSHOT_BYTES} bytes")
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, RecursionError) as exc:
        raise DriftError(f"{path}: not a snapshot ({type(exc).__name__})") from exc
    if not isinstance(data, dict) or data.get("format") != FORMAT:
        raise DriftError(f"{path}: not a {FORMAT} snapshot")
    return data


def collect_live(backend: Any, namespaces: list[str]) -> tuple[list[dict[str, Any]], list[str]]:
    """Objects for a live snapshot through the read-only backend (never Secrets), and what could not be read."""
    from kube_noob.errors import KubeNoobError

    objects: list[dict[str, Any]] = []
    not_read: list[str] = []
    resources = {**LIVE_RESOURCES, **EXTRA_LIVE}
    for resource, kind in resources.items():
        cluster = resource in CLUSTER_SCOPED_LIVE
        scopes: list[str | None] = [None] if cluster or not namespaces else list(namespaces)
        for ns in scopes:
            try:
                data = backend.get(resource, namespace=ns)
            except KubeNoobError as exc:
                not_read.append(f"{resource}{' in ' + ns if ns else ''}: {str(exc)[:160]}")
                continue
            for item in data.get("items") or [] if isinstance(data, dict) else []:
                if isinstance(item, dict):
                    objects.append({**item, "kind": kind})
    if namespaces:
        wanted = set(namespaces)
        objects = [o for o in objects if o["kind"] != "Namespace" or (o.get("metadata") or {}).get("name") in wanted]
    return objects, not_read


def write_report(state_dir: Path, snap: dict[str, Any], keep: int = 14) -> tuple[dict[str, Any], dict[str, Path]]:
    """Diff ``snap`` against the newest snapshot in ``state_dir``, write the snapshot and the report (JSON and
    Markdown, owner-only), and keep the newest ``keep`` snapshots."""
    if not 1 <= keep <= 365:
        raise DriftError("keep must be 1-365")
    state_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    earlier = sorted(state_dir.glob("snapshot-*.json"))
    previous = load(earlier[-1]) if earlier else None
    report = diff(previous, snap) if previous else first_report(snap)
    stamp = snap["takenAt"].replace(":", "").replace("-", "")
    paths = {
        "snapshot": state_dir / f"snapshot-{stamp}.json",
        "report": state_dir / f"report-{stamp}.json",
        "markdown": state_dir / f"report-{stamp}.md",
    }
    for key, text in (
        ("snapshot", json.dumps(snap, sort_keys=True)),
        ("report", json.dumps(report, indent=1, sort_keys=True)),
        ("markdown", markdown(report)),
    ):
        tmp = paths[key].with_suffix(paths[key].suffix + ".tmp")
        tmp.write_text(text, encoding="utf-8")
        tmp.chmod(0o600)
        tmp.replace(paths[key])
    snaps = sorted(state_dir.glob("snapshot-*.json"))
    for old in snaps[:-keep]:
        old.unlink(missing_ok=True)
        stem = old.name.removeprefix("snapshot-").removesuffix(".json")
        for suffix in (".json", ".md"):
            (state_dir / f"report-{stem}{suffix}").unlink(missing_ok=True)
    return report, paths


def latest_report(state_dir: Path) -> dict[str, Any] | None:
    reports = sorted(state_dir.glob("report-*.json")) if state_dir.is_dir() else []
    if not reports:
        return None
    try:
        data = json.loads(reports[-1].read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) and data.get("format") == REPORT_FORMAT else None
