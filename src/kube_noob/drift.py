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
) -> dict[str, Any]:
    """A snapshot of ``objects`` (dicts read from manifests or the cluster); ``exceptions``: an exceptions Review."""
    from kube_noob.audit.engine import analyze
    from kube_noob.audit.exceptions import match
    from kube_noob.audit.model import Severity, Stage
    from kube_noob.yamlio import load_documents

    objs = watched(objects)
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
    docs = load_documents(yaml.safe_dump_all([{k: v for k, v in o.items() if k != "status"} for o in objs]))
    report = analyze(docs, platform, version, stages={Stage.VALIDATE, Stage.AUDIT, Stage.CALIBRATE}, schema=False)
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
    return {
        "format": FORMAT,
        "takenAt": when.isoformat().replace("+00:00", "Z"),
        "source": source,
        "platform": platform,
        "objects": dict(sorted(items.items())),
        "findings": sorted(findings, key=lambda x: str(x["id"])),
    }


def _counts(rows: list[dict[str, Any]], key: str) -> list[dict[str, Any]]:
    by: dict[str, Counter[str]] = {}
    for r in rows:
        by.setdefault(str(r.get(key) or "-"), Counter())[str(r["severity"])] += 1
    out = [{key: k, "findings": sum(c.values()), **dict(sorted(c.items()))} for k, c in by.items()]
    return sorted(out, key=lambda x: (-int(x["findings"]), str(x[key])))


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

    return {
        "format": REPORT_FORMAT,
        "from": old["takenAt"],
        "to": new["takenAt"],
        "objects": {
            "added": sorted(set(b) - set(a)),
            "removed": sorted(set(a) - set(b)),
            "changed": changed,
            "unchanged": sum(1 for k in set(a) & set(b) if a[k]["hash"] == b[k]["hash"]),
        },
        "findings": {
            "new": [brief(new_f[i]) for i in sorted(set(new_f) - set(old_f))],
            "fixed": [brief(old_f[i]) for i in sorted(set(old_f) - set(new_f))],
            "open": len(open_rows),
            "excepted": sum(1 for f in new["findings"] if f.get("excepted")),
        },
        "violations": {
            "byNamespace": _counts(open_rows, "namespace"),
            "byOwner": _counts(open_rows, "owner"),
            "byRule": _counts(open_rows, "ruleId"),
        },
    }


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
    if o["changed"]:
        lines += ["## Changed", "", "| Object | Owner | Fields |", "| --- | --- | --- |"]
        for c in o["changed"]:
            more = f" +{c['more']}" if c.get("more") else ""
            lines.append(f"| {c['object']} | {c['owner']} | {', '.join(c['fields'])}{more} |")
        lines.append("")
    for title, keys in (("Added", o["added"]), ("Removed", o["removed"])):
        if keys:
            lines += [f"## {title}", "", *[f"- {k}" for k in keys], ""]
    for title, rows in (("New findings", f["new"]), ("Fixed findings", f["fixed"])):
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
