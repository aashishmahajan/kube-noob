"""Helpers to locate pod templates and containers inside workload objects."""

from __future__ import annotations

import math
from collections.abc import Iterator
from dataclasses import dataclass
from typing import Any

from kube_noob.yamlio import Document, PathT, get_path

POD_SPEC_PATHS: dict[str, PathT] = {
    "Pod": ("spec",),
    "Deployment": ("spec", "template", "spec"),
    "StatefulSet": ("spec", "template", "spec"),
    "DaemonSet": ("spec", "template", "spec"),
    "ReplicaSet": ("spec", "template", "spec"),
    "ReplicationController": ("spec", "template", "spec"),
    "Job": ("spec", "template", "spec"),
    "CronJob": ("spec", "jobTemplate", "spec", "template", "spec"),
    "DeploymentConfig": ("spec", "template", "spec"),
}

LONG_RUNNING_KINDS = frozenset({"Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "DeploymentConfig"})
REPLICATED_KINDS = frozenset({"Deployment", "StatefulSet", "ReplicaSet", "DeploymentConfig"})


@dataclass
class PodTemplate:
    doc: Document
    spec: dict[str, Any]
    path: PathT

    @property
    def template_metadata_path(self) -> PathT:
        return self.path[:-1] + ("metadata",)

    def labels(self) -> dict[str, str]:
        meta = get_path(self.doc.data, self.template_metadata_path)
        if self.doc.kind == "Pod":
            meta = get_path(self.doc.data, ("metadata",))
        if isinstance(meta, dict) and isinstance(meta.get("labels"), dict):
            return {str(k): str(v) for k, v in meta["labels"].items()}
        return {}


@dataclass
class ContainerRef:
    pod: PodTemplate
    container: dict[str, Any]
    path: PathT
    init: bool

    @property
    def name(self) -> str:
        return str(self.container.get("name", "<unnamed>"))


def pod_template(doc: Document) -> PodTemplate | None:
    path = POD_SPEC_PATHS.get(doc.kind)
    if path is None:
        return None
    spec = get_path(doc.data, path)
    if not isinstance(spec, dict):
        return None
    return PodTemplate(doc=doc, spec=spec, path=path)


def containers(pod: PodTemplate, include_init: bool = True, *, ephemeral: bool = True) -> Iterator[ContainerRef]:
    """App containers, then (``include_init``) init containers and, unless ``ephemeral`` is False, ephemeral ones."""
    keys: tuple[str, ...] = ("containers", "initContainers", "ephemeralContainers") if include_init else ("containers",)
    if not ephemeral:
        keys = tuple(k for k in keys if k != "ephemeralContainers")
    for key in keys:
        items = pod.spec.get(key)
        if not isinstance(items, list):
            continue
        for i, c in enumerate(items):
            if isinstance(c, dict):
                yield ContainerRef(pod=pod, container=c, path=(*pod.path, key, i), init=key != "containers")


def replicas(doc: Document) -> int | None:
    if doc.kind not in REPLICATED_KINDS:
        return None
    spec = doc.data.get("spec") if isinstance(doc.data, dict) else None
    if not isinstance(spec, dict):
        return 1
    r = spec.get("replicas", 1)
    return r if isinstance(r, int) else None


def effective_security(pod: PodTemplate, c: ContainerRef, field: str) -> Any:
    """Container securityContext wins over pod securityContext (for fields that exist on both)."""
    csc = c.container.get("securityContext")
    if isinstance(csc, dict) and field in csc:
        return csc[field]
    psc = pod.spec.get("securityContext")
    if isinstance(psc, dict) and field in psc:
        return psc[field]
    return None


def selector_matches(selector: dict[str, Any] | None, labels: dict[str, str]) -> bool:
    """Evaluate a LabelSelector (matchLabels + matchExpressions)."""
    if selector is None:
        return False
    if selector == {}:
        return True
    ml = selector.get("matchLabels") or {}
    if not isinstance(ml, dict):
        return False
    for k, v in ml.items():
        if labels.get(str(k)) != str(v):
            return False
    for expr in selector.get("matchExpressions") or []:
        if not isinstance(expr, dict):
            return False
        key, op, values = str(expr.get("key")), expr.get("operator"), [str(x) for x in expr.get("values") or []]
        if op == "In" and labels.get(key) not in values:
            return False
        if op == "NotIn" and labels.get(key) in values:
            return False
        if op == "Exists" and key not in labels:
            return False
        if op == "DoesNotExist" and key in labels:
            return False
    return True


def _scaled(value: Any, total: int) -> int | None:
    """IntOrString as the disruption controller scales it (percentages round up)."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        v = value.strip()
        if v.endswith("%") and v[:-1].isdigit():
            return math.ceil(int(v[:-1]) * total / 100)
        if v.isdigit():
            return int(v)
    return None


def pdb_allows_no_disruption(spec: dict[str, Any], replica_count: int) -> bool:
    """True when a PDB with this spec permits zero voluntary evictions for ``replica_count`` healthy pods."""
    mu = _scaled(spec.get("maxUnavailable"), replica_count)
    if mu is not None:
        return mu <= 0
    ma = _scaled(spec.get("minAvailable"), replica_count)
    return ma is not None and ma >= replica_count
