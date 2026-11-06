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

#: Kinds that carry one or more pod specs somewhere other than the nine places above, with ``*`` standing for
#: every element of a list (or every value of a mapping). Every path here was read out of the published CRD
#: schema on 2026-11-06, not inferred from a tutorial:
#:
#: * ``serving.kserve.io/v1beta1`` InferenceService -- `predictor`, `transformer` and `explainer` are each a
#:   full PodSpec inline (all of `containers`, `volumes`, `serviceAccountName`, `nodeSelector`, `tolerations`,
#:   `initContainers`, `securityContext`, `hostNetwork`, `hostPID`, `hostIPC`,
#:   `automountServiceAccountToken` appear in the schema), from
#:   config/crd/full/serving.kserve.io_inferenceservices.yaml.
#: * ``ray.io/v1`` and ``v1alpha1`` RayCluster -- `headGroupSpec.template` and each `workerGroupSpecs[].template`
#:   are ordinary PodTemplateSpecs (`metadata` + `spec`), from
#:   helm-chart/kuberay-operator/crds/ray.io_rayclusters.yaml.
#: * RayService wraps the same cluster under `rayClusterConfig`, RayJob under `rayClusterSpec`.
#:
#: Why this exists: without it every pod-level rule in the catalogue returns nothing for these objects. A
#: KServe predictor running privileged, as root, with `hostPath: /` and a mutable tag produced **14 findings
#: as a Deployment and zero as an InferenceService** -- not "not evaluated", clean (G229).
EMBEDDED_POD_SPEC_PATHS: dict[str, tuple[PathT, ...]] = {
    "InferenceService": (("spec", "predictor"), ("spec", "transformer"), ("spec", "explainer")),
    "RayCluster": (
        ("spec", "headGroupSpec", "template", "spec"),
        ("spec", "workerGroupSpecs", "*", "template", "spec"),
    ),
    "RayService": (
        ("spec", "rayClusterConfig", "headGroupSpec", "template", "spec"),
        ("spec", "rayClusterConfig", "workerGroupSpecs", "*", "template", "spec"),
    ),
    "RayJob": (
        ("spec", "rayClusterSpec", "headGroupSpec", "template", "spec"),
        ("spec", "rayClusterSpec", "workerGroupSpecs", "*", "template", "spec"),
    ),
}

#: The API groups each embedded kind belongs to. A `RayCluster` from some other group is a different object
#: that happens to share a name, and is not read (G227). An object with *no* `apiVersion` is a different case:
#: the live collectors set `kind` from the resource they listed and API list items carry no apiVersion of their
#: own, so a missing group is an unknown, not a contradiction, and the pod specs are read. Refusing it would put
#: the G229 blind spot straight back for every `--live` scan, which is the mistake this registry exists to fix.
EMBEDDED_POD_SPEC_GROUPS: dict[str, frozenset[str]] = {
    "InferenceService": frozenset({"serving.kserve.io"}),
    "RayCluster": frozenset({"ray.io"}),
    "RayService": frozenset({"ray.io"}),
    "RayJob": frozenset({"ray.io"}),
}

LONG_RUNNING_KINDS = frozenset({"Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "DeploymentConfig"})
REPLICATED_KINDS = frozenset({"Deployment", "StatefulSet", "ReplicaSet", "DeploymentConfig"})


@dataclass
class PodTemplate:
    doc: Document
    spec: dict[str, Any]
    path: PathT
    #: Where this template's own metadata lives, when it has any. `None` means it has none of its own -- a
    #: KServe component is a bare PodSpec with no PodTemplateSpec around it -- and `labels()` then returns
    #: nothing rather than borrowing the object's labels, which are not what lands on the pod.
    meta_path: PathT | None = None

    @property
    def component(self) -> str:
        """Which pod spec this is, for the kinds that carry several: `predictor`, `headGroupSpec`,
        `workerGroupSpecs/0`. Empty for an ordinary workload, which has exactly one and needs no name."""
        if self.doc.kind not in EMBEDDED_POD_SPEC_PATHS:
            return ""
        parts = [str(p) for p in self.path[1:] if p not in ("template", "spec")]
        return "/".join(parts)

    @property
    def template_metadata_path(self) -> PathT | None:
        if self.meta_path is not None:
            return self.meta_path
        return self.path[:-1] + ("metadata",)

    def labels(self) -> dict[str, str]:
        path = self.template_metadata_path
        if path is None:
            return {}
        meta = get_path(self.doc.data, path)
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
    """The one pod spec of an ordinary workload kind. Kinds that carry several have `pod_templates`."""
    path = POD_SPEC_PATHS.get(doc.kind)
    if path is None:
        return None
    spec = get_path(doc.data, path)
    if not isinstance(spec, dict):
        return None
    return PodTemplate(doc=doc, spec=spec, path=path)


def _expand(data: Any, path: PathT) -> Iterator[PathT]:
    """Every concrete path `path` names, with `*` standing for each index of a list or each key of a mapping."""
    if "*" not in path:
        yield path
        return
    i = path.index("*")
    head, tail = path[:i], path[i + 1 :]
    node = get_path(data, head)
    if isinstance(node, list):
        keys: list[Any] = list(range(len(node)))
    elif isinstance(node, dict):
        keys = sorted(node)
    else:
        return
    for k in keys:
        yield from _expand(data, (*head, k, *tail))


def pod_templates(doc: Document) -> list[PodTemplate]:
    """Every pod spec in this object, wherever it lives.

    One for an ordinary workload, several for the kinds in `EMBEDDED_POD_SPEC_PATHS` -- a RayCluster has a head
    and one per worker group, an InferenceService up to three components. Returning a list rather than an
    Optional is the whole point: the previous single-template reader silently found nothing in these kinds, so
    every pod-level rule passed them (G229).
    """
    one = pod_template(doc)
    if one is not None:
        return [one]
    paths = EMBEDDED_POD_SPEC_PATHS.get(doc.kind)
    if paths is None or not isinstance(doc.data, dict):
        return []
    groups = EMBEDDED_POD_SPEC_GROUPS.get(doc.kind)
    group = doc.api_version.split("/", 1)[0]
    if groups is not None and group and group not in groups:
        return []  # same kind name, a different API group: a different object (G227)
    out: list[PodTemplate] = []
    for template in paths:
        for path in _expand(doc.data, template):
            spec = get_path(doc.data, path)
            if not isinstance(spec, dict):
                continue
            # A PodTemplateSpec ends in `spec` and has `metadata` beside it; a bare inline PodSpec (KServe's
            # components) has no metadata of its own, and claiming the object's labels are the pod's would be
            # an invention that the selector-matching rules would then act on.
            meta: PathT | None = path[:-1] + ("metadata",) if path[-1] == "spec" else None
            out.append(PodTemplate(doc=doc, spec=spec, path=path, meta_path=meta))
    return out


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
