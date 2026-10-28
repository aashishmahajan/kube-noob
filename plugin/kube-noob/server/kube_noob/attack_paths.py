"""Attack paths: from what is exposed to what a compromised pod could do (requirements R3.2). Read-only, tier R.

A path starts at an exposure (a Route, an Ingress, a LoadBalancer, NodePort or externalIPs Service), goes to the
Service and the workloads it selects, and ends at what those pods can do if an attacker runs code in them:

- on the node: a privileged container, a hostPath volume (the container runtime socket or a system directory is
  worst), the host's PID, network or IPC namespace, or near-root capabilities;
- through the Kubernetes API, with the ServiceAccount token mounted in the pod: the RBAC it is bound to (read
  Secrets, exec into pods, create or change workloads, escalate, bind or impersonate, nodes/proxy, full control), and
  on OpenShift a privileged SecurityContextConstraints it may use together with the right to create workloads.

Each path scores exposure x blast radius (internet 3, node network or restricted load balancer 2, internal network 1;
blast radius 1-10, cluster-wide above namespace) and lists every step with the field that proves it. Paths are ranked
by score, then by fewer steps.

What it reads: Routes, Ingresses, Services, workloads, ServiceAccounts, Roles, RoleBindings, ClusterRoles,
ClusterRoleBindings and SecurityContextConstraints, from manifests or (``--live``) the cluster's read-only allowlist.
Never Secrets: Secret objects in a bundle are dropped before analysis, and the live allowlist refuses them. Not
modelled: NetworkPolicies on the entry edge (``kube-noob policy reach`` checks them), cloud IAM, admission-time
mutation (an SCC adding a UID), and tokens mounted by hand through projected volumes.

The built-in ClusterRoles cluster-admin, admin, edit and view are known by their documented meaning when a bundle
does not carry them (https://kubernetes.io/docs/reference/access-authn-authz/rbac/#user-facing-roles: edit and admin
can read Secrets and run pods as any ServiceAccount of the namespace; view cannot read Secrets).
"""

from __future__ import annotations

from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from typing import Any

from kube_noob.audit.podspec import selector_matches
from kube_noob.audit.rules import (
    ESCALATION_VERBS,
    INTERNAL_LB_ANNOTATIONS,
    RUNTIME_SOCKETS,
    WORKLOAD_RESOURCES,
)

MAX_OBJECTS = 50_000
MAX_PATHS = 200
DEFAULT_TOP = 20

# kind of each list the live scan reads (API list items carry no kind of their own)
LIVE_RESOURCES: dict[str, str] = {
    "routes": "Route",
    "ingresses": "Ingress",
    "services": "Service",
    "pods": "Pod",
    "deployments": "Deployment",
    "statefulsets": "StatefulSet",
    "daemonsets": "DaemonSet",
    "replicasets": "ReplicaSet",
    "jobs": "Job",
    "cronjobs": "CronJob",
    "deploymentconfigs": "DeploymentConfig",
    "serviceaccounts": "ServiceAccount",
    "roles": "Role",
    "rolebindings": "RoleBinding",
    "clusterroles": "ClusterRole",
    "clusterrolebindings": "ClusterRoleBinding",
    "securitycontextconstraints": "SecurityContextConstraints",
}
CLUSTER_SCOPED = frozenset({"clusterroles", "clusterrolebindings", "securitycontextconstraints"})
KINDS = frozenset(LIVE_RESOURCES.values())
_POD_PATHS: dict[str, tuple[str, ...]] = {
    "Pod": ("spec",),
    "CronJob": ("spec", "jobTemplate", "spec", "template", "spec"),
}
_WORKLOAD_KINDS = frozenset(
    {"Pod", "Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "Job", "CronJob", "DeploymentConfig"}
)
_NODE_CAPS = frozenset({"SYS_ADMIN", "SYS_PTRACE", "SYS_MODULE", "DAC_READ_SEARCH", "BPF", "NET_ADMIN", "ALL"})
_SYSTEM_PATHS = frozenset({"/", "/etc", "/var/lib/kubelet", "/proc", "/root", "/var/run", "/run"})
PRIVILEGED_SCCS = frozenset(
    {"privileged", "hostaccess", "hostmount-anyuid", "hostnetwork", "hostnetwork-v2", "node-exporter"}
)
_RBAC_GROUP = "rbac.authorization.k8s.io"
_IDENTITY_RESOURCES = frozenset({"roles", "clusterroles", "users", "groups", "serviceaccounts"})

# Documented meaning of the user-facing ClusterRoles, used only when the input does not carry them.
BUILTIN_CLUSTER_ROLES: dict[str, list[dict[str, Any]]] = {
    "cluster-admin": [{"apiGroups": ["*"], "resources": ["*"], "verbs": ["*"]}],
    "admin": [
        {"apiGroups": [""], "resources": ["secrets"], "verbs": ["get", "list", "watch", "create", "update", "delete"]},
        {"apiGroups": [""], "resources": ["pods/exec", "pods/attach"], "verbs": ["create", "get"]},
        {
            "apiGroups": ["", "apps", "batch"],
            "resources": ["pods", "deployments", "statefulsets", "daemonsets", "replicasets", "jobs", "cronjobs"],
            "verbs": ["create", "update", "patch", "delete"],
        },
        {"apiGroups": [_RBAC_GROUP], "resources": ["roles", "rolebindings"], "verbs": ["create", "update", "patch"]},
    ],
    "edit": [
        {"apiGroups": [""], "resources": ["secrets"], "verbs": ["get", "list", "watch", "create", "update", "delete"]},
        {"apiGroups": [""], "resources": ["pods/exec", "pods/attach"], "verbs": ["create", "get"]},
        {
            "apiGroups": ["", "apps", "batch"],
            "resources": ["pods", "deployments", "statefulsets", "daemonsets", "replicasets", "jobs", "cronjobs"],
            "verbs": ["create", "update", "patch", "delete"],
        },
    ],
    "view": [{"apiGroups": ["", "apps", "batch"], "resources": ["pods", "services", "deployments"], "verbs": ["get"]}],
}


class ScanError(ValueError):
    """The input cannot be scanned (too many objects, nothing to read)."""


@dataclass(frozen=True)
class Step:
    source: str
    target: str
    edge: str
    evidence: str

    def as_dict(self) -> dict[str, str]:
        return {"from": self.source, "to": self.target, "edge": self.edge, "evidence": self.evidence}


@dataclass(frozen=True)
class Capability:
    name: str
    scope: str  # "node", "cluster" or "namespace <ns>"
    weight: int
    evidence: str
    fix: str


@dataclass(frozen=True)
class Entry:
    exposure: str
    weight: int
    steps: tuple[Step, ...]
    namespace: str
    service: str
    fix: str


@dataclass
class AttackPath:
    entry: Entry
    steps: list[Step]
    capability: Capability
    score: int = field(init=False)

    def __post_init__(self) -> None:
        self.score = self.entry.weight * self.capability.weight

    def as_dict(self, rank: int) -> dict[str, Any]:
        return {
            "rank": rank,
            "score": self.score,
            "exposure": {"kind": self.entry.exposure, "weight": self.entry.weight},
            "blastRadius": {
                "capability": self.capability.name,
                "scope": self.capability.scope,
                "weight": self.capability.weight,
            },
            "summary": " -> ".join([self.steps[0].source, *(s.target for s in self.steps)]),
            "steps": [s.as_dict() for s in self.steps],
            "fix": [self.capability.fix, self.entry.fix],
        }


def _ref(obj: dict[str, Any]) -> str:
    meta = obj.get("metadata") or {}
    ns = meta.get("namespace")
    return f"{obj.get('kind')}/{ns}/{meta.get('name')}" if ns else f"{obj.get('kind')}/{meta.get('name')}"


object_ref = _ref  # Kind/namespace/name (Kind/name without a namespace), as audit findings name resources


def _ns(obj: dict[str, Any]) -> str:
    return str((obj.get("metadata") or {}).get("namespace") or "default")


def _name(obj: dict[str, Any]) -> str:
    return str((obj.get("metadata") or {}).get("name") or "")


def _get(obj: Any, *path: str) -> Any:
    for key in path:
        if not isinstance(obj, dict):
            return None
        obj = obj.get(key)
    return obj


def _list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _strs(value: Any) -> set[str]:
    return {str(x) for x in _list(value)}


@dataclass
class Inventory:
    objects: dict[str, list[dict[str, Any]]] = field(default_factory=dict)
    not_read: list[str] = field(default_factory=list)
    dropped_secrets: int = 0

    def add(self, obj: Any, kind: str | None = None) -> None:
        if not isinstance(obj, dict):
            return
        k = kind or str(obj.get("kind") or "")
        if k == "Secret":
            self.dropped_secrets += 1  # never analysed, never echoed
            return
        if k not in KINDS:
            return
        if sum(len(v) for v in self.objects.values()) >= MAX_OBJECTS:
            raise ScanError(f"more than {MAX_OBJECTS} objects; scan fewer namespaces")
        obj = {**obj, "kind": k}
        self.objects.setdefault(k, []).append(obj)

    def of(self, *kinds: str) -> list[dict[str, Any]]:
        return [o for k in kinds for o in self.objects.get(k, [])]

    @classmethod
    def from_documents(cls, docs: Iterable[Any]) -> Inventory:
        inv = cls()
        for d in docs:
            if isinstance(d, dict) and d.get("kind") == "List":
                for item in _list(d.get("items")):
                    inv.add(item)
            else:
                inv.add(d)
        return inv


def _pod_spec(obj: dict[str, Any]) -> dict[str, Any] | None:
    spec = _get(obj, *_POD_PATHS.get(str(obj.get("kind")), ("spec", "template", "spec")))
    return spec if isinstance(spec, dict) else None


def _template_labels(obj: dict[str, Any]) -> dict[str, str]:
    if obj.get("kind") == "Pod":
        labels = _get(obj, "metadata", "labels")
    elif obj.get("kind") == "CronJob":
        labels = _get(obj, "spec", "jobTemplate", "spec", "template", "metadata", "labels")
    else:
        labels = _get(obj, "spec", "template", "metadata", "labels")
    return {str(k): str(v) for k, v in labels.items()} if isinstance(labels, dict) else {}


def _owned(obj: dict[str, Any]) -> bool:
    return any(
        isinstance(o, dict) and o.get("controller") is True for o in _list(_get(obj, "metadata", "ownerReferences"))
    )


def _containers(spec: dict[str, Any]) -> Iterator[dict[str, Any]]:
    for key in ("initContainers", "containers", "ephemeralContainers"):
        for c in _list(spec.get(key)):
            if isinstance(c, dict):
                yield c


# --- exposure ----------------------------------------------------------------------------------------------------


def _service_exposure(svc: dict[str, Any]) -> tuple[str, int, str, str] | None:
    """(exposure, weight, evidence, fix) for a Service that is itself an entry, else None."""
    spec = svc.get("spec") or {}
    stype = spec.get("type") or "ClusterIP"
    if stype == "LoadBalancer":
        ann = _get(svc, "metadata", "annotations") or {}
        internal = isinstance(ann, dict) and any(
            str(ann.get(k, "")).strip().lower() in v for k, v in INTERNAL_LB_ANNOTATIONS.items()
        )
        ranges = _strs(spec.get("loadBalancerSourceRanges"))
        if internal:
            return (
                "internal network (internal load balancer)",
                1,
                "spec.type=LoadBalancer, internal annotation",
                "keep the load balancer internal and limit who can reach it",
            )
        if ranges and not ranges & {"0.0.0.0/0", "::/0"}:
            return (
                "restricted internet (load balancer source ranges)",
                2,
                f"spec.type=LoadBalancer, loadBalancerSourceRanges={sorted(ranges)}",
                "keep loadBalancerSourceRanges as narrow as the clients",
            )
        return (
            "internet (public load balancer)",
            3,
            "spec.type=LoadBalancer, no source ranges, not internal",
            "set loadBalancerSourceRanges or make the load balancer internal",
        )
    if stype == "NodePort":
        return ("node network (NodePort)", 2, "spec.type=NodePort", "use ClusterIP behind a Route or Ingress")
    if _list(spec.get("externalIPs")):
        return (
            "node network (externalIPs)",
            2,
            f"spec.externalIPs={_list(spec.get('externalIPs'))[:3]}",
            "remove spec.externalIPs",
        )
    return None


def _entries(inv: Inventory) -> list[Entry]:
    services = {(_ns(s), _name(s)) for s in inv.of("Service")}
    out: list[Entry] = []
    for r in inv.of("Route"):
        backends = [_get(r, "spec", "to")] + _list(_get(r, "spec", "alternateBackends"))
        host = _get(r, "spec", "host") or "the router's default host"
        for b in backends:
            if isinstance(b, dict) and b.get("name") and (b.get("kind") or "Service") == "Service":
                svc = str(b["name"])
                step = Step("internet", _ref(r), "exposed by", f"Route host {host}")
                step2 = Step(_ref(r), f"Service/{_ns(r)}/{svc}", "routes to", f"spec.to.name={svc}")
                if (_ns(r), svc) in services:
                    out.append(
                        Entry(
                            "internet (Route)",
                            3,
                            (step, step2),
                            _ns(r),
                            svc,
                            "remove the Route or put authentication in front of it",
                        )
                    )
    for ing in inv.of("Ingress"):
        names: list[str] = []
        default = _get(ing, "spec", "defaultBackend", "service", "name")
        if default:
            names.append(str(default))
        for rule in _list(_get(ing, "spec", "rules")):
            for p in _list(_get(rule, "http", "paths")):
                n = _get(p, "backend", "service", "name")
                if n:
                    names.append(str(n))
        for svc in dict.fromkeys(names):
            if (_ns(ing), svc) in services:
                hosts = [str(_get(x, "host")) for x in _list(_get(ing, "spec", "rules")) if _get(x, "host")]
                step = Step("internet", _ref(ing), "exposed by", f"Ingress hosts {hosts[:3] or ['*']}")
                step2 = Step(_ref(ing), f"Service/{_ns(ing)}/{svc}", "routes to", f"backend.service.name={svc}")
                out.append(
                    Entry(
                        "internet (Ingress)",
                        3,
                        (step, step2),
                        _ns(ing),
                        svc,
                        "remove the Ingress rule or put authentication in front of it",
                    )
                )
    for s in inv.of("Service"):
        exp = _service_exposure(s)
        if exp:
            label, weight, evidence, fix = exp
            src = label.split(" (")[0]
            out.append(Entry(label, weight, (Step(src, _ref(s), "exposed by", evidence),), _ns(s), _name(s), fix))
    return out


# --- what a pod can do -------------------------------------------------------------------------------------------


def _node_capabilities(w: dict[str, Any], spec: dict[str, Any]) -> list[Capability]:
    out: list[Capability] = []
    for c in _containers(spec):
        name = c.get("name")
        raw_sc = c.get("securityContext")
        sc: dict[str, Any] = raw_sc if isinstance(raw_sc, dict) else {}
        if sc.get("privileged") is True:
            out.append(
                Capability(
                    "privileged container: full access to the node",
                    "node",
                    9,
                    f"container {name} securityContext.privileged=true",
                    "remove privileged; grant only the capability needed",
                )
            )
        caps = {str(x).upper().removeprefix("CAP_") for x in _list(_get(sc, "capabilities", "add"))}
        if caps & _NODE_CAPS:
            out.append(
                Capability(
                    f"near-root capabilities {sorted(caps & _NODE_CAPS)}",
                    "node",
                    7,
                    f"container {name} capabilities.add={sorted(caps)}",
                    "drop the added capabilities",
                )
            )
    for v in _list(spec.get("volumes")):
        path = _get(v, "hostPath", "path")
        if isinstance(path, str):
            norm = path.rstrip("/") or "/"
            worst = norm in _SYSTEM_PATHS or any(norm.endswith(s) for s in RUNTIME_SOCKETS)
            out.append(
                Capability(
                    f"host path {path}" + (": node takeover" if worst else ""),
                    "node",
                    9 if worst else 7,
                    f"volume {v.get('name')} hostPath.path={path}",
                    "replace the hostPath volume with a PVC, emptyDir or ConfigMap",
                )
            )
    for fld, weight in (("hostPID", 8), ("hostNetwork", 6), ("hostIPC", 5)):
        if spec.get(fld) is True:
            out.append(Capability(f"host namespace {fld}", "node", weight, f"spec.{fld}=true", f"remove {fld}"))
    return out


@dataclass(frozen=True)
class Grant:
    """One RBAC rule that applies to a ServiceAccount, with where it came from."""

    rule: dict[str, Any]
    cluster: bool
    namespace: str
    evidence: str
    role_ref: str


def _role_rules(inv: Inventory) -> tuple[dict[tuple[str, str], list[Any]], dict[str, list[Any]]]:
    roles = {(_ns(r), _name(r)): _list(r.get("rules")) for r in inv.of("Role")}
    cluster_roles = {_name(r): _list(r.get("rules")) for r in inv.of("ClusterRole")}
    # aggregated ClusterRoles in a bundle: the controller fills their rules in a cluster; do it here
    labels = {
        _name(r): {str(k): str(v) for k, v in (_get(r, "metadata", "labels") or {}).items()}
        for r in inv.of("ClusterRole")
    }
    for r in inv.of("ClusterRole"):
        selectors = _list(_get(r, "aggregationRule", "clusterRoleSelectors"))
        if selectors and not cluster_roles.get(_name(r)):
            merged: list[Any] = []
            for other, lab in labels.items():
                if other != _name(r) and any(isinstance(s, dict) and selector_matches(s, lab) for s in selectors):
                    merged += cluster_roles.get(other, [])
            cluster_roles[_name(r)] = merged
    for name, rules in BUILTIN_CLUSTER_ROLES.items():
        cluster_roles.setdefault(name, rules)
    return roles, cluster_roles


def _sa_groups(sa_ns: str) -> set[str]:
    return {"system:serviceaccounts", f"system:serviceaccounts:{sa_ns}", "system:authenticated"}


def _subject_matches(subj: Any, sa_ns: str, sa: str, binding_ns: str | None) -> str | None:
    if not isinstance(subj, dict):
        return None
    kind, name = subj.get("kind"), str(subj.get("name") or "")
    if kind == "ServiceAccount":
        ns = subj.get("namespace") or binding_ns
        return f"subject ServiceAccount {ns}/{name}" if name == sa and ns == sa_ns else None
    if kind == "Group" and name in {
        "system:serviceaccounts",
        f"system:serviceaccounts:{sa_ns}",
        "system:authenticated",
    }:
        return f"subject Group {name}"
    if kind == "User" and name == f"system:serviceaccount:{sa_ns}:{sa}":
        return f"subject User {name}"
    return None


def _grants(inv: Inventory, sa_ns: str, sa: str) -> list[Grant]:
    roles, cluster_roles = _role_rules(inv)
    out: list[Grant] = []
    for b in inv.of("RoleBinding", "ClusterRoleBinding"):
        cluster = b.get("kind") == "ClusterRoleBinding"
        bns = None if cluster else _ns(b)
        if (
            not cluster
            and bns != sa_ns
            and not any(isinstance(s, dict) and s.get("kind") == "ServiceAccount" for s in _list(b.get("subjects")))
        ):
            continue
        who = next((m for s in _list(b.get("subjects")) if (m := _subject_matches(s, sa_ns, sa, bns))), None)
        if who is None:
            continue
        ref = b.get("roleRef") or {}
        rname = str(ref.get("name") or "")
        if ref.get("kind") == "Role" and not cluster:
            rules = roles.get((str(bns), rname))
            role_ref = f"Role/{bns}/{rname}"
        else:
            rules = cluster_roles.get(rname)
            role_ref = f"ClusterRole/{rname}"
        if rules is None:
            inv.not_read.append(f"{role_ref} (bound by {_ref(b)}) is not in the input")
            continue
        for i, rule in enumerate(rules):
            if isinstance(rule, dict):
                out.append(
                    Grant(rule, cluster, str(bns or ""), f"{_ref(b)} ({who}) -> {role_ref} rules[{i}]", role_ref)
                )
    # OpenShift legacy: an SCC listing the ServiceAccount (or its groups) lets it use the SCC
    for scc in inv.of("SecurityContextConstraints"):
        users = _strs(scc.get("users"))
        groups = _strs(scc.get("groups"))
        if f"system:serviceaccount:{sa_ns}:{sa}" in users or groups & _sa_groups(sa_ns):
            rule = {
                "apiGroups": ["security.openshift.io"],
                "resources": ["securitycontextconstraints"],
                "verbs": ["use"],
                "resourceNames": [_name(scc)],
            }
            out.append(Grant(rule, True, "", f"{_ref(scc)} users/groups name the ServiceAccount", _ref(scc)))
    return out


def _privileged_scc_names(inv: Inventory) -> set[str]:
    names = set(PRIVILEGED_SCCS)
    for scc in inv.of("SecurityContextConstraints"):
        if scc.get("allowPrivilegedContainer") is True or scc.get("allowHostDirVolumePlugin") is True:
            names.add(_name(scc))
    return names


def _api_capabilities(inv: Inventory, grants: list[Grant]) -> list[Capability]:
    found: dict[tuple[str, str], Capability] = {}
    workload_grant: Grant | None = None
    scc_grant: tuple[Grant, str] | None = None
    privileged = _privileged_scc_names(inv)

    def add(name: str, g: Grant, cluster_w: int, ns_w: int, fix: str, named: bool = False) -> None:
        scope = "cluster" if g.cluster else f"namespace {g.namespace}"
        weight = (cluster_w if g.cluster else ns_w) - (2 if named else 0)
        cap = Capability(name + (" (named objects only)" if named else ""), scope, weight, g.evidence, fix)
        key = (cap.name, scope)
        if key not in found or found[key].weight < weight:
            found[key] = cap

    for g in grants:
        verbs, res = _strs(g.rule.get("verbs")), _strs(g.rule.get("resources"))
        groups, names = _strs(g.rule.get("apiGroups")), _strs(g.rule.get("resourceNames"))
        any_res, any_verb = "*" in res, "*" in verbs
        core = bool(groups & {"", "*"}) or not groups
        builtin = g.role_ref.removeprefix("ClusterRole/") in BUILTIN_CLUSTER_ROLES or ":" in g.role_ref.split("/")[-1]
        narrow = (
            f"bind a narrower Role than the built-in {g.role_ref}"
            if builtin
            else f"narrow {g.evidence.split(' -> ')[-1]}"
        )
        if any_res and any_verb and "*" in groups:
            add("full control", g, 10, 7, f"bind a narrower role than {g.role_ref}")
        if core and (any_res or "secrets" in res) and (any_verb or verbs & {"get", "list", "watch"}):
            add(
                "read Secrets (credentials, tokens of other ServiceAccounts)",
                g,
                8,
                6,
                f"{narrow}: drop secrets",
                named=bool(names),
            )
        if verbs & ESCALATION_VERBS or (any_verb and (any_res or res & _IDENTITY_RESOURCES)):
            add("escalate, bind or impersonate", g, 9, 6, f"{narrow}: drop escalate, bind and impersonate")
        if (any_res or res & {"pods/exec", "pods/attach"}) and (any_verb or "create" in verbs):
            add("exec into pods", g, 7, 5, f"{narrow}: drop pods/exec and pods/attach")
        if (any_res or res & WORKLOAD_RESOURCES) and (any_verb or verbs & {"create", "patch", "update"}):
            add(
                "create or change workloads (run as any ServiceAccount of the namespace)",
                g,
                7,
                5,
                f"{narrow}: drop create/patch/update on workloads",
            )
            workload_grant = workload_grant or g
        if (any_res or "nodes/proxy" in res) and (any_verb or verbs & {"get", "create"}) and g.cluster:
            add("kubelet API through nodes/proxy", g, 8, 8, f"{narrow}: drop nodes/proxy")
        if "securitycontextconstraints" in res and (any_verb or "use" in verbs):
            usable = names & privileged if names else privileged
            if usable:
                scc_grant = (g, sorted(usable)[0])
    if workload_grant and scc_grant:
        g, scc = scc_grant
        found[("run privileged pods", "node")] = Capability(
            f"run privileged pods (SCC {scc} + create workloads)",
            "node",
            9,
            f"{g.evidence}; and {workload_grant.evidence}",
            f"remove the 'use' grant on SCC {scc} or the right to create workloads",
        )
    return list(found.values())


def _token(inv: Inventory, w: dict[str, Any], spec: dict[str, Any]) -> tuple[str, str] | None:
    """(ServiceAccount, evidence) when the pod mounts a token, else None."""
    sa = str(spec.get("serviceAccountName") or spec.get("serviceAccount") or "default")
    pod_flag = spec.get("automountServiceAccountToken")
    if pod_flag is False:
        return None
    if pod_flag is not True:
        for obj in inv.of("ServiceAccount"):
            if _ns(obj) == _ns(w) and _name(obj) == sa and obj.get("automountServiceAccountToken") is False:
                return None
    how = "automountServiceAccountToken=true" if pod_flag is True else "token mounted (automount not turned off)"
    return sa, f"spec.serviceAccountName={sa}; {how}"


# --- the scan ----------------------------------------------------------------------------------------------------


@dataclass
class Reach:
    """What an attacker running code in one workload's pods gets, and how they would arrive (VUL1 ranks findings in
    the workload's images with it)."""

    ref: str
    namespace: str
    images: list[str]
    entries: list[tuple[int, Entry, list[Step]]]  # (index in the entry list, entry, steps up to the workload)
    node: list[Capability]
    api: list[tuple[Capability, list[Step]]]  # capability and the steps from the workload to it
    token: tuple[str, str] | None = None  # (ServiceAccount ref, evidence) when the pods mount its token

    def paths_from(self, index: int) -> list[AttackPath]:
        out: list[AttackPath] = []
        for i, entry, base in self.entries:
            if i != index:
                continue
            for cap in self.node:
                out.append(AttackPath(entry, [*base, Step(self.ref, "node", "runs on", cap.evidence)], cap))
            for cap, tail in self.api:
                out.append(AttackPath(entry, [*base, *tail], cap))
        return out

    def paths(self) -> list[AttackPath]:
        out = [p for i in dict.fromkeys(i for i, _, _ in self.entries) for p in self.paths_from(i)]
        out.sort(key=lambda p: (-p.score, len(p.steps), p.as_dict(0)["summary"]))
        return out

    @property
    def exposure(self) -> Entry | None:
        """The widest exposure that reaches the workload (internet before node network before internal)."""
        best = sorted(self.entries, key=lambda e: (-e[1].weight, e[0]))
        return best[0][1] if best else None

    @property
    def capabilities(self) -> list[Capability]:
        caps = [*self.node, *(c for c, _ in self.api)]
        return sorted(caps, key=lambda c: (-c.weight, c.name))

    def entry_steps(self) -> list[Step]:
        best = sorted(self.entries, key=lambda e: (-e[1].weight, e[0]))
        return list(best[0][2]) if best else []


def _reach(
    inv: Inventory,
    w: dict[str, Any],
    spec: dict[str, Any],
    entries: list[Entry],
    sa_caps: dict[tuple[str, str], list[Capability]],
) -> Reach:
    ref = _ref(w)
    reach_entries: list[tuple[int, Entry, list[Step]]] = []
    for i, entry in enumerate(entries):
        if _ns(w) != entry.namespace:
            continue
        svc = next((s for s in inv.of("Service") if _ns(s) == entry.namespace and _name(s) == entry.service), None)
        selector = _get(svc, "spec", "selector") if svc else None
        if not isinstance(selector, dict) or not selector:
            continue
        if not selector_matches({"matchLabels": selector}, _template_labels(w)):
            continue
        to_w = Step(
            f"Service/{entry.namespace}/{entry.service}",
            ref,
            "selects",
            f"selector {selector} matches the pod template labels",
        )
        reach_entries.append((i, entry, [*entry.steps, to_w]))
    api: list[tuple[Capability, list[Step]]] = []
    tok = _token(inv, w, spec)
    if tok is not None:
        sa, evidence = tok
        key = (_ns(w), sa)
        if key not in sa_caps:
            sa_caps[key] = _api_capabilities(inv, _grants(inv, *key))
        sa_ref = f"ServiceAccount/{key[0]}/{sa}"
        for cap in sa_caps[key]:
            target = "node" if cap.scope == "node" else ("cluster" if cap.scope == "cluster" else key[0])
            api.append(
                (
                    cap,
                    [
                        Step(ref, sa_ref, "uses token of", evidence),
                        Step(sa_ref, f"{cap.name} ({target})", "is allowed to", cap.evidence),
                    ],
                )
            )
    images = [str(c.get("image")) for c in _containers(spec) if isinstance(c.get("image"), str) and c.get("image")]
    token = (f"ServiceAccount/{_ns(w)}/{tok[0]}", tok[1]) if tok else None
    return Reach(ref, _ns(w), images, reach_entries, _node_capabilities(w, spec), api, token)


def workload_reach(inv: Inventory) -> dict[str, Reach]:
    """Every workload (not owned by another) with its exposures, node and API capabilities, keyed by Kind/ns/name."""
    entries = _entries(inv)
    sa_caps: dict[tuple[str, str], list[Capability]] = {}
    out: dict[str, Reach] = {}
    for w in inv.of(*_WORKLOAD_KINDS):
        if _owned(w):
            continue
        spec = _pod_spec(w)
        if spec is not None:
            out[_ref(w)] = _reach(inv, w, spec, entries, sa_caps)
    return out


def scan(inv: Inventory, *, top: int = DEFAULT_TOP) -> dict[str, Any]:
    if not 1 <= top <= MAX_PATHS:
        raise ScanError(f"top must be 1-{MAX_PATHS}")
    workloads = [w for w in inv.of(*_WORKLOAD_KINDS) if not _owned(w)]
    entries = _entries(inv)
    sa_caps: dict[tuple[str, str], list[Capability]] = {}
    reach: list[Reach] = []
    for w in workloads:
        spec = _pod_spec(w)
        if spec is not None:
            reach.append(_reach(inv, w, spec, entries, sa_caps))
    paths: list[AttackPath] = []
    for i in range(len(entries)):
        for r in reach:
            paths.extend(r.paths_from(i))
    paths.sort(key=lambda p: (-p.score, len(p.steps), p.as_dict(0)["summary"]))
    out_paths = [p.as_dict(i + 1) for i, p in enumerate(paths[:top])]
    head = out_paths[0]["summary"] if out_paths else "no path from an exposure to a node or to API rights"
    return {
        "paths": out_paths,
        "total": len(paths),
        "entries": len(entries),
        "workloads": len(workloads),
        "summary": f"{len(paths)} attack paths from {len(entries)} exposures; top: {head}",
        "notRead": sorted(set(inv.not_read))[:50],
        "secretsIgnored": inv.dropped_secrets,
        "limitations": [
            "NetworkPolicies on the entry edge are not applied: check a path with `kube-noob policy reach`.",
            "Cloud IAM, admission-time mutation and tokens mounted through projected volumes are not modelled.",
            "Roles that are not in the input are reported in notRead; cluster-admin, admin, edit and view are known.",
        ],
    }


def scan_manifests(text: str, *, top: int = DEFAULT_TOP) -> dict[str, Any]:
    from kube_noob.yamlio import load_documents

    docs = load_documents(text)
    return scan(Inventory.from_documents(d.data for d in docs), top=top)


def collect_live(backend: Any, namespaces: list[str]) -> Inventory:
    """Read the inventory from the cluster through the read-only backend: never Secrets (not in its allowlist)."""
    from kube_noob.errors import KubeNoobError

    inv = Inventory()
    for resource, kind in LIVE_RESOURCES.items():
        scopes: list[str | None] = [None] if resource in CLUSTER_SCOPED or not namespaces else list(namespaces)
        for ns in scopes:
            try:
                data = backend.get(resource, namespace=ns)
            except KubeNoobError as exc:  # forbidden or not served (no Routes or SCCs on Kubernetes)
                inv.not_read.append(f"{resource}{' in ' + ns if ns else ''}: {str(exc)[:160]}")
                continue
            for item in _list(data.get("items")) if isinstance(data, dict) else []:
                inv.add(item, kind)
    return inv
