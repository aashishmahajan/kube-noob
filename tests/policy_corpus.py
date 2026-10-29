"""Seeded random manifests for the policy/audit equivalence test: every field the generated policies read, with the
values that sit on either side of each rule (missing, empty, case variants, zero, the boundary)."""

from __future__ import annotations

import copy
import random
from typing import Any

IMAGES = (
    "quay.io/acme/web@sha256:" + "a" * 64,
    "quay.io/acme/web:1.2.3",
    "quay.io/acme/web:latest",
    "quay.io/acme/web",
    "registry.local:5000/team/app",
    "registry.local:5000/team/app:v2",
    "app:latest@sha256:" + "b" * 64,
    "app:v1@sha256:short",
    "app:x:latest",
    "nginx:",
    "",
)
CAPS_ADD = ([], ["NET_BIND_SERVICE"], ["net_bind_service"], ["CAP_NET_BIND_SERVICE"], ["SYS_ADMIN"], ["CHOWN"], ["ALL"])
CAPS_DROP = (None, [], ["ALL"], ["all"], ["NET_RAW"], ["NET_RAW", "ALL"])
SECCOMP = (None, "RuntimeDefault", "Localhost", "Unconfined")
ENV = (
    [],
    [{"name": "LOG_LEVEL", "value": "info"}],
    [{"name": "DB_PASSWORD", "value": "hunter2"}],
    [{"name": "db_password", "value": "$(DB_PASSWORD)"}],
    [{"name": "API_KEY", "value": "   "}],
    [{"name": "API_KEY", "value": "<redacted>"}],
    [{"name": "DATABASE_URL", "value": "postgres://app:s3cr3t@db:5432/app"}],
    [{"name": "AWS", "value": "AKIA" + "ABCDEFGHIJKLMNOP"}],
    [{"name": "TOKEN", "valueFrom": {"secretKeyRef": {"name": "t", "key": "t"}}}],
    [{"name": "JWT", "value": "eyJhbGciOiJIUzI1.eyJzdWIiOiIxMjM0.SflKxwRJSMeKKF2Q"}],
)
ARGS = (
    None,
    ["--port=8080"],
    ["--password=hunter2"],
    ["--password=$(PASS)"],
    ["--db-token:abc"],
    ["--password-file=/run/secrets/p"],
    ["serve", "--api-key=   "],
    ["-token=***"],
    ["--url=https://u:p@host/"],
)
KINDS = ("Pod", "Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "ReplicationController", "Job", "CronJob")


def _maybe(rng: random.Random, value: Any, p: float = 0.5) -> Any:
    return value if rng.random() < p else None


def _set(d: dict[str, Any], key: str, value: Any) -> None:
    if value is not None:
        d[key] = value


def _sc(rng: random.Random, container: bool) -> dict[str, Any] | None:
    if rng.random() < 0.12:
        return None
    sc: dict[str, Any] = {}
    _set(sc, "runAsUser", _maybe(rng, rng.choice((0, 1000, 1001)), 0.4))
    _set(sc, "runAsNonRoot", _maybe(rng, rng.choice((True, False)), 0.6))
    _set(sc, "fsGroup", None if container else _maybe(rng, rng.choice((0, 2000)), 0.3))
    profile = rng.choice(SECCOMP)
    if profile is not None:
        sc["seccompProfile"] = {"type": profile}
    if container:
        _set(sc, "privileged", _maybe(rng, rng.choice((True, False)), 0.3))
        _set(sc, "allowPrivilegeEscalation", _maybe(rng, rng.choice((True, False)), 0.7))
        _set(sc, "readOnlyRootFilesystem", _maybe(rng, rng.choice((True, False)), 0.7))
        _set(sc, "procMount", _maybe(rng, rng.choice(("Default", "Unmasked")), 0.2))
        caps: dict[str, Any] = {}
        add = rng.choice(CAPS_ADD)
        if add:
            caps["add"] = add
        drop = rng.choice(CAPS_DROP)
        if drop is not None:
            caps["drop"] = drop
        if caps or rng.random() < 0.2:
            sc["capabilities"] = caps
    return sc


def _probe(rng: random.Random) -> dict[str, Any] | None:
    if rng.random() < 0.3:
        return None
    p: dict[str, Any] = {"httpGet": {"path": "/healthz", "port": 8080}}
    _set(p, "periodSeconds", _maybe(rng, rng.choice((1, 4, 5, 10, 30)), 0.6))
    _set(p, "failureThreshold", _maybe(rng, rng.choice((1, 2, 3)), 0.6))
    _set(p, "timeoutSeconds", _maybe(rng, rng.choice((1, 5, 10, 30)), 0.5))
    return p


def _resources(rng: random.Random) -> dict[str, Any] | None:
    if rng.random() < 0.15:
        return None
    r: dict[str, Any] = {}
    req = {k: v for k, v in (("cpu", "100m"), ("memory", "128Mi")) if rng.random() < 0.8}
    if req or rng.random() < 0.2:
        r["requests"] = req
    if rng.random() < 0.75:
        r["limits"] = {"memory": "256Mi"} if rng.random() < 0.85 else {"cpu": "1"}
    return r


def _container(rng: random.Random, name: str, app: bool) -> dict[str, Any]:
    c: dict[str, Any] = {"name": name}
    image = rng.choice(IMAGES)
    if image or rng.random() < 0.5:
        c["image"] = image
    _set(c, "securityContext", _sc(rng, True))
    _set(c, "resources", _resources(rng))
    env = rng.choice(ENV)
    if env:
        c["env"] = copy.deepcopy(env)
    args = rng.choice(ARGS)
    if args is not None:
        c[rng.choice(("args", "command"))] = list(args)
    if rng.random() < 0.3:
        c["ports"] = [{"containerPort": 8080, **({"hostPort": rng.choice((0, 80))} if rng.random() < 0.5 else {})}]
    if app:
        _set(c, "readinessProbe", _probe(rng))
        _set(c, "livenessProbe", _probe(rng))
    return c


def pod_spec(rng: random.Random) -> dict[str, Any]:
    spec: dict[str, Any] = {"containers": [_container(rng, f"app{i}", True) for i in range(rng.choice((1, 1, 2)))]}
    if rng.random() < 0.25:
        spec["initContainers"] = [_container(rng, "init", False)]
    _set(spec, "securityContext", _sc(rng, False))
    for f in ("hostNetwork", "hostPID", "hostIPC"):
        _set(spec, f, _maybe(rng, rng.choice((True, False)), 0.12))
    _set(spec, "automountServiceAccountToken", _maybe(rng, rng.choice((True, False)), 0.6))
    _set(spec, "terminationGracePeriodSeconds", _maybe(rng, rng.choice((0, 30)), 0.3))
    if rng.random() < 0.3:
        spec["volumes"] = [
            {"name": "v", "hostPath": {"path": rng.choice(("/var/log", "/var/run/docker.sock"))}}
            if rng.random() < 0.5
            else {"name": "v", "emptyDir": {}}
        ]
    if rng.random() < 0.3:
        spec["topologySpreadConstraints"] = [
            {"maxSkew": 1, "topologyKey": "topology.kubernetes.io/zone", "whenUnsatisfiable": "ScheduleAnyway"}
        ]
    elif rng.random() < 0.2:
        spec["affinity"] = {
            "podAntiAffinity": {
                "preferredDuringSchedulingIgnoredDuringExecution": [
                    {"weight": 1, "podAffinityTerm": {"topologyKey": "kubernetes.io/hostname"}}
                ]
            }
        }
    return spec


def workload(rng: random.Random, i: int, kinds: tuple[str, ...] = KINDS) -> dict[str, Any]:
    kind = rng.choice(kinds)
    meta = {"name": f"w{i}", "namespace": "shop"}
    labels = {"app": f"w{i}"}
    spec = pod_spec(rng)
    if kind == "Pod":
        return {"apiVersion": "v1", "kind": kind, "metadata": {**meta, "labels": labels}, "spec": spec}
    template = {"metadata": {"labels": labels}, "spec": spec}
    api = {"ReplicationController": "v1", "Job": "batch/v1", "CronJob": "batch/v1"}.get(kind, "apps/v1")
    if kind == "DeploymentConfig":
        api = "apps.openshift.io/v1"
    if kind == "CronJob":
        body: dict[str, Any] = {"schedule": "*/5 * * * *", "jobTemplate": {"spec": {"template": template}}}
    elif kind in {"Job", "DaemonSet"}:
        body = {"template": template}
    else:
        body = {
            "selector": {"matchLabels": labels} if kind != "ReplicationController" else labels,
            "template": template,
        }
        if kind == "DeploymentConfig":
            body["selector"] = labels
        replicas = rng.choice((None, 0, 1, 2, 3))
        if replicas is not None:
            body["replicas"] = replicas
    return {"apiVersion": api, "kind": kind, "metadata": meta, "spec": body}


def rbac(rng: random.Random, i: int) -> dict[str, Any]:
    verbs = (
        ["get", "list"],
        ["*"],
        ["create"],
        ["escalate"],
        ["bind"],
        ["patch"],
        ["update"],
        ["watch"],
        ["impersonate"],
    )
    resources = (
        ["pods"],
        ["*"],
        ["secrets"],
        ["pods/exec"],
        ["pods/attach"],
        ["nodes/proxy"],
        ["deployments"],
        ["cronjobs"],
        ["pods/ephemeralcontainers"],
        ["persistentvolumes"],
        ["configmaps"],
    )
    kind = rng.choice(("Role", "ClusterRole"))
    rules = []
    for _ in range(rng.choice((1, 1, 2))):
        r: dict[str, Any] = {"apiGroups": rng.choice(([""], ["apps"], ["*"])), "resources": list(rng.choice(resources))}
        r["verbs"] = list(rng.choice(verbs))
        rules.append(r)
    meta: dict[str, Any] = {"name": f"role-{i}"}
    if kind == "Role":
        meta["namespace"] = "shop"
    return {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": kind, "metadata": meta, "rules": rules}


def binding(rng: random.Random, i: int) -> dict[str, Any]:
    kind = rng.choice(("RoleBinding", "ClusterRoleBinding"))
    meta: dict[str, Any] = {"name": f"b-{i}"}
    if kind == "RoleBinding":
        meta["namespace"] = "shop"
    role = rng.choice(("cluster-admin", "view", "edit"))
    return {
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": kind,
        "metadata": meta,
        "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "ClusterRole", "name": role},
        "subjects": [{"kind": "ServiceAccount", "name": "web", "namespace": "shop"}],
    }


def service(rng: random.Random, i: int) -> dict[str, Any]:
    spec: dict[str, Any] = {"selector": {"app": "web"}, "ports": [{"port": 443}]}
    _set(spec, "type", rng.choice((None, "ClusterIP", "NodePort", "LoadBalancer", "LoadBalancer")))
    ranges = rng.choice((None, [], ["203.0.113.0/24"], ["0.0.0.0/0"], [" ::/0 "]))
    if ranges is not None:
        spec["loadBalancerSourceRanges"] = ranges
    meta: dict[str, Any] = {"name": f"s{i}", "namespace": "shop"}
    ann = rng.choice(
        (
            None,
            {"service.beta.kubernetes.io/aws-load-balancer-internal": "true"},
            {"service.beta.kubernetes.io/aws-load-balancer-internal": " TRUE "},
            {"service.beta.kubernetes.io/aws-load-balancer-internal": "false"},
            {"service.beta.kubernetes.io/aws-load-balancer-scheme": "internal"},
            {"networking.gke.io/load-balancer-type": "Internal"},
            {"other": "x"},
        )
    )
    if ann is not None:
        meta["annotations"] = ann
    return {"apiVersion": "v1", "kind": "Service", "metadata": meta, "spec": spec}


def route(rng: random.Random, i: int) -> dict[str, Any]:
    spec: dict[str, Any] = {"to": {"kind": "Service", "name": "web"}}
    if rng.random() < 0.8:
        tls: dict[str, Any] = {}
        _set(tls, "termination", rng.choice((None, "edge", "passthrough", "reencrypt", "edge-ish")))
        _set(tls, "insecureEdgeTerminationPolicy", rng.choice((None, "", "None", "Redirect", "Allow", "Bogus")))
        _set(tls, "certificate", rng.choice((None, None, "", "-----BEGIN CERTIFICATE-----")))
        spec["tls"] = tls
    return {
        "apiVersion": "route.openshift.io/v1",
        "kind": "Route",
        "metadata": {"name": f"r{i}", "namespace": "shop"},
        "spec": spec,
    }


def ingress(rng: random.Random, i: int) -> dict[str, Any]:
    spec: dict[str, Any] = {"rules": [{"host": "web.example.com"}]}
    tls = rng.choice((None, [], [{"hosts": ["web.example.com"], "secretName": "t"}]))
    if tls is not None:
        spec["tls"] = tls
    return {
        "apiVersion": "networking.k8s.io/v1",
        "kind": "Ingress",
        "metadata": {"name": f"i{i}", "namespace": "shop"},
        "spec": spec,
    }


def netpol(rng: random.Random, i: int) -> dict[str, Any]:
    peers = (
        {"podSelector": {"matchLabels": {"app": "front"}}},
        {"namespaceSelector": {}},
        {"namespaceSelector": {}, "podSelector": {}},
        {"namespaceSelector": {}, "podSelector": {"matchLabels": {"app": "x"}}},
        {"namespaceSelector": {"matchLabels": {"team": "a"}}},
        {"ipBlock": {"cidr": "0.0.0.0/0"}},
        {"ipBlock": {"cidr": "0.0.0.0/0", "except": ["10.0.0.0/8"]}},
        {"ipBlock": {"cidr": "10.0.0.0/8"}},
    )
    ingress_rules = []
    for _ in range(rng.choice((0, 1, 2))):
        r: dict[str, Any] = {}
        if rng.random() < 0.7:
            r["from"] = [copy.deepcopy(rng.choice(peers)) for _ in range(rng.choice((0, 1, 2)))]
        if rng.random() < 0.4:
            r["ports"] = [{"port": 8080}]
        ingress_rules.append(r)
    spec: dict[str, Any] = {"podSelector": {}}
    if ingress_rules or rng.random() < 0.5:
        spec["ingress"] = ingress_rules
    return {
        "apiVersion": "networking.k8s.io/v1",
        "kind": "NetworkPolicy",
        "metadata": {"name": f"n{i}", "namespace": "shop"},
        "spec": spec,
    }


def egress_firewall(rng: random.Random, i: int) -> dict[str, Any]:
    rules = (
        {"type": "Allow", "to": {"dnsName": "api.example.com"}},
        {"type": "Deny", "to": {"cidrSelector": "0.0.0.0/0"}},
        {"type": "Deny", "to": {"cidrSelector": "::/0"}},
        {"type": "Deny", "to": {"cidrSelector": "0.0.0.0/0"}, "ports": [{"protocol": "TCP", "port": 25}]},
        {"type": "Allow", "to": {"cidrSelector": "10.0.0.0/8"}},
    )
    egress = [copy.deepcopy(rng.choice(rules)) for _ in range(rng.choice((0, 1, 2, 3)))]
    name = rng.choice(("default", "default", "egress"))
    return {
        "apiVersion": "k8s.ovn.org/v1",
        "kind": "EgressFirewall",
        "metadata": {"name": name, "namespace": "shop"},
        "spec": {"egress": egress},
    }


def scc(rng: random.Random, i: int) -> dict[str, Any]:
    doc: dict[str, Any] = {
        "apiVersion": "security.openshift.io/v1",
        "kind": "SecurityContextConstraints",
        "metadata": {"name": f"scc{i}"},
    }
    for f in (
        "allowPrivilegedContainer",
        "allowHostNetwork",
        "allowHostPID",
        "allowHostIPC",
        "allowHostDirVolumePlugin",
        "allowHostPorts",
        "allowPrivilegeEscalation",
    ):
        _set(doc, f, _maybe(rng, rng.random() < 0.2, 0.5))
    doc["runAsUser"] = {"type": rng.choice(("MustRunAsRange", "RunAsAny", "MustRunAsNonRoot"))}
    return doc


def storage_class(rng: random.Random, i: int) -> dict[str, Any]:
    prov = rng.choice(
        ("ebs.csi.aws.com", "efs.csi.aws.com", "disk.csi.azure.com", "topolvm.io", "kubernetes.io/aws-ebs")
    )
    doc: dict[str, Any] = {
        "apiVersion": "storage.k8s.io/v1",
        "kind": "StorageClass",
        "metadata": {"name": f"sc{i}"},
        "provisioner": prov,
    }
    _set(doc, "volumeBindingMode", rng.choice((None, "Immediate", "WaitForFirstConsumer")))
    params = rng.choice(
        (
            None,
            {},
            {"provisioningMode": "efs-ap"},
            {"provisioningMode": "efs-ap", "fileSystemId": "fs-1"},
            {"provisioningMode": "", "fileSystemId": "fs-1"},
        )
    )
    if params is not None:
        doc["parameters"] = params
    return doc


def pdb(rng: random.Random, i: int) -> dict[str, Any]:
    spec: dict[str, Any] = {"selector": {"matchLabels": {"app": "w"}}}
    choice = rng.choice(
        (
            ("maxUnavailable", 0),
            ("maxUnavailable", 1),
            ("maxUnavailable", "0%"),
            ("maxUnavailable", "25%"),
            ("minAvailable", "100%"),
            ("minAvailable", 1),
            ("minAvailable", "50%"),
            ("minAvailable", 2),
        )
    )
    spec[choice[0]] = choice[1]
    return {
        "apiVersion": "policy/v1",
        "kind": "PodDisruptionBudget",
        "metadata": {"name": f"p{i}", "namespace": "shop"},
        "spec": spec,
    }


def machine_config(rng: random.Random, i: int) -> dict[str, Any]:
    kind = rng.choice(("MachineConfig", "MachineConfigPool"))
    return {
        "apiVersion": "machineconfiguration.openshift.io/v1",
        "kind": kind,
        "metadata": {"name": f"99-mc-{i}"},
        "spec": {},
    }


def corpus(seed: int, n: int, openshift: bool) -> list[dict[str, Any]]:
    rng = random.Random(seed)
    makers = [rbac, binding, service, ingress, netpol, storage_class, pdb]
    if openshift:
        makers += [route, egress_firewall, scc, machine_config]
    kinds = (*KINDS, "DeploymentConfig") if openshift else KINDS
    out: list[dict[str, Any]] = []
    for i in range(n):
        if rng.random() < 0.6:
            out.append(workload(rng, i, kinds))
        else:
            out.append(rng.choice(makers)(rng, i))
    return out
