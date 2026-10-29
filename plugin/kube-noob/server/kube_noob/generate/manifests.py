"""Step 6 - Generate: deterministic, production-grade manifests for Kubernetes, OpenShift and ROSA.

Every generated bundle is fed back through the validate/audit/red-team pipeline (see ``generate_verified``); the
generator's own tests assert that output never carries HIGH/CRITICAL findings.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from kube_noob import __version__
from kube_noob.catalog import DEFAULT_STORAGE_CLASS, OPENSHIFT_FAMILY
from kube_noob.errors import ClarificationNeeded
from kube_noob.generate.blueprint import Blueprint, clarify
from kube_noob.yamlio import dump_documents

OCP_ROUTER_NS_LABEL = {"policy-group.network.openshift.io/ingress": ""}
OCP_MONITORING_NS_LABEL = {"network.openshift.io/policy-group": "monitoring"}
SERVING_CERT_ANNOTATION = "service.beta.openshift.io/serving-cert-secret-name"
SERVICE_PORT = 80
SERVICE_PORT_TLS = 443


@dataclass
class Generated:
    objects: list[dict[str, Any]]
    assumptions: list[str] = field(default_factory=list)
    prerequisites: list[str] = field(default_factory=list)

    def yaml(self) -> str:
        return dump_documents(self.objects)


def _labels(bp: Blueprint) -> dict[str, str]:
    return {
        "app.kubernetes.io/name": bp.name,
        "app.kubernetes.io/instance": bp.name,
        "app.kubernetes.io/managed-by": "kube-noob",
    }


def _selector(bp: Blueprint) -> dict[str, str]:
    return {"app.kubernetes.io/name": bp.name, "app.kubernetes.io/instance": bp.name}


def _meta(bp: Blueprint, name: str | None = None, extra: dict[str, Any] | None = None) -> dict[str, Any]:
    m: dict[str, Any] = {"name": name or bp.name, "namespace": bp.namespace, "labels": _labels(bp)}
    if extra:
        m.update(extra)
    return m


def _probe(bp: Blueprint, path: str, *, liveness: bool) -> dict[str, Any]:
    handler: dict[str, Any]
    if bp.probe == "tcp":
        handler = {"tcpSocket": {"port": bp.port_name}}
    else:
        # reencrypt and passthrough Routes both mean the pod itself serves TLS on its port.
        tls_in_pod = bp.exposure.type == "route" and bp.exposure.tls in {"reencrypt", "passthrough"}
        scheme = "HTTPS" if tls_in_pod else "HTTP"
        handler = {"httpGet": {"path": path, "port": bp.port_name, "scheme": scheme}}
    timing = (
        {"periodSeconds": 10, "timeoutSeconds": 3, "failureThreshold": 3}
        if liveness
        else {"periodSeconds": 5, "timeoutSeconds": 2, "failureThreshold": 3}
    )
    return {**handler, **timing}


def _container(bp: Blueprint) -> dict[str, Any]:
    res: dict[str, Any] = {
        "requests": {"cpu": bp.resources.cpu_request, "memory": bp.resources.memory_request},
        "limits": {"memory": bp.resources.memory_limit},
    }
    if bp.resources.cpu_limit:
        res["limits"]["cpu"] = bp.resources.cpu_limit
    sc: dict[str, Any] = {
        "allowPrivilegeEscalation": False,
        "readOnlyRootFilesystem": bp.read_only_root_fs,
        "runAsNonRoot": True,
        "capabilities": {"drop": ["ALL"]},
    }
    if bp.run_as_user is not None:
        sc["runAsUser"] = bp.run_as_user
    c: dict[str, Any] = {
        "name": bp.name,
        "image": bp.image,
        "imagePullPolicy": "IfNotPresent",
        "ports": [{"name": bp.port_name, "containerPort": bp.port, "protocol": "TCP"}],
        "resources": res,
        "securityContext": sc,
    }
    env: list[dict[str, Any]] = [{"name": k, "value": v} for k, v in sorted(bp.env.items())]
    for k, ref in sorted(bp.secret_env.items()):
        secret, key = ref.split("/", 1)
        env.append({"name": k, "valueFrom": {"secretKeyRef": {"name": secret, "key": key}}})
    if env:
        c["env"] = env
    if bp.probe != "none":
        c["readinessProbe"] = _probe(bp, bp.readiness_path, liveness=False)
        c["livenessProbe"] = _probe(bp, bp.liveness_path, liveness=True)
        if bp.startup_seconds:
            startup = _probe(bp, bp.liveness_path, liveness=True)
            startup["failureThreshold"] = max(1, -(-bp.startup_seconds // startup["periodSeconds"]))
            c["startupProbe"] = startup
    mounts: list[dict[str, Any]] = []
    if bp.read_only_root_fs:
        for i, p in enumerate(bp.writable_paths):
            mounts.append({"name": f"writable-{i}", "mountPath": p})
    if bp.storage is not None:
        mounts.append({"name": "data", "mountPath": bp.storage.mount_path})
    if bp.exposure.type == "route" and bp.exposure.tls == "reencrypt":
        mounts.append({"name": "serving-cert", "mountPath": "/etc/tls/private", "readOnly": True})
    if mounts:
        c["volumeMounts"] = mounts
    return c


def _pod_spec(bp: Blueprint) -> dict[str, Any]:
    pod_sc: dict[str, Any] = {"runAsNonRoot": True, "seccompProfile": {"type": "RuntimeDefault"}}
    spec: dict[str, Any] = {
        "serviceAccountName": bp.name,
        "automountServiceAccountToken": False,
        "securityContext": pod_sc,
        "terminationGracePeriodSeconds": 30,
        "containers": [_container(bp)],
    }
    if bp.replicas >= 2:
        spec["topologySpreadConstraints"] = [
            {
                "maxSkew": 1,
                "topologyKey": key,
                "whenUnsatisfiable": "ScheduleAnyway",
                "labelSelector": {"matchLabels": _selector(bp)},
            }
            for key in ("topology.kubernetes.io/zone", "kubernetes.io/hostname")
        ]
    volumes: list[dict[str, Any]] = []
    if bp.read_only_root_fs:
        volumes.extend(
            {"name": f"writable-{i}", "emptyDir": {"sizeLimit": "256Mi"}} for i in range(len(bp.writable_paths))
        )
    if bp.storage is not None and bp.workload == "deployment":
        volumes.append({"name": "data", "persistentVolumeClaim": {"claimName": f"{bp.name}-data"}})
    if bp.exposure.type == "route" and bp.exposure.tls == "reencrypt":
        volumes.append({"name": "serving-cert", "secret": {"secretName": f"{bp.name}-tls"}})
    if volumes:
        spec["volumes"] = volumes
    return spec


def _storage_class(bp: Blueprint) -> str | None:
    assert bp.storage is not None  # noqa: S101 - guarded by callers
    if bp.storage.storage_class:
        return bp.storage.storage_class
    mode = "ReadWriteMany" if bp.storage.access_mode == "ReadWriteMany" else "ReadWriteOnce"
    return DEFAULT_STORAGE_CLASS[bp.platform][mode]


def _pvc_spec(bp: Blueprint) -> dict[str, Any]:
    assert bp.storage is not None  # noqa: S101
    spec: dict[str, Any] = {
        "accessModes": [bp.storage.access_mode],
        "resources": {"requests": {"storage": bp.storage.size}},
    }
    sc = _storage_class(bp)
    if sc:
        spec["storageClassName"] = sc
    return spec


def _workload(bp: Blueprint) -> dict[str, Any]:
    template = {"metadata": {"labels": _labels(bp)}, "spec": _pod_spec(bp)}
    if bp.workload == "statefulset":
        spec: dict[str, Any] = {
            "serviceName": f"{bp.name}-headless",
            "replicas": bp.replicas,
            "selector": {"matchLabels": _selector(bp)},
            "podManagementPolicy": "OrderedReady",
            "updateStrategy": {"type": "RollingUpdate"},
            "template": template,
        }
        if bp.storage is not None:
            spec["volumeClaimTemplates"] = [{"metadata": {"name": "data"}, "spec": _pvc_spec(bp)}]
        return {
            "apiVersion": "apps/v1",
            "kind": "StatefulSet",
            "metadata": _meta(bp),
            "spec": _hpa_owns_replicas(bp, spec),
        }
    strategy: dict[str, Any] = {"type": "RollingUpdate", "rollingUpdate": {"maxSurge": "25%", "maxUnavailable": 0}}
    if bp.storage is not None and bp.storage.access_mode != "ReadWriteMany":
        strategy = {"type": "Recreate"}
    spec = {
        "replicas": bp.replicas,
        "revisionHistoryLimit": 5,
        "selector": {"matchLabels": _selector(bp)},
        "strategy": strategy,
        "template": template,
    }
    return {"apiVersion": "apps/v1", "kind": "Deployment", "metadata": _meta(bp), "spec": _hpa_owns_replicas(bp, spec)}


def _hpa_owns_replicas(bp: Blueprint, spec: dict[str, Any]) -> dict[str, Any]:
    """With an HPA the manifest leaves spec.replicas out, so an apply never resets the autoscaled count (KN-C014)."""
    if bp.hpa_max_replicas:
        spec.pop("replicas", None)
    return spec


def _service(bp: Blueprint) -> list[dict[str, Any]]:
    port = {
        "name": bp.port_name,
        "port": SERVICE_PORT_TLS if _reencrypt(bp) else SERVICE_PORT,
        "targetPort": bp.port_name,
        "protocol": "TCP",
    }
    svc: dict[str, Any] = {
        "apiVersion": "v1",
        "kind": "Service",
        "metadata": _meta(bp),
        "spec": {"type": "ClusterIP", "selector": _selector(bp), "ports": [port]},
    }
    if _reencrypt(bp):
        svc["metadata"]["annotations"] = {SERVING_CERT_ANNOTATION: f"{bp.name}-tls"}
    if bp.exposure.type == "loadbalancer":
        svc["spec"]["type"] = "LoadBalancer"
        if bp.exposure.lb_source_ranges:
            svc["spec"]["loadBalancerSourceRanges"] = list(bp.exposure.lb_source_ranges)
        if bp.exposure.internal_lb:
            ann = svc["metadata"].setdefault("annotations", {})
            if bp.platform in {"rosa-classic", "rosa-hcp"}:
                ann["service.beta.kubernetes.io/aws-load-balancer-internal"] = "true"
            else:
                ann["networking.gke.io/load-balancer-type"] = "Internal"
                ann["service.beta.kubernetes.io/aws-load-balancer-internal"] = "true"
                ann["service.beta.kubernetes.io/azure-load-balancer-internal"] = "true"
    out = [svc]
    if bp.workload == "statefulset":
        out.append(
            {
                "apiVersion": "v1",
                "kind": "Service",
                "metadata": _meta(bp, f"{bp.name}-headless"),
                "spec": {
                    "clusterIP": "None",
                    "selector": _selector(bp),
                    "publishNotReadyAddresses": False,
                    "ports": [{"name": bp.port_name, "port": bp.port, "targetPort": bp.port_name, "protocol": "TCP"}],
                },
            }
        )
    return out


def _reencrypt(bp: Blueprint) -> bool:
    return bp.exposure.type == "route" and bp.exposure.tls == "reencrypt"


def _exposure(bp: Blueprint) -> list[dict[str, Any]]:
    ex = bp.exposure
    if ex.type == "route":
        tls: dict[str, Any] = {"termination": ex.tls, "insecureEdgeTerminationPolicy": "Redirect"}
        spec: dict[str, Any] = {
            "to": {"kind": "Service", "name": bp.name, "weight": 100},
            "port": {"targetPort": bp.port_name},
            "tls": tls,
            "wildcardPolicy": "None",
        }
        if ex.host:
            spec["host"] = ex.host
        if ex.path != "/" and ex.tls != "passthrough":
            spec["path"] = ex.path
        return [{"apiVersion": "route.openshift.io/v1", "kind": "Route", "metadata": _meta(bp), "spec": spec}]
    if ex.type == "ingress":
        ing_spec: dict[str, Any] = {
            "tls": [{"hosts": [ex.host], "secretName": ex.tls_secret or f"{bp.name}-tls"}],
            "rules": [
                {
                    "host": ex.host,
                    "http": {
                        "paths": [
                            {
                                "path": ex.path,
                                "pathType": "Prefix",
                                "backend": {"service": {"name": bp.name, "port": {"name": bp.port_name}}},
                            }
                        ]
                    },
                }
            ],
        }
        if ex.ingress_class:
            ing_spec = {"ingressClassName": ex.ingress_class, **ing_spec}
        return [{"apiVersion": "networking.k8s.io/v1", "kind": "Ingress", "metadata": _meta(bp), "spec": ing_spec}]
    if ex.type == "gateway":
        parent: dict[str, Any] = {"name": ex.gateway_name}
        if ex.gateway_namespace:
            parent["namespace"] = ex.gateway_namespace
        hr_spec: dict[str, Any] = {
            "parentRefs": [parent],
            "rules": [
                {
                    "matches": [{"path": {"type": "PathPrefix", "value": ex.path}}],
                    "backendRefs": [{"name": bp.name, "port": SERVICE_PORT}],
                }
            ],
        }
        if ex.host:
            hr_spec["hostnames"] = [ex.host]
        return [
            {"apiVersion": "gateway.networking.k8s.io/v1", "kind": "HTTPRoute", "metadata": _meta(bp), "spec": hr_spec}
        ]
    return []


def _network_policies(bp: Blueprint) -> list[dict[str, Any]]:
    is_ocp = bp.platform in OPENSHIFT_FAMILY
    pols: list[dict[str, Any]] = [
        {
            "apiVersion": "networking.k8s.io/v1",
            "kind": "NetworkPolicy",
            "metadata": _meta(bp, f"{bp.name}-default-deny"),
            "spec": {"podSelector": {"matchLabels": _selector(bp)}, "policyTypes": ["Ingress"]},
        }
    ]
    peers: list[dict[str, Any]] = [{"podSelector": {}}]  # same-namespace callers
    if bp.exposure.type in {"route", "ingress", "gateway"}:
        if is_ocp:
            peers.append({"namespaceSelector": {"matchLabels": OCP_ROUTER_NS_LABEL}})
        elif bp.exposure.type == "ingress":
            peers.append({"namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": "ingress-nginx"}}})
        elif bp.exposure.gateway_namespace:
            peers.append(
                {"namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": bp.exposure.gateway_namespace}}}
            )
    if bp.allow_monitoring and is_ocp:
        peers.append({"namespaceSelector": {"matchLabels": OCP_MONITORING_NS_LABEL}})
    allow: dict[str, Any] = {
        "apiVersion": "networking.k8s.io/v1",
        "kind": "NetworkPolicy",
        "metadata": _meta(bp, f"{bp.name}-allow-ingress"),
        "spec": {
            "podSelector": {"matchLabels": _selector(bp)},
            "policyTypes": ["Ingress"],
            "ingress": [{"from": peers, "ports": [{"protocol": "TCP", "port": bp.port}]}],
        },
    }
    pols.append(allow)
    if bp.egress in {"dns-only", "cidrs"}:
        dns_peer: dict[str, Any] = (
            {"namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": "openshift-dns"}}}
            if is_ocp
            else {"namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": "kube-system"}}}
        )
        dns_ports = (
            [{"protocol": "UDP", "port": 5353}, {"protocol": "TCP", "port": 5353}]
            if is_ocp
            else [{"protocol": "UDP", "port": 53}, {"protocol": "TCP", "port": 53}]
        )
        egress_rules: list[dict[str, Any]] = [{"to": [dns_peer], "ports": dns_ports}]
        if bp.egress == "cidrs":
            egress_rules.append({"to": [{"ipBlock": {"cidr": c}} for c in bp.egress_cidrs]})
        pols.append(
            {
                "apiVersion": "networking.k8s.io/v1",
                "kind": "NetworkPolicy",
                "metadata": _meta(bp, f"{bp.name}-egress"),
                "spec": {
                    "podSelector": {"matchLabels": _selector(bp)},
                    "policyTypes": ["Egress"],
                    "egress": egress_rules,
                },
            }
        )
    return pols


def _egress_firewall(bp: Blueprint) -> list[dict[str, Any]]:
    if not bp.egress_dns_names:
        return []
    rules: list[dict[str, Any]] = [{"type": "Allow", "to": {"dnsName": d}} for d in bp.egress_dns_names]
    rules.extend({"type": "Allow", "to": {"cidrSelector": c}} for c in bp.egress_cidrs)
    rules.append({"type": "Deny", "to": {"cidrSelector": "0.0.0.0/0"}})
    return [
        {
            "apiVersion": "k8s.ovn.org/v1",
            "kind": "EgressFirewall",
            "metadata": {"name": "default", "namespace": bp.namespace, "labels": _labels(bp)},
            "spec": {"egress": rules},
        }
    ]


def generate(bp: Blueprint) -> Generated:
    questions, assumptions = clarify(bp)
    if questions:
        raise ClarificationNeeded(questions)
    objs: list[dict[str, Any]] = []
    prereq: list[str] = []
    if bp.create_namespace:
        ns: dict[str, Any] = {
            "apiVersion": "v1",
            "kind": "Namespace",
            "metadata": {
                "name": bp.namespace,
                "labels": {
                    "pod-security.kubernetes.io/enforce": "restricted",
                    "pod-security.kubernetes.io/audit": "restricted",
                    "pod-security.kubernetes.io/warn": "restricted",
                },
            },
        }
        objs.append(ns)
    objs.append(
        {
            "apiVersion": "v1",
            "kind": "ServiceAccount",
            "metadata": _meta(bp),
            "automountServiceAccountToken": False,
        }
    )
    if bp.storage is not None and bp.workload == "deployment":
        objs.append(
            {
                "apiVersion": "v1",
                "kind": "PersistentVolumeClaim",
                "metadata": _meta(bp, f"{bp.name}-data"),
                "spec": _pvc_spec(bp),
            }
        )
    objs.append(_workload(bp))
    objs.extend(_service(bp))
    objs.extend(_exposure(bp))
    if bp.replicas >= 2:
        objs.append(
            {
                "apiVersion": "policy/v1",
                "kind": "PodDisruptionBudget",
                "metadata": _meta(bp),
                "spec": {"maxUnavailable": 1, "selector": {"matchLabels": _selector(bp)}},
            }
        )
    if bp.hpa_max_replicas:
        objs.append(
            {
                "apiVersion": "autoscaling/v2",
                "kind": "HorizontalPodAutoscaler",
                "metadata": _meta(bp),
                "spec": {
                    "scaleTargetRef": {
                        "apiVersion": "apps/v1",
                        "kind": "StatefulSet" if bp.workload == "statefulset" else "Deployment",
                        "name": bp.name,
                    },
                    "minReplicas": max(2, bp.replicas),
                    "maxReplicas": max(bp.hpa_max_replicas, bp.replicas),
                    "metrics": [
                        {
                            "type": "Resource",
                            "resource": {"name": "cpu", "target": {"type": "Utilization", "averageUtilization": 70}},
                        }
                    ],
                },
            }
        )
    objs.extend(_network_policies(bp))
    if bp.platform in OPENSHIFT_FAMILY:
        objs.extend(_egress_firewall(bp))
    if bp.exposure.type == "ingress":
        prereq.append(
            f"An Ingress controller and a TLS Secret '{bp.exposure.tls_secret or bp.name + '-tls'}' "
            "(e.g. issued by cert-manager) in the namespace."
        )
        if bp.platform not in OPENSHIFT_FAMILY:
            prereq.append(
                "NetworkPolicy allow rule assumes the ingress controller runs in namespace 'ingress-nginx'; "
                "adjust the namespaceSelector for other controllers."
            )
    if bp.exposure.type == "gateway":
        if bp.platform in OPENSHIFT_FAMILY:
            prereq.append(
                "A Gateway that allows routes from this namespace, backed by a GatewayClass with controllerName "
                "openshift.io/gateway-controller/v1 (OpenShift 4.19+ manages the Gateway API CRDs; earlier versions "
                "need them installed)."
            )
        else:
            prereq.append("Gateway API CRDs and a Gateway that allows routes from this namespace.")
    if bp.exposure.type == "route" and bp.exposure.tls == "passthrough":
        prereq.append(
            "passthrough: the router forwards encrypted traffic untouched, so the app must serve TLS on port "
            f"{bp.port} with a certificate valid for the Route host (probes use HTTPS; no path-based routing)."
        )
    if _reencrypt(bp):
        prereq.append(
            f"The app must serve TLS on port {bp.port} using /etc/tls/private/tls.crt and tls.key (the "
            "OpenShift service CA writes them via the serving-cert annotation)."
        )
    if bp.secret_env:
        prereq.append(
            "Secrets referenced by secretEnv must exist: "
            + ", ".join(sorted({r.split("/")[0] for r in bp.secret_env.values()}))
        )
    if bp.egress in {"dns-only", "cidrs"} and bp.platform not in OPENSHIFT_FAMILY:
        prereq.append("Egress NetworkPolicy assumes cluster DNS pods run in kube-system on port 53.")
    for o in objs:
        o.setdefault("metadata", {}).setdefault("annotations", {})["kube-noob.io/generated-by"] = (
            f"kube-noob {__version__}"
        )
    return Generated(objects=objs, assumptions=assumptions, prerequisites=prereq)
