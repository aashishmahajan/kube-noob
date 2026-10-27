"""Read-only live cluster access (opt-in: ``cluster.enabled: true``).

Two backends share one allowlist:
  * ``KubectlBackend`` - shells out to ``kubectl``/``oc`` (argv list, never a shell) using the operator's kubeconfig.
  * ``InClusterBackend`` - talks to the API server with the pod's ServiceAccount token (sidecar mode).

Guarantees: only GET-style operations on allowlisted resources; Secrets are never read; ConfigMap values, sensitive
env values and token-like strings in logs are redacted; arguments are validated against strict patterns.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

from kube_noob.audit.rules import SENSITIVE_ENV
from kube_noob.config import Settings
from kube_noob.errors import ClusterAccessError
from kube_noob.net import cluster_client

SA_DIR = Path("/var/run/secrets/kubernetes.io/serviceaccount")


@dataclass(frozen=True)
class ResourceDef:
    group_version: str  # "v1" for core
    plural: str
    namespaced: bool

    def path(self, namespace: str | None, name: str | None) -> str:
        base = "/api/v1" if self.group_version == "v1" else f"/apis/{self.group_version}"
        ns = f"/namespaces/{namespace}" if self.namespaced and namespace else ""
        tail = f"/{name}" if name else ""
        return f"{base}{ns}/{self.plural}{tail}"


ALLOWED_RESOURCES: dict[str, ResourceDef] = {
    "pods": ResourceDef("v1", "pods", True),
    "services": ResourceDef("v1", "services", True),
    "endpoints": ResourceDef("v1", "endpoints", True),
    "events": ResourceDef("v1", "events", True),
    "configmaps": ResourceDef("v1", "configmaps", True),
    "persistentvolumeclaims": ResourceDef("v1", "persistentvolumeclaims", True),
    "persistentvolumes": ResourceDef("v1", "persistentvolumes", False),
    "nodes": ResourceDef("v1", "nodes", False),
    "namespaces": ResourceDef("v1", "namespaces", False),
    "resourcequotas": ResourceDef("v1", "resourcequotas", True),
    "limitranges": ResourceDef("v1", "limitranges", True),
    "serviceaccounts": ResourceDef("v1", "serviceaccounts", True),
    "deployments": ResourceDef("apps/v1", "deployments", True),
    "replicasets": ResourceDef("apps/v1", "replicasets", True),
    "statefulsets": ResourceDef("apps/v1", "statefulsets", True),
    "daemonsets": ResourceDef("apps/v1", "daemonsets", True),
    "jobs": ResourceDef("batch/v1", "jobs", True),
    "cronjobs": ResourceDef("batch/v1", "cronjobs", True),
    "ingresses": ResourceDef("networking.k8s.io/v1", "ingresses", True),
    "networkpolicies": ResourceDef("networking.k8s.io/v1", "networkpolicies", True),
    "poddisruptionbudgets": ResourceDef("policy/v1", "poddisruptionbudgets", True),
    "horizontalpodautoscalers": ResourceDef("autoscaling/v2", "horizontalpodautoscalers", True),
    "storageclasses": ResourceDef("storage.k8s.io/v1", "storageclasses", False),
    "routes": ResourceDef("route.openshift.io/v1", "routes", True),
    "clusteroperators": ResourceDef("config.openshift.io/v1", "clusteroperators", False),
    "clusterversions": ResourceDef("config.openshift.io/v1", "clusterversions", False),
    "securitycontextconstraints": ResourceDef("security.openshift.io/v1", "securitycontextconstraints", False),
    "egressfirewalls": ResourceDef("k8s.ovn.org/v1", "egressfirewalls", True),
    "centrals": ResourceDef("platform.stackrox.io/v1alpha1", "centrals", True),
    "securedclusters": ResourceDef("platform.stackrox.io/v1alpha1", "securedclusters", True),
}

ALIASES = {
    "pod": "pods",
    "po": "pods",
    "svc": "services",
    "service": "services",
    "ep": "endpoints",
    "event": "events",
    "ev": "events",
    "cm": "configmaps",
    "configmap": "configmaps",
    "pvc": "persistentvolumeclaims",
    "pv": "persistentvolumes",
    "node": "nodes",
    "no": "nodes",
    "ns": "namespaces",
    "namespace": "namespaces",
    "quota": "resourcequotas",
    "sa": "serviceaccounts",
    "deploy": "deployments",
    "deployment": "deployments",
    "rs": "replicasets",
    "sts": "statefulsets",
    "statefulset": "statefulsets",
    "ds": "daemonsets",
    "daemonset": "daemonsets",
    "job": "jobs",
    "cj": "cronjobs",
    "cronjob": "cronjobs",
    "ing": "ingresses",
    "ingress": "ingresses",
    "netpol": "networkpolicies",
    "networkpolicy": "networkpolicies",
    "pdb": "poddisruptionbudgets",
    "hpa": "horizontalpodautoscalers",
    "sc": "storageclasses",
    "storageclass": "storageclasses",
    "route": "routes",
    "co": "clusteroperators",
    "clusteroperator": "clusteroperators",
    "clusterversion": "clusterversions",
    "scc": "securitycontextconstraints",
    "egressfirewall": "egressfirewalls",
    "central": "centrals",
    "securedcluster": "securedclusters",
}

_NAME = re.compile(r"^[a-z0-9]([-a-z0-9.]{0,251}[a-z0-9])?$")
_SELECTOR = re.compile(r"^[A-Za-z0-9._/\-=!,() ]{1,512}$")
_FIELD_SELECTOR = re.compile(r"^[A-Za-z0-9._/\-=!,]{1,512}$")
_CONTAINER = re.compile(r"^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$")

_LOG_REDACTIONS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"(?i)(authorization:\s*bearer\s+)[A-Za-z0-9._~+/=-]+"), r"\1***"),
    (re.compile(r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"), "***JWT***"),
    (re.compile(r"\b(AKIA|ASIA)[A-Z0-9]{16}\b"), "***AWS_KEY_ID***"),
    (
        re.compile(r"(?i)\b(password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key)(\"?\s*[:=]\s*\"?)[^\s\"',;]+"),
        r"\1\2***",
    ),
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----"), "***PRIVATE KEY***"),
    (re.compile(r"(?i)(://[^:/\s]+:)[^@/\s]+@"), r"\1***@"),
]


def redact_text(text: str) -> str:
    for pat, repl in _LOG_REDACTIONS:
        text = pat.sub(repl, text)
    return text


def _redact_obj(obj: Any, kind_hint: str | None = None) -> Any:
    if isinstance(obj, dict):
        out: dict[str, Any] = {}
        kind = obj.get("kind", kind_hint)
        for k, v in obj.items():
            if k == "managedFields":
                continue
            if kind == "ConfigMap" and k in {"data", "binaryData"} and isinstance(v, dict):
                out[k] = {key: f"<redacted {len(str(val))} bytes>" for key, val in v.items()}
                continue
            if k == "annotations" and isinstance(v, dict):
                out[k] = {ak: ("<redacted>" if "last-applied-configuration" in ak else av) for ak, av in v.items()}
                continue
            if k == "env" and isinstance(v, list):
                out[k] = [
                    {**e, "value": "***"}
                    if isinstance(e, dict) and "value" in e and SENSITIVE_ENV.search(str(e.get("name", "")))
                    else e
                    for e in v
                ]
                continue
            out[k] = _redact_obj(v, kind)
        return out
    if isinstance(obj, list):
        return [_redact_obj(x, kind_hint) for x in obj]
    return obj


def resolve_resource(resource: str) -> tuple[str, ResourceDef]:
    r = resource.strip().lower()
    if r in {"secret", "secrets"}:
        raise ClusterAccessError("Reading Secrets is not permitted by kube-noob's read-only guard.")
    r = ALIASES.get(r, r)
    if r not in ALLOWED_RESOURCES:
        raise ClusterAccessError(
            f"Resource '{resource}' is not in the read-only allowlist: {', '.join(sorted(ALLOWED_RESOURCES))}"
        )
    return r, ALLOWED_RESOURCES[r]


def _check(value: str | None, pattern: re.Pattern[str], what: str) -> None:
    if value is not None and not pattern.match(value):
        raise ClusterAccessError(f"Invalid {what}: {value!r}")


class Backend(Protocol):
    name: str

    def get(
        self,
        resource: str,
        name: str | None = None,
        namespace: str | None = None,
        selector: str | None = None,
        field_selector: str | None = None,
    ) -> dict[str, Any]: ...

    def logs(self, namespace: str, pod: str, container: str | None, tail: int, previous: bool) -> str: ...

    def version(self) -> dict[str, Any]: ...


class KubectlBackend:
    def __init__(self, binary: str, context: str | None, timeout: float) -> None:
        path = shutil.which(binary)
        if path is None:
            raise ClusterAccessError(f"'{binary}' not found on PATH. Install it or set cluster.backend.")
        self.binary = path
        self.name = binary
        self.context = context
        self.timeout = timeout
        if context is not None:
            _check(context, re.compile(r"^[A-Za-z0-9._:/@-]{1,253}$"), "context")

    def _run(self, args: list[str]) -> str:
        argv = [self.binary, *args, "--request-timeout", f"{int(self.timeout)}s"]
        if self.context:
            argv += ["--context", self.context]
        try:
            proc = subprocess.run(
                argv, capture_output=True, text=True, timeout=self.timeout + 5, check=False, stdin=subprocess.DEVNULL
            )
        except subprocess.TimeoutExpired as exc:
            raise ClusterAccessError(f"{self.name} timed out after {self.timeout}s") from exc
        if proc.returncode != 0:
            raise ClusterAccessError(
                f"{self.name} {' '.join(args[:3])} failed: {redact_text(proc.stderr.strip())[:800]}"
            )
        return proc.stdout

    def get(
        self,
        resource: str,
        name: str | None = None,
        namespace: str | None = None,
        selector: str | None = None,
        field_selector: str | None = None,
    ) -> dict[str, Any]:
        plural, rdef = resolve_resource(resource)
        _check(name, _NAME, "name")
        _check(namespace, _NAME, "namespace")
        _check(selector, _SELECTOR, "label selector")
        _check(field_selector, _FIELD_SELECTOR, "field selector")
        group = rdef.group_version.split("/")[0] if "/" in rdef.group_version else ""
        args = ["get", f"{plural}.{group}" if group else plural]
        if name:
            args.append(name)
        if rdef.namespaced:
            args += ["--namespace", namespace] if namespace else ["--all-namespaces"]
        if selector:
            args += ["--selector", selector]
        if field_selector:
            args += ["--field-selector", field_selector]
        args += ["--output", "json"]
        return _redact_obj(json.loads(self._run(args) or "{}"))  # type: ignore[no-any-return]

    def logs(self, namespace: str, pod: str, container: str | None, tail: int, previous: bool) -> str:
        _check(namespace, _NAME, "namespace")
        _check(pod, _NAME, "pod")
        _check(container, _CONTAINER, "container")
        args = ["logs", pod, "--namespace", namespace, f"--tail={int(tail)}"]
        if container:
            args += ["--container", container]
        if previous:
            args.append("--previous")
        return redact_text(self._run(args))

    def version(self) -> dict[str, Any]:
        return json.loads(self._run(["version", "--output", "json"]))  # type: ignore[no-any-return]


class InClusterBackend:
    name = "in-cluster"

    def __init__(self, timeout: float) -> None:
        host, port = os.environ.get("KUBERNETES_SERVICE_HOST"), os.environ.get("KUBERNETES_SERVICE_PORT", "443")
        token_file, ca_file = SA_DIR / "token", SA_DIR / "ca.crt"
        if not host or not token_file.is_file() or not ca_file.is_file():
            raise ClusterAccessError(
                "Not running in a pod with a mounted ServiceAccount token; use backend "
                "'kubectl' or 'oc' outside the cluster."
            )
        if ":" in host and not host.startswith("["):
            host = f"[{host}]"
        self.timeout = timeout
        self._base = f"https://{host}:{port}"
        self._token_file = token_file
        self._ca = str(ca_file)

    def _get(self, path: str, params: dict[str, Any] | None = None, as_text: bool = False) -> Any:
        token = self._token_file.read_text(encoding="utf-8").strip()  # re-read: projected tokens rotate
        with cluster_client(self._base, token, self._ca, self.timeout) as c:
            resp = c.get(path, params=params)
        if resp.status_code == 403:
            raise ClusterAccessError(
                f"Forbidden by RBAC: GET {path}. Grant the sidecar's ServiceAccount read "
                "access (see deploy/helm values rbac.*)."
            )
        if resp.status_code == 404:
            raise ClusterAccessError(f"Not found: GET {path}")
        if resp.status_code >= 400:
            raise ClusterAccessError(f"API error {resp.status_code} for GET {path}: {resp.text[:300]}")
        return resp.text if as_text else resp.json()

    def get(
        self,
        resource: str,
        name: str | None = None,
        namespace: str | None = None,
        selector: str | None = None,
        field_selector: str | None = None,
    ) -> dict[str, Any]:
        _plural, rdef = resolve_resource(resource)
        _check(name, _NAME, "name")
        _check(namespace, _NAME, "namespace")
        _check(selector, _SELECTOR, "label selector")
        _check(field_selector, _FIELD_SELECTOR, "field selector")
        params: dict[str, Any] = {}
        if selector:
            params["labelSelector"] = selector
        if field_selector:
            params["fieldSelector"] = field_selector
        return _redact_obj(self._get(rdef.path(namespace, name), params))  # type: ignore[no-any-return]

    def logs(self, namespace: str, pod: str, container: str | None, tail: int, previous: bool) -> str:
        _check(namespace, _NAME, "namespace")
        _check(pod, _NAME, "pod")
        _check(container, _CONTAINER, "container")
        params: dict[str, Any] = {"tailLines": int(tail), "previous": str(previous).lower()}
        if container:
            params["container"] = container
        return redact_text(self._get(f"/api/v1/namespaces/{namespace}/pods/{pod}/log", params, as_text=True))

    def version(self) -> dict[str, Any]:
        return {"serverVersion": self._get("/version")}


def get_backend(settings: Settings) -> Backend:
    if not settings.cluster.enabled:
        raise ClusterAccessError(
            "Live cluster access is disabled. Set `cluster.enabled: true` in kube-noob.yaml "
            "or KUBE_NOOB_CLUSTER_ENABLED=true (read-only; Secrets are never read)."
        )
    b = settings.cluster.backend
    t = settings.cluster.timeout_seconds
    if b == "in-cluster" or (
        b == "auto" and (SA_DIR / "token").is_file() and os.environ.get("KUBERNETES_SERVICE_HOST")
    ):
        return InClusterBackend(t)
    if b in {"kubectl", "oc"}:
        return KubectlBackend(b, settings.cluster.context, t)
    for candidate in ("oc", "kubectl"):
        if shutil.which(candidate):
            return KubectlBackend(candidate, settings.cluster.context, t)
    raise ClusterAccessError("No cluster backend available: not in a pod and neither `oc` nor `kubectl` is on PATH.")
