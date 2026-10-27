"""Deterministic rule set.

Each rule has stable metadata (id, title, stage, default severity, remediation, citations) and a check function
``check(ctx) -> Iterable[Finding]``. Rule ids are part of the public contract (graders, exercises and the training
reward refer to them), so never renumber; retire with ``deprecated=True`` instead.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Iterable, Iterator
from dataclasses import dataclass, field
from typing import Any

from kube_noob.audit.model import Finding, Severity, Stage
from kube_noob.audit.podspec import (
    LONG_RUNNING_KINDS,
    REPLICATED_KINDS,
    ContainerRef,
    PodTemplate,
    containers,
    effective_security,
    pod_template,
    replicas,
    selector_matches,
)
from kube_noob.audit.quantity import parse_quantity
from kube_noob.catalog import (
    ADDON_GROUPS_ON_VANILLA,
    KIND_API_VERSIONS,
    KNOWN_STORAGE_CLASSES,
    OPENSHIFT_FAMILY,
    OPENSHIFT_ONLY_GROUPS,
    PROVISIONERS,
    ROSA_FAMILY,
    api_group,
    deprecated_api,
    parse_minor,
    removed_api,
)
from kube_noob.yamlio import Document, PathT, fmt_path, get_path


@dataclass
class AuditContext:
    docs: list[Document]
    platform: str
    k8s_version: str
    platform_version: str | None = None

    @property
    def is_openshift(self) -> bool:
        return self.platform in OPENSHIFT_FAMILY

    @property
    def is_rosa(self) -> bool:
        return self.platform in ROSA_FAMILY

    def by_kind(self, *kinds: str) -> list[Document]:
        return [d for d in self.docs if d.kind in kinds]

    def workloads(self) -> Iterator[tuple[Document, PodTemplate]]:
        for d in self.docs:
            pt = pod_template(d)
            if pt is not None:
                yield d, pt

    def ns(self, doc: Document) -> str:
        return doc.namespace or "<default>"


@dataclass(frozen=True)
class Rule:
    rule_id: str
    title: str
    stage: Stage
    category: str
    severity: Severity
    remediation: str
    description: str
    citations: tuple[str, ...] = ()
    stackrox_policies: tuple[str, ...] = ()
    check: Callable[[AuditContext, Rule], Iterable[Finding]] | None = field(default=None, compare=False)

    def finding(
        self,
        doc: Document | None,
        path: PathT,
        message: str,
        *,
        severity: Severity | None = None,
        remediation: str | None = None,
        resource: str | None = None,
    ) -> Finding:
        return Finding(
            rule_id=self.rule_id,
            title=self.title,
            severity=severity if severity is not None else self.severity,
            stage=self.stage,
            category=self.category,
            resource=resource or (doc.ref() if doc else "<bundle>"),
            message=message,
            remediation=remediation or self.remediation,
            path=fmt_path(path),
            line=doc.line_for(path) if doc else None,
            doc_index=doc.index if doc else None,
            citations=list(self.citations),
            stackrox_policies=list(self.stackrox_policies),
        )

    def as_dict(self) -> dict[str, Any]:
        return {
            "ruleId": self.rule_id,
            "title": self.title,
            "stage": self.stage.value,
            "category": self.category,
            "defaultSeverity": self.severity.name.lower(),
            "description": self.description,
            "remediation": self.remediation,
            "citations": list(self.citations),
            "stackroxPolicies": list(self.stackrox_policies),
        }


RULES: dict[str, Rule] = {}


def rule(
    rule_id: str,
    title: str,
    stage: Stage,
    category: str,
    severity: Severity,
    remediation: str,
    description: str,
    citations: tuple[str, ...] = (),
    stackrox: tuple[str, ...] = (),
) -> Callable[[Callable[[AuditContext, Rule], Iterable[Finding]]], Callable[[AuditContext, Rule], Iterable[Finding]]]:
    def deco(
        fn: Callable[[AuditContext, Rule], Iterable[Finding]],
    ) -> Callable[[AuditContext, Rule], Iterable[Finding]]:
        if rule_id in RULES:
            raise RuntimeError(f"duplicate rule id {rule_id}")
        RULES[rule_id] = Rule(
            rule_id, title, stage, category, severity, remediation, description, citations, stackrox, fn
        )
        return fn

    return deco


DNS1123_SUBDOMAIN = re.compile(r"^[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*$")
NAMESPACED_EXEMPT = frozenset(
    {
        "Namespace",
        "ClusterRole",
        "ClusterRoleBinding",
        "StorageClass",
        "PersistentVolume",
        "CustomResourceDefinition",
        "PriorityClass",
        "RuntimeClass",
        "IngressClass",
        "CSIDriver",
        "ValidatingWebhookConfiguration",
        "MutatingWebhookConfiguration",
        "SecurityContextConstraints",
        "MachineConfig",
        "MachineConfigPool",
        "KubeletConfig",
        "ClusterResourceQuota",
        "GatewayClass",
        "Project",
    }
)

# =====================================================================================================
# VALIDATE
# =====================================================================================================


@rule(
    "KN-V001",
    "Object is missing apiVersion, kind or metadata.name",
    Stage.VALIDATE,
    "schema",
    Severity.HIGH,
    "Every object needs apiVersion, kind and metadata.name (or metadata.generateName).",
    "kubectl/oc reject objects without these identity fields.",
)
def _v001(ctx: AuditContext, r: Rule) -> Iterator[Finding]:
    for d in ctx.docs:
        if not isinstance(d.data, dict):
            yield r.finding(
                d, (), "Document is not a mapping; it cannot be a Kubernetes object.", resource=f"doc[{d.index}]"
            )
            continue
        missing = [k for k in ("apiVersion", "kind") if not d.data.get(k)]
        meta = d.data.get("metadata")
        if not isinstance(meta, dict) or not (meta.get("name") or meta.get("generateName")):
            missing.append("metadata.name")
        if missing:
            yield r.finding(d, (), f"Missing required field(s): {', '.join(missing)}.", resource=f"doc[{d.index}]")


@rule(
    "KN-V002",
    "apiVersion does not serve this kind",
    Stage.VALIDATE,
    "api",
    Severity.CRITICAL,
    "Use the apiVersion that serves this kind (see message).",
    "A kind sent to an API group/version that does not serve it fails with 'no matches for kind'. "
    "Classic example: Route is route.openshift.io/v1, not apps.openshift.io/v1 (that group serves DeploymentConfig).",
    ("k8s-deprecation-guide", "ocp-routes"),
)
def _v002(ctx: AuditContext, r: Rule) -> Iterator[Finding]:
    for d in ctx.docs:
        if not isinstance(d.data, dict):
            continue
        valid = KIND_API_VERSIONS.get(d.kind)
        if not valid or d.api_version in valid:
            continue
        if removed_api(d.api_version, d.kind, "99.0") is not None:
            continue  # handled by the deprecation rules with a precise version message
        yield r.finding(d, ("apiVersion",), f"{d.kind} is not served by '{d.api_version}'. Use {' or '.join(valid)}.")


@rule(
    "KN-V003",
    "OpenShift-only API used on a non-OpenShift target",
    Stage.VALIDATE,
    "platform",
    Severity.CRITICAL,
    "Target an OpenShift platform, or replace with the upstream equivalent (Route -> Ingress/Gateway API "
    "HTTPRoute, DeploymentConfig -> Deployment, SCC -> Pod Security Admission labels).",
    "Groups such as route.openshift.io or security.openshift.io do not exist on vanilla Kubernetes.",
    ("ocp-routes", "k8s-pss"),
)
def _v003(ctx: AuditContext, r: Rule) -> Iterator[Finding]:
    if ctx.is_openshift:
        return
    for d in ctx.docs:
        g = api_group(d.api_version)
        if g in OPENSHIFT_ONLY_GROUPS:
            yield r.finding(
                d,
                ("apiVersion",),
                f"{d.kind} ({d.api_version}) only exists on OpenShift; target platform is '{ctx.platform}'.",
            )


@rule(
    "KN-V004",
    "API requires an add-on on this platform",
    Stage.VALIDATE,
    "platform",
    Severity.MEDIUM,
    "Install the add-on (or its CRDs) before applying, or remove the object.",
    "Some API groups are present by default on OpenShift but need an operator/CRDs on vanilla Kubernetes.",
)
def _v004(ctx: AuditContext, r: Rule) -> Iterator[Finding]:
    for d in ctx.docs:
        g = api_group(d.api_version)
        if g in ADDON_GROUPS_ON_VANILLA:
            if ctx.is_openshift and g in {"k8s.ovn.org", "monitoring.coreos.com", "operators.coreos.com"}:
                continue
            yield r.finding(d, ("apiVersion",), f"{d.kind} needs: {ADDON_GROUPS_ON_VANILLA[g]}.")


@rule(
    "KN-V005",
    "API removed in the target Kubernetes version",
    Stage.VALIDATE,
    "deprecation",
    Severity.CRITICAL,
    "Migrate to the replacement apiVersion (see message); `kube-noob fix` performs mechanical migrations.",
    "Removed APIs are rejected by the API server; the object will not apply.",
    ("k8s-deprecation-guide",),
)
def _v005(ctx: AuditContext, r: Rule) -> Iterator[Finding]:
    for d in ctx.docs:
        rem = removed_api(d.api_version, d.kind, ctx.k8s_version)
        if rem:
            repl = f"use {rem.replacement}" if rem.replacement else "no replacement API"
            note = f" Note: {rem.notes}." if rem.notes else ""
            yield r.finding(
                d,
                ("apiVersion",),
                f"{d.kind} {d.api_version} was removed in Kubernetes "
                f"{rem.removed_in} (target {ctx.k8s_version}); {repl}.{note}",
            )


@rule(
    "KN-V006",
    "Deprecated API in the target Kubernetes version",
    Stage.VALIDATE,
    "deprecation",
    Severity.MEDIUM,
    "Migrate before the removal release.",
    "Deprecated APIs still work but will be removed.",
    ("k8s-deprecation-guide",),
)
def _v006(ctx: AuditContext, r: Rule) -> Iterator[Finding]:
    for d in ctx.docs:
        dep = deprecated_api(d.api_version, d.kind, ctx.k8s_version)
        if dep:
            yield r.finding(
                d,
                ("apiVersion",),
                f"{d.kind} {d.api_version} is deprecated and is removed in "
                f"Kubernetes {dep.removed_in}; migrate to {dep.replacement or 'a supported API'}.",
            )


@rule(
    "KN-V008",
    "DeploymentConfig is deprecated",
    Stage.VALIDATE,
    "deprecation",
    Severity.MEDIUM,
    "Use apps/v1 Deployment (with image triggers via the image.openshift.io/triggers annotation if needed).",
    "DeploymentConfig (apps.openshift.io/v1) is deprecated since OpenShift 4.14.",
    ("ocp-deploymentconfig-deprecation",),
)
def _v008(ctx: AuditContext, r: Rule) -> Iterator[Finding]:
    if not ctx.is_openshift:
        return
    if ctx.platform_version and parse_minor(ctx.platform_version) < (4, 14):
        return
    for d in ctx.by_kind("DeploymentConfig"):
        yield r.finding(
            d, ("kind",), "DeploymentConfig is deprecated (OpenShift 4.14+); new workloads should use Deployment."
        )


@rule(
    "KN-V009",
    "metadata.name is not a valid DNS-1123 name",
    Stage.VALIDATE,
    "schema",
    Severity.HIGH,
    "Use lowercase alphanumerics, '-' and '.', starting and ending with an alphanumeric, max 253 chars "
    "(63 for Services, Namespaces and labels).",
    "The API server rejects invalid object names.",
)
def _v009(ctx: AuditContext, r: Rule) -> Iterator[Finding]:
    for d in ctx.docs:
        name = d.name
        if not name:
            continue
        limit = 63 if d.kind in {"Service", "Namespace", "Project"} else 253
        if len(name) > limit or not DNS1123_SUBDOMAIN.match(name) or (d.kind == "Service" and "." in name):
            yield r.finding(d, ("metadata", "name"), f"'{name}' is not a valid name for {d.kind} (limit {limit}).")


@rule(
    "KN-V010",
    "Workload selector does not match its pod template labels",
    Stage.VALIDATE,
    "schema",
    Severity.CRITICAL,
    "Make spec.selector.matchLabels a subset of spec.template.metadata.labels.",
    "apps/v1 rejects workloads whose selector does not select their own template ('selector does not match "
    "template labels').",
)
def _v010(ctx: AuditContext, r: Rule) -> Iterator[Finding]:
    for d, pt in ctx.workloads():
        if d.kind not in {"Deployment", "StatefulSet", "DaemonSet", "ReplicaSet"}:
            continue
        sel = get_path(d.data, ("spec", "selector"))
        if not isinstance(sel, dict) or not sel:
            yield r.finding(d, ("spec", "selector"), "spec.selector is required for apps/v1 workloads.")
            continue
        if not selector_matches(sel, pt.labels()):
            yield r.finding(
                d,
                ("spec", "selector"),
                f"Selector {sel.get('matchLabels') or sel} does not match template labels {pt.labels()}.",
            )


@rule(
    "KN-V011",
    "Service selects no pods in this bundle",
    Stage.VALIDATE,
    "wiring",
    Severity.MEDIUM,
    "Align Service spec.selector with the pod template labels of the workload it fronts.",
    "A Service whose selector matches no pods has no endpoints; Routes/Ingresses in front of it return 503.",
)
def _v011(ctx: AuditContext, r: Rule) -> Iterator[Finding]:
    workloads = list(ctx.workloads())
    if not workloads:
        return
    for svc in ctx.by_kind("Service"):
        sel = get_path(svc.data, ("spec", "selector"))
        if not isinstance(sel, dict) or not sel:
            continue  # headless/external services without selectors are legitimate
        ns = ctx.ns(svc)
        same_ns = [pt for d, pt in workloads if ctx.ns(d) == ns]
        if not same_ns:
            continue
        if not any(selector_matches({"matchLabels": sel}, pt.labels()) for pt in same_ns):
            yield r.finding(
                svc,
                ("spec", "selector"),
                f"Selector {sel} matches no pod template in namespace {ns}; the Service will have no endpoints.",
            )


@rule(
    "KN-V012",
    "Service targetPort name is not declared by the selected containers",
    Stage.VALIDATE,
    "wiring",
    Severity.HIGH,
    "Declare the named containerPort or use the numeric port.",
    "A named targetPort that no selected container exposes results in a Service without ready endpoints.",
)
def _v012(ctx: AuditContext, r: Rule) -> Iterator[Finding]:
    workloads = list(ctx.workloads())
    for svc in ctx.by_kind("Service"):
        sel = get_path(svc.data, ("spec", "selector"))
        if not isinstance(sel, dict) or not sel:
            continue
        pods = [
            pt
            for d, pt in workloads
            if ctx.ns(d) == ctx.ns(svc) and selector_matches({"matchLabels": sel}, pt.labels())
        ]
        if not pods:
            continue
        names = {
            str(p.get("name"))
            for pt in pods
            for c in containers(pt, include_init=False)
            for p in (c.container.get("ports") or [])
            if isinstance(p, dict) and p.get("name")
        }
        for i, port in enumerate(get_path(svc.data, ("spec", "ports")) or []):
            tp = port.get("targetPort") if isinstance(port, dict) else None
            if isinstance(tp, str) and not tp.isdigit() and tp not in names:
                yield r.finding(
                    svc,
                    ("spec", "ports", i, "targetPort"),
                    f"targetPort '{tp}' is not a named "
                    f"containerPort of the selected pods (named ports: {sorted(names) or 'none'}).",
                )


@rule(
    "KN-V014",
    "Duplicate object in bundle",
    Stage.VALIDATE,
    "schema",
    Severity.HIGH,
    "Remove or rename the duplicate; the later object silently overwrites the earlier one on apply.",
    "Two objects with the same kind, namespace and name collide.",
)
def _v014(ctx: AuditContext, r: Rule) -> Iterator[Finding]:
    seen: dict[tuple[str, str, str], Document] = {}
    for d in ctx.docs:
        if not d.kind or not d.name:
            continue
        key = (d.kind, d.namespace or "", d.name)
        if key in seen:
            yield r.finding(d, ("metadata", "name"), f"Duplicates doc[{seen[key].index}] ({d.ref()}).")
        else:
            seen[key] = d


@rule(
    "KN-V015",
    "EgressFirewall must be named 'default'",
    Stage.VALIDATE,
    "network",
    Severity.HIGH,
    "Rename the EgressFirewall to 'default' and keep one per namespace.",
    "OVN-Kubernetes accepts a single EgressFirewall per namespace and it must be named 'default'; other names "
    "are rejected/ignored.",
    ("ocp-egressfirewall",),
)
def _v015(ctx: AuditContext, r: Rule) -> Iterator[Finding]:
    per_ns: dict[str, int] = {}
    for d in ctx.by_kind("EgressFirewall"):
        per_ns[ctx.ns(d)] = per_ns.get(ctx.ns(d), 0) + 1
        if d.name != "default":
            yield r.finding(d, ("metadata", "name"), f"EgressFirewall is named '{d.name}', must be 'default'.")
    for ns, n in per_ns.items():
        if n > 1:
            yield r.finding(
                None,
                (),
                f"{n} EgressFirewall objects in namespace {ns}; only one is allowed.",
                resource=f"EgressFirewall/{ns}/*",
            )


@rule(
    "KN-V016",
    "Route TLS configuration is invalid",
    Stage.VALIDATE,
    "network",
    Severity.HIGH,
    "termination must be edge, passthrough or reencrypt; passthrough supports insecureEdgeTerminationPolicy "
    "None or Redirect only; certificates are not allowed with passthrough.",
    "The router rejects Routes with invalid TLS settings.",
    ("ocp-routes",),
)
def _v016(ctx: AuditContext, r: Rule) -> Iterator[Finding]:
    for d in ctx.by_kind("Route"):
        tls = get_path(d.data, ("spec", "tls"))
        if not isinstance(tls, dict):
            continue
        term = tls.get("termination")
        if term not in {"edge", "passthrough", "reencrypt"}:
            yield r.finding(d, ("spec", "tls", "termination"), f"Invalid termination {term!r}.")
            continue
        policy = tls.get("insecureEdgeTerminationPolicy")
        if policy not in {None, "", "None", "Redirect", "Allow"}:
            yield r.finding(d, ("spec", "tls", "insecureEdgeTerminationPolicy"), f"Invalid policy {policy!r}.")
        if term == "passthrough" and policy == "Allow":
            yield r.finding(
                d,
                ("spec", "tls", "insecureEdgeTerminationPolicy"),
                "passthrough Routes cannot use insecureEdgeTerminationPolicy: Allow.",
            )
        if term == "passthrough" and any(tls.get(k) for k in ("certificate", "key", "caCertificate")):
            yield r.finding(
                d, ("spec", "tls"), "passthrough Routes must not carry certificates; the backend terminates TLS."
            )


@rule(
    "KN-V017",
    "MachineConfig is not a customer lever on ROSA",
    Stage.VALIDATE,
    "platform",
    Severity.HIGH,
    "Use the managed interfaces instead: `rosa create kubeletconfig` for kubelet tuning and machine pools "
    "(`rosa create/edit machinepool`) for node sizing, labels and taints.",
    "ROSA is a managed service. On ROSA with HCP the Machine Config Operator does not run in the hosted cluster "
    "(HyperShift applies node configuration from the management side via NodePool config), and Red Hat's guidance "
    "is not to rely on customer-owned MachineConfig changes on ROSA.",
    ("rosa-hcp-architecture",),
)
def _v017(ctx: AuditContext, r: Rule) -> Iterator[Finding]:
    if not ctx.is_rosa:
        return
    for d in ctx.by_kind("MachineConfig", "MachineConfigPool"):
        yield r.finding(d, ("kind",), f"{d.kind} is not a supported customer lever on {ctx.platform}.")


# =====================================================================================================
# AUDIT - security
# =====================================================================================================

DANGEROUS_CAPS = frozenset(
    {
        "ALL",
        "SYS_ADMIN",
        "NET_ADMIN",
        "SYS_PTRACE",
        "SYS_MODULE",
        "DAC_READ_SEARCH",
        "NET_RAW",
        "SYS_RAWIO",
        "SYS_BOOT",
        "MAC_ADMIN",
        "MAC_OVERRIDE",
        "BPF",
        "PERFMON",
        "SYS_CHROOT",
        "SETFCAP",
        "SYS_TIME",
        "SYSLOG",
        "DAC_OVERRIDE",
        "LINUX_IMMUTABLE",
    }
)
PSS_RESTRICTED_ALLOWED_ADD = frozenset({"NET_BIND_SERVICE"})
SENSITIVE_ENV = re.compile(
    r"(PASS(WORD|WD)?|SECRET|TOKEN|API[_-]?KEY|PRIVATE[_-]?KEY|CREDENTIAL|ACCESS[_-]?KEY)", re.IGNORECASE
)
RUNTIME_SOCKETS = ("docker.sock", "containerd.sock", "crio.sock", "cri-dockerd.sock")


def _containers(ctx: AuditContext) -> Iterator[tuple[Document, PodTemplate, ContainerRef]]:
    for d, pt in ctx.workloads():
        for c in containers(pt):
            yield d, pt, c


@rule(
    "KN-S001",
    "Privileged container",
    Stage.AUDIT,
    "security",
    Severity.CRITICAL,
    "Remove securityContext.privileged; grant only the specific capability required.",
    "A privileged container has full access to the host (all devices, all capabilities). On OpenShift it is "
    "rejected unless the ServiceAccount is granted the 'privileged' SCC.",
    ("k8s-pss", "ocp-scc"),
    ("Privileged Container",),
)
def _s001(ctx: AuditContext, r: Rule) -> Iterator[Finding]:
    for d, _pt, c in _containers(ctx):
        sc = c.container.get("securityContext")
        if isinstance(sc, dict) and sc.get("privileged") is True:
            yield r.finding(d, (*c.path, "securityContext", "privileged"), f"Container '{c.name}' is privileged.")


@rule(
    "KN-S002",
    "Privilege escalation not disabled",
    Stage.AUDIT,
    "security",
    Severity.MEDIUM,
    "Set securityContext.allowPrivilegeEscalation: false on every container.",
    "Required by the Pod Security 'restricted' profile; prevents setuid binaries from gaining privileges. "
    "OpenShift's restricted-v2 SCC (default for new 4.11+ installs) defaults it to false and rejects an explicit "
    "true; clusters upgraded from 4.10 or earlier may still admit pods under the legacy 'restricted' SCC.",
    ("k8s-pss", "ocp-scc"),
    ("Container with privilege escalation allowed",),
)
def _s002(ctx: AuditContext, r: Rule) -> Iterator[Finding]:
    for d, _pt, c in _containers(ctx):
        raw_sc = c.container.get("securityContext")
        sc: dict[str, Any] = raw_sc if isinstance(raw_sc, dict) else {}
        val = sc.get("allowPrivilegeEscalation")
        path = (*c.path, "securityContext", "allowPrivilegeEscalation")
        if val is True:
            yield r.finding(
                d, path, f"Container '{c.name}' explicitly allows privilege escalation.", severity=Severity.HIGH
            )
        elif val is None:
            # restricted-v2 (new 4.11+ installs) defaults it to false; clusters upgraded from <=4.10 still
            # admit pods under the legacy 'restricted' SCC, which does not.
            sev = Severity.LOW if ctx.is_openshift else Severity.MEDIUM
            yield r.finding(
                d, path, f"Container '{c.name}' does not set allowPrivilegeEscalation: false.", severity=sev
            )


@rule(
    "KN-S003",
    "Container may run as root",
    Stage.AUDIT,
    "security",
    Severity.MEDIUM,
    "Set runAsNonRoot: true (pod or container securityContext) and build images with a non-root USER.",
    "Running as UID 0 widens the impact of a container breakout. On OpenShift the restricted-v2 SCC assigns an "
    "arbitrary non-root UID, so images must also work as a random UID in group 0.",
    ("k8s-pss", "ocp-scc"),
    ("Docker CIS 4.1: Ensure That a User for the Container Has Been Created",),
)
def _s003(ctx: AuditContext, r: Rule) -> Iterator[Finding]:
    for d, pt, c in _containers(ctx):
        uid = effective_security(pt, c, "runAsUser")
        non_root = effective_security(pt, c, "runAsNonRoot")
        if uid == 0:
            yield r.finding(
                d,
                (*c.path, "securityContext", "runAsUser"),
                f"Container '{c.name}' runs as UID 0.",
                severity=Severity.HIGH,
            )
        elif non_root is not True and not (isinstance(uid, int) and uid > 0):
            sev = Severity.INFO if ctx.is_openshift else Severity.MEDIUM
            yield r.finding(
                d,
                (*c.path, "securityContext"),
                f"Container '{c.name}' does not enforce runAsNonRoot: true.",
                severity=sev,
            )


@rule(
    "KN-S004",
    "Fixed UID/GID conflicts with OpenShift restricted-v2 SCC",
    Stage.AUDIT,
    "platform",
    Severity.HIGH,
    "Remove runAsUser/runAsGroup/fsGroup and let OpenShift assign IDs from the namespace range; keep "
    "runAsNonRoot: true. If a fixed UID is truly required, bind the ServiceAccount to the nonroot-v2 SCC.",
    "restricted-v2 uses MustRunAsRange: pods requesting a UID outside the namespace's "
    "openshift.io/sa.scc.uid-range annotation are rejected ('unable to validate against any security context "
    "constraint').",
    ("ocp-scc",),
)
def _s004(ctx: AuditContext, r: Rule) -> Iterator[Finding]:
    if not ctx.is_openshift:
        return
    for d, pt in ctx.workloads():
        psc = pt.spec.get("securityContext")
        if isinstance(psc, dict):
            for f in ("runAsUser", "runAsGroup", "fsGroup"):
                if isinstance(psc.get(f), int) and psc[f] != 0:
                    yield r.finding(
                        d,
                        (*pt.path, "securityContext", f),
                        f"Pod sets {f}: {psc[f]}; restricted-v2 will reject IDs outside the namespace range.",
                    )
        for c in containers(pt):
            csc = c.container.get("securityContext")
            if isinstance(csc, dict):
                for f in ("runAsUser", "runAsGroup"):
                    if isinstance(csc.get(f), int) and csc[f] != 0:
                        yield r.finding(
                            d,
                            (*c.path, "securityContext", f),
                            f"Container '{c.name}' sets {f}: "
                            f"{csc[f]}; restricted-v2 will reject IDs outside the namespace range.",
                        )


@rule(
    "KN-S005",
    "Dangerous Linux capabilities added",
    Stage.AUDIT,
    "security",
    Severity.HIGH,
    "Remove the capability; the Pod Security 'restricted' profile only allows adding NET_BIND_SERVICE.",
    "Capabilities like SYS_ADMIN or NET_ADMIN are near-root and enable container escapes.",
    ("k8s-pss",),
    ("CAP_SYS_ADMIN capability added",),
)
def _s005(ctx: AuditContext, r: Rule) -> Iterator[Finding]:
    for d, _pt, c in _containers(ctx):
        add = get_path(c.container, ("securityContext", "capabilities", "add")) or []
        for i, cap in enumerate(add if isinstance(add, list) else []):
            cap_u = str(cap).upper().removeprefix("CAP_")
            if cap_u in DANGEROUS_CAPS:
                yield r.finding(
                    d, (*c.path, "securityContext", "capabilities", "add", i), f"Container '{c.name}' adds {cap_u}."
                )
            elif cap_u not in PSS_RESTRICTED_ALLOWED_ADD:
                yield r.finding(
                    d,
                    (*c.path, "securityContext", "capabilities", "add", i),
                    f"Container '{c.name}' adds {cap_u} (not allowed by PSS restricted).",
                    severity=Severity.MEDIUM,
                )


@rule(
    "KN-S006",
    "Capabilities not dropped",
    Stage.AUDIT,
    "security",
    Severity.LOW,
    'Set securityContext.capabilities.drop: ["ALL"].',
    "Pod Security 'restricted' requires dropping ALL capabilities. OpenShift restricted-v2 drops them for you, the "
    "legacy 'restricted' SCC (clusters upgraded from <=4.10) does not.",
    ("k8s-pss", "ocp-scc"),
    ("Drop All Capabilities",),
)
def _s006(ctx: AuditContext, r: Rule) -> Iterator[Finding]:
    for d, _pt, c in _containers(ctx):
        drop = get_path(c.container, ("securityContext", "capabilities", "drop")) or []
        if not any(str(x).upper() == "ALL" for x in (drop if isinstance(drop, list) else [])):
            yield r.finding(
                d, (*c.path, "securityContext", "capabilities"), f"Container '{c.name}' does not drop ALL capabilities."
            )


@rule(
    "KN-S007",
    "Writable root filesystem",
    Stage.AUDIT,
    "security",
    Severity.LOW,
    "Set readOnlyRootFilesystem: true and mount emptyDir volumes for paths the app writes (e.g. /tmp).",
    "A read-only root filesystem blocks tampering and many post-exploitation techniques.",
    ("k8s-pss",),
    ("Container using read-write root filesystem",),
)
def _s007(ctx: AuditContext, r: Rule) -> Iterator[Finding]:
    for d, _pt, c in _containers(ctx):
        if get_path(c.container, ("securityContext", "readOnlyRootFilesystem")) is not True:
            yield r.finding(d, (*c.path, "securityContext"), f"Container '{c.name}' has a writable root filesystem.")


@rule(
    "KN-S008",
    "Seccomp profile not set to RuntimeDefault",
    Stage.AUDIT,
    "security",
    Severity.LOW,
    "Set securityContext.seccompProfile.type: RuntimeDefault at pod level.",
    "Pod Security 'restricted' requires RuntimeDefault or Localhost seccomp; Unconfined disables syscall "
    "filtering. OpenShift restricted-v2 applies RuntimeDefault by default.",
    ("k8s-pss", "ocp-scc"),
    ("Docker CIS 5.21: Ensure the default seccomp profile is not disabled",),
)
def _s008(ctx: AuditContext, r: Rule) -> Iterator[Finding]:
    for d, pt in ctx.workloads():
        pod_t = get_path(pt.spec, ("securityContext", "seccompProfile", "type"))
        for c in containers(pt):
            ct = get_path(c.container, ("securityContext", "seccompProfile", "type"))
            eff = ct or pod_t
            if eff == "Unconfined":
                yield r.finding(
                    d,
                    (*c.path, "securityContext", "seccompProfile"),
                    f"Container '{c.name}' runs with seccomp Unconfined.",
                    severity=Severity.MEDIUM,
                )
            elif eff not in {"RuntimeDefault", "Localhost"}:
                yield r.finding(
                    d,
                    (*pt.path, "securityContext", "seccompProfile"),
                    f"Container '{c.name}' has no RuntimeDefault seccomp profile.",
                )


@rule(
    "KN-S009",
    "Host namespaces shared",
    Stage.AUDIT,
    "security",
    Severity.HIGH,
    "Remove hostNetwork/hostPID/hostIPC unless this is a node agent that truly needs it.",
    "Sharing host namespaces exposes host processes and network; OpenShift requires a privileged/hostnetwork SCC.",
    ("k8s-pss", "ocp-scc"),
    (
        "Docker CIS 5.9 and 5.20: Ensure that the host's network namespace is not shared",
        "Docker CIS 5.15: Ensure that the host's process namespace is not shared",
        "Docker CIS 5.16: Ensure that the host's IPC namespace is not shared",
    ),
)
def _s009(ctx: AuditContext, r: Rule) -> Iterator[Finding]:
    for d, pt in ctx.workloads():
        for f in ("hostNetwork", "hostPID", "hostIPC"):
            if pt.spec.get(f) is True:
                yield r.finding(d, (*pt.path, f), f"Pod sets {f}: true.")


@rule(
    "KN-S010",
    "hostPath volume",
    Stage.AUDIT,
    "security",
    Severity.HIGH,
    "Replace hostPath with a PVC, emptyDir, ConfigMap/Secret or a CSI ephemeral volume.",
    "hostPath mounts let a container read or modify the node filesystem; container runtime sockets give full "
    "node takeover.",
    ("k8s-pss",),
    ("Mounting Sensitive Host Directories", "Mount Container Runtime Socket"),
)
def _s010(ctx: AuditContext, r: Rule) -> Iterator[Finding]:
    for d, pt in ctx.workloads():
        for i, v in enumerate(pt.spec.get("volumes") or []):
            if not isinstance(v, dict) or not isinstance(v.get("hostPath"), dict):
                continue
            p = str(v["hostPath"].get("path", ""))
            crit = p in {"/", "/etc", "/var/lib/kubelet", "/proc"} or any(p.endswith(s) for s in RUNTIME_SOCKETS)
            yield r.finding(
                d,
                (*pt.path, "volumes", i, "hostPath"),
                f"Volume '{v.get('name')}' mounts host path '{p}'.",
                severity=Severity.CRITICAL if crit else Severity.HIGH,
            )


@rule(
    "KN-S011",
    "hostPort used",
    Stage.AUDIT,
    "security",
    Severity.MEDIUM,
    "Expose the container through a Service instead of hostPort.",
    "hostPort binds directly on the node, bypasses NetworkPolicy expectations and limits scheduling.",
    ("k8s-pss",),
)
def _s011(ctx: AuditContext, r: Rule) -> Iterator[Finding]:
    for d, _pt, c in _containers(ctx):
        for i, p in enumerate(c.container.get("ports") or []):
            if isinstance(p, dict) and p.get("hostPort"):
                yield r.finding(
                    d, (*c.path, "ports", i, "hostPort"), f"Container '{c.name}' binds hostPort {p['hostPort']}."
                )


_DIGEST = re.compile(r"@sha256:[0-9a-f]{64}$")


def image_tag(image: str) -> tuple[str | None, bool]:
    """Return (tag, has_digest). Handles registry ports ('host:5000/app')."""
    has_digest = bool(_DIGEST.search(image))
    ref = image.split("@", 1)[0]
    last = ref.rsplit("/", 1)[-1]
    tag = last.split(":", 1)[1] if ":" in last else None
    return tag, has_digest


@rule(
    "KN-S012",
    "Mutable image reference",
    Stage.AUDIT,
    "supply-chain",
    Severity.MEDIUM,
    "Pin an explicit version tag, ideally an immutable digest (image@sha256:...).",
    "':latest' or untagged images change underneath you, break rollbacks and defeat image scanning/signing.",
    ("k8s-images",),
    ("Latest tag",),
)
def _s012(ctx: AuditContext, r: Rule) -> Iterator[Finding]:
    for d, _pt, c in _containers(ctx):
        image = c.container.get("image")
        if not isinstance(image, str) or not image:
            yield r.finding(d, c.path, f"Container '{c.name}' has no image.", severity=Severity.HIGH)
            continue
        tag, digest = image_tag(image)
        if digest:
            continue
        if tag in (None, "latest"):
            yield r.finding(d, (*c.path, "image"), f"Container '{c.name}' uses mutable image '{image}'.")
        else:
            yield r.finding(
                d,
                (*c.path, "image"),
                f"Container '{c.name}' image '{image}' is not pinned by digest.",
                severity=Severity.INFO,
            )


@rule(
    "KN-S013",
    "Secret value hard-coded in environment",
    Stage.AUDIT,
    "secrets",
    Severity.HIGH,
    "Move the value to a Secret and reference it with valueFrom.secretKeyRef (or an external secret store).",
    "Literal credentials in manifests leak through Git history, `oc get -o yaml`, logs and audit trails.",
    ("k8s-secrets-good-practices",),
    ("Environment Variable Contains Secret",),
)
def _s013(ctx: AuditContext, r: Rule) -> Iterator[Finding]:
    for d, _pt, c in _containers(ctx):
        for i, e in enumerate(c.container.get("env") or []):
            if isinstance(e, dict) and SENSITIVE_ENV.search(str(e.get("name", ""))) and e.get("value"):
                yield r.finding(
                    d, (*c.path, "env", i, "value"), f"Container '{c.name}' sets {e['name']} as a literal value."
                )


@rule(
    "KN-S014",
    "ServiceAccount token automounted",
    Stage.AUDIT,
    "security",
    Severity.LOW,
    "Set automountServiceAccountToken: false on the pod (or ServiceAccount) unless the app calls the API.",
    "A mounted token turns any RCE into authenticated Kubernetes API access.",
    ("k8s-rbac-good-practices",),
    ("Pod Service Account Token Automatically Mounted",),
)
def _s014(ctx: AuditContext, r: Rule) -> Iterator[Finding]:
    sa_opt_out = {
        (ctx.ns(d), d.name)
        for d in ctx.by_kind("ServiceAccount")
        if isinstance(d.data, dict) and d.data.get("automountServiceAccountToken") is False
    }
    for d, pt in ctx.workloads():
        if pt.spec.get("automountServiceAccountToken") is False:
            continue
        sa = str(pt.spec.get("serviceAccountName") or "default")
        if (ctx.ns(d), sa) in sa_opt_out and pt.spec.get("automountServiceAccountToken") is not True:
            continue
        yield r.finding(d, pt.path, f"Pod automounts the token of ServiceAccount '{sa}'.")


def _rules_of(d: Document) -> list[tuple[int, dict[str, Any]]]:
    rules = d.data.get("rules") if isinstance(d.data, dict) else None
    return [(i, x) for i, x in enumerate(rules or []) if isinstance(x, dict)]


@rule(
    "KN-S015",
    "RBAC wildcard grants",
    Stage.AUDIT,
    "rbac",
    Severity.HIGH,
    "Enumerate the exact apiGroups, resources and verbs needed.",
    "Wildcards grant every current and future resource/verb, including secrets and escalation paths.",
    ("k8s-rbac-good-practices",),
)
def _s015(ctx: AuditContext, r: Rule) -> Iterator[Finding]:
    for d in ctx.by_kind("Role", "ClusterRole"):
        for i, rr in _rules_of(d):
            wild = [k for k in ("verbs", "resources", "apiGroups") if "*" in (rr.get(k) or [])]
            if wild:
                yield r.finding(d, ("rules", i), f"Rule uses '*' in {', '.join(wild)}.")


@rule(
    "KN-S016",
    "Binding to cluster-admin",
    Stage.AUDIT,
    "rbac",
    Severity.CRITICAL,
    "Bind a narrowly scoped Role instead; cluster-admin should only be held by break-glass identities.",
    "cluster-admin is full control of the cluster.",
    ("k8s-rbac-good-practices",),
)
def _s016(ctx: AuditContext, r: Rule) -> Iterator[Finding]:
    for d in ctx.by_kind("ClusterRoleBinding", "RoleBinding"):
        if get_path(d.data, ("roleRef", "name")) == "cluster-admin":
            subjects = [f"{s.get('kind')}/{s.get('name')}" for s in d.data.get("subjects") or [] if isinstance(s, dict)]
            sev = Severity.CRITICAL if d.kind == "ClusterRoleBinding" else Severity.HIGH
            yield r.finding(d, ("roleRef", "name"), f"{d.kind} grants cluster-admin to {subjects}.", severity=sev)


ESCALATION_VERBS = frozenset({"escalate", "bind", "impersonate"})


@rule(
    "KN-S017",
    "RBAC privilege-escalation paths",
    Stage.AUDIT,
    "rbac",
    Severity.HIGH,
    "Remove escalate/bind/impersonate, cluster-wide secret reads, nodes/proxy and pod exec unless essential.",
    "These permissions let a subject obtain more privileges than it was granted.",
    ("k8s-rbac-good-practices",),
)
def _s017(ctx: AuditContext, r: Rule) -> Iterator[Finding]:
    for d in ctx.by_kind("Role", "ClusterRole"):
        for i, rr in _rules_of(d):
            verbs = {str(v) for v in rr.get("verbs") or []}
            resources = {str(x) for x in rr.get("resources") or []}
            if verbs & ESCALATION_VERBS:
                yield r.finding(d, ("rules", i, "verbs"), f"Grants {sorted(verbs & ESCALATION_VERBS)}.")
            if "secrets" in resources and verbs & {"get", "list", "watch", "*"}:
                sev = Severity.HIGH if d.kind == "ClusterRole" else Severity.LOW
                yield r.finding(d, ("rules", i, "resources"), f"{d.kind} can read Secrets.", severity=sev)
            if resources & {"pods/exec", "pods/attach"} and verbs & {"create", "*"}:
                yield r.finding(d, ("rules", i, "resources"), "Grants exec/attach into pods.", severity=Severity.MEDIUM)
            if "nodes/proxy" in resources:
                yield r.finding(d, ("rules", i, "resources"), "Grants nodes/proxy (kubelet API access).")


@rule(
    "KN-S018",
    "Secret material committed in manifests",
    Stage.AUDIT,
    "secrets",
    Severity.MEDIUM,
    "Deliver secrets with an external secret store (External Secrets Operator, Vault, AWS Secrets Manager on "
    "ROSA) or Sealed Secrets; never commit base64 'data' to Git.",
    "base64 is an encoding, not encryption.",
    ("k8s-secrets-good-practices",),
)
def _s018(ctx: AuditContext, r: Rule) -> Iterator[Finding]:
    for d in ctx.by_kind("Secret"):
        if isinstance(d.data, dict) and (d.data.get("data") or d.data.get("stringData")):
            if d.data.get("type") == "kubernetes.io/service-account-token":
                continue
            yield r.finding(
                d, ("data",) if d.data.get("data") else ("stringData",), "Secret contains inline key material."
            )


@rule(
    "KN-S019",
    "Permissive SecurityContextConstraints",
    Stage.AUDIT,
    "security",
    Severity.HIGH,
    "Prefer the built-in restricted-v2 / nonroot-v2 SCCs; custom SCCs must not allow privileged, host "
    "namespaces, host directories or RunAsAny UIDs.",
    "A permissive SCC bound to a ServiceAccount defeats OpenShift's default pod isolation.",
    ("ocp-scc",),
)
def _s019(ctx: AuditContext, r: Rule) -> Iterator[Finding]:
    for d in ctx.by_kind("SecurityContextConstraints"):
        data = d.data
        bad = [
            k
            for k in (
                "allowPrivilegedContainer",
                "allowHostNetwork",
                "allowHostPID",
                "allowHostIPC",
                "allowHostDirVolumePlugin",
                "allowHostPorts",
                "allowPrivilegeEscalation",
            )
            if data.get(k) is True
        ]
        if get_path(data, ("runAsUser", "type")) == "RunAsAny":
            bad.append("runAsUser: RunAsAny")
        if bad:
            yield r.finding(d, (), f"SCC allows: {', '.join(bad)}.")


@rule(
    "KN-S020",
    "Unmasked /proc",
    Stage.AUDIT,
    "security",
    Severity.HIGH,
    "Remove securityContext.procMount: Unmasked.",
    "Unmasked /proc exposes host kernel interfaces.",
    ("k8s-pss",),
)
def _s020(ctx: AuditContext, r: Rule) -> Iterator[Finding]:
    for d, _pt, c in _containers(ctx):
        if get_path(c.container, ("securityContext", "procMount")) == "Unmasked":
            yield r.finding(d, (*c.path, "securityContext", "procMount"), f"Container '{c.name}' unmasks /proc.")


# =====================================================================================================
# AUDIT - network exposure
# =====================================================================================================


@rule(
    "KN-N001",
    "Namespace has workloads but no NetworkPolicy",
    Stage.AUDIT,
    "network",
    Severity.MEDIUM,
    "Add a default-deny ingress NetworkPolicy plus explicit allows (router/ingress controller, monitoring, "
    "same-app traffic).",
    "Without NetworkPolicy every pod in the cluster can reach these pods (lateral movement).",
    ("k8s-networkpolicy",),
    ("Deployments should have at least one ingress Network Policy",),
)
def _n001(ctx: AuditContext, r: Rule) -> Iterator[Finding]:
    netpol_ns = {ctx.ns(d) for d in ctx.by_kind("NetworkPolicy")}
    flagged: set[str] = set()
    for d, _pt in ctx.workloads():
        ns = ctx.ns(d)
        if d.kind in LONG_RUNNING_KINDS | {"Pod"} and ns not in netpol_ns and ns not in flagged:
            flagged.add(ns)
            yield r.finding(d, ("metadata",), f"No NetworkPolicy for namespace {ns} in this bundle.")


@rule(
    "KN-N002",
    "Route without TLS",
    Stage.AUDIT,
    "network",
    Severity.HIGH,
    "Add spec.tls with termination: edge (or reencrypt/passthrough) and insecureEdgeTerminationPolicy: Redirect.",
    "Plain-HTTP Routes expose credentials and session cookies to anyone on the path.",
    ("ocp-routes",),
)
def _n002(ctx: AuditContext, r: Rule) -> Iterator[Finding]:
    for d in ctx.by_kind("Route"):
        tls = get_path(d.data, ("spec", "tls"))
        if not isinstance(tls, dict):
            yield r.finding(d, ("spec",), "Route serves plain HTTP (no spec.tls).")
        elif tls.get("insecureEdgeTerminationPolicy") == "Allow":
            yield r.finding(
                d,
                ("spec", "tls", "insecureEdgeTerminationPolicy"),
                "insecureEdgeTerminationPolicy: Allow also serves plain HTTP.",
                severity=Severity.MEDIUM,
            )


@rule(
    "KN-N003",
    "Ingress without TLS",
    Stage.AUDIT,
    "network",
    Severity.MEDIUM,
    "Add spec.tls with a certificate Secret (cert-manager can issue it).",
    "Plain-HTTP ingress exposes traffic in transit.",
    ("k8s-networkpolicy",),
)
def _n003(ctx: AuditContext, r: Rule) -> Iterator[Finding]:
    for d in ctx.by_kind("Ingress"):
        if not get_path(d.data, ("spec", "tls")):
            yield r.finding(d, ("spec",), "Ingress has no spec.tls.")


@rule(
    "KN-N004",
    "LoadBalancer Service open to the internet",
    Stage.AUDIT,
    "network",
    Severity.MEDIUM,
    "Set spec.loadBalancerSourceRanges, or make it internal (on AWS/ROSA: annotation "
    'service.beta.kubernetes.io/aws-load-balancer-internal: "true"), or front it with a Route/Ingress.',
    "A public cloud load balancer without source ranges is reachable from anywhere.",
    ("k8s-service-lb",),
    ("Deployments with externally exposed endpoints",),
)
def _n004(ctx: AuditContext, r: Rule) -> Iterator[Finding]:
    for d in ctx.by_kind("Service"):
        if get_path(d.data, ("spec", "type")) != "LoadBalancer":
            continue
        ann = get_path(d.data, ("metadata", "annotations")) or {}
        internal = any("internal" in str(k) and str(v).lower() in {"true", "0.0.0.0/0"} for k, v in ann.items())
        if not get_path(d.data, ("spec", "loadBalancerSourceRanges")) and not internal:
            yield r.finding(
                d, ("spec", "type"), "type: LoadBalancer without loadBalancerSourceRanges or an internal annotation."
            )


@rule(
    "KN-N005",
    "NodePort Service",
    Stage.AUDIT,
    "network",
    Severity.LOW,
    "Prefer ClusterIP + Route/Ingress; NodePorts open a port on every node.",
    "NodePorts widen the attack surface.",
    ("k8s-service-lb",),
)
def _n005(ctx: AuditContext, r: Rule) -> Iterator[Finding]:
    for d in ctx.by_kind("Service"):
        if get_path(d.data, ("spec", "type")) == "NodePort":
            yield r.finding(d, ("spec", "type"), "type: NodePort exposes a port on every node.")


_ANY_CIDR = {"0.0.0.0/0", "::/0"}


@rule(
    "KN-N006",
    "EgressFirewall rule is shadowed",
    Stage.AUDIT,
    "network",
    Severity.HIGH,
    "Put specific Allow rules first and the catch-all Deny 0.0.0.0/0 last.",
    "EgressFirewall rules are evaluated in order and the first match wins, so an early catch-all Deny makes every "
    "later Allow dead code.",
    ("ocp-egressfirewall",),
)
def _n006(ctx: AuditContext, r: Rule) -> Iterator[Finding]:
    for d in ctx.by_kind("EgressFirewall"):
        egress = get_path(d.data, ("spec", "egress")) or []
        catch_all_at: int | None = None
        for i, e in enumerate(egress):
            if not isinstance(e, dict):
                continue
            cidr = get_path(e, ("to", "cidrSelector"))
            if catch_all_at is not None:
                yield r.finding(
                    d,
                    ("spec", "egress", i),
                    f"Rule {i} ({e.get('type')}) can never match: rule "
                    f"{catch_all_at} already matches all destinations.",
                )
            elif cidr in _ANY_CIDR and not e.get("ports"):
                catch_all_at = i


@rule(
    "KN-N007",
    "NetworkPolicy allows all ingress",
    Stage.AUDIT,
    "network",
    Severity.MEDIUM,
    "Restrict 'from' to specific namespaceSelector/podSelector peers and ports.",
    "An ingress rule of {} admits traffic from every pod and every external source.",
    ("k8s-networkpolicy",),
)
def _n007(ctx: AuditContext, r: Rule) -> Iterator[Finding]:
    for d in ctx.by_kind("NetworkPolicy"):
        for i, rule_ in enumerate(get_path(d.data, ("spec", "ingress")) or []):
            if rule_ == {} or (isinstance(rule_, dict) and not rule_.get("from") and not rule_.get("ports")):
                yield r.finding(d, ("spec", "ingress", i), "Ingress rule admits all sources on all ports.")


# =====================================================================================================
# AUDIT - storage
# =====================================================================================================


def _storage_classes(ctx: AuditContext) -> dict[str, dict[str, Any]]:
    return {d.name: d.data for d in ctx.by_kind("StorageClass") if isinstance(d.data, dict)}


def _provisioner_for(ctx: AuditContext, sc_name: str | None) -> str | None:
    if sc_name is None:
        return None
    local = _storage_classes(ctx).get(sc_name)
    if local and local.get("provisioner"):
        return str(local["provisioner"])
    return KNOWN_STORAGE_CLASSES.get(sc_name)


def _pvc_like(ctx: AuditContext) -> Iterator[tuple[Document, PathT, dict[str, Any]]]:
    for d in ctx.by_kind("PersistentVolumeClaim"):
        if isinstance(d.data.get("spec"), dict):
            yield d, ("spec",), d.data["spec"]
    for d in ctx.by_kind("StatefulSet"):
        for i, vct in enumerate(get_path(d.data, ("spec", "volumeClaimTemplates")) or []):
            if isinstance(vct, dict) and isinstance(vct.get("spec"), dict):
                yield d, ("spec", "volumeClaimTemplates", i, "spec"), vct["spec"]


@rule(
    "KN-ST001",
    "ReadWriteMany requested from a ReadWriteOnce-only StorageClass",
    Stage.AUDIT,
    "storage",
    Severity.HIGH,
    "Use a shared-filesystem class: efs-sc (AWS EFS CSI) on ROSA/EKS, ocs-storagecluster-cephfs (ODF) or NFS on "
    "OpenShift on-prem, azurefile-csi on Azure. gp3-csi/gp2-csi (EBS) are block volumes and only support "
    "ReadWriteOnce.",
    "The provisioner cannot satisfy RWX, so the PVC stays Pending (ProvisioningFailed).",
    ("k8s-pv-access-modes", "aws-ebs-csi", "aws-efs-csi", "odf-access-modes"),
)
def _st001(ctx: AuditContext, r: Rule) -> Iterator[Finding]:
    for d, path, spec in _pvc_like(ctx):
        modes = spec.get("accessModes") or []
        if "ReadWriteMany" not in modes:
            continue
        sc = spec.get("storageClassName")
        prov = _provisioner_for(ctx, sc)
        if prov is None:
            if sc is None:
                if ctx.is_rosa:
                    yield r.finding(
                        d,
                        (*path, "accessModes"),
                        "RWX without storageClassName: the ROSA default "
                        "class (gp3-csi, EBS) is RWO-only, so this PVC will not bind.",
                    )
                elif ctx.is_openshift:
                    yield r.finding(
                        d,
                        (*path, "accessModes"),
                        "RWX without storageClassName: verify the cluster "
                        "default StorageClass supports ReadWriteMany (most block classes do not).",
                        severity=Severity.MEDIUM,
                    )
            continue
        p = PROVISIONERS.get(prov)
        if p is None:
            continue
        block = spec.get("volumeMode") == "Block"
        if not (p.rwx_filesystem or (block and p.rwx_block)):
            hint = " (RWX is only possible with volumeMode: Block)" if p.rwx_block else ""
            yield r.finding(
                d,
                (*path, "storageClassName"),
                f"StorageClass '{sc}' ({prov}: {p.description}) cannot provide ReadWriteMany{hint}.",
            )


@rule(
    "KN-ST002",
    "ReadWriteOnce volume shared by a rolling Deployment",
    Stage.AUDIT,
    "storage",
    Severity.HIGH,
    "Use a StatefulSet with volumeClaimTemplates, strategy: Recreate with replicas: 1, or a RWX class if the app "
    "supports concurrent writers.",
    "A RWO volume attaches to one node. Extra replicas or surge pods scheduled elsewhere hang in "
    "ContainerCreating with 'Multi-Attach error for volume'.",
    ("k8s-pv-access-modes",),
)
def _st002(ctx: AuditContext, r: Rule) -> Iterator[Finding]:
    pvcs = {(ctx.ns(d), d.name): d.data.get("spec", {}) for d in ctx.by_kind("PersistentVolumeClaim")}
    for d in ctx.by_kind("Deployment", "DeploymentConfig"):
        pt = pod_template(d)
        if pt is None:
            continue
        for i, v in enumerate(pt.spec.get("volumes") or []):
            claim = get_path(v, ("persistentVolumeClaim", "claimName")) if isinstance(v, dict) else None
            if not claim:
                continue
            spec = pvcs.get((ctx.ns(d), str(claim)))
            modes = (spec or {}).get("accessModes") or []
            if spec is None or "ReadWriteMany" in modes or "ReadOnlyMany" in modes:
                continue
            reps = replicas(d) or 1
            strategy = get_path(d.data, ("spec", "strategy", "type")) or "RollingUpdate"
            if reps > 1:
                yield r.finding(
                    d,
                    (*pt.path, "volumes", i),
                    f"{reps} replicas share RWO PVC '{claim}'; pods on other nodes cannot attach it.",
                )
            elif strategy in {"RollingUpdate", "Rolling"}:
                yield r.finding(
                    d,
                    ("spec", "strategy"),
                    f"RollingUpdate with RWO PVC '{claim}': the surge pod "
                    "can deadlock on Multi-Attach. Use strategy: Recreate.",
                    severity=Severity.MEDIUM,
                )


@rule(
    "KN-ST003",
    "Zonal storage with Immediate volume binding",
    Stage.AUDIT,
    "storage",
    Severity.MEDIUM,
    "Set volumeBindingMode: WaitForFirstConsumer so the volume is created in the zone the pod is scheduled to.",
    "Immediate binding may create the volume in a zone where the pod cannot run, leaving it Pending.",
    ("k8s-storageclass-binding",),
)
def _st003(ctx: AuditContext, r: Rule) -> Iterator[Finding]:
    for d in ctx.by_kind("StorageClass"):
        p = PROVISIONERS.get(str(d.data.get("provisioner")))
        mode = d.data.get("volumeBindingMode", "Immediate")
        if p and p.zonal and mode == "Immediate":
            yield r.finding(d, ("volumeBindingMode",), f"{p.name} is zonal but volumeBindingMode is Immediate.")


@rule(
    "KN-ST004",
    "EFS StorageClass is missing required parameters",
    Stage.AUDIT,
    "storage",
    Severity.HIGH,
    "Set parameters.provisioningMode: efs-ap and parameters.fileSystemId: fs-xxxxxxxx (plus directoryPerms).",
    "Dynamic provisioning with the AWS EFS CSI driver uses access points and needs the file system id.",
    ("aws-efs-csi", "rosa-efs"),
)
def _st004(ctx: AuditContext, r: Rule) -> Iterator[Finding]:
    for d in ctx.by_kind("StorageClass"):
        if d.data.get("provisioner") != "efs.csi.aws.com":
            continue
        params = d.data.get("parameters") or {}
        missing = [k for k in ("provisioningMode", "fileSystemId") if not params.get(k)]
        if missing:
            yield r.finding(d, ("parameters",), f"Missing parameter(s): {', '.join(missing)}.")


@rule(
    "KN-ST005",
    "PVC has no storage request",
    Stage.VALIDATE,
    "storage",
    Severity.HIGH,
    "Set spec.resources.requests.storage (e.g. 10Gi).",
    "The API server rejects PersistentVolumeClaims without a storage request.",
    ("k8s-pv-access-modes",),
)
def _st005(ctx: AuditContext, r: Rule) -> Iterator[Finding]:
    for d, path, spec in _pvc_like(ctx):
        if not get_path(spec, ("resources", "requests", "storage")):
            yield r.finding(d, (*path, "resources"), "spec.resources.requests.storage is missing.")


# =====================================================================================================
# CALIBRATE - reliability, HA, efficiency
# =====================================================================================================


def _long_running_containers(ctx: AuditContext) -> Iterator[tuple[Document, PodTemplate, ContainerRef]]:
    for d, pt in ctx.workloads():
        if d.kind in LONG_RUNNING_KINDS:
            for c in containers(pt, include_init=False):
                yield d, pt, c


@rule(
    "KN-C001",
    "No readiness probe",
    Stage.CALIBRATE,
    "reliability",
    Severity.MEDIUM,
    "Add a readinessProbe (httpGet on a /ready endpoint, or tcpSocket) so traffic only reaches ready pods.",
    "Without readiness, Services route to pods that are still starting or degraded, and rollouts cannot detect "
    "bad versions.",
    ("k8s-probes",),
)
def _c001(ctx: AuditContext, r: Rule) -> Iterator[Finding]:
    for d, _pt, c in _long_running_containers(ctx):
        if not c.container.get("readinessProbe"):
            yield r.finding(d, c.path, f"Container '{c.name}' has no readinessProbe.")


@rule(
    "KN-C002",
    "No liveness probe",
    Stage.CALIBRATE,
    "reliability",
    Severity.LOW,
    "Add a livenessProbe that checks the process itself (not its dependencies); use a startupProbe for slow starts.",
    "Deadlocked processes are never restarted without liveness.",
    ("k8s-probes",),
)
def _c002(ctx: AuditContext, r: Rule) -> Iterator[Finding]:
    for d, _pt, c in _long_running_containers(ctx):
        if not c.container.get("livenessProbe"):
            yield r.finding(d, c.path, f"Container '{c.name}' has no livenessProbe.")


@rule(
    "KN-C003",
    "Liveness probe is aggressive",
    Stage.CALIBRATE,
    "reliability",
    Severity.MEDIUM,
    "Use periodSeconds >= 10, failureThreshold >= 3 and timeoutSeconds < periodSeconds; add a startupProbe "
    "for slow boots.",
    "Aggressive liveness turns a slow dependency or GC pause into a restart storm (red-team: cascading failure).",
    ("k8s-probes",),
)
def _c003(ctx: AuditContext, r: Rule) -> Iterator[Finding]:
    for d, _pt, c in _long_running_containers(ctx):
        p = c.container.get("livenessProbe")
        if not isinstance(p, dict):
            continue
        period, fail = p.get("periodSeconds", 10), p.get("failureThreshold", 3)
        timeout = p.get("timeoutSeconds", 1)
        issues = []
        if isinstance(fail, int) and fail < 2:
            issues.append(f"failureThreshold={fail}")
        if isinstance(period, int) and period < 5:
            issues.append(f"periodSeconds={period}")
        if isinstance(timeout, int) and isinstance(period, int) and timeout >= period:
            issues.append(f"timeoutSeconds({timeout}) >= periodSeconds({period})")
        if issues:
            yield r.finding(d, (*c.path, "livenessProbe"), f"Container '{c.name}': {', '.join(issues)}.")


@rule(
    "KN-C004",
    "Missing CPU/memory requests",
    Stage.CALIBRATE,
    "resources",
    Severity.MEDIUM,
    "Set resources.requests.cpu and resources.requests.memory from observed usage (p95).",
    "Without requests the scheduler overcommits nodes, pods get BestEffort QoS and are evicted first; HPA cannot "
    "compute utilization.",
    ("k8s-resources",),
    ("No CPU request or memory limit specified",),
)
def _c004(ctx: AuditContext, r: Rule) -> Iterator[Finding]:
    for d, _pt, c in _containers(ctx):
        req = get_path(c.container, ("resources", "requests")) or {}
        missing = [k for k in ("cpu", "memory") if k not in req]
        if missing:
            yield r.finding(d, (*c.path, "resources"), f"Container '{c.name}' has no {'/'.join(missing)} request.")


@rule(
    "KN-C005",
    "Missing memory limit",
    Stage.CALIBRATE,
    "resources",
    Severity.MEDIUM,
    "Set resources.limits.memory (typically 1-2x the request).",
    "An unbounded container can exhaust node memory and trigger node-level OOM kills of other workloads.",
    ("k8s-resources",),
    ("No CPU request or memory limit specified",),
)
def _c005(ctx: AuditContext, r: Rule) -> Iterator[Finding]:
    for d, _pt, c in _containers(ctx):
        if not get_path(c.container, ("resources", "limits", "memory")):
            yield r.finding(d, (*c.path, "resources"), f"Container '{c.name}' has no memory limit.")


@rule(
    "KN-C006",
    "Request exceeds limit",
    Stage.VALIDATE,
    "resources",
    Severity.HIGH,
    "Make every request <= its limit.",
    "The API server rejects containers whose request is greater than the limit.",
    ("k8s-resources",),
)
def _c006(ctx: AuditContext, r: Rule) -> Iterator[Finding]:
    for d, _pt, c in _containers(ctx):
        req = get_path(c.container, ("resources", "requests")) or {}
        lim = get_path(c.container, ("resources", "limits")) or {}
        for k in ("cpu", "memory", "ephemeral-storage"):
            if k in req and k in lim:
                try:
                    if parse_quantity(req[k]) > parse_quantity(lim[k]):
                        yield r.finding(
                            d,
                            (*c.path, "resources", "requests", k),
                            f"Container '{c.name}' {k} request {req[k]} > limit {lim[k]}.",
                        )
                except ValueError as exc:
                    yield r.finding(d, (*c.path, "resources"), f"Container '{c.name}': {exc}.")


@rule(
    "KN-C007",
    "Single replica",
    Stage.CALIBRATE,
    "availability",
    Severity.MEDIUM,
    "Run at least 2 replicas (3 across zones for production) with a PodDisruptionBudget.",
    "One replica means downtime on every node drain, upgrade or node failure.",
    ("k8s-pdb",),
)
def _c007(ctx: AuditContext, r: Rule) -> Iterator[Finding]:
    for d in ctx.by_kind(*REPLICATED_KINDS):
        reps = replicas(d)
        if reps is not None and reps < 2 and not _has_hpa(ctx, d):
            yield r.finding(d, ("spec", "replicas"), f"{d.kind} runs {reps} replica(s).")


def _has_hpa(ctx: AuditContext, d: Document) -> bool:
    for h in ctx.by_kind("HorizontalPodAutoscaler"):
        ref = get_path(h.data, ("spec", "scaleTargetRef")) or {}
        if ref.get("name") == d.name and ref.get("kind") == d.kind and ctx.ns(h) == ctx.ns(d):
            return True
    return False


def _pdbs_for(ctx: AuditContext, d: Document, labels: dict[str, str]) -> list[Document]:
    return [
        p
        for p in ctx.by_kind("PodDisruptionBudget")
        if ctx.ns(p) == ctx.ns(d) and selector_matches(get_path(p.data, ("spec", "selector")), labels)
    ]


@rule(
    "KN-C008",
    "No PodDisruptionBudget",
    Stage.CALIBRATE,
    "availability",
    Severity.LOW,
    "Add a PodDisruptionBudget with maxUnavailable: 1 for replicated workloads.",
    "Without a PDB a node drain may evict all replicas at once.",
    ("k8s-pdb",),
)
def _c008(ctx: AuditContext, r: Rule) -> Iterator[Finding]:
    for d, pt in ctx.workloads():
        if d.kind in REPLICATED_KINDS and (replicas(d) or 1) >= 2 and not _pdbs_for(ctx, d, pt.labels()):
            yield r.finding(d, ("spec",), "No PodDisruptionBudget selects this workload.")


@rule(
    "KN-C009",
    "PodDisruptionBudget blocks all voluntary evictions",
    Stage.CALIBRATE,
    "availability",
    Severity.HIGH,
    "Use maxUnavailable: 1 (or minAvailable < replicas).",
    "A PDB that allows zero disruptions blocks node drains, so cluster upgrades (including managed ROSA "
    "upgrades) stall on this node.",
    ("k8s-pdb",),
)
def _c009(ctx: AuditContext, r: Rule) -> Iterator[Finding]:
    for d, pt in ctx.workloads():
        if d.kind not in REPLICATED_KINDS:
            continue
        reps = replicas(d) or 1
        for p in _pdbs_for(ctx, d, pt.labels()):
            spec = p.data.get("spec") or {}
            mu, ma = spec.get("maxUnavailable"), spec.get("minAvailable")
            blocked = mu in (0, "0", "0%") or (isinstance(ma, int) and ma >= reps) or ma == "100%"
            if blocked:
                yield r.finding(p, ("spec",), f"{p.ref()} allows no disruptions for {d.ref()} ({reps} replicas).")


@rule(
    "KN-C010",
    "Replicas not spread across zones/nodes",
    Stage.CALIBRATE,
    "availability",
    Severity.LOW,
    "Add topologySpreadConstraints on topology.kubernetes.io/zone (and kubernetes.io/hostname) or pod anti-affinity.",
    "Replicas may all land on one node or zone; a single failure takes the app down.",
    ("k8s-topology-spread",),
)
def _c010(ctx: AuditContext, r: Rule) -> Iterator[Finding]:
    for d, pt in ctx.workloads():
        if d.kind not in REPLICATED_KINDS or (replicas(d) or 1) < 2:
            continue
        if pt.spec.get("topologySpreadConstraints") or get_path(pt.spec, ("affinity", "podAntiAffinity")):
            continue
        sev = Severity.MEDIUM if ctx.is_rosa else Severity.LOW
        yield r.finding(d, pt.path, "No topologySpreadConstraints or podAntiAffinity.", severity=sev)


@rule(
    "KN-C011",
    "terminationGracePeriodSeconds is 0",
    Stage.CALIBRATE,
    "reliability",
    Severity.LOW,
    "Allow time for graceful shutdown (default 30s) and handle SIGTERM.",
    "A zero grace period kills in-flight requests and can corrupt state.",
    ("k8s-probes",),
)
def _c011(ctx: AuditContext, r: Rule) -> Iterator[Finding]:
    for d, pt in ctx.workloads():
        if pt.spec.get("terminationGracePeriodSeconds") == 0:
            yield r.finding(d, (*pt.path, "terminationGracePeriodSeconds"), "Grace period is 0.")


@rule(
    "KN-C012",
    "HPA cannot compute CPU utilization",
    Stage.CALIBRATE,
    "resources",
    Severity.MEDIUM,
    "Set CPU requests on every container of the target workload.",
    "Utilization-based HPA divides usage by the request; missing requests leave the HPA at <unknown>.",
    ("k8s-resources",),
)
def _c012(ctx: AuditContext, r: Rule) -> Iterator[Finding]:
    for h in ctx.by_kind("HorizontalPodAutoscaler"):
        ref = get_path(h.data, ("spec", "scaleTargetRef")) or {}
        metrics = get_path(h.data, ("spec", "metrics")) or []
        uses_cpu_util = any(
            get_path(m, ("resource", "name")) == "cpu" and get_path(m, ("resource", "target", "type")) == "Utilization"
            for m in metrics
            if isinstance(m, dict)
        )
        if not uses_cpu_util:
            continue
        for d, pt in ctx.workloads():
            is_target = d.name == ref.get("name") and d.kind == ref.get("kind") and ctx.ns(d) == ctx.ns(h)
            if is_target and any(
                not get_path(c.container, ("resources", "requests", "cpu")) for c in containers(pt, include_init=False)
            ):
                yield r.finding(h, ("spec", "metrics"), f"Target {d.ref()} has containers without CPU requests.")


def run_rules(ctx: AuditContext, stages: set[Stage] | None = None) -> list[Finding]:
    findings: list[Finding] = []
    for r in RULES.values():
        if stages is not None and r.stage not in stages:
            continue
        if r.check is not None:
            findings.extend(r.check(ctx, r))
    return findings
