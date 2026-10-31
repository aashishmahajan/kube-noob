"""Would this connection be allowed? Kubernetes NetworkPolicy semantics, evaluated offline.

Given NetworkPolicies, the workloads they apply to (Pods, Deployments, StatefulSets, DaemonSets, ReplicaSets, Jobs,
CronJobs, DeploymentConfigs) and optionally Namespaces, decide whether a connection from a source to a destination on a
port is allowed. Both directions must allow it: egress from the source pod and ingress to the destination pod. Each
verdict names the policy and the rule that decided it, explains why every other rule did not match (wrong peer or
wrong port), and, when the answer is no, proposes the smallest NetworkPolicy that would allow it.

The same evaluation runs on objects read from a live cluster (read-only) through ``inventory_from_cluster``.

Not evaluated, and said so in every result: AdminNetworkPolicy and BaselineAdminNetworkPolicy, OpenShift EgressFirewall
and EgressNetworkPolicy, CNI-specific policies (Cilium, Calico), host-network pods, and firewalls outside the cluster.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from typing import Any

import yaml

from kube_noob.debug.steps import classify_step, split_comment
from kube_noob.yamlio import load_documents

IPNet = ipaddress.IPv4Network | ipaddress.IPv6Network

WORKLOAD_KINDS = (
    "Deployment",
    "StatefulSet",
    "DaemonSet",
    "DeploymentConfig",
    "ReplicaSet",
    "ReplicationController",
    "Job",
    "CronJob",
    "Pod",
)
_KIND_RANK = {k.lower(): i for i, k in enumerate(WORKLOAD_KINDS)}
ANP_KIND = "AdminNetworkPolicy"
BANP_KIND = "BaselineAdminNetworkPolicy"
OTHER_POLICY_KINDS = {
    ANP_KIND,
    BANP_KIND,
    "EgressFirewall",
    "EgressNetworkPolicy",
    "CiliumNetworkPolicy",
    "CiliumClusterwideNetworkPolicy",
    "GlobalNetworkPolicy",
    "MultiNetworkPolicy",
}
NOT_EVALUATED = (
    "OpenShift EgressFirewall / EgressNetworkPolicy (egress to destinations outside the cluster)",
    "CNI-specific policies (Cilium, Calico) and firewalls or security groups outside the cluster",
    "pods with hostNetwork: true (NetworkPolicy does not apply to them on most network plugins)",
)
_LABEL_VALUE = re.compile(r"^[A-Za-z0-9]([-A-Za-z0-9_.]*[A-Za-z0-9])?\Z")
_DNS = re.compile(r"^[a-z0-9]([-a-z0-9.]*[a-z0-9])?\Z")
_PORT_NAME = re.compile(r"^[a-z0-9]([-a-z0-9]*[a-z0-9])?\Z")
_LABEL_KEY = re.compile(r"^([a-z0-9]([-a-z0-9.]{0,251}[a-z0-9])?/)?[A-Za-z0-9]([-A-Za-z0-9_.]{0,61}[A-Za-z0-9])?\Z")
_CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")


def _shell_safe_selector(labels: dict[str, str]) -> str | None:
    """``k=v,k2=v2`` for a command line, or None when a key or value is not valid label syntax (it came from a
    manifest or the cluster, so it could carry shell syntax)."""
    if not labels or not all(_LABEL_KEY.match(k) and (v == "" or _LABEL_VALUE.match(v)) for k, v in labels.items()):
        return None
    return ",".join(f"{k}={v}" for k, v in sorted(labels.items()))


def _labelstr(v: Any) -> str:
    if isinstance(v, bool):
        return "true" if v else "false"
    return str(v)


def _labels(d: Any) -> dict[str, str]:
    return {str(k): _labelstr(v) for k, v in d.items()} if isinstance(d, dict) else {}


@dataclass
class Endpoint:
    """One side of a connection: a workload's pods, a label set, or an address outside the cluster."""

    namespace: str | None
    ref: str
    labels: dict[str, str] = field(default_factory=dict)
    selector: dict[str, str] = field(default_factory=dict)  # labels that select it in a generated policy
    ports: dict[str, tuple[int, str]] = field(default_factory=dict)  # named container ports
    net: IPNet | None = None
    host_network: bool = False

    @property
    def external(self) -> bool:
        return self.net is not None

    def describe(self) -> str:
        if self.net is not None:
            return str(self.net) if self.net.num_addresses > 1 else str(self.net.network_address)
        return f"{self.namespace}/{self.ref}"


def selector_matches(sel: Any, labels: dict[str, str]) -> bool:
    """A Kubernetes label selector: matchLabels plus matchExpressions; ``{}`` selects everything."""
    if not isinstance(sel, dict):
        return False
    for k, v in (sel.get("matchLabels") or {}).items():
        if labels.get(str(k)) != _labelstr(v):
            return False
    for e in sel.get("matchExpressions") or []:
        key = str(e.get("key"))
        op = e.get("operator")
        values = [_labelstr(v) for v in e.get("values") or []]
        if op == "In" and labels.get(key) not in values:
            return False
        if op == "NotIn" and key in labels and labels[key] in values:
            return False
        if op == "Exists" and key not in labels:
            return False
        if op == "DoesNotExist" and key in labels:
            return False
        if op not in {"In", "NotIn", "Exists", "DoesNotExist"}:
            return False
    return True


def describe_selector(sel: Any) -> str:
    if not isinstance(sel, dict):
        return "nothing"
    parts = [f"{k}={_labelstr(v)}" for k, v in sorted((sel.get("matchLabels") or {}).items())]
    for e in sel.get("matchExpressions") or []:
        vals = ",".join(_labelstr(v) for v in e.get("values") or [])
        parts.append(f"{e.get('key')} {e.get('operator')}" + (f" ({vals})" if vals else ""))
    return ", ".join(parts) or "all"


def _template(kind: str, data: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    spec = data.get("spec") or {}
    if kind == "Pod":
        return data.get("metadata") or {}, spec
    if kind == "CronJob":
        tpl = ((spec.get("jobTemplate") or {}).get("spec") or {}).get("template") or {}
    else:
        tpl = spec.get("template") or {}
    return tpl.get("metadata") or {}, tpl.get("spec") or {}


def _endpoint_from(kind: str, data: dict[str, Any], default_ns: str) -> Endpoint:
    meta = data.get("metadata") or {}
    ns = str(meta.get("namespace") or default_ns)
    tmeta, tspec = _template(kind, data)
    labels = _labels(tmeta.get("labels"))
    sel = (data.get("spec") or {}).get("selector")
    if kind in {"Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "Job"} and isinstance(sel, dict):
        selector = _labels(sel.get("matchLabels")) or labels
    elif kind in {"DeploymentConfig", "ReplicationController"} and isinstance(sel, dict):
        selector = _labels(sel) or labels
    else:
        selector = labels
    ports: dict[str, tuple[int, str]] = {}
    for c in tspec.get("containers") or []:
        for p in (c or {}).get("ports") or []:
            if isinstance(p, dict) and p.get("name") and isinstance(p.get("containerPort"), int):
                ports[str(p["name"])] = (p["containerPort"], str(p.get("protocol") or "TCP").upper())
    return Endpoint(
        namespace=ns,
        ref=f"{kind.lower()}/{meta.get('name', '<unnamed>')}",
        labels=labels,
        selector=selector,
        ports=ports,
        host_network=bool(tspec.get("hostNetwork")),
    )


class Inventory:
    """NetworkPolicies, workloads and namespace labels: what the evaluation reads."""

    def __init__(self, objects: list[dict[str, Any]], default_namespace: str = "default") -> None:
        self.default_namespace = default_namespace
        self.policies: list[dict[str, Any]] = []
        self.workloads: dict[tuple[str, str, str], Endpoint] = {}
        self.namespace_labels: dict[str, dict[str, str]] = {}
        self.other_policies: list[str] = []
        self.notes: list[str] = []
        self.admin: list[dict[str, Any]] = []
        self.baseline: list[dict[str, Any]] = []
        for obj in objects:
            if not isinstance(obj, dict):
                continue
            kind = str(obj.get("kind", ""))
            meta = obj.get("metadata") or {}
            name = str(meta.get("name", ""))
            if kind == "NetworkPolicy":
                pol = dict(obj)
                pol["metadata"] = {**meta, "namespace": str(meta.get("namespace") or default_namespace)}
                self.policies.append(pol)
            elif kind == "Namespace":
                self.namespace_labels[name] = _labels(meta.get("labels"))
            elif kind in WORKLOAD_KINDS:
                ep = _endpoint_from(kind, obj, default_namespace)
                self.workloads[(str(ep.namespace), kind.lower(), name)] = ep
            elif kind in OTHER_POLICY_KINDS:
                ns = meta.get("namespace")
                self.other_policies.append(f"{kind}/{ns + '/' if ns else ''}{name}")
        from kube_noob.debug.anp import collect

        self.admin, self.baseline = collect(self, objects)
        admin_kinds = {ANP_KIND, BANP_KIND}
        if self.admin or self.baseline:
            # Evaluated now, so they must not also be listed as policies that were only found.
            self.other_policies = [p for p in self.other_policies if p.split("/", 1)[0] not in admin_kinds]

    @classmethod
    def from_yaml(cls, text: str, default_namespace: str = "default") -> Inventory:
        return cls([d.data for d in load_documents(text)], default_namespace)

    def ns_labels(self, ns: str) -> dict[str, str]:
        return {**self.namespace_labels.get(ns, {}), "kubernetes.io/metadata.name": ns}

    def known(self) -> list[str]:
        return [f"{ns}/{kind}/{name}" for ns, kind, name in sorted(self.workloads)][:25]

    def resolve(self, spec: str) -> Endpoint:
        """``ns/name``, ``ns/kind/name``, ``ns:key=value,key2=value2``, or an IP address / CIDR outside the cluster."""
        spec = spec.strip()
        if spec.startswith("ip:"):
            spec = spec[3:]
        try:
            net = ipaddress.ip_network(spec, strict=False)
        except ValueError:
            net = None
        if net is not None:
            return Endpoint(namespace=None, ref=str(net), net=net)
        if ":" in spec and "=" in spec:
            ns, _, sel = spec.partition(":")
            labels: dict[str, str] = {}
            for part in sel.split(","):
                k, eq, v = part.partition("=")
                if not eq or not _LABEL_KEY.match(k.strip()) or not _LABEL_VALUE.match(v.strip() or "x"):
                    raise ValueError(f"bad label in {spec!r}: use ns:key=value,key2=value2")
                labels[k.strip()] = v.strip()
            if not _DNS.match(ns):
                raise ValueError(f"bad namespace in {spec!r}")
            return Endpoint(namespace=ns, ref=f"pods {sel}", labels=labels, selector=dict(labels))
        parts = spec.split("/")
        if len(parts) == 3:
            ns, kind, name = parts
            ep = self.workloads.get((ns, kind.lower(), name))
            if ep is None:
                raise ValueError(
                    f"{spec} is not in the manifests; known workloads: {', '.join(self.known()) or 'none'}"
                )
            return ep
        if len(parts) == 2:
            ns, name = parts
            hits = sorted(
                ((k, ep) for (n, k, nm), ep in self.workloads.items() if n == ns and nm == name),
                key=lambda kv: _KIND_RANK.get(kv[0], 99),
            )
            if hits:
                return hits[0][1]
            raise ValueError(f"{spec} is not in the manifests; known workloads: {', '.join(self.known()) or 'none'}")
        named = [ep for (_, _, nm), ep in self.workloads.items() if nm == spec]
        if len(named) == 1:
            return named[0]
        raise ValueError(
            f"use namespace/name for {spec!r} (or ns:key=value for a label set); known workloads: "
            f"{', '.join(self.known()) or 'none'}"
        )


def policy_types(spec: dict[str, Any]) -> set[str]:
    types = spec.get("policyTypes")
    if types:
        return {str(t) for t in types}
    out = {"Ingress"}
    if spec.get("egress"):
        out.add("Egress")
    return out


def _peer_matches(peer: dict[str, Any], policy_ns: str, other: Endpoint, inv: Inventory) -> tuple[bool, str]:
    if "ipBlock" in peer:
        block = peer.get("ipBlock") or {}
        try:
            cidr = ipaddress.ip_network(str(block.get("cidr")), strict=False)
            excepts = [ipaddress.ip_network(str(x), strict=False) for x in block.get("except") or []]
        except ValueError:
            return False, f"ipBlock {block.get('cidr')} (not a valid CIDR)"
        label = f"ipBlock {cidr}" + (f" except {', '.join(str(x) for x in excepts)}" if excepts else "")
        if other.net is None:
            return False, f"{label} (matches addresses outside the cluster, not pods)"
        inside = other.net.version == cidr.version and other.net.subnet_of(cidr)  # type: ignore[arg-type]
        excluded = any(other.net.version == x.version and other.net.overlaps(x) for x in excepts)
        return inside and not excluded, label
    ns_sel, pod_sel = peer.get("namespaceSelector"), peer.get("podSelector")
    if ns_sel is None and pod_sel is None:
        return False, "an empty peer (matches nothing)"
    if ns_sel is not None:
        where = f"namespaces {describe_selector(ns_sel)}"
    else:
        where = f"namespace {policy_ns}"
    who = f"pods {describe_selector(pod_sel)}" if pod_sel is not None else "all pods"
    label = f"{who} in {where}"
    if other.net is not None:
        return False, label
    if ns_sel is not None:
        if not selector_matches(ns_sel, inv.ns_labels(str(other.namespace))):
            return False, label
    elif other.namespace != policy_ns:
        return False, label
    if pod_sel is not None and not selector_matches(pod_sel, other.labels):
        return False, label
    return True, label


def _port_matches(rule_ports: Any, port: int | str, protocol: str, dest: Endpoint) -> tuple[bool, str]:
    if not rule_ports:
        return True, "all ports"
    number = port if isinstance(port, int) else (dest.ports.get(port) or (None, ""))[0]
    labels = []
    ok = False
    for entry in rule_ports:
        rp = entry or {}
        proto = str(rp.get("protocol") or "TCP").upper()
        p = rp.get("port")
        end = rp.get("endPort")
        labels.append(f"{proto} {p if p is not None else 'any'}" + (f"-{end}" if end else ""))
        if proto != protocol or ok:
            continue
        if p is None:
            ok = True
        elif isinstance(p, int) or (isinstance(p, str) and p.isdigit()):
            lo = int(p)
            hi = int(end) if end else lo
            ok = number is not None and lo <= number <= hi
        else:  # a named port resolves against the destination pod's container ports
            named = dest.ports.get(str(p))
            ok = (isinstance(port, str) and p == port) or (
                named is not None and number is not None and named[0] == number and named[1] == protocol
            )
    return ok, ", ".join(labels)


def _direction(
    inv: Inventory, subject: Endpoint, other: Endpoint, direction: str, port: int | str, protocol: str, dest: Endpoint
) -> dict[str, Any]:
    """Does this traffic leave ``subject`` (Egress) or reach it (Ingress)?

    Three tiers decide, in order: AdminNetworkPolicy, then the NetworkPolicies in the namespace, then
    BaselineAdminNetworkPolicy where no NetworkPolicy selects the pod. ``kube_noob.debug.anp`` has the semantics.
    """
    from kube_noob.debug.anp import tier_after, tier_before

    admin = tier_before(inv, inv.admin, subject, other, direction, port, protocol, dest)
    if admin.outcome in ("allow", "deny"):
        return {
            "evaluated": True,
            "tier": ANP_KIND,
            "isolated": admin.outcome == "deny",
            "allowed": admin.outcome == "allow",
            "policy": admin.policy,
            "rule": admin.rule,
            "reason": admin.reason,
        }
    np = _networkpolicy_tier(inv, subject, other, direction, port, protocol, dest)
    if admin.outcome == "passed":
        np["passedBy"] = admin.policy
        np["reason"] = f"{admin.reason} {np['reason']}"
    if np.get("isolated") or not np.get("evaluated"):
        return np
    base = tier_after(inv, inv.baseline, subject, other, direction, port, protocol, dest)
    if base.outcome in ("allow", "deny"):
        return {
            "evaluated": True,
            "tier": BANP_KIND,
            "isolated": base.outcome == "deny",
            "allowed": base.outcome == "allow",
            "policy": base.policy,
            "rule": base.rule,
            "reason": f"{np['reason']} {base.reason}",
        }
    return np


def _networkpolicy_tier(
    inv: Inventory, subject: Endpoint, other: Endpoint, direction: str, port: int | str, protocol: str, dest: Endpoint
) -> dict[str, Any]:
    """Does ``subject``'s namespace let this traffic out (Egress) or in (Ingress)?"""
    word = direction.lower()
    if subject.external:
        return {
            "evaluated": False,
            "tier": "NetworkPolicy",
            "allowed": True,
            "reason": f"{subject.describe()} is outside the cluster; no NetworkPolicy governs its {word}.",
        }
    if subject.host_network:
        return {
            "evaluated": False,
            "tier": "NetworkPolicy",
            "allowed": True,
            "reason": f"{subject.describe()} uses hostNetwork; NetworkPolicy does not apply to its {word} on most "
            "network plugins.",
        }
    selecting = [
        p
        for p in inv.policies
        if p["metadata"]["namespace"] == subject.namespace
        and selector_matches((p.get("spec") or {}).get("podSelector") or {}, subject.labels)
        and direction in policy_types(p.get("spec") or {})
    ]
    if not selecting:
        return {
            "evaluated": True,
            "tier": "NetworkPolicy",
            "isolated": False,
            "allowed": True,
            "policies": [],
            "reason": f"No NetworkPolicy in {subject.namespace} selects {subject.describe()} for {direction}, so all "
            f"{word} traffic is allowed.",
        }
    decisions: list[dict[str, Any]] = []
    for pol in selecting:
        spec = pol.get("spec") or {}
        rules = spec.get("ingress" if direction == "Ingress" else "egress") or []
        name = f"{pol['metadata']['namespace']}/{pol['metadata'].get('name')}"
        verdicts = []
        allowing = None
        for i, raw in enumerate(rules, 1):
            rule = raw or {}
            peers = rule.get("from" if direction == "Ingress" else "to") or []
            if peers:
                results = [_peer_matches(p or {}, pol["metadata"]["namespace"], other, inv) for p in peers]
                peer_ok = any(ok for ok, _ in results)
                peer_label = "; ".join(lbl for _, lbl in results)
            else:
                peer_ok, peer_label = True, "anywhere"
            port_ok, port_label = _port_matches(rule.get("ports"), port, protocol, dest)
            verdicts.append(
                {
                    "rule": i,
                    "allows": peer_ok and port_ok,
                    "peer": peer_label,
                    "peerMatches": peer_ok,
                    "ports": port_label,
                    "portMatches": port_ok,
                }
            )
            if peer_ok and port_ok and allowing is None:
                allowing = i
        decisions.append(
            {
                "policy": name,
                "allows": allowing is not None,
                "rule": allowing,
                "rules": verdicts,
                **({} if rules else {"note": f"no {word} rules: denies all {word} for the pods it selects"}),
            }
        )
    allowed = any(d["allows"] for d in decisions)
    if allowed:
        first = next(d for d in decisions if d["allows"])
        reason = f"Allowed by {first['policy']}, {word} rule {first['rule']}."
    else:
        names = ", ".join(str(d["policy"]) for d in decisions)
        reason = (
            f"{len(decisions)} NetworkPolic{'y' if len(decisions) == 1 else 'ies'} ({names}) "
            f"select{'s' if len(decisions) == 1 else ''} "
            f"{subject.describe()} for {direction}, and no rule allows {other.describe()} on {protocol} {port}."
        )
    return {
        "evaluated": True,
        "tier": "NetworkPolicy",
        "isolated": True,
        "allowed": allowed,
        "policies": decisions,
        "reason": reason,
    }


def _dns_name(*parts: str) -> str:
    raw = "-".join(re.sub(r"[^a-z0-9-]+", "-", p.lower()).strip("-") for p in parts if p)
    return raw[:63].rstrip("-") or "allow-traffic"


def _short(ep: Endpoint) -> str:
    return ep.ref.split("/")[-1] if ep.net is None else "external"


def _allow_policy(direction: str, subject: Endpoint, other: Endpoint, port: int | str, protocol: str) -> str:
    peer: dict[str, Any]
    if other.net is not None:
        peer = {"ipBlock": {"cidr": str(other.net)}}
    else:
        peer = {"podSelector": {"matchLabels": dict(other.selector)}}
        if other.namespace != subject.namespace:
            peer = {"namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": other.namespace}}, **peer}
    src, dst = (other, subject) if direction == "Ingress" else (subject, other)
    name = _dns_name("allow", _short(src), "to", _short(dst), str(port))
    policy = {
        "apiVersion": "networking.k8s.io/v1",
        "kind": "NetworkPolicy",
        "metadata": {"name": name, "namespace": subject.namespace},
        "spec": {
            "podSelector": {"matchLabels": dict(subject.selector)},
            "policyTypes": [direction],
            direction.lower(): [
                {"from" if direction == "Ingress" else "to": [peer], "ports": [{"protocol": protocol, "port": port}]}
            ],
        },
    }
    return yaml.safe_dump(policy, sort_keys=False)


def _step(check: str) -> dict[str, str]:
    cmd, why = split_comment(check)
    return {"command": cmd, **({"why": why} if why else {})}


def check_reachability(
    inv: Inventory, source: str, destination: str, port: int | str, protocol: str = "TCP", cli: str = "kubectl"
) -> dict[str, Any]:
    protocol = protocol.upper()
    if protocol not in {"TCP", "UDP", "SCTP"}:
        raise ValueError("protocol must be TCP, UDP or SCTP")
    if isinstance(port, str) and port.isdigit():
        port = int(port)
    if isinstance(port, int) and not 1 <= port <= 65535:
        raise ValueError("port must be 1-65535 or a named container port")
    if isinstance(port, str) and not _PORT_NAME.match(port):
        raise ValueError(f"bad port name {port!r}")
    src, dst = inv.resolve(source), inv.resolve(destination)
    if src.external and dst.external:
        raise ValueError("at least one side must be a workload in the cluster")
    egress = _direction(inv, src, dst, "Egress", port, protocol, dst)
    ingress = _direction(inv, dst, src, "Ingress", port, protocol, dst)
    allowed = bool(egress["allowed"] and ingress["allowed"])
    out: dict[str, Any] = {
        "verdict": "allowed" if allowed else "denied",
        "source": src.describe(),
        "destination": dst.describe(),
        "port": port,
        "protocol": protocol,
        "egress": egress,
        "ingress": ingress,
    }
    if isinstance(port, str) and port not in dst.ports:
        out["warning"] = f"named port {port!r} is not declared by {dst.describe()}'s containers in these manifests"
    blocked = [d for d, r in (("Egress", egress), ("Ingress", ingress)) if not r["allowed"]]
    if allowed:
        out["summary"] = (
            f"Allowed: {src.describe()} -> {dst.describe()} on {protocol} {port}. "
            f"{egress['reason']} {ingress['reason']}"
        )
    else:
        out["summary"] = (
            f"Denied: {src.describe()} -> {dst.describe()} on {protocol} {port} is blocked by "
            + " and ".join(f"the {d.lower()} policies of {(src if d == 'Egress' else dst).describe()}" for d in blocked)
            + "."
        )
    changes = []
    for direction in blocked:
        verdict = ingress if direction == "Ingress" else egress
        subject, peer = (dst, src) if direction == "Ingress" else (src, dst)
        word = direction.lower()
        if verdict.get("tier") == ANP_KIND:
            # A NetworkPolicy cannot undo this: the admin tier runs first and has already decided. Proposing one
            # would be applied, change nothing, and cost the next verdict its credibility.
            changes.append(
                {
                    "change": f"{verdict['policy']} {word} rule {verdict['rule']!r} denies this, and it is "
                    f"cluster-scoped: no NetworkPolicy in {subject.namespace} can override it. A cluster "
                    f"administrator has to narrow that rule's peers or ports, or add an Allow or Pass rule at a "
                    f"lower priority, for {peer.describe()} on {protocol} {port}.",
                    "requiresApproval": True,
                    "ownedBy": "cluster administrator",
                    "policy": verdict["policy"],
                    "rule": verdict["rule"],
                }
            )
            continue
        baseline = verdict.get("tier") == BANP_KIND
        changes.append(
            {
                "change": f"Allow {word} {'to' if direction == 'Ingress' else 'from'} {subject.describe()} "
                f"{'from' if direction == 'Ingress' else 'to'} {peer.describe()} on {protocol} {port}"
                + (
                    f" -- {verdict['policy']} denies it as the baseline, and any NetworkPolicy that selects "
                    f"{subject.describe()} for {direction} takes the decision away from the baseline"
                    if baseline
                    else ""
                ),
                "manifest": _allow_policy(direction, subject, peer, port, protocol),
                "requiresApproval": True,
            }
        )
    if "Egress" in blocked:
        changes.append(
            {
                "change": "If the source reaches the destination by name, its egress must also allow DNS: UDP and "
                "TCP 5353 to namespace openshift-dns on OpenShift, 53 to kube-system elsewhere.",
                "requiresApproval": True,
            }
        )
    if changes:
        out["proposedChanges"] = changes
    # Names and labels come from manifests or the cluster: only Kubernetes syntax goes into a command line.
    checks = []
    safe_ns = [ns for ns in dict.fromkeys(e.namespace for e in (src, dst) if e.namespace) if _DNS.match(ns)]
    for ns in safe_ns:
        checks.append(f"{cli} get networkpolicy -n {ns} -o yaml")
        checks.append(f"{cli} get namespace {ns} --show-labels")
    for e in (src, dst):
        sel = _shell_safe_selector(e.selector)
        if e.namespace in safe_ns and sel:
            checks.append(f"{cli} get pods -n {e.namespace} -l {sel} -o wide --show-labels")
    # The admin tiers are upstream CRDs, not an OpenShift feature, so they are worth reading on either CLI - and
    # first, when one of them is what decided the verdict.
    anp_check = f"{cli} get adminnetworkpolicy,baselineadminnetworkpolicy"
    if {egress.get("tier"), ingress.get("tier")} & {ANP_KIND, BANP_KIND}:
        checks.insert(0, anp_check)
    else:
        checks.append(anp_check)
    if cli == "oc" and src.namespace in safe_ns:
        checks.append(f"oc get egressfirewall -n {src.namespace} -o yaml")
    out["readOnlyNextSteps"] = [_step(c) for c in checks if classify_step(c) == "read"]
    kind, _, name = src.ref.partition("/")
    if src.namespace in safe_ns and kind.isalpha() and _DNS.match(name) and (dst.external or dst.namespace in safe_ns):
        target = dst.describe() if dst.external else f"<{_short(dst)}-service>.{dst.namespace}.svc"
        probe = f"{cli} exec -n {src.namespace} {src.ref} -- curl -sS -o /dev/null --max-time 5 {target}:{port}"
        out["diagnosticCommands"] = [{"command": probe, "requiresApproval": True}]
    not_evaluated = list(NOT_EVALUATED)
    if inv.other_policies:
        not_evaluated.insert(0, "found in the input but not evaluated: " + ", ".join(inv.other_policies[:10]))
    out["notEvaluated"] = not_evaluated
    if inv.notes:
        out["notes"] = list(inv.notes)
    return out


def inventory_from_cluster(backend: Any, source: str, destination: str) -> Inventory:
    """Read (never write) the NetworkPolicies, namespaces and workloads the two endpoints need."""
    from kube_noob.errors import ClusterAccessError

    objects: list[dict[str, Any]] = []
    namespaces: list[str] = []
    notes: list[str] = []
    for spec in (source, destination):
        s = spec.strip()
        if ":" in s and "=" in s:
            ns = s.split(":", 1)[0]
        elif "/" in s:
            ns = s.split("/", 1)[0]
        else:
            continue  # an IP address
        if not _DNS.match(ns):
            raise ValueError(f"bad namespace in {spec!r}")
        if ns not in namespaces:
            namespaces.append(ns)
        parts = s.split("/")
        if len(parts) in (2, 3) and "=" not in s:
            name = parts[-1]
            kinds = [parts[1].lower()] if len(parts) == 3 else ["deployments", "statefulsets", "daemonsets", "pods"]
            plural = {
                "deployment": "deployments",
                "statefulset": "statefulsets",
                "daemonset": "daemonsets",
                "pod": "pods",
                "replicaset": "replicasets",
                "job": "jobs",
                "cronjob": "cronjobs",
            }
            for kind in kinds:
                try:
                    obj = backend.get(plural.get(kind, kind), name=name, namespace=ns)
                except ClusterAccessError:
                    continue
                if isinstance(obj, dict) and obj.get("kind"):
                    objects.append(obj)
                    break
    for ns in namespaces:
        for item in backend.get("networkpolicies", namespace=ns).get("items", []):
            objects.append({**item, "kind": "NetworkPolicy"})
        try:
            nso = backend.get("namespaces", name=ns)
            objects.append({**nso, "kind": "Namespace"})
        except ClusterAccessError:
            notes.append(
                f"could not read namespace {ns}'s labels; only kubernetes.io/metadata.name is used for "
                "namespaceSelector matches"
            )
    # The admin tiers are cluster-scoped: read once, not per namespace. A cluster without the network-policy-api
    # CRDs answers 404, which means the tier is not installed - not that the read failed.
    for tier_plural, tier_kind in (("adminnetworkpolicies", ANP_KIND), ("baselineadminnetworkpolicies", BANP_KIND)):
        try:
            items = backend.get(tier_plural, namespace=None).get("items", [])
        except ClusterAccessError:
            notes.append(
                f"{tier_kind} is not installed on this cluster, or could not be read; the answer is NetworkPolicy only"
            )
            continue
        objects += [{**item, "kind": tier_kind} for item in items if isinstance(item, dict)]
    inv = Inventory(objects)
    inv.notes.extend(notes)
    return inv
