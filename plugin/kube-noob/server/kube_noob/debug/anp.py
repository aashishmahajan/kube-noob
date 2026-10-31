"""AdminNetworkPolicy and BaselineAdminNetworkPolicy, evaluated offline.

These two cluster-scoped resources (``policy.networking.k8s.io``) sit on either side of NetworkPolicy, so leaving
them out does not narrow an answer, it changes it: an AdminNetworkPolicy ``Deny`` blocks traffic every NetworkPolicy
in the namespace allows, an ``Allow`` permits traffic every NetworkPolicy denies, and a BaselineAdminNetworkPolicy
decides the traffic no NetworkPolicy selects at all.

Precedence, as OVN-Kubernetes implements it:

1. **AdminNetworkPolicy** - every policy by ``priority`` ascending (lower number first), rules within a policy in
   order, first match wins. ``Allow`` and ``Deny`` are final. ``Pass`` ends this tier and hands the decision down.
   No match anywhere in the tier also hands it down: the tier has no implicit deny of its own.
2. **NetworkPolicy** - the namespaced evaluation in ``kube_noob.debug.netpol``. If any NetworkPolicy selects the pod
   for that direction, its answer is final and the baseline is not consulted.
3. **BaselineAdminNetworkPolicy** - the singleton named ``default``. ``Allow`` and ``Deny`` only, no priority, first
   matching rule wins. No match means allowed.

Sources: https://ovn-kubernetes.io/features/network-security-controls/admin-network-policy/ and
https://network-policy-api.sigs.k8s.io/api-overview/. Note that upstream is replacing both with
``ClusterNetworkPolicy`` in v1alpha2; the tiers and the action semantics are the same, under the names
``Accept``/``Deny``/``Pass``.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from kube_noob.debug.netpol import Endpoint, Inventory, selector_matches

ANP_KIND = "AdminNetworkPolicy"
BANP_KIND = "BaselineAdminNetworkPolicy"
ANP_ACTIONS = ("Allow", "Deny", "Pass")
BANP_ACTIONS = ("Allow", "Deny")
PRIORITY_MAX = 1000  # the API's range; OVN-Kubernetes implements 0-99 and warns above that
OVN_PRIORITY_MAX = 99


@dataclass
class Decision:
    """A tier's answer: ``allow`` and ``deny`` are final, ``passed`` hands the decision to the next tier."""

    outcome: str  # "allow" | "deny" | "passed" | "nomatch"
    policy: str = ""
    rule: str = ""
    reason: str = ""


def _str(v: Any) -> str:
    return v if isinstance(v, str) else ""


def _peer_matches(peer: Any, other: Endpoint, inv: Inventory) -> bool:
    """One ``from``/``to`` entry of an admin rule. ``namespaces`` is a namespace selector; ``pods`` carries both a
    namespace and a pod selector. ``nodes`` and ``networks`` are egress-only and are not matched here: a node or a
    CIDR peer is reported as unevaluated rather than guessed at, because guessing either way is a wrong verdict."""
    if not isinstance(peer, dict):
        return False
    if "namespaces" in peer:
        if other.namespace is None:
            return False
        return selector_matches(peer.get("namespaces") or {}, inv.ns_labels(other.namespace))
    if "pods" in peer:
        pods = peer.get("pods") or {}
        if not isinstance(pods, dict) or other.namespace is None:
            return False
        return selector_matches(
            pods.get("namespaceSelector") or {}, inv.ns_labels(other.namespace)
        ) and selector_matches(pods.get("podSelector") or {}, other.labels)
    return False


def _port_matches(ports: Any, port: int | str, protocol: str, dest: Endpoint) -> bool:
    """``portNumber`` {protocol, port}, ``portRange`` {protocol, start, end} or ``namedPort``. No ``ports`` at all
    means every port, as in NetworkPolicy."""
    if not ports:
        return True
    if not isinstance(ports, list):
        return False
    declared = None if isinstance(port, int) else dest.ports.get(port)
    number = port if isinstance(port, int) else (declared[0] if declared else None)
    for entry in ports:
        if not isinstance(entry, dict):
            continue
        if "namedPort" in entry:
            if isinstance(port, str) and _str(entry.get("namedPort")) == port:
                return True
            continue
        if "portNumber" in entry:
            spec = entry.get("portNumber") or {}
            if not isinstance(spec, dict):
                continue
            if _str(spec.get("protocol")).upper() not in ("", protocol):
                continue
            if number is not None and spec.get("port") == number:
                return True
            continue
        if "portRange" in entry:
            spec = entry.get("portRange") or {}
            if not isinstance(spec, dict):
                continue
            if _str(spec.get("protocol")).upper() not in ("", protocol):
                continue
            start, end = spec.get("start"), spec.get("end")
            if number is None or not isinstance(start, int) or not isinstance(end, int):
                continue
            if start <= number <= end:
                return True
    return False


def _subject_matches(subject: Any, subject_ep: Endpoint, inv: Inventory) -> bool:
    """``spec.subject`` is exactly one of ``namespaces`` (a namespace selector) or ``pods`` (both selectors)."""
    if not isinstance(subject, dict) or subject_ep.namespace is None:
        return False
    if "namespaces" in subject:
        return selector_matches(subject.get("namespaces") or {}, inv.ns_labels(subject_ep.namespace))
    if "pods" in subject:
        pods = subject.get("pods") or {}
        if not isinstance(pods, dict):
            return False
        return selector_matches(
            pods.get("namespaceSelector") or {}, inv.ns_labels(subject_ep.namespace)
        ) and selector_matches(pods.get("podSelector") or {}, subject_ep.labels)
    return False


def _rules(spec: Any, direction: str) -> list[Any]:
    if not isinstance(spec, dict):
        return []
    rules = spec.get("ingress" if direction == "Ingress" else "egress")
    return rules if isinstance(rules, list) else []


def _evaluate(
    policies: list[dict[str, Any]],
    actions: tuple[str, ...],
    subject_ep: Endpoint,
    other: Endpoint,
    direction: str,
    port: int | str,
    protocol: str,
    dest: Endpoint,
    inv: Inventory,
    notes: list[str],
) -> Decision:
    """The first rule of the first selecting policy whose peer and ports both match. ``policies`` arrives in
    precedence order."""
    for pol in policies:
        meta = pol.get("metadata") or {}
        name = f"{pol.get('kind')}/{meta.get('name')}"
        spec = pol.get("spec") or {}
        if not _subject_matches(spec.get("subject") if isinstance(spec, dict) else None, subject_ep, inv):
            continue
        for i, raw in enumerate(_rules(spec, direction), 1):
            rule = raw if isinstance(raw, dict) else {}
            action = _str(rule.get("action"))
            label = _str(rule.get("name")) or f"rule {i}"
            if action not in actions:
                notes.append(
                    f"{name} {direction.lower()} {label}: action {action or '(empty)'!r} is not one of "
                    f"{', '.join(actions)}; the rule is skipped rather than read as the nearest valid action"
                )
                continue
            peers = rule.get("from" if direction == "Ingress" else "to")
            peers = peers if isinstance(peers, list) else []
            if direction == "Egress":
                for peer in peers:
                    if isinstance(peer, dict) and ("nodes" in peer or "networks" in peer):
                        notes.append(
                            f"{name} {direction.lower()} {label}: a 'nodes' or 'networks' peer is not evaluated "
                            "offline, so this rule may decide the traffic on the cluster"
                        )
            if not any(_peer_matches(p, other, inv) for p in peers):
                continue
            if not _port_matches(rule.get("ports"), port, protocol, dest):
                continue
            if action == "Pass":
                return Decision(
                    "passed",
                    name,
                    label,
                    f"{name} {direction.lower()} {label} passes {other.describe()} on {protocol} {port} down to the "
                    "NetworkPolicies in the namespace.",
                )
            return Decision(
                "allow" if action == "Allow" else "deny",
                name,
                label,
                f"{'Allowed' if action == 'Allow' else 'Denied'} by {name} {direction.lower()} {label} "
                f"(priority {spec.get('priority')})."
                if pol.get("kind") == ANP_KIND
                else f"{'Allowed' if action == 'Allow' else 'Denied'} by {name} {direction.lower()} {label}.",
            )
    return Decision("nomatch")


def collect(inv: Inventory, objects: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """(AdminNetworkPolicies in precedence order, BaselineAdminNetworkPolicies). Notes about a policy the API server
    would itself refuse are appended to ``inv.notes``, because such a manifest is a mistake to report rather than a
    policy to evaluate."""
    anps: list[tuple[int, int, dict[str, Any]]] = []
    banps: list[dict[str, Any]] = []
    for i, obj in enumerate(objects):
        if not isinstance(obj, dict):
            continue
        kind = _str(obj.get("kind"))
        meta = obj.get("metadata") or {}
        name = _str(meta.get("name") if isinstance(meta, dict) else "")
        if kind == ANP_KIND:
            spec = obj.get("spec") or {}
            priority = spec.get("priority") if isinstance(spec, dict) else None
            if not isinstance(priority, int) or isinstance(priority, bool) or not 0 <= priority <= PRIORITY_MAX:
                inv.notes.append(
                    f"{kind}/{name}: priority {priority!r} is outside 0-{PRIORITY_MAX}, which the API server "
                    "refuses, so this policy is not evaluated"
                )
                continue
            if priority > OVN_PRIORITY_MAX:
                inv.notes.append(
                    f"{kind}/{name}: priority {priority} is above {OVN_PRIORITY_MAX}, which OVN-Kubernetes does not "
                    "implement (it raises ANPWithUnsupportedPriority and the policy has no effect on the cluster); "
                    "it is evaluated here in priority order"
                )
            anps.append((priority, i, obj))
        elif kind == BANP_KIND:
            if name != "default":
                inv.notes.append(
                    f"{kind}/{name}: a BaselineAdminNetworkPolicy is a singleton that must be named 'default'; the "
                    "API server refuses any other name, so this one is not evaluated"
                )
                continue
            banps.append(obj)
    anps.sort(key=lambda t: (t[0], t[1]))
    return [obj for _, _, obj in anps], banps


def tier_before(
    inv: Inventory,
    anps: list[dict[str, Any]],
    subject: Endpoint,
    other: Endpoint,
    direction: str,
    port: int | str,
    protocol: str,
    dest: Endpoint,
) -> Decision:
    """The AdminNetworkPolicy tier, which runs before any NetworkPolicy."""
    if not anps or subject.external:
        return Decision("nomatch")
    return _evaluate(anps, ANP_ACTIONS, subject, other, direction, port, protocol, dest, inv, inv.notes)


def tier_after(
    inv: Inventory,
    banps: list[dict[str, Any]],
    subject: Endpoint,
    other: Endpoint,
    direction: str,
    port: int | str,
    protocol: str,
    dest: Endpoint,
) -> Decision:
    """The BaselineAdminNetworkPolicy tier, which runs only where no NetworkPolicy selects the pod."""
    if not banps or subject.external:
        return Decision("nomatch")
    return _evaluate(banps, BANP_ACTIONS, subject, other, direction, port, protocol, dest, inv, inv.notes)
