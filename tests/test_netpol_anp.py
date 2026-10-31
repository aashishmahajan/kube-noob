"""AdminNetworkPolicy and BaselineAdminNetworkPolicy change the answer, so they are evaluated.

The NetworkPolicy evaluator used to list ANP and BANP under "not evaluated". That is not a gap in coverage, it is a
wrong verdict: an ANP ``Deny`` blocks traffic every NetworkPolicy allows, an ANP ``Allow`` permits traffic every
NetworkPolicy denies, and a BANP decides the cases no NetworkPolicy selects. Precedence is ANP, then NetworkPolicy,
then BANP; within the ANP tier, lower ``priority`` first and then rule order, first match wins.
"""

from __future__ import annotations

from typing import Any

import pytest

from kube_noob.debug.netpol import Inventory, check_reachability

WORKLOADS = """
apiVersion: v1
kind: Namespace
metadata:
  name: shop
  labels:
    tier: app
---
apiVersion: v1
kind: Namespace
metadata:
  name: monitoring
  labels:
    tier: platform
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: orders
  namespace: shop
spec:
  template:
    metadata:
      labels:
        app: orders
    spec:
      containers:
        - name: c
          image: orders:1
          ports:
            - name: http
              containerPort: 8080
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: prometheus
  namespace: monitoring
spec:
  template:
    metadata:
      labels:
        app: prometheus
    spec:
      containers:
        - name: c
          image: prom:1
"""

ALLOW_ALL_NP = """
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-everything
  namespace: shop
spec:
  podSelector:
    matchLabels:
      app: orders
  policyTypes: [Ingress]
  ingress:
    - {}
"""

DENY_ALL_NP = """
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: deny-everything
  namespace: shop
spec:
  podSelector:
    matchLabels:
      app: orders
  policyTypes: [Ingress]
"""


def _anp(priority: int, action: str, name: str = "guardrail", from_ns: str = "monitoring") -> str:
    return f"""
apiVersion: policy.networking.k8s.io/v1alpha1
kind: AdminNetworkPolicy
metadata:
  name: {name}
spec:
  priority: {priority}
  subject:
    namespaces:
      matchLabels:
        tier: app
  ingress:
    - name: "from-{from_ns}"
      action: "{action}"
      from:
        - namespaces:
            matchLabels:
              kubernetes.io/metadata.name: {from_ns}
"""


def _banp(action: str) -> str:
    return f"""
apiVersion: policy.networking.k8s.io/v1alpha1
kind: BaselineAdminNetworkPolicy
metadata:
  name: default
spec:
  subject:
    namespaces:
      matchLabels:
        tier: app
  ingress:
    - name: "baseline"
      action: "{action}"
      from:
        - namespaces: {{}}
"""


def _check(*parts: str, port: int | str = 8080) -> dict[str, Any]:
    inv = Inventory.from_yaml("\n---\n".join((WORKLOADS, *parts)))
    return check_reachability(inv, "monitoring/prometheus", "shop/orders", port)


def test_an_admin_deny_beats_a_networkpolicy_that_allows_everything() -> None:
    """The verdict without ANP is 'allowed'. With a cluster admin's Deny in front of it, the traffic does not flow,
    and reporting 'allowed' would send an operator looking for the problem in the wrong namespace."""
    assert _check(ALLOW_ALL_NP)["verdict"] == "allowed"
    out = _check(ALLOW_ALL_NP, _anp(10, "Deny"))
    assert out["verdict"] == "denied"
    assert out["ingress"]["tier"] == "AdminNetworkPolicy"
    assert "guardrail" in out["ingress"]["reason"]
    assert "allow-everything" not in out["summary"]


def test_an_admin_allow_beats_a_networkpolicy_that_denies_everything() -> None:
    """The mirror case: an admin Allow short-circuits the tier, so the namespace's own deny never runs."""
    assert _check(DENY_ALL_NP)["verdict"] == "denied"
    out = _check(DENY_ALL_NP, _anp(10, "Allow"))
    assert out["verdict"] == "allowed"
    assert out["ingress"]["tier"] == "AdminNetworkPolicy"


def test_pass_hands_the_decision_back_to_the_namespace() -> None:
    """Pass is the delegation action: it stops the ANP tier and lets the NetworkPolicy decide, which is the whole
    point of the tier for a platform team that wants to set guardrails without owning every namespace."""
    allowed = _check(ALLOW_ALL_NP, _anp(10, "Pass"))
    assert allowed["verdict"] == "allowed"
    assert allowed["ingress"]["tier"] == "NetworkPolicy"
    assert allowed["ingress"]["passedBy"] == "AdminNetworkPolicy/guardrail"
    assert "guardrail" in allowed["ingress"]["reason"] and "allow-everything" in allowed["ingress"]["reason"]
    denied = _check(DENY_ALL_NP, _anp(10, "Pass"))
    assert denied["verdict"] == "denied"
    assert denied["ingress"]["tier"] == "NetworkPolicy"
    assert denied["ingress"]["passedBy"] == "AdminNetworkPolicy/guardrail"


def test_the_lowest_priority_number_decides() -> None:
    """Lower priority wins, so a Deny at 10 beats an Allow at 20 and the order in the file is irrelevant."""
    for parts in (
        (_anp(10, "Deny", "deny-first"), _anp(20, "Allow", "allow-second")),
        (_anp(20, "Allow", "allow-second"), _anp(10, "Deny", "deny-first")),
    ):
        out = _check(ALLOW_ALL_NP, *parts)
        assert out["verdict"] == "denied"
        assert "deny-first" in out["ingress"]["reason"]


def test_rule_order_inside_one_policy_decides() -> None:
    """Within one ANP the first matching rule wins, whatever the later rules say."""
    both = """
apiVersion: policy.networking.k8s.io/v1alpha1
kind: AdminNetworkPolicy
metadata:
  name: ordered
spec:
  priority: 5
  subject:
    namespaces:
      matchLabels:
        tier: app
  ingress:
    - name: "first-allow"
      action: "Allow"
      from:
        - namespaces: {}
    - name: "then-deny"
      action: "Deny"
      from:
        - namespaces: {}
"""
    out = _check(DENY_ALL_NP, both)
    assert out["verdict"] == "allowed"
    assert "first-allow" in out["ingress"]["reason"]


def test_the_baseline_decides_only_what_no_networkpolicy_selects() -> None:
    """BANP is the tier for traffic nobody wrote a NetworkPolicy for. Where a NetworkPolicy does select the pod,
    the namespace's answer is final and the baseline never runs -- which is what makes BANP safe to default-deny."""
    bare = _check(_banp("Deny"))
    assert bare["verdict"] == "denied"
    assert bare["ingress"]["tier"] == "BaselineAdminNetworkPolicy"
    covered = _check(ALLOW_ALL_NP, _banp("Deny"))
    assert covered["verdict"] == "allowed"
    assert covered["ingress"]["tier"] == "NetworkPolicy"


def test_nothing_matching_anywhere_is_allowed() -> None:
    """No tier has an implicit deny of its own: with no NetworkPolicy and a baseline that does not select the pod,
    the traffic flows."""
    elsewhere = _banp("Deny").replace("tier: app", "tier: nothing-here")
    out = _check(elsewhere)
    assert out["verdict"] == "allowed"
    assert out["ingress"]["tier"] == "NetworkPolicy"


def test_a_pod_subject_is_narrower_than_a_namespace_subject() -> None:
    """``subject.pods`` carries a namespaceSelector and a podSelector; a policy whose pod selector misses the
    workload must not decide its traffic."""
    missing = """
apiVersion: policy.networking.k8s.io/v1alpha1
kind: AdminNetworkPolicy
metadata:
  name: other-pods
spec:
  priority: 1
  subject:
    pods:
      namespaceSelector:
        matchLabels:
          tier: app
      podSelector:
        matchLabels:
          app: payments
  ingress:
    - name: "deny"
      action: "Deny"
      from:
        - namespaces: {}
"""
    assert _check(ALLOW_ALL_NP, missing)["verdict"] == "allowed"
    hits = missing.replace("app: payments", "app: orders")
    assert _check(ALLOW_ALL_NP, hits)["verdict"] == "denied"


def test_ports_narrow_an_admin_rule() -> None:
    """An ANP rule with ports only decides the ports it names; other ports fall through to the next tier."""
    scoped = """
apiVersion: policy.networking.k8s.io/v1alpha1
kind: AdminNetworkPolicy
metadata:
  name: port-scoped
spec:
  priority: 1
  subject:
    namespaces:
      matchLabels:
        tier: app
  ingress:
    - name: "deny-9090"
      action: "Deny"
      from:
        - namespaces: {}
      ports:
        - portNumber:
            protocol: TCP
            port: 9090
"""
    assert _check(ALLOW_ALL_NP, scoped, port=9090)["verdict"] == "denied"
    other = _check(ALLOW_ALL_NP, scoped, port=8080)
    assert other["verdict"] == "allowed"
    assert other["ingress"]["tier"] == "NetworkPolicy"


def test_a_port_range_is_honoured() -> None:
    ranged = """
apiVersion: policy.networking.k8s.io/v1alpha1
kind: AdminNetworkPolicy
metadata:
  name: ranged
spec:
  priority: 1
  subject:
    namespaces:
      matchLabels:
        tier: app
  ingress:
    - name: "deny-range"
      action: "Deny"
      from:
        - namespaces: {}
      ports:
        - portRange:
            protocol: TCP
            start: 8000
            end: 8100
"""
    assert _check(ALLOW_ALL_NP, ranged, port=8080)["verdict"] == "denied"
    assert _check(ALLOW_ALL_NP, ranged, port=9000)["verdict"] == "allowed"


def test_egress_is_evaluated_in_the_same_tiers() -> None:
    """Both directions must allow, so an ANP that denies the source's egress denies the connection."""
    egress_deny = """
apiVersion: policy.networking.k8s.io/v1alpha1
kind: AdminNetworkPolicy
metadata:
  name: no-egress
spec:
  priority: 3
  subject:
    namespaces:
      matchLabels:
        tier: platform
  egress:
    - name: "deny-to-shop"
      action: "Deny"
      to:
        - namespaces:
            matchLabels:
              tier: app
"""
    out = _check(ALLOW_ALL_NP, egress_deny)
    assert out["verdict"] == "denied"
    assert out["egress"]["tier"] == "AdminNetworkPolicy"


def test_the_tiers_it_now_evaluates_leave_the_not_evaluated_list() -> None:
    """The list is read as the limits of the answer, so a tier that is evaluated must not still be listed as one
    that is not -- and the tiers that genuinely are not evaluated must stay."""
    out = _check(ALLOW_ALL_NP, _anp(10, "Deny"))
    joined = " ".join(out["notEvaluated"])
    assert "AdminNetworkPolicy" not in joined
    assert "EgressFirewall" in joined and "Cilium" in joined
    assert "AdminNetworkPolicy/guardrail" not in " ".join(out.get("notes", []))


def test_a_baseline_not_named_default_is_reported_not_applied() -> None:
    """BANP is a singleton that must be named ``default``; the API server rejects any other name, so a manifest
    with one is a mistake worth naming rather than a policy to evaluate."""
    wrong = _banp("Deny").replace("name: default", "name: baseline")
    out = _check(wrong)
    assert out["verdict"] == "allowed"
    assert any("default" in n for n in out.get("notes", [])), out.get("notes")


@pytest.mark.parametrize("priority", [-1, 1001])
def test_an_out_of_range_priority_is_reported(priority: int) -> None:
    out = _check(ALLOW_ALL_NP, _anp(priority, "Deny"))
    assert any("priority" in n for n in out.get("notes", [])), out.get("notes")


def test_an_unknown_action_is_reported_and_not_guessed() -> None:
    """A typo in ``action`` must not be read as the nearest valid action; the rule is skipped and said so."""
    out = _check(ALLOW_ALL_NP, _anp(10, "Drop"))
    assert out["verdict"] == "allowed"
    assert any("Drop" in n for n in out.get("notes", [])), out.get("notes")


def test_the_live_check_reads_the_admin_tiers_too() -> None:
    """The offline and live checks must not disagree. The live path reads the cluster, so it has to read the two
    cluster-scoped tiers as well, or the same traffic gets opposite verdicts depending on where the manifests came
    from -- and the live one, which an operator trusts more, would be the wrong one."""
    from kube_noob.debug.cluster import ALLOWED_RESOURCES as RESOURCES
    from kube_noob.debug.netpol import inventory_from_cluster

    assert "adminnetworkpolicies" in RESOURCES
    assert "baselineadminnetworkpolicies" in RESOURCES
    assert RESOURCES["adminnetworkpolicies"].namespaced is False
    assert RESOURCES["baselineadminnetworkpolicies"].namespaced is False

    reads: list[tuple[str, Any]] = []

    class Backend:
        name = "fake"

        def get(self, plural: str, name: str | None = None, namespace: str | None = None) -> dict[str, Any]:
            reads.append((plural, namespace))
            if plural == "adminnetworkpolicies":
                import yaml

                return {"items": [yaml.safe_load(_anp(10, "Deny"))]}
            if plural == "baselineadminnetworkpolicies":
                return {"items": []}
            if plural == "namespaces":
                return {"kind": "Namespace", "metadata": {"name": name, "labels": {"tier": "app"}}}
            if plural == "networkpolicies":
                return {"items": []}
            if name == "orders":
                import yaml

                for doc in yaml.safe_load_all(WORKLOADS):
                    if doc and doc.get("metadata", {}).get("name") == "orders":
                        return dict(doc)
            raise __import__("kube_noob.errors", fromlist=["x"]).ClusterAccessError("not there")

    inv = inventory_from_cluster(Backend(), "monitoring/prometheus", "shop/orders")
    assert [p for p, _ in reads].count("adminnetworkpolicies") == 1, "read once, not per namespace"
    assert len(inv.admin) == 1


def test_a_cluster_that_has_no_admin_tier_api_is_not_an_error() -> None:
    """ANP and BANP are a separate API that many clusters do not have installed. A 404 on them is normal and must
    leave a working NetworkPolicy answer, with a note rather than a failure."""
    from kube_noob.debug.netpol import inventory_from_cluster
    from kube_noob.errors import ClusterAccessError

    class Backend:
        name = "fake"

        def get(self, plural: str, name: str | None = None, namespace: str | None = None) -> dict[str, Any]:
            if plural in ("adminnetworkpolicies", "baselineadminnetworkpolicies"):
                raise ClusterAccessError("the server could not find the requested resource")
            if plural == "namespaces":
                return {"kind": "Namespace", "metadata": {"name": name, "labels": {}}}
            if plural == "networkpolicies":
                return {"items": []}
            raise ClusterAccessError("not there")

    inv = inventory_from_cluster(Backend(), "monitoring/prometheus", "shop/orders")
    assert inv.admin == [] and inv.baseline == []
    assert any("AdminNetworkPolicy" in n for n in inv.notes), inv.notes


def test_it_does_not_propose_a_change_that_the_admin_tier_would_still_block() -> None:
    """A proposed NetworkPolicy cannot unblock an AdminNetworkPolicy Deny: the admin tier runs first and decides.
    Handing one over is worse than proposing nothing -- the operator applies it, the traffic still fails, and the
    next verdict from this tool is not believed. The change has to name the policy and rule that actually decided,
    and say who can change it."""
    out = _check(ALLOW_ALL_NP, _anp(10, "Deny"))
    assert out["verdict"] == "denied"
    changes = out.get("proposedChanges") or []
    assert changes, "a denied verdict still explains what would change it"
    manifests = " ".join(str(c.get("manifest", "")) for c in changes)
    assert "kind: NetworkPolicy" not in manifests, "a NetworkPolicy would not survive the admin tier"
    text = " ".join(str(c.get("change", "")) for c in changes)
    assert "AdminNetworkPolicy/guardrail" in text
    assert "from-monitoring" in text
    assert "administrator" in text.lower() or "cluster-scoped" in text.lower()


def test_a_baseline_denial_is_fixed_by_a_networkpolicy_and_says_so() -> None:
    """The mirror case: a BANP denial IS fixed by a NetworkPolicy, because any NetworkPolicy that selects the pod
    takes the decision away from the baseline. That change is worth proposing, and the reason is worth stating."""
    out = _check(_banp("Deny"))
    assert out["verdict"] == "denied"
    changes = out.get("proposedChanges") or []
    manifests = " ".join(str(c.get("manifest", "")) for c in changes)
    assert "kind: NetworkPolicy" in manifests
    assert any("baseline" in str(c.get("change", "")).lower() for c in changes), changes


def test_the_read_only_steps_name_the_tier_that_decided_first() -> None:
    """The next steps are what an operator runs to confirm the verdict. When an admin tier decided it, reading the
    namespace's NetworkPolicies first sends them to the wrong place; and the tiers are upstream CRDs, so they are
    worth reading on kubectl too, not only on oc."""
    out = _check(ALLOW_ALL_NP, _anp(10, "Deny"))
    steps = [s["command"] for s in out["readOnlyNextSteps"]]
    assert steps[0].endswith("get adminnetworkpolicy,baselineadminnetworkpolicy")
    assert steps[0].startswith("kubectl ")
    plain = _check(DENY_ALL_NP)
    plain_steps = [s["command"] for s in plain["readOnlyNextSteps"]]
    assert any("adminnetworkpolicy" in s for s in plain_steps)
    assert not plain_steps[0].endswith("get adminnetworkpolicy,baselineadminnetworkpolicy")
