"""A ClusterNetworkPolicy in the input must never be dropped without a word.

`policy.networking.k8s.io/v1alpha1` AdminNetworkPolicy and BaselineAdminNetworkPolicy are listed by
kubernetes-sigs/network-policy-api as "Previous (APIs that have evolved to the next stage and are no longer actively
developed)". The API under active development is `ClusterNetworkPolicy` v1alpha2, one cluster-scoped CRD carrying
both tiers in `spec.tier`. Calico 3.32, Cilium 1.20, Kube-OVN and kube-network-policies enforce it.

kube-noob did not know the kind at all, so a cluster-scoped Admin-tier Deny written in the current API was dropped
in silence: the verdict was attributed to the NetworkPolicy tier, and the proposed fix was a NetworkPolicy that the
Admin tier would override -- applied, changing nothing. A tool whose pitch is that it says what it could not
determine cannot do that. Until the evaluator reads v1alpha2, the kind is named and every namespace-scoped fix
carries the caveat.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from kube_noob.debug.netpol import Inventory, check_reachability

ROOT = Path(__file__).resolve().parents[1]

_CNP = """
apiVersion: policy.networking.k8s.io/v1alpha2
kind: ClusterNetworkPolicy
metadata:
  name: no-cross-team-payments
spec:
  tier: Admin
  priority: 10
  subject:
    pods:
      namespaceSelector:
        matchLabels:
          team: shop
      podSelector:
        matchLabels:
          app: payments
  ingress:
    - name: "only-shop-reaches-payments"
      action: "Deny"
      from:
        - namespaces:
            matchExpressions:
              - key: team
                operator: NotIn
                values: ["shop"]
"""


def _without_admin_tier() -> str:
    """The shipped example, with its v1alpha1 admin tier removed: NetworkPolicies and workloads only."""
    text = (ROOT / "examples" / "netpol-admin-tiers.yaml").read_text(encoding="utf-8")
    return text.split("# A platform team's cluster-wide guardrail")[0]


def _reach(yaml_text: str) -> dict[str, Any]:
    inv = Inventory.from_yaml(yaml_text)
    return check_reachability(inv, "web/frontend", "shop/payments", "9090", "TCP")


def test_a_clusternetworkpolicy_is_named_not_dropped() -> None:
    out = _reach(_without_admin_tier() + _CNP)
    listed = " ".join(out.get("notEvaluated", []))
    assert "ClusterNetworkPolicy" in listed, (
        "a cluster-scoped policy of the current API was in the input and the answer never mentioned it; "
        f"notEvaluated was {out.get('notEvaluated')}"
    )


def test_a_namespace_scoped_fix_is_caveated_when_a_cluster_scoped_policy_was_not_evaluated() -> None:
    """The fix kube-noob proposes here is a NetworkPolicy. If an Admin-tier ClusterNetworkPolicy denies the same
    traffic, that NetworkPolicy is applied and changes nothing. The caveat is what keeps the next verdict credible.
    """
    out = _reach(_without_admin_tier() + _CNP)
    proposed = out.get("proposedChanges") or []
    with_manifest = [c for c in proposed if c.get("manifest")]
    assert with_manifest, "expected a proposed NetworkPolicy to caveat"
    for change in with_manifest:
        assert change.get("caveat"), f"a namespace-scoped fix went out with no caveat: {change['change']!r}"
        assert "ClusterNetworkPolicy" in change["caveat"]


def test_no_caveat_when_nothing_cluster_scoped_is_in_the_input() -> None:
    """The caveat has to be noise-free or it stops being read."""
    out = _reach(_without_admin_tier())
    for change in out.get("proposedChanges") or []:
        assert not change.get("caveat"), f"caveat added with no cluster-scoped policy present: {change}"
    assert "ClusterNetworkPolicy" not in " ".join(out.get("notEvaluated", []))


def test_the_evaluated_v1alpha1_tier_is_not_listed_as_unevaluated() -> None:
    """AdminNetworkPolicy IS evaluated, so it must not appear in the not-evaluated list alongside the new kind."""
    text = (ROOT / "examples" / "netpol-admin-tiers.yaml").read_text(encoding="utf-8")
    out = _reach(text)
    listed = " ".join(out.get("notEvaluated", []))
    assert "AdminNetworkPolicy" not in listed
    assert out["ingress"]["tier"] == "AdminNetworkPolicy"


def test_the_caveat_is_printed_where_the_fix_is_read(tmp_path: Path, capsys: Any) -> None:
    """A caveat only in the JSON is a caveat nobody sees: `policy reach` prints text by default."""
    from kube_noob.cli import main

    manifest = tmp_path / "cnp.yaml"
    manifest.write_text(_without_admin_tier() + _CNP, encoding="utf-8")
    code = main(
        [
            "policy",
            "reach",
            "--from",
            "web/frontend",
            "--to",
            "shop/payments",
            "--port",
            "9090",
            "-f",
            str(manifest),
            "--format",
            "text",
        ]
    )
    text = capsys.readouterr().out
    assert code == 1, f"a denied reachability check must exit 1; got {code}"
    assert "caveat:" in text, f"the caveat never reached the text output:\n{text}"
    assert "ClusterNetworkPolicy" in text.split("caveat:", 1)[1]


def test_the_live_cluster_check_reads_clusternetworkpolicies_too() -> None:
    """The guard above covered pasted manifests only. `inventory_from_cluster` read the two v1alpha1 tiers and not
    `clusternetworkpolicies`, so on a cluster running the current API the live answer -- the one an operator
    trusts more, because it came from their cluster -- went back to being confidently wrong with no caveat and no
    mention under "not evaluated". The evaluator still does not understand v1alpha2; reading the kind is what puts
    it in `other_policies`, which is what makes the answer honest.
    """
    from kube_noob.debug.cluster import ALLOWED_RESOURCES as RESOURCES
    from kube_noob.debug.netpol import inventory_from_cluster

    assert "clusternetworkpolicies" in RESOURCES, "the read-only allowlist has no entry for the current API"
    assert RESOURCES["clusternetworkpolicies"].namespaced is False
    assert RESOURCES["clusternetworkpolicies"].group_version.endswith("v1alpha2")

    reads: list[str] = []

    class Backend:
        name = "fake"

        def get(self, plural: str, name: str | None = None, namespace: str | None = None) -> dict[str, Any]:
            reads.append(plural)
            if plural == "clusternetworkpolicies":
                import yaml

                return {"items": [yaml.safe_load(_CNP)]}
            if plural in {"adminnetworkpolicies", "baselineadminnetworkpolicies", "networkpolicies"}:
                return {"items": []}
            if plural == "namespaces":
                return {"kind": "Namespace", "metadata": {"name": name, "labels": {"team": name}}}
            raise __import__("kube_noob.errors", fromlist=["x"]).ClusterAccessError("not there")

    inv = inventory_from_cluster(Backend(), "web/frontend", "shop/payments")
    assert reads.count("clusternetworkpolicies") == 1, "read once, cluster-scoped, not per namespace"
    assert any(ref.startswith("ClusterNetworkPolicy/") for ref in inv.other_policies), (
        f"the kind was read but never recorded as unevaluated: {inv.other_policies}"
    )


def test_a_cluster_without_the_current_api_is_not_an_error() -> None:
    """Most clusters do not have the v1alpha2 CRD. A 404 is normal and must leave a working answer with a note."""
    from kube_noob.debug.netpol import inventory_from_cluster
    from kube_noob.errors import ClusterAccessError

    class Backend:
        name = "fake"

        def get(self, plural: str, name: str | None = None, namespace: str | None = None) -> dict[str, Any]:
            if plural == "clusternetworkpolicies":
                raise ClusterAccessError("the server could not find the requested resource")
            if plural in {"adminnetworkpolicies", "baselineadminnetworkpolicies", "networkpolicies"}:
                return {"items": []}
            if plural == "namespaces":
                return {"kind": "Namespace", "metadata": {"name": name, "labels": {}}}
            raise ClusterAccessError("not there")

    inv = inventory_from_cluster(Backend(), "web/frontend", "shop/payments")
    assert any("ClusterNetworkPolicy" in n for n in inv.notes), f"no note explaining the gap: {inv.notes}"
    assert inv.other_policies == []


def test_the_caveat_names_the_cluster_s_own_command() -> None:
    """On OpenShift the whole answer is written in `oc`; a lone `kubectl` in the caveat is a command the reader
    may not have."""
    inv = Inventory.from_yaml(_without_admin_tier() + _CNP)
    out = check_reachability(inv, "web/frontend", "shop/payments", "9090", "TCP", cli="oc")
    caveats = [c["caveat"] for c in out.get("proposedChanges", []) if c.get("caveat")]
    assert caveats, "expected a caveated fix"
    for c in caveats:
        assert "oc get clusternetworkpolicy" in c, c
        assert "kubectl" not in c, c
