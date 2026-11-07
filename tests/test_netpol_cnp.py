"""ClusterNetworkPolicy v1alpha2, evaluated (P4).

`kube_noob.debug.cnp` exists because four things changed between v1alpha1 and v1alpha2, and each of them would
make the older evaluator read a valid policy WRONG rather than refuse it: `Allow` became `Accept`, `ports`
became `protocols`, the Baseline tier stopped being a singleton and gained `priority`, and a peer whose shape
this reader does not know must fail closed rather than be skipped. Every test here is one of those, or the
consequence of getting one of them wrong.

The shapes are checked against kubernetes-sigs/network-policy-api at 2383f01,
`apis/v1alpha2/clusternetworkpolicy_types.go`.
"""

from __future__ import annotations

from typing import Any

import pytest

from kube_noob.debug.netpol import Inventory, check_reachability

WORKLOADS = """
apiVersion: v1
kind: Namespace
metadata: {name: web, labels: {team: web}}
---
apiVersion: v1
kind: Namespace
metadata: {name: shop, labels: {team: shop}}
---
apiVersion: apps/v1
kind: Deployment
metadata: {name: frontend, namespace: web}
spec:
  template:
    metadata: {labels: {app: frontend}}
    spec:
      containers:
        - name: app
          image: nginx:1.27
---
apiVersion: apps/v1
kind: Deployment
metadata: {name: payments, namespace: shop}
spec:
  template:
    metadata: {labels: {app: payments}}
    spec:
      containers:
        - name: app
          image: nginx:1.27
          ports:
            - {name: metrics, containerPort: 9090}
            - {name: api, containerPort: 8080}
"""


def _cnp(body: str) -> str:
    return "---\napiVersion: policy.networking.k8s.io/v1alpha2\nkind: ClusterNetworkPolicy\n" + body.strip("\n") + "\n"


def _reach(extra: str, port: str = "9090") -> dict[str, Any]:
    inv = Inventory.from_yaml(WORKLOADS + extra)
    return check_reachability(inv, "web/frontend", "shop/payments", port, "TCP")


ADMIN_DENY_ALL = _cnp("""
metadata: {name: lockdown}
spec:
  tier: Admin
  priority: 10
  subject:
    namespaces:
      matchLabels: {team: shop}
  ingress:
    - name: deny-everything
      action: Deny
      from:
        - namespaces: {}
""")


def test_an_admin_tier_deny_decides_before_any_networkpolicy() -> None:
    out = _reach(ADMIN_DENY_ALL)
    assert out["verdict"] == "denied"
    assert out["ingress"]["tier"] == "ClusterNetworkPolicy"
    assert out["ingress"]["policy"] == "ClusterNetworkPolicy/lockdown"


def test_accept_is_the_action_and_allow_is_not() -> None:
    """v1alpha2 renamed `Allow` to `Accept`. Reading an `Allow` here as the nearest valid action would turn a
    document the API server rejects into a verdict; the rule is skipped and the reason says why."""
    accept = ADMIN_DENY_ALL.replace("action: Deny", "action: Accept").replace("deny-everything", "let-it-in")
    out = _reach(accept)
    assert out["verdict"] == "allowed"
    assert "Accepted by ClusterNetworkPolicy/lockdown" in out["ingress"]["reason"]

    legacy = ADMIN_DENY_ALL.replace("action: Deny", "action: Allow")
    inv = Inventory.from_yaml(WORKLOADS + legacy)
    check_reachability(inv, "web/frontend", "shop/payments", "9090", "TCP")
    assert any("renamed Allow to Accept" in n for n in inv.notes), inv.notes


@pytest.mark.parametrize(
    ("protocols", "port", "denied"),
    [
        ("[{tcp: {destinationPort: {number: 9090}}}]", "9090", True),
        ("[{tcp: {destinationPort: {number: 9090}}}]", "8080", False),
        ("[{tcp: {destinationPort: {range: {start: 9000, end: 9100}}}}]", "9090", True),
        ("[{tcp: {destinationPort: {range: {start: 9000, end: 9100}}}}]", "8080", False),
        ("[{udp: {destinationPort: {number: 9090}}}]", "9090", False),
        ("[{tcp: {destinationPort: {number: 9090}}}, {udp: {}}]", "9090", True),
        ("[{destinationNamedPort: metrics}]", "9090", True),
        ("[{destinationNamedPort: metrics}]", "8080", False),
    ],
)
def test_protocols_scope_a_rule_to_its_ports(protocols: str, port: str, denied: bool) -> None:
    """The change that would have been silently wrong. The v1alpha1 matcher reads an absent `ports` key as
    "every port", so handing it a v1alpha2 rule scoped to one port widens the rule to all of them -- a verdict
    wrong in the dangerous direction. A rule naming TCP 9090 must not decide TCP 8080, and a UDP rule must not
    decide TCP at all.
    """
    body = ADMIN_DENY_ALL.replace(
        "        - namespaces: {}", f"        - namespaces: {{}}\n      protocols: {protocols}"
    )
    out = _reach(body, port=port)
    assert (out["verdict"] == "denied") is denied, out["ingress"]


def test_a_rule_with_no_protocols_is_every_port() -> None:
    assert _reach(ADMIN_DENY_ALL, port="8080")["verdict"] == "denied"
    assert _reach(ADMIN_DENY_ALL, port="9090")["verdict"] == "denied"


def test_the_baseline_tier_is_not_a_singleton_and_is_ordered_by_priority() -> None:
    """v1alpha1's baseline was one policy named `default`. v1alpha2's is a tier like any other, so two
    policies in it are ordered by priority, and the lower number decides."""
    allow = _cnp("""
metadata: {name: baseline-allow}
spec:
  tier: Baseline
  priority: 5
  subject:
    namespaces: {matchLabels: {team: shop}}
  ingress:
    - {name: ok, action: Accept, from: [{namespaces: {}}]}
""")
    deny = _cnp("""
metadata: {name: baseline-deny}
spec:
  tier: Baseline
  priority: 50
  subject:
    namespaces: {matchLabels: {team: shop}}
  ingress:
    - {name: no, action: Deny, from: [{namespaces: {}}]}
""")
    out = _reach(allow + deny)
    assert out["verdict"] == "allowed"
    assert out["ingress"]["policy"] == "ClusterNetworkPolicy/baseline-allow"
    # ... and reversing the priorities reverses the answer, which is what proves the order is read.
    swapped = allow.replace("priority: 5", "priority: 90")
    assert _reach(swapped + deny)["verdict"] == "denied"


def test_two_baseline_policies_at_one_priority_are_undetermined() -> None:
    """Unreachable in v1alpha1, where the baseline was a singleton. Here it is reachable, and the API does not
    say which policy wins -- so the answer is not settled by the order the documents arrived in."""
    a = _cnp("""
metadata: {name: b-allow}
spec:
  tier: Baseline
  priority: 20
  subject: {namespaces: {matchLabels: {team: shop}}}
  ingress: [{name: ok, action: Accept, from: [{namespaces: {}}]}]
""")
    b = _cnp("""
metadata: {name: b-deny}
spec:
  tier: Baseline
  priority: 20
  subject: {namespaces: {matchLabels: {team: shop}}}
  ingress: [{name: no, action: Deny, from: [{namespaces: {}}]}]
""")
    out = _reach(a + b)
    assert out["ingress"].get("undetermined") is True
    assert out["ingress"]["allowed"] is False, "an unknown must never read as a pass"
    assert set(out["ingress"]["tiedPolicies"]) == {"ClusterNetworkPolicy/b-allow", "ClusterNetworkPolicy/b-deny"}


def test_pass_in_the_admin_tier_hands_the_decision_down() -> None:
    body = ADMIN_DENY_ALL.replace("action: Deny", "action: Pass").replace("deny-everything", "hand-it-down")
    out = _reach(body)
    assert out["verdict"] == "allowed", "nothing below denies it"
    assert out["ingress"]["tier"] == "NetworkPolicy"
    assert out["ingress"]["passedBy"] == "ClusterNetworkPolicy/lockdown"


def test_an_unrecognised_peer_fails_closed_on_a_deny_rule() -> None:
    """The API states this outright: a peer with no field the reader knows means a CRD newer than the reader,
    and "for Deny and Pass rules, fail closed means treat the rule as a Deny all rule". Skipping it would let a
    later rule accept traffic a newer policy denies."""
    body = ADMIN_DENY_ALL.replace("        - namespaces: {}", "        - somethingNewer: {matchLabels: {a: b}}")
    out = _reach(body)
    assert out["verdict"] == "denied"
    assert "no field this version of kube-noob recognises" in out["ingress"]["reason"]
    assert "fail closed" in out["ingress"]["reason"]


def test_an_unrecognised_peer_on_an_accept_rule_matches_nothing() -> None:
    """The other half of the same sentence: for Accept rules, fail closed means the rule matches no traffic.
    Treating it as a match would ACCEPT traffic on the strength of a field this code cannot read."""
    body = ADMIN_DENY_ALL.replace("action: Deny", "action: Accept").replace(
        "        - namespaces: {}", "        - somethingNewer: {matchLabels: {a: b}}"
    )
    out = _reach(body)
    assert out["verdict"] == "allowed", "nothing else decides, so the default applies"
    assert out["ingress"]["tier"] == "NetworkPolicy", "the Accept rule did not decide it"


@pytest.mark.parametrize(
    ("broken", "why"),
    [
        ("tier: Nonsense", "is not one of Admin, Baseline"),
        ("priority: 5000", "outside 0-1000"),
        ("priority: -1", "outside 0-1000"),
    ],
)
def test_a_document_the_api_server_would_refuse_is_reported_not_evaluated(broken: str, why: str) -> None:
    """Leaving it out is only safe because it is said out loud: silence here is the same defect as dropping
    the kind entirely."""
    key = broken.split(":", maxsplit=1)[0]
    body = ADMIN_DENY_ALL.replace(f"  {key}: Admin" if key == "tier" else "  priority: 10", f"  {broken}")
    inv = Inventory.from_yaml(WORKLOADS + body)
    out = check_reachability(inv, "web/frontend", "shop/payments", "9090", "TCP")
    # Not "allowed". The refused policy decided nothing, and nothing is not permission: it was read, it could
    # not be evaluated, and the answer over it is unknown. The first version asserted `allowed` here, which
    # enshrined exactly the fail-open that making this kind readable introduced.
    assert out["verdict"] == "undetermined", out.get("summary")
    assert any(why in n for n in inv.notes), inv.notes


def test_more_rules_than_the_api_allows_is_reported_not_truncated() -> None:
    """v1alpha2 caps every list at 25. Evaluating the first 25 of 30 rules answers a question about a policy
    that cannot exist."""
    rules = "\n".join(f"    - {{name: r{i}, action: Deny, from: [{{namespaces: {{}}}}]}}" for i in range(30))
    body = _cnp(
        "metadata: {name: toomany}\nspec:\n  tier: Admin\n  priority: 10\n"
        "  subject: {namespaces: {matchLabels: {team: shop}}}\n  ingress:\n" + rules
    )
    inv = Inventory.from_yaml(WORKLOADS + body)
    out = check_reachability(inv, "web/frontend", "shop/payments", "9090", "TCP")
    assert out["verdict"] == "undetermined", out.get("summary")
    assert any("above the API's limit of 25" in n for n in inv.notes), inv.notes


def test_a_v1alpha1_document_wearing_the_v1alpha2_kind_is_refused() -> None:
    body = ADMIN_DENY_ALL.replace("/v1alpha2", "/v1alpha1")
    inv = Inventory.from_yaml(WORKLOADS + body)
    out = check_reachability(inv, "web/frontend", "shop/payments", "9090", "TCP")
    assert out["verdict"] == "undetermined", out.get("summary")
    assert any("is not policy.networking.k8s.io/v1alpha2" in n for n in inv.notes), inv.notes


def test_a_cluster_running_both_apis_says_which_one_decided() -> None:
    """A migration state. Which API the CNI honours is not something a manifest says, so the note states the
    ambiguity and the verdict names the policy it came from."""
    v1alpha1 = """
---
apiVersion: policy.networking.k8s.io/v1alpha1
kind: AdminNetworkPolicy
metadata: {name: old-guardrail}
spec:
  priority: 20
  subject: {namespaces: {matchLabels: {team: shop}}}
  ingress: [{name: legacy, action: Deny, from: [{namespaces: {}}]}]
"""
    inv = Inventory.from_yaml(WORKLOADS + ADMIN_DENY_ALL + v1alpha1)
    out = check_reachability(inv, "web/frontend", "shop/payments", "9090", "TCP")
    assert any("both AdminNetworkPolicy" in n and "ClusterNetworkPolicy" in n for n in inv.notes), inv.notes
    assert out["ingress"]["policy"].startswith("ClusterNetworkPolicy/"), "the current API is read first"


def test_egress_peers_gain_networks_and_a_catch_all_one_denies() -> None:
    """Egress peers gain `nodes`, `networks` and `domainNames`. `0.0.0.0/0` selects everything, so this one is
    decided rather than uncheckable -- the uncheckable case is the test below it."""
    body = _cnp("""
metadata: {name: egress-lock}
spec:
  tier: Admin
  priority: 10
  subject: {namespaces: {matchLabels: {team: web}}}
  egress:
    - name: no-egress
      action: Deny
      to:
        - networks: ["0.0.0.0/0"]
""")
    out = _reach(body)
    assert out["verdict"] == "denied"
    assert out["egress"]["tier"] == "ClusterNetworkPolicy"


def test_a_calico_too_old_for_the_kind_reports_the_policy_inert() -> None:
    """Calico added ClusterNetworkPolicy in 3.32. On 3.31 the CRD is not applied, so a policy written against
    it is in the cluster deciding nothing -- which is the same defect as an unenforced AdminNetworkPolicy, in
    the other direction."""
    inv = Inventory.from_yaml(WORKLOADS + ADMIN_DENY_ALL, cni="calico:3.31")
    out = check_reachability(inv, "web/frontend", "shop/payments", "9090", "TCP")
    assert out["verdict"] == "allowed", "an inert policy must not produce a deny that is not happening"
    assert [i["policy"] for i in inv.inert] == ["ClusterNetworkPolicy/lockdown"]
    assert "added ClusterNetworkPolicy in 3.32" in inv.inert[0]["reason"]


def test_calico_from_the_version_that_has_it_enforces_it() -> None:
    inv = Inventory.from_yaml(WORKLOADS + ADMIN_DENY_ALL, cni="calico:3.32")
    out = check_reachability(inv, "web/frontend", "shop/payments", "9090", "TCP")
    assert out["verdict"] == "denied"
    assert inv.inert == []


def test_a_cni_upstream_says_nothing_about_is_not_assumed_either_way() -> None:
    inv = Inventory.from_yaml(WORKLOADS + ADMIN_DENY_ALL, cni="cilium:1.20")
    check_reachability(inv, "web/frontend", "shop/payments", "9090", "TCP")
    assert inv.enforcement_unknown == ["ClusterNetworkPolicy/lockdown"]
    assert any("not something upstream states" in n for n in inv.notes), inv.notes


def test_not_enforcing_the_old_api_is_not_the_same_claim_as_enforcing_the_new_one() -> None:
    """The inverse-derivation trap. Calico 3.32 does not enforce AdminNetworkPolicy AND does enforce
    ClusterNetworkPolicy -- but those are two sourced facts, not one. A CNI that enforces neither must not be
    read as enforcing the second because it fails the first."""
    from kube_noob.debug.cni import admin_tier_support, cnp_support

    assert admin_tier_support("calico", "3.32") == "not-enforced"
    assert cnp_support("calico", "3.32") == "enforced"
    assert admin_tier_support("cilium", "1.20") == "unknown"
    assert cnp_support("cilium", "1.20") == "unknown", "unknown stays unknown rather than inheriting an answer"
    assert cnp_support("ovn-kubernetes") == "unknown", "enforcing ANP says nothing about enforcing CNP"
    assert cnp_support("calico") == "unknown", "the version is what decides, so without it there is no answer"
    assert cnp_support("calico", "3") == "unknown", "too coarse to sit on either side of 3.32"


def test_making_one_kind_readable_did_not_retire_the_guard_for_the_others() -> None:
    """The regression P4 could most easily have caused. The undetermined-verdict protection belongs to the
    CLASS of unread cluster-scoped policy, not to ClusterNetworkPolicy -- so a Cilium clusterwide policy still
    makes the answer unknown now that the kind it was written against is read."""
    from kube_noob.debug.netpol import UNEVALUATED_POLICY_KINDS

    assert "ClusterNetworkPolicy" not in UNEVALUATED_POLICY_KINDS, "it is evaluated now"
    assert {"CiliumClusterwideNetworkPolicy", "GlobalNetworkPolicy"} <= UNEVALUATED_POLICY_KINDS

    cilium = """
---
apiVersion: cilium.io/v2
kind: CiliumClusterwideNetworkPolicy
metadata: {name: unread}
spec: {endpointSelector: {}}
"""
    out = _reach(cilium)
    assert out["verdict"] == "undetermined"
    assert out["undeterminedBy"] == ["CiliumClusterwideNetworkPolicy/unread"]


def test_a_refused_clusternetworkpolicy_is_still_listed_rather_than_lost() -> None:
    """Evaluated does not mean "always evaluated": a document the API server would refuse is dropped from the
    tier, and it has to stay visible somewhere or the reader sees a clean answer over a policy nobody read."""
    inv = Inventory.from_yaml(WORKLOADS + ADMIN_DENY_ALL.replace("tier: Admin", "tier: Nonsense"))
    assert any(ref.startswith("ClusterNetworkPolicy/") for ref in inv.other_policies), inv.other_policies


# --- Everything below is a defect a red-team pass found in the first version of this module. Each one was a
# --- wrong ALLOW or a false sentence, and each is the project's own recurring shape: an unknown read as a fact.


def test_a_policy_whose_enforcement_is_unknown_is_withheld_rather_than_believed() -> None:
    """The worst of them. `without_admin_tier` built the second reading by clearing the v1alpha1 tiers only,
    so every v1alpha2 policy survived into both readings, the two always agreed, the withholding never fired,
    and a ClusterNetworkPolicy on a CNI nobody says enforces it decided the answer -- while the page said both
    readings agreed."""
    accept = ADMIN_DENY_ALL.replace("action: Deny", "action: Accept").replace("deny-everything", "let-in")
    deny_all_np = """
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: {name: deny-all, namespace: shop}
spec: {podSelector: {}, policyTypes: [Ingress]}
"""
    inv = Inventory.from_yaml(WORKLOADS + accept + deny_all_np, cni="cilium:1.20")
    out = check_reachability(inv, "web/frontend", "shop/payments", "9090", "TCP")
    assert out["verdict"] == "undetermined", out.get("summary")
    assert out["undeterminedBy"] == ["ClusterNetworkPolicy/lockdown"]

    # And where the two readings genuinely agree, it is still answered rather than withheld.
    agreeing = Inventory.from_yaml(WORKLOADS + ADMIN_DENY_ALL + deny_all_np, cni="cilium:1.20")
    assert check_reachability(agreeing, "web/frontend", "shop/payments", "9090", "TCP")["verdict"] == "denied"


@pytest.mark.parametrize(
    "broken",
    [
        "apiVersion: policy.networking.k8s.io/v1alpha3",
        "  subject: {somethingNewer: {}}",
        "  subject: {}",
        "  tier: Nonsense",
        "  priority: 5000",
    ],
)
def test_a_policy_that_cannot_be_evaluated_makes_the_answer_undetermined(broken: str) -> None:
    """Before P4, ANY ClusterNetworkPolicy made the verdict undetermined, because none was evaluated. Making
    most of them readable must not turn the few that still are not into a clean allow -- which is exactly what
    the first version did: a note, and `allowed` with exit 0."""
    body = ADMIN_DENY_ALL
    if broken.startswith("apiVersion"):
        body = body.replace("apiVersion: policy.networking.k8s.io/v1alpha2", broken)
    elif broken.strip().startswith("subject"):
        body = body.replace("  subject:\n    namespaces:\n      matchLabels: {team: shop}", broken)
    else:
        key = broken.split(":", maxsplit=1)[0].strip()
        body = body.replace(f"  {key}: Admin" if key == "tier" else "  priority: 10", broken)
    inv = Inventory.from_yaml(WORKLOADS + body)
    out = check_reachability(inv, "web/frontend", "shop/payments", "9090", "TCP")
    assert out["verdict"] == "undetermined", f"{broken} produced {out['verdict']}: {out.get('summary')}"
    assert any("ClusterNetworkPolicy/lockdown" in ref for ref in out["undeterminedBy"])


def test_a_named_port_is_matched_on_its_own_protocol() -> None:
    """`destinationNamedPort` resolved by number alone, so a rule naming a UDP port accepted TCP on the same
    number -- traffic the rule does not name, accepted past a NetworkPolicy that denies it."""
    workloads = WORKLOADS.replace(
        "            - {name: api, containerPort: 8080}",
        "            - {name: api, containerPort: 8080}\n            - {name: dns, containerPort: 53, protocol: UDP}",
    )
    body = ADMIN_DENY_ALL.replace("action: Deny", "action: Accept").replace(
        "        - namespaces: {}", "        - namespaces: {}\n      protocols: [{destinationNamedPort: dns}]"
    )
    deny_all = """
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: {name: deny-all, namespace: shop}
spec: {podSelector: {}, policyTypes: [Ingress]}
"""
    inv = Inventory.from_yaml(workloads + body + deny_all)
    tcp = check_reachability(inv, "web/frontend", "shop/payments", "53", "TCP")
    assert tcp["verdict"] == "denied", "the named port is UDP 53; TCP 53 is not it"
    udp = check_reachability(
        Inventory.from_yaml(workloads + body + deny_all), "web/frontend", "shop/payments", "53", "UDP"
    )
    assert udp["verdict"] == "allowed"


def test_a_baseline_deny_is_fixable_with_a_networkpolicy_and_an_admin_deny_is_not() -> None:
    """The spec says it in as many words: "Baseline tier is a cluster-wide policy that can be overridden by
    the v1.NetworkPolicy". Both CNP tiers report the same `tier`, so the fix branch sent a Baseline deny down
    the cluster-administrator path and told the reader no NetworkPolicy could help -- when one is exactly what
    helps."""
    baseline = ADMIN_DENY_ALL.replace("tier: Admin", "tier: Baseline").replace("lockdown", "base")
    out = _reach(baseline)
    assert out["verdict"] == "denied"
    changes = out["proposedChanges"]
    assert any(c.get("manifest") for c in changes), f"a NetworkPolicy does override a Baseline deny: {changes}"
    assert not any(c.get("ownedBy") == "cluster administrator" for c in changes)

    admin = _reach(ADMIN_DENY_ALL)["proposedChanges"]
    assert all(c.get("ownedBy") == "cluster administrator" for c in admin)
    assert not any(c.get("manifest") for c in admin)


@pytest.mark.parametrize(
    "rule",
    [
        "      protocols: []",
        "      protocols: [{tcp: {}}]",
        "      protocols: [{somethingNewer: {}}]",
        "      protocols: notalist",
    ],
)
def test_a_protocols_shape_the_api_refuses_is_not_read_as_every_port(rule: str) -> None:
    """Each of these is refused by the CRD (`minItems: 1`, `minProperties: 1`) or is a newer field. Read as
    "every port" they widen an Accept rule past anything it says; read as "no port" they drop a Deny in
    silence. Unreadable is the third answer, and the rule's action decides which way it falls."""
    accept = (
        ADMIN_DENY_ALL.replace("action: Deny", "action: Accept")
        .replace("deny-everything", "let-in")
        .replace("        - namespaces: {}", f"        - namespaces: {{}}\n{rule}")
    )
    deny_all = """
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: {name: deny-all, namespace: shop}
spec: {podSelector: {}, policyTypes: [Ingress]}
"""
    inv = Inventory.from_yaml(WORKLOADS + accept + deny_all)
    assert check_reachability(inv, "web/frontend", "shop/payments", "9090", "TCP")["verdict"] == "denied", (
        "an Accept rule nobody can read accepts nothing"
    )
    assert any("cannot read" in n or "not evaluated" in n for n in inv.notes), inv.notes

    deny = ADMIN_DENY_ALL.replace("        - namespaces: {}", f"        - namespaces: {{}}\n{rule}")
    out = _reach(deny)
    assert out["verdict"] == "denied", "and an unreadable Deny rule is a deny-all"


@pytest.mark.parametrize("peers", ["      from: []", "      from: notalist"])
def test_a_rule_with_no_peers_is_not_read_as_matching_nothing(peers: str) -> None:
    """`from` is required with MinItems=1. Reading an empty one as "this rule matches nothing" dropped a Deny
    without a word."""
    body = ADMIN_DENY_ALL.replace("      from:\n        - namespaces: {}", peers)
    out = _reach(body)
    assert out["verdict"] == "denied"


def test_an_uncheckable_peer_is_not_described_as_an_unrecognised_field() -> None:
    """Two different reasons a peer cannot be decided, and the first version printed the sentence for one of
    them over the other: a CIDR kube-noob cannot compare is recognised perfectly well."""
    body = _cnp("""
metadata: {name: egress-cidr}
spec:
  tier: Admin
  priority: 10
  subject: {namespaces: {matchLabels: {team: web}}}
  egress:
    - {name: no-egress, action: Deny, to: [{networks: ['10.0.0.0/8']}]}
""")
    out = _reach(body)
    assert out["verdict"] == "denied"
    reason = out["egress"]["reason"]
    assert "cannot be checked from the manifests" in reason, reason
    assert "does not recognise" not in reason and "newer CRD" not in reason


@pytest.mark.parametrize(
    "selector",
    [
        "{matchExpressions: [{key: team, operator: Exist}]}",
        "{matchLabels: notamap}",
        "{matchExpressions: [null]}",
    ],
)
def test_a_selector_the_api_refuses_does_not_crash_and_does_not_vanish(selector: str) -> None:
    """These aborted `policy reach` with an AttributeError, or skipped the policy silently. An unreadable
    selector is an unreadable rule: the command keeps working and the answer stops being clean."""
    subject = ADMIN_DENY_ALL.replace("    namespaces:\n      matchLabels: {team: shop}", f"    namespaces: {selector}")
    inv = Inventory.from_yaml(WORKLOADS + subject)
    out = check_reachability(inv, "web/frontend", "shop/payments", "9090", "TCP")
    assert out["verdict"] == "undetermined", out.get("summary")

    peer = ADMIN_DENY_ALL.replace("        - namespaces: {}", f"        - namespaces: {selector}")
    out = check_reachability(Inventory.from_yaml(WORKLOADS + peer), "web/frontend", "shop/payments", "9090", "TCP")
    assert out["verdict"] == "denied", "a Deny rule whose peer cannot be read is a deny-all"
