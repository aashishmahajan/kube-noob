"""An invalid NetworkPolicy must not read as a policy that selects nothing.

A label selector the API server would refuse is not a selector that matches no pods, but the matcher treated it
that way: an unknown ``matchExpressions`` operator made ``selector_matches`` return False for every pod, so a
default-deny policy looked like it selected nothing, the namespace looked unprotected, and the verdict flipped
from denied to allowed. One character -- ``Exist`` for ``Exists`` -- turned a deny into an allow, and the
explanation stated positively that no NetworkPolicy selected the pod, which was false: one did, and it was
invalid.

Dropping a policy that cannot be read only ever widens the answer, which is the failure mode kube-noob exists to
avoid, so an unreadable policy is reported as undetermined instead of evaluated.
"""

from __future__ import annotations

from typing import Any

import yaml

from kube_noob.debug.netpol import Inventory, check_reachability, policy_problem, selector_problem

_SRC = """
apiVersion: apps/v1
kind: Deployment
metadata: {name: frontend, namespace: web}
spec:
  replicas: 1
  selector: {matchLabels: {app: frontend}}
  template:
    metadata: {labels: {app: frontend}}
    spec:
      containers: [{name: web, image: acme/web:1.0}]
---
apiVersion: apps/v1
kind: Deployment
metadata: {name: payments, namespace: shop}
spec:
  replicas: 1
  selector: {matchLabels: {app: payments}}
  template:
    metadata: {labels: {app: payments}}
    spec:
      containers: [{name: api, image: acme/api:1.0, ports: [{containerPort: 9090}]}]
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: {name: default-deny, namespace: shop}
spec:
  podSelector:
    matchExpressions:
      - {key: app, operator: %s}
  policyTypes: [Ingress]
"""


def _verdict(operator: str) -> dict[str, Any]:
    objects = [d for d in yaml.safe_load_all(_SRC % operator) if d]
    inv = Inventory(objects)
    return check_reachability(inv, "web/frontend", "shop/payments", 9090, "TCP")


def test_valid_selector_still_denies() -> None:
    """The correct spelling must keep working: the fix must not buy safety by refusing everything."""
    out = _verdict("Exists")
    assert out["verdict"] == "denied", out


def test_invalid_operator_is_undetermined_not_allowed() -> None:
    """The one-character typo must never read as allowed."""
    out = _verdict("Exist")
    assert out["verdict"] == "undetermined", out
    assert out["verdict"] != "allowed"


def test_invalid_policy_is_named_with_its_field() -> None:
    """Saying 'undetermined' is not enough; the reader has to be able to fix it."""
    out = _verdict("Exist")
    blob = yaml.safe_dump(out)
    assert "default-deny" in blob, blob
    assert "podSelector" in blob, blob
    assert "Exist" in blob, blob


def test_invalid_policy_is_not_counted_as_evaluated() -> None:
    """It must be reported as unread, not quietly dropped from the inventory."""
    objects = [d for d in yaml.safe_load_all(_SRC % "Exist") if d]
    inv = Inventory(objects)
    assert inv.invalid_policies, "an invalid policy was dropped without a word"
    assert not inv.policies, "an invalid policy must not be evaluated as if it were valid"


def test_selector_problem_accepts_what_the_api_server_accepts() -> None:
    assert selector_problem(None) is None
    assert selector_problem({}) is None
    assert selector_problem({"matchLabels": {"app": "web"}}) is None
    for op in ("Exists", "DoesNotExist"):
        assert selector_problem({"matchExpressions": [{"key": "a", "operator": op}]}) is None
    for op in ("In", "NotIn"):
        assert selector_problem({"matchExpressions": [{"key": "a", "operator": op, "values": ["x"]}]}) is None


def test_selector_problem_names_each_refusal() -> None:
    assert "not a mapping" in (selector_problem("app=web") or "")
    assert "not a mapping" in (selector_problem({"matchLabels": ["a"]}) or "")
    assert "not a list" in (selector_problem({"matchExpressions": {"key": "a"}}) or "")
    assert "operator" in (selector_problem({"matchExpressions": [{"key": "a", "operator": "Exist"}]}) or "")
    bad_in = {"matchExpressions": [{"key": "a", "operator": "In"}]}
    assert "values" in (selector_problem(bad_in) or ""), "In with no values is refused by the API server"


def test_policy_problem_reaches_peer_selectors() -> None:
    """A peer selector is as capable of widening the answer as the pod selector."""
    pol = {
        "kind": "NetworkPolicy",
        "metadata": {"name": "p", "namespace": "shop"},
        "spec": {
            "podSelector": {},
            "policyTypes": ["Ingress"],
            "ingress": [{"from": [{"namespaceSelector": {"matchExpressions": [{"key": "k", "operator": "Exist"}]}}]}],
        },
    }
    why = policy_problem(pol)
    assert why and "ingress[0].from[0].namespaceSelector" in why, why
    pol["spec"]["ingress"] = [{"from": [{"podSelector": {"matchLabels": {"app": "web"}}}]}]
    assert policy_problem(pol) is None
