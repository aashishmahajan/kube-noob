"""A rule that fires because another object is absent must not fire on part of a namespace.

`audit -f one-deployment.yaml` reported "No NetworkPolicy for namespace prod in this bundle" and "No
PodDisruptionBudget selects this workload" for a workload whose NetworkPolicy and PDB sat in the next file.
Audited together the same workload scored 100. So the tool told a correct repository it had two problems,
in the configuration it most needs to get right, and a per-file hook or IDE integration would have repeated
both on every commit forever.

The guard is an explicit flag, never `len(docs)`: the admission webhook audits a one-document bundle on
purpose and needs these rules to fire (tests/test_admission.py). And silence is not the fix either -- a
suppressed rule is reported in the report's assumptions, so a reader can tell "not evaluated" from "clean".
"""

from __future__ import annotations

import pytest

from kube_noob.audit.engine import analyze

_WORKLOAD = """
apiVersion: apps/v1
kind: Deployment
metadata: {name: payments, namespace: prod}
spec:
  replicas: 3
  selector: {matchLabels: {app: payments}}
  template:
    metadata: {labels: {app: payments}}
    spec:
      containers: [{name: api, image: acme/api@sha256:%s}]
""" % ("a" * 64)

_NETPOL = """
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: {name: default-deny, namespace: prod}
spec:
  podSelector: {}
  policyTypes: [Ingress]
"""

_PDB = """
apiVersion: policy/v1
kind: PodDisruptionBudget
metadata: {name: payments, namespace: prod}
spec:
  maxUnavailable: 1
  selector: {matchLabels: {app: payments}}
"""

_BUNDLE_RULES = ("KN-N001", "KN-C008")


def _rule_ids(manifests: str, *, partial: bool) -> set[str]:
    rep = analyze(manifests, "kubernetes", None, partial_bundle=partial)
    return {f.rule_id for f in rep.findings}


def test_partial_bundle_does_not_report_an_absent_object() -> None:
    """The phantom findings: the policy and the budget are real, they are just in another file."""
    found = _rule_ids(_WORKLOAD, partial=True)
    assert not (found & set(_BUNDLE_RULES)), f"reported {found & set(_BUNDLE_RULES)} from one file"


def test_a_complete_bundle_still_reports_a_real_gap() -> None:
    """The false negative this must not buy: a namespace genuinely without a policy is still a finding."""
    found = _rule_ids(_WORKLOAD, partial=False)
    assert set(_BUNDLE_RULES) <= found, f"a real gap went unreported; got {sorted(found)}"


def test_the_whole_bundle_is_clean() -> None:
    """With the policy and the budget present, neither rule fires in either mode."""
    whole = "\n---\n".join((_WORKLOAD, _NETPOL, _PDB))
    for partial in (True, False):
        assert not (_rule_ids(whole, partial=partial) & set(_BUNDLE_RULES))


def test_suppression_is_stated_not_silent() -> None:
    """A reader must be able to tell 'not evaluated' from 'nothing wrong'."""
    rep = analyze(_WORKLOAD, "kubernetes", None, partial_bundle=True)
    said = " ".join(rep.assumptions)
    assert "part of a namespace" in said, said
    assert "not evaluated" in said, said
    assert "directory" in said, "the note has to say how to get the rules evaluated"


def test_complete_is_the_default() -> None:
    """Every existing caller -- the admission webhook above all -- keeps the old behaviour untouched."""
    assert _rule_ids(_WORKLOAD, partial=False) == {f.rule_id for f in analyze(_WORKLOAD, "kubernetes", None).findings}


@pytest.mark.parametrize("rule_id", _BUNDLE_RULES)
def test_each_bundle_rule_is_covered_both_ways(rule_id: str) -> None:
    assert rule_id in _rule_ids(_WORKLOAD, partial=False)
    assert rule_id not in _rule_ids(_WORKLOAD, partial=True)
