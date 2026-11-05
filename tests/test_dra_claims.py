"""Dynamic Resource Allocation: the two claim defects a manifest alone proves (G192).

DRA went GA in Kubernetes 1.34 and the only feedback a user gets for a bad claim wiring is a scheduler event,
so these two run offline, before apply. Both mirror checks in upstream's own
``pkg/apis/core/validation/validation.go`` -- ``validateResourceClaimNames`` ("must be one of the names in
pod.spec.resourceClaims") and ``validatePodResourceClaim`` ("must specify one of: ``resourceClaimName``,
``resourceClaimTemplateName``") -- which the bundled OpenAPI schemas cannot express: one is a cross-field
reference, the other a mutual exclusion the schema states no ``oneOf`` for.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from kube_noob.audit.engine import analyze
from kube_noob.audit.model import Severity, Stage
from kube_noob.audit.rules import RULES

FIX = Path(__file__).resolve().parent / "fixtures" / "rules"
DRA_RULES = ("KN-V020", "KN-V021")


def _fixture(rule_id: str) -> dict[str, str]:
    data = yaml.safe_load((FIX / f"{rule_id}.yaml").read_text(encoding="utf-8"))
    assert isinstance(data, dict)
    return data


def _findings(text: str, rule_id: str) -> list:
    return [f for f in analyze(text, "kubernetes").findings if f.rule_id == rule_id]


@pytest.mark.parametrize("rule_id", DRA_RULES)
def test_fixture_bad_fires_and_good_is_silent(rule_id: str) -> None:
    data = _fixture(rule_id)
    assert _findings(data["bad"], rule_id), f"{rule_id} did not fire on its bad fixture"
    assert _findings(data["good"], rule_id) == [], f"{rule_id} fired on its good fixture"


@pytest.mark.parametrize("rule_id", DRA_RULES)
def test_rule_is_a_validate_stage_rule_that_states_the_field(rule_id: str) -> None:
    r = RULES[rule_id]
    assert r.stage is Stage.VALIDATE and r.severity >= Severity.HIGH
    # The message has to name the offending value, or the reader cannot find it in a 400-line template.
    for f in _findings(_fixture(rule_id)["bad"], rule_id):
        assert f.locator and f.path, f
        assert f.line is not None, "a defect the file proves must carry its line"


def test_undeclared_claim_names_the_typo_and_the_declared_names() -> None:
    found = _findings(_fixture("KN-V020")["bad"], "KN-V020")
    assert len(found) == 1
    msg = found[0].message
    assert "'gpus'" in msg and "gpu" in msg, msg
    assert found[0].path.endswith("resources.claims[0].name"), found[0].path


def test_undeclared_claim_fires_when_the_pod_declares_no_claims_at_all() -> None:
    text = """
apiVersion: v1
kind: Pod
metadata: {name: p, namespace: ml}
spec:
  containers:
  - name: c
    image: registry.example.com/c@sha256:1a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f809
    resources:
      claims:
      - name: gpu
"""
    found = _findings(text, "KN-V020")
    assert len(found) == 1 and "declares none" in found[0].message, found


def test_undeclared_claim_checks_init_containers_but_not_ephemeral_ones() -> None:
    base = """
apiVersion: v1
kind: Pod
metadata: {name: p, namespace: ml}
spec:
  resourceClaims:
  - name: gpu
    resourceClaimTemplateName: t
  __KEY__:
  - name: c
    image: registry.example.com/c@sha256:1a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f809
    resources:
      claims:
      - name: nope
  containers:
  - name: main
    image: registry.example.com/c@sha256:1a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f809
"""
    assert len(_findings(base.replace("__KEY__", "initContainers"), "KN-V020")) == 1
    # The API refuses `resources` on an ephemeral container, so there is nothing there to fix.
    assert _findings(base.replace("__KEY__", "ephemeralContainers"), "KN-V020") == []


def test_claim_source_reports_both_set_and_neither_set_separately() -> None:
    found = _findings(_fixture("KN-V021")["bad"], "KN-V021")
    assert len(found) == 2, found
    both = next(f for f in found if "both" in f.message)
    neither = next(f for f in found if "neither" in f.message)
    assert "'gpu'" in both.message and "'fpga'" in neither.message
    assert both.path.endswith("resourceClaims[0]") and neither.path.endswith("resourceClaims[1]")


def test_claim_rules_survive_a_non_mapping_spec() -> None:
    for text in (
        "apiVersion: v1\nkind: Pod\nmetadata: {name: p}\nspec:\n  resourceClaims: notalist\n  containers: []\n",
        "apiVersion: v1\nkind: Pod\nmetadata: {name: p}\nspec:\n  resourceClaims: [one, two]\n  containers: []\n",
        "apiVersion: v1\nkind: Pod\nmetadata: {name: p}\nspec:\n"
        "  containers:\n  - name: c\n    image: i\n    resources: {claims: notalist}\n",
        "apiVersion: v1\nkind: Pod\nmetadata: {name: p}\nspec:\n"
        "  containers:\n  - name: c\n    image: i\n    resources: {claims: [7]}\n",
    ):
        for rule_id in DRA_RULES:
            assert _findings(text, rule_id) == [], (rule_id, text)


def test_partial_bundle_does_not_silence_them() -> None:
    """Both defects live inside the one document, so a partial bundle changes nothing (G186)."""
    for rule_id in DRA_RULES:
        bad = _fixture(rule_id)["bad"]
        whole = [f.rule_id for f in analyze(bad, "kubernetes").findings if f.rule_id == rule_id]
        part = [f.rule_id for f in analyze(bad, "kubernetes", partial_bundle=True).findings if f.rule_id == rule_id]
        assert whole == part and whole, rule_id
