"""Pod Security admission is a namespace label, and its absence means different things per platform (G198).

Upstream `pod-security-admission/api/constants.go` gives the label names and the three levels. OpenShift's
label syncer sets `warn` and `audit` from the SCCs a namespace's service accounts can use and deliberately not
`enforce` -- the platform enforces privileged globally and leaves real enforcement to SCCs -- so an absent
`enforce` label there is the platform's design, not a gap.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from kube_noob.audit.engine import analyze
from kube_noob.audit.model import Severity
from kube_noob.audit.rules import PSA_ENFORCE_LABEL, PSA_LEVELS

ROOT = Path(__file__).resolve().parents[1]
FIX = ROOT / "tests" / "fixtures" / "rules"


def _findings(text: str, platform: str = "kubernetes", version: str | None = None) -> list:
    return [f for f in analyze(text, platform, version).findings if f.rule_id == "KN-S032"]


def _ns(name: str = "shop", labels: dict[str, str] | None = None) -> str:
    doc: dict = {"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": name}}
    if labels is not None:
        doc["metadata"]["labels"] = labels
    return yaml.safe_dump(doc)


def test_the_label_names_and_levels_are_upstreams() -> None:
    assert PSA_ENFORCE_LABEL == "pod-security.kubernetes.io/enforce"
    assert PSA_LEVELS == ("privileged", "baseline", "restricted")


def test_the_fixture_fires_and_clears() -> None:
    data = yaml.safe_load((FIX / "KN-S032.yaml").read_text(encoding="utf-8"))
    assert _findings(data["bad"])
    assert _findings(data["good"]) == []


def test_privileged_is_reported_as_the_no_restrictions_level() -> None:
    found = _findings(_ns(labels={PSA_ENFORCE_LABEL: "privileged"}))
    assert len(found) == 1 and found[0].severity is Severity.HIGH
    assert found[0].path.endswith(f"metadata.labels.{PSA_ENFORCE_LABEL}"), found[0].path
    assert "no-restrictions" in found[0].message


def test_privileged_is_reported_on_openshift_too() -> None:
    """The syncer not setting `enforce` is one thing; an explicit opt-out is a decision on any platform."""
    assert len(_findings(_ns(labels={PSA_ENFORCE_LABEL: "privileged"}), "openshift", "4.22")) == 1


@pytest.mark.parametrize("level", ["baseline", "restricted"])
def test_baseline_and_restricted_are_judgements_not_defects(level: str) -> None:
    assert _findings(_ns(labels={PSA_ENFORCE_LABEL: level})) == []


def test_no_label_is_reported_on_kubernetes_and_names_the_cluster_default() -> None:
    found = _findings(_ns())
    assert len(found) == 1 and found[0].severity is Severity.MEDIUM
    # The manifest cannot see the cluster's AdmissionConfiguration, so the message must not claim it enforces
    # nothing -- only that the answer is not in the repository.
    assert "AdmissionConfiguration default" in found[0].message
    assert "these manifests show" in found[0].message


def test_no_label_is_silent_on_openshift_because_the_syncer_sets_warn_and_audit_only() -> None:
    assert _findings(_ns(), "openshift", "4.22") == []
    assert _findings(_ns(), "rosa-hcp") == []


def test_an_empty_labels_map_is_the_same_as_no_labels() -> None:
    assert len(_findings(_ns(labels={}))) == 1


@pytest.mark.parametrize("name", ["kube-system", "kube-public", "kube-node-lease", "openshift", "default"])
def test_the_namespaces_the_platform_owns_are_skipped(name: str) -> None:
    assert _findings(_ns(name)) == []


def test_a_system_openshift_namespace_is_skipped() -> None:
    """Pod Security sync is permanently off for openshift-* system namespaces."""
    assert _findings(_ns("openshift-monitoring")) == []
    assert _findings(_ns("openshift-operators")) == []


def test_a_user_namespace_whose_name_merely_contains_openshift_is_not_skipped() -> None:
    assert len(_findings(_ns("my-openshift-apps"))) == 1


def test_a_workload_without_its_namespace_object_is_not_a_finding() -> None:
    """The rule reads Namespace objects in the bundle; it never infers one is missing."""
    text = """
apiVersion: v1
kind: Pod
metadata: {name: p, namespace: shop}
spec:
  containers: [{name: c, image: i}]
"""
    assert _findings(text) == []


def test_it_survives_a_non_mapping_metadata_or_labels() -> None:
    for text in (
        "apiVersion: v1\nkind: Namespace\nmetadata: notamap\n",
        "apiVersion: v1\nkind: Namespace\nmetadata: {name: shop, labels: notamap}\n",
        "apiVersion: v1\nkind: Namespace\nmetadata: {name: shop, labels: [a, b]}\n",
        "apiVersion: v1\nkind: Namespace\nmetadata: {name: 7}\n",
    ):
        _findings(text)  # must not raise


def test_the_finding_carries_a_line_and_a_locator() -> None:
    for f in _findings(_ns(labels={PSA_ENFORCE_LABEL: "privileged"})):
        assert f.line is not None and f.locator
