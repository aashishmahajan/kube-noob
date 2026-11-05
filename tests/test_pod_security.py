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


@pytest.mark.parametrize("name", ["kube-system", "kube-public", "kube-node-lease", "default"])
def test_the_namespaces_the_platform_owns_are_skipped(name: str) -> None:
    assert _findings(_ns(name)) == []


def test_a_system_openshift_namespace_is_skipped_on_openshift() -> None:
    """Pod Security sync is permanently off for openshift-* system namespaces -- on OpenShift.

    This test first asserted the skip on the default platform, which is `kubernetes`, and so pinned the bug a
    red team later found: a namespace merely NAMED openshift-something on EKS or GKE got a silent pass.
    """
    for name in ("openshift-monitoring", "openshift-operators", "openshift"):
        assert _findings(_ns(name), "openshift", "4.22") == [], name
        assert len(_findings(_ns(name))) == 1, f"{name} is an ordinary namespace on vanilla Kubernetes"


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


# =====================================================================================================
# Red team, 2026-11-05 (G204)
# =====================================================================================================


@pytest.mark.parametrize("value", ["Privileged", "Restricted", "RESTRICTED", "resticted", "baseline-ish", "true"])
def test_a_value_that_is_not_one_of_the_three_levels_is_reported(value: str) -> None:
    """The enum is exactly privileged/baseline/restricted. Anything else is a typo, not a judgement.

    Before this, `Privileged` was SILENT while an absent label was MEDIUM: the rule was quieter about a
    namespace that looks privileged than about one with no label at all.
    """
    found = _findings(_ns(labels={PSA_ENFORCE_LABEL: value}))
    assert len(found) == 1, f"{value!r} cleared the rule"
    assert repr(value) in found[0].message or value in found[0].message
    assert "privileged, baseline or restricted" in found[0].message


def test_an_openshift_namespace_name_is_only_special_on_openshift() -> None:
    """The skip exists because OpenShift's syncer owns those namespaces. Vanilla Kubernetes has no syncer."""
    assert len(_findings(_ns("openshift-apps"))) == 1, "an ordinary namespace on EKS/GKE got a silent pass"
    assert len(_findings(_ns("openshift"))) == 1
    assert _findings(_ns("openshift-apps"), "openshift", "4.22") == []
    assert _findings(_ns("openshift"), "openshift", "4.22") == []


@pytest.mark.parametrize("name", ["kube-system", "kube-public", "kube-node-lease", "default"])
def test_the_kubernetes_system_namespaces_are_skipped_on_every_platform(name: str) -> None:
    assert _findings(_ns(name)) == []
    assert _findings(_ns(name), "openshift", "4.22") == []


def test_a_namespace_with_no_usable_name_is_left_to_the_schema_rule() -> None:
    """A finding about a nameless namespace is unactionable, and KN-V007 already refuses the object."""
    for meta in ("{name: 7}", "{name: null}", "{}", "notamap"):
        text = f"apiVersion: v1\nkind: Namespace\nmetadata: {meta}\n"
        assert _findings(text) == [], meta


def test_the_same_namespace_declared_twice_is_reported_once() -> None:
    assert len(_findings(_ns("shop") + "---\n" + _ns("shop"))) == 1
