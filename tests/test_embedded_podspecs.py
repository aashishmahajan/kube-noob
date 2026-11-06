"""The pod specs that are not at `spec.template.spec` (G229).

An operator CRD that carries its own pod spec -- a KServe component, a Ray head or worker group -- used to
produce no findings at all: the readers looked only at the nine ordinary workload paths, found nothing, and every
pod-level rule in the catalogue passed. Not "not evaluated": clean. These tests pin the shape of the fix, so that
the same pod spec scores the same whichever object carries it.
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from kube_noob import attack_paths as ap
from kube_noob.audit.engine import analyze
from kube_noob.audit.podspec import (
    EMBEDDED_POD_SPEC_GROUPS,
    EMBEDDED_POD_SPEC_PATHS,
    POD_SPEC_PATHS,
    pod_templates,
)
from kube_noob.yamlio import Document

# privileged, root, escalating, host path /, a mutable tag and a mounted token: the loudest pod spec there is
BAD_POD: dict[str, Any] = {
    "serviceAccountName": "runner",
    "containers": [
        {
            "name": "c",
            "image": "model:latest",
            "securityContext": {"privileged": True, "allowPrivilegeEscalation": True, "runAsUser": 0},
            "volumeMounts": [{"name": "h", "mountPath": "/host"}],
        }
    ],
    "volumes": [{"name": "h", "hostPath": {"path": "/"}}],
}
LABELS = {"app": "m"}


def _deployment() -> dict[str, Any]:
    return {
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": {"name": "d", "namespace": "ns"},
        "spec": {
            "replicas": 1,
            "selector": {"matchLabels": LABELS},
            "template": {"metadata": {"labels": LABELS}, "spec": BAD_POD},
        },
    }


def _isvc() -> dict[str, Any]:
    return {
        "apiVersion": "serving.kserve.io/v1beta1",
        "kind": "InferenceService",
        "metadata": {"name": "i", "namespace": "ns", "labels": LABELS},
        "spec": {"predictor": BAD_POD},
    }


def _raycluster() -> dict[str, Any]:
    template = {"metadata": {"labels": LABELS}, "spec": BAD_POD}
    return {
        "apiVersion": "ray.io/v1",
        "kind": "RayCluster",
        "metadata": {"name": "r", "namespace": "ns"},
        "spec": {
            "headGroupSpec": {"template": template},
            "workerGroupSpecs": [{"groupName": "g0", "template": template}],
        },
    }


def _rule_ids(obj: dict[str, Any]) -> set[str]:
    return {f.rule_id for f in analyze(json.dumps(obj)).findings}


# --- the blind spot itself ---------------------------------------------------------------------------------------


def test_an_inference_service_is_audited_not_passed() -> None:
    """The defect: this returned an empty set, so the predictor counted as clean."""
    found = _rule_ids(_isvc())
    assert found, "an InferenceService predictor produced no findings at all"
    # the pod-level rules that do not depend on labels, replicas or probes
    for rule in ("KN-S001", "KN-S002", "KN-S003", "KN-S006", "KN-S007", "KN-S010", "KN-S012"):
        assert rule in found, f"{rule} did not fire on an inline KServe PodSpec"


def test_every_pod_level_rule_that_fires_on_a_deployment_fires_on_a_ray_cluster() -> None:
    """A RayCluster head template IS a PodTemplateSpec, so nothing about it is inapplicable: the rules that fire
    on the same spec in a Deployment must fire here too, bar the ones scoped to replicated or long-running kinds."""
    kind_scoped = {"KN-C001", "KN-C002", "KN-C007", "KN-N001"}  # probes, replicas, NetworkPolicy selector
    missing = (_rule_ids(_deployment()) - kind_scoped) - _rule_ids(_raycluster())
    assert not missing, f"rules lost when the same pod spec moved into a RayCluster: {sorted(missing)}"


def test_each_component_and_worker_group_is_its_own_pod_spec() -> None:
    isvc = _isvc()
    isvc["spec"]["transformer"] = BAD_POD
    assert [t.component for t in pod_templates(Document(index=0, data=isvc))] == ["predictor", "transformer"]
    ray = _raycluster()
    ray["spec"]["workerGroupSpecs"].append({"groupName": "g1", "template": {"spec": BAD_POD}})
    assert [t.component for t in pod_templates(Document(index=0, data=ray))] == [
        "headGroupSpec",
        "workerGroupSpecs/0",
        "workerGroupSpecs/1",
    ]


def test_a_findings_path_points_into_the_component_that_carries_it() -> None:
    paths = {f.path for f in analyze(json.dumps(_raycluster())).findings}
    assert any("workerGroupSpecs" in p for p in paths), f"no finding names a worker group: {sorted(paths)[:5]}"
    assert any("headGroupSpec" in p for p in paths), f"no finding names the head: {sorted(paths)[:5]}"


# --- what must NOT happen ---------------------------------------------------------------------------------------


def test_a_same_named_kind_from_another_group_is_not_read() -> None:
    """`RayCluster` in someone else's group is a different object; reading its `spec.headGroupSpec` would be a
    guess about a schema this registry has never seen (G227)."""
    other = _raycluster()
    other["apiVersion"] = "example.com/v1"
    assert pod_templates(Document(index=0, data=other)) == []


def test_a_kind_with_no_api_version_is_read_because_the_live_collectors_drop_it() -> None:
    """API list items carry no apiVersion, and both live collectors set only `kind`. Refusing an absent group
    would restore the blind spot for every `--live` scan -- an unknown is not a contradiction."""
    live = _raycluster()
    del live["apiVersion"]
    assert len(pod_templates(Document(index=0, data=live))) == 2


def test_a_kserve_component_does_not_borrow_the_objects_labels() -> None:
    """A bare inline PodSpec has no pod metadata. The InferenceService's own labels are not what lands on the
    pod -- the operator generates those -- so claiming them would make selector matching fabricate an edge."""
    templates = pod_templates(Document(index=0, data=_isvc()))
    assert [t.labels() for t in templates] == [{}]


def test_a_ray_template_keeps_its_own_labels() -> None:
    templates = pod_templates(Document(index=0, data=_raycluster()))
    assert [t.labels() for t in templates] == [LABELS, LABELS]


def test_the_two_registries_do_not_overlap() -> None:
    assert not set(POD_SPEC_PATHS) & set(EMBEDDED_POD_SPEC_PATHS)
    assert set(EMBEDDED_POD_SPEC_GROUPS) == set(EMBEDDED_POD_SPEC_PATHS), "every embedded kind needs its group"


@pytest.mark.parametrize("broken", [{"spec": {"predictor": "not-a-mapping"}}, {"spec": []}, {}, {"spec": None}])
def test_malformed_input_yields_no_templates_and_does_not_raise(broken: dict[str, Any]) -> None:
    doc = {"apiVersion": "serving.kserve.io/v1beta1", "kind": "InferenceService", "metadata": {"name": "i"}, **broken}
    assert pod_templates(Document(index=0, data=doc)) == []


def test_a_worker_group_list_that_is_not_a_list_is_skipped() -> None:
    ray = _raycluster()
    ray["spec"]["workerGroupSpecs"] = "nope"
    assert [t.component for t in pod_templates(Document(index=0, data=ray))] == ["headGroupSpec"]


# --- the attack-path scan ---------------------------------------------------------------------------------------


def _sa_and_cluster_admin() -> list[dict[str, Any]]:
    return [
        {"apiVersion": "v1", "kind": "ServiceAccount", "metadata": {"name": "runner", "namespace": "ns"}},
        {
            "apiVersion": "rbac.authorization.k8s.io/v1",
            "kind": "ClusterRole",
            "metadata": {"name": "ca"},
            "rules": [{"apiGroups": ["*"], "resources": ["*"], "verbs": ["*"]}],
        },
        {
            "apiVersion": "rbac.authorization.k8s.io/v1",
            "kind": "ClusterRoleBinding",
            "metadata": {"name": "b"},
            "roleRef": {"kind": "ClusterRole", "name": "ca"},
            "subjects": [{"kind": "ServiceAccount", "name": "runner", "namespace": "ns"}],
        },
    ]


def _service() -> dict[str, Any]:
    return {
        "apiVersion": "v1",
        "kind": "Service",
        "metadata": {"name": "s", "namespace": "ns"},
        "spec": {"type": "LoadBalancer", "selector": LABELS, "ports": [{"port": 80}]},
    }


def test_the_scan_reaches_a_ray_head_and_every_worker_group() -> None:
    inv = ap.Inventory.from_documents([_service(), _raycluster(), *_sa_and_cluster_admin()])
    reach = ap.workload_reach(inv)
    assert set(reach) == {"RayCluster/ns/r[headGroupSpec]", "RayCluster/ns/r[workerGroupSpecs/0]"}
    deploy = ap.workload_reach(ap.Inventory.from_documents([_service(), _deployment(), *_sa_and_cluster_admin()]))
    one = deploy["Deployment/ns/d"]
    for r in reach.values():
        assert [c.name for c in r.capabilities] == [c.name for c in one.capabilities]
        assert r.exposure is not None, "the head and each worker group are selected by the Service"
    out = ap.scan(inv, top=50)
    assert out["workloads"] == 1, "one object, even though it carries two pod specs"
    assert (
        out["total"]
        == 2
        * ap.scan(ap.Inventory.from_documents([_service(), _deployment(), *_sa_and_cluster_admin()]), top=50)["total"]
    )


def test_an_unmatchable_component_is_named_as_undetermined_not_left_silent() -> None:
    """Its capabilities are scored, but with no pod labels in the manifest no exposure edge can be traced. Saying
    nothing would read as "not exposed", which is the failure this change exists to remove."""
    inv = ap.Inventory.from_documents([_service(), _isvc(), *_sa_and_cluster_admin()])
    reach = ap.workload_reach(inv)
    assert [c.name for c in reach["InferenceService/ns/i[predictor]"].capabilities], "capabilities still scored"
    out = ap.scan(inv, top=50)
    assert any("InferenceService/ns/i[predictor]" in line for line in out["limitations"])
    assert any("set by the operator" in line for line in out["limitations"])


def test_the_scan_reads_every_embedded_kind_it_claims_to() -> None:
    """A kind in the registry that the scan's own inventory rejects would be read by the audit and dropped here."""
    assert set(EMBEDDED_POD_SPEC_PATHS) <= ap.KINDS
    assert set(EMBEDDED_POD_SPEC_PATHS) <= set(ap.LIVE_RESOURCES.values())


def test_every_embedded_kind_is_in_the_read_only_allowlist() -> None:
    """Without this the live scan is refused by the guard before it ever reaches the cluster."""
    from kube_noob.debug.cluster import ALLOWED_RESOURCES

    for resource, kind in ap.LIVE_RESOURCES.items():
        if kind in EMBEDDED_POD_SPEC_PATHS:
            assert resource in ALLOWED_RESOURCES, f"{resource} is scanned but not in the read-only allowlist"
            group = ALLOWED_RESOURCES[resource].group_version.split("/", 1)[0]
            assert group in EMBEDDED_POD_SPEC_GROUPS[kind], f"{resource} is read from a group the reader refuses"
