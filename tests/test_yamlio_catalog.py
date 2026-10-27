from __future__ import annotations

import pytest

from kube_noob.catalog import OCP_TO_K8S, REMOVED_APIS, deprecated_api, k8s_version_for, parse_minor, removed_api
from kube_noob.errors import ManifestError
from kube_noob.yamlio import dump_documents, load_documents


def test_line_numbers_and_refs() -> None:
    docs = load_documents("a: 1\n---\napiVersion: v1\nkind: Pod\nmetadata:\n  name: p\n  namespace: n\nspec:\n  x: 1\n")
    assert len(docs) == 2
    pod = docs[1]
    assert pod.ref() == "Pod/n/p"
    assert pod.line_for(("spec", "x")) == 9
    assert pod.line_for(("spec", "missing", "deep")) == 8


def test_list_kind_is_flattened() -> None:
    docs = load_documents(
        "apiVersion: v1\nkind: List\nitems:\n- {apiVersion: v1, kind: ConfigMap, metadata: {name: a}}\n"
        "- {apiVersion: v1, kind: ConfigMap, metadata: {name: b}}\n"
    )
    assert [d.name for d in docs] == ["a", "b"]


def test_alias_bomb_rejected() -> None:
    bomb = "a: &a [x,x,x,x,x,x,x,x,x,x]\n"
    prev = "a"
    for i in range(1, 9):
        bomb += f"l{i}: &l{i} [" + ",".join([f"*{prev}"] * 10) + "]\n"
        prev = f"l{i}"
    with pytest.raises(ManifestError, match="too complex"):
        load_documents(bomb)


def test_invalid_yaml_raises_manifest_error() -> None:
    with pytest.raises(ManifestError):
        load_documents("a: [1, 2\n")


def test_dump_roundtrip() -> None:
    text = dump_documents([{"kind": "A", "b": "multi\nline"}, {"kind": "B"}])
    assert [d.data["kind"] for d in load_documents(text)] == ["A", "B"]


def test_ocp_version_map_is_contiguous() -> None:
    for ocp, k8s in OCP_TO_K8S.items():
        assert parse_minor(k8s)[1] == parse_minor(ocp)[1] + 13
    assert k8s_version_for("openshift", "4.22") == "1.35"
    assert k8s_version_for("rosa-hcp", "4.20") == "1.33"
    assert k8s_version_for("openshift", None) == "1.35"
    assert k8s_version_for("kubernetes", "v1.29.3") == "1.29"
    assert k8s_version_for("openshift", "4.23") == "1.36"  # future minors follow the documented cadence


def test_removed_and_deprecated_lookup() -> None:
    assert removed_api("policy/v1beta1", "PodDisruptionBudget", "1.25") is not None
    assert removed_api("policy/v1beta1", "PodDisruptionBudget", "1.24") is None
    assert deprecated_api("policy/v1beta1", "PodDisruptionBudget", "1.24") is not None
    assert len(REMOVED_APIS) == 50
    assert all(parse_minor(r.removed_in) <= (1, 32) for r in REMOVED_APIS)
