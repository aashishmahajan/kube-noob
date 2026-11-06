"""Telling a `list` on Secrets apart from a `get` (G240).

`KN-S017`'s Secret branch reported `get`, `list`, `watch` and `*` with one message and one severity per role
kind. They are not the same grant: `list` and `watch` return the objects' CONTENTS, so a single namespaced grant
hands over the value of every Secret in that namespace, while a `get` hands over the ones whose names the holder
already knows. All three external reviews of this catalogue asked for the distinction, and this project's own
bundled RBAC guidance has said "list returns contents" the whole time.

The same branch had a false positive that matters more: a `get` narrowed by `resourceNames` is the least-privilege
pattern the upstream guidance recommends, and the rule was calling it a privilege-escalation path.
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from kube_noob.audit.engine import analyze
from kube_noob.audit.model import Severity


def _role(verbs: list[str], names: list[str] | None = None, kind: str = "Role") -> dict[str, Any]:
    rule: dict[str, Any] = {"apiGroups": [""], "resources": ["secrets"], "verbs": verbs}
    if names is not None:
        rule["resourceNames"] = names
    return {
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": kind,
        "metadata": {"name": "reader", "namespace": "shop"},
        "rules": [rule],
    }


def _s017(doc: dict[str, Any]) -> list[tuple[Severity, str]]:
    return [(f.severity, f.message) for f in analyze(json.dumps(doc)).findings if f.rule_id == "KN-S017"]


def test_list_on_secrets_outranks_get_because_it_returns_their_contents() -> None:
    (get_sev, _), (list_sev, list_msg) = _s017(_role(["get"]))[0], _s017(_role(["list"]))[0]
    assert list_sev.value > get_sev.value, f"{list_sev} is not above {get_sev}"
    assert "contents" in list_msg and "every Secret in the namespace" in list_msg


@pytest.mark.parametrize("verb", ["list", "watch", "*"])
def test_every_content_returning_verb_is_treated_as_one(verb: str) -> None:
    found = _s017(_role([verb]))
    assert found, verb
    assert found[0][0] is Severity.MEDIUM, f"{verb} -> {found[0][0]}"


def test_a_get_narrowed_to_named_secrets_is_not_an_escalation_path() -> None:
    """The one thing a security rule must not do is tell someone their correct configuration is a defect."""
    assert _s017(_role(["get"], ["my-app-tls"])) == []
    assert _s017(_role(["get", "watch"], ["my-app-tls"])), "but a watch beside it still is"


def test_an_unrestricted_get_is_still_reported() -> None:
    """Narrowing the rule must not silence it: with no `resourceNames` the grant covers every Secret's name."""
    found = _s017(_role(["get"]))
    assert found and found[0][0] is Severity.LOW


def test_list_is_reported_whatever_resource_names_says() -> None:
    """Whether `resourceNames` narrows a LIST request is a question about the authorizer that this project has
    not verified against the published reference. The conservative reading is right whichever way it falls, and
    resting a verdict on an unverified fact is the mistake G229 and G231 record."""
    with_names = _s017(_role(["list"], ["my-app-tls"]))
    without = _s017(_role(["list"]))
    assert with_names and without
    assert with_names[0][0] is without[0][0]


def test_a_cluster_role_outranks_a_role_for_the_same_verbs() -> None:
    assert _s017(_role(["list"], kind="ClusterRole"))[0][0] is Severity.HIGH
    assert _s017(_role(["list"]))[0][0] is Severity.MEDIUM
    assert "every Secret in the cluster" in _s017(_role(["list"], kind="ClusterRole"))[0][1]


def test_the_bundled_guidance_already_said_this() -> None:
    """The corpus this product ships has said "list returns contents" the whole time, which is why the rule not
    acting on it is worth a guidance row rather than a quiet commit."""
    from pathlib import Path

    doc = Path(__file__).resolve().parents[1] / "src" / "kube_noob" / "data" / "knowledge" / "k8s-rbac.md"
    assert "list returns contents" in doc.read_text(encoding="utf-8")
