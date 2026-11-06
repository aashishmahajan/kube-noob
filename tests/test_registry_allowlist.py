"""`KN-S036`: an image from a registry nobody approved (R3, G241).

A policy, not a fact about a manifest. No document states which registries an organisation has approved, so the
rule declines to decide when none are configured rather than reporting every image as fine -- the same shape as
KN-N014 and the CNI.

The reference parser is the part worth testing hardest. Docker's rule is that the first path component is the
registry only when it looks like a host (a dot, a colon, or exactly `localhost`), so `nginx` and `bitnami/nginx`
both come from Docker Hub however little they look like it; an allowlist that missed that would pass every
unqualified image, which is the commonest image reference there is.
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from kube_noob.audit.engine import analyze
from kube_noob.audit.rules import image_registry


def _deployment(image: str) -> dict[str, Any]:
    return {
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": {"name": "web", "namespace": "shop"},
        "spec": {
            "selector": {"matchLabels": {"app": "web"}},
            "template": {
                "metadata": {"labels": {"app": "web"}},
                "spec": {"containers": [{"name": "web", "image": image}]},
            },
        },
    }


def _report(image: str, allowed: tuple[str, ...]):
    return analyze(json.dumps(_deployment(image)), allowed_registries=allowed)


def _fired(image: str, allowed: tuple[str, ...]) -> list[str]:
    return [f.message for f in _report(image, allowed).findings if f.rule_id == "KN-S036"]


@pytest.mark.parametrize(
    ("image", "registry"),
    [
        ("nginx", "docker.io"),
        ("nginx:1.27", "docker.io"),
        ("bitnami/nginx", "docker.io"),
        ("docker.io/library/nginx", "docker.io"),
        ("quay.io/org/app", "quay.io"),
        ("registry.example.com/a/b", "registry.example.com"),
        ("localhost:5000/app", "localhost:5000"),
        ("my-registry:5000/team/app", "my-registry:5000"),
        ("gcr.io/proj/img@sha256:" + "a" * 64, "gcr.io"),
        (
            "image-registry.openshift-image-registry.svc:5000/shop/web",
            "image-registry.openshift-image-registry.svc:5000",
        ),
    ],
)
def test_the_registry_is_read_the_way_a_runtime_reads_it(image: str, registry: str) -> None:
    assert image_registry(image) == registry


def test_it_declines_rather_than_passing_everything_when_no_policy_is_configured() -> None:
    """The absence-read-as-pass case: with no allowlist, every image would otherwise be reported as approved."""
    report = analyze(json.dumps(_deployment("quay.io/anyone/app:1")))
    assert not [f for f in report.findings if f.rule_id == "KN-S036"]
    assert "KN-S036" not in report.evaluated_rules, "a declined rule must not be recorded as checked and clean"


def test_an_allowed_registry_passes_and_an_unknown_one_does_not() -> None:
    assert not _fired("quay.io/my-org/app:1", ("quay.io/my-org",))
    assert _fired("ghcr.io/someone/app:1", ("quay.io/my-org",))


def test_an_entry_can_narrow_to_one_organisation() -> None:
    """Which is the point of an allowlist for a registry anyone can push to."""
    assert not _fired("quay.io/my-org/app:1", ("quay.io/my-org",))
    assert _fired("quay.io/someone-else/app:1", ("quay.io/my-org",))


def test_a_prefix_cannot_be_impersonated_by_a_longer_name() -> None:
    """`quay.io/my-org-evil/app` must not pass an allowlist of `quay.io/my-org`."""
    assert _fired("quay.io/my-org-evil/app:1", ("quay.io/my-org",))


def test_a_host_entry_allows_the_whole_registry() -> None:
    assert not _fired("registry.example.com/any/thing:1", ("registry.example.com",))
    assert not _fired("registry.example.com/other:1", ("registry.example.com",))


def test_an_unqualified_image_is_measured_against_docker_hub_and_says_so() -> None:
    """The reference says nothing about a registry, and that is exactly when a reader needs telling which one
    they are actually pulling from."""
    found = _fired("nginx:1.27", ("quay.io/my-org",))
    assert found and "docker.io" in found[0]
    assert "unqualified" in found[0]
    assert not _fired("nginx:1.27", ("docker.io",))


def test_an_embedded_pod_spec_is_checked_too() -> None:
    """It reads `ctx.workloads()`, so the G229 work carries: a KServe predictor's image is an image."""
    isvc = {
        "apiVersion": "serving.kserve.io/v1beta1",
        "kind": "InferenceService",
        "metadata": {"name": "i", "namespace": "shop"},
        "spec": {"predictor": {"model": {"modelFormat": {"name": "sklearn"}, "image": "ghcr.io/someone/serve:1"}}},
    }
    found = [
        f for f in analyze(json.dumps(isvc), allowed_registries=("quay.io/my-org",)).findings if f.rule_id == "KN-S036"
    ]
    assert found, "a predictor's image went unchecked"


def test_the_finding_names_the_field_and_the_policy() -> None:
    report = _report("ghcr.io/someone/app:1", ("quay.io/my-org", "registry.example.com"))
    finding = next(f for f in report.findings if f.rule_id == "KN-S036")
    assert "image" in str(finding.path)
    assert "quay.io/my-org" in finding.message and "registry.example.com" in finding.message


def test_a_blank_or_missing_image_is_not_a_registry_finding() -> None:
    """KN-V001 and the schema own a malformed container; this rule says nothing about one."""
    for image in ("", "   "):
        assert not _fired(image, ("quay.io/my-org",))
