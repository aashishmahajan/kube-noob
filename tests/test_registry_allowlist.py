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


# --- R3b: the same verdict at admission (G242) ---------------------------------------------------------------


#: Every reference shape where the generated CEL and `_registry_allowed` could plausibly part company: an entry
#: hit exactly, a digest on that exact entry, a tag on it (the audit compares the tag as part of the path, so
#: this is NOT allowed), a longer organisation that shares the prefix, the same host on another port, and the
#: three unqualified forms that resolve to Docker Hub. The test asserts the two agree, rather than asserting a
#: verdict twice: the generator's contract is that a policy refuses exactly what the audit reports.
_PARITY_IMAGES = (
    "quay.io/my-org/app:1.2.3",
    "quay.io/my-org/app@sha256:" + "a" * 64,
    "quay.io/my-org",
    "quay.io/my-org@sha256:" + "b" * 64,
    "quay.io/my-org:1",
    "quay.io/my-org-evil/app:1",
    "quay.io/my-orgx/app",
    "quay.io:443/my-org/app:1",
    "quay.io",
    "nginx",
    "nginx:1.27",
    "bitnami/nginx",
    "docker.io/library/nginx",
    "localhost:5000/app:1",
    "registry.example.com:5000/team/app:2",
    "registry.example.com:5000/team",
    "ghcr.io/org/app",
    "app:x:latest",
    "nginx:",
    "",
    "   ",
    " quay.io/my-org/app:1",
    "quay.io/my-org ",
    "\tquay.io/my-org/app",
    "quay.io/my-org/app\n",
)
_PARITY_LISTS = (
    ("quay.io",),
    ("quay.io/my-org",),
    ("registry.example.com:5000/team", "quay.io/my-org"),
    ("localhost:5000",),
)


@pytest.mark.parametrize("allowed", _PARITY_LISTS)
@pytest.mark.parametrize("image", _PARITY_IMAGES)
def test_the_generated_policy_refuses_exactly_what_the_audit_reports(image: str, allowed: tuple[str, ...]) -> None:
    from kube_noob.generate import policies as pol
    from tests.policy_cel import failures

    check = pol.checks_for("kubernetes", None, allowed)["KN-S036"]
    policy = pol.documents(check, "vap", "enforce", "kubernetes")[0]
    refused = bool(failures(policy, _deployment(image)))
    assert refused == bool(_fired(image, allowed)), f"{image!r} against {allowed}: policy={refused}"


def test_an_allowlist_the_generator_cannot_compile_emits_nothing() -> None:
    """Refusing to emit is the only safe answer: a policy that disagrees with the audit is worse than none.

    `docker.io` needs the "is the first path component a host" test, which the API server's CEL cannot do
    without `split`. A host with no dot, port or `localhost` (`myregistry`) is never a registry to a runtime, so
    `myregistry/app` comes from Docker Hub and a `startsWith('myregistry/')` policy would admit an image the
    audit reports. Both are stated in the skip reason instead.
    """
    from kube_noob.generate.policies import registry_cel

    assert registry_cel(()) is None
    assert registry_cel(("docker.io",)) is None
    assert registry_cel(("docker.io/library",)) is None
    assert registry_cel(("myregistry",)) is None
    assert registry_cel(("quay.io/My-Org",)) is None
    assert registry_cel(("quay.io/my-org'; true || '",)) is None
    blank = r"c.image.matches('^[ \t\n\r\f\v]*$')"  # the audit's BLANK_IMAGE_CHARS, as an RE2 class
    assert registry_cel(("quay.io",)) == (
        f"variables.containers.all(c, !has(c.image) || {blank} || c.image.startsWith('quay.io/'))"
    )
    assert registry_cel(("quay.io/my-org",)) == (
        f"variables.containers.all(c, !has(c.image) || {blank} || c.image == 'quay.io/my-org' || "
        "c.image.startsWith('quay.io/my-org/') || c.image.startsWith('quay.io/my-org@'))"
    )


def test_an_entry_that_could_never_match_is_refused_at_load() -> None:
    """A typo in the allowlist is a startup error, not a cluster where every image is suddenly unapproved.

    `MyRegistry` and `myregistry` match no reference a runtime can pull from that registry -- an image
    reference is lower-case, and a first component with no dot, port or `localhost` is a Docker Hub
    repository. Left in, such an entry reports every image in the cluster against a registry that does not
    exist, which reads as 93 rules working and one lying (G243).
    """
    from kube_noob.config import MAX_ALLOWED_REGISTRIES, load_settings
    from kube_noob.errors import ConfigError

    ok = load_settings(overrides={"audit": {"allowedRegistries": [" quay.io/my-org ", "localhost:5000"]}})
    assert ok.audit.allowed_registries == ["quay.io/my-org", "localhost:5000"]
    for bad in (
        ["MyRegistry"],
        ["myregistry"],
        ["quay.io/My-Org"],
        ["quay.io/"],
        ["quay.io/my-org'; true || '"],
        ["quay.io"] * (MAX_ALLOWED_REGISTRIES + 1),
    ):
        with pytest.raises(ConfigError):
            load_settings(overrides={"audit": {"allowedRegistries": bad}})


def test_the_webhook_and_the_audit_read_the_same_list() -> None:
    """One configured list, the same verdict from the webhook as from `kube-noob audit` (R3c, G243)."""
    from kube_noob import admission as adm

    allowed = ("quay.io/my-org",)
    cfg = adm.Config.build(platform="kubernetes", allowed_registries=list(allowed))
    for image, refused in (("quay.io/my-org/app:1", False), ("ghcr.io/someone/app:1", True)):
        review = {
            "apiVersion": "admission.k8s.io/v1",
            "kind": "AdmissionReview",
            "request": {
                "uid": "u1",
                "operation": "CREATE",
                "namespace": "shop",
                "userInfo": {"username": "alice"},
                "object": _deployment(image),
            },
        }
        warnings = adm.review(review, cfg)["response"].get("warnings", [])
        hit = any(w.startswith("[KN-S036]") for w in warnings)
        assert hit == refused, image
        assert hit == bool(_fired(image, allowed)), f"{image}: webhook and audit disagree"


def test_one_image_written_three_ways_gets_one_verdict() -> None:
    """The reference normalisation (G245). `nginx`, `library/nginx` and `docker.io/library/nginx` are one image.

    Before this, an allowlist of `docker.io/library` admitted the middle spelling and reported the other two,
    and `docker.io/bitnami` reported `docker.io/bitnami/nginx` -- the fully qualified form of the thing it was
    written to allow. Under G243 that list reaches the admission webhook, so a false report became a denial.
    """
    for allowed, images in (
        (("docker.io/library",), ("nginx:1.27", "library/nginx:1.27", "docker.io/library/nginx:1.27")),
        (("docker.io/bitnami",), ("bitnami/nginx", "docker.io/bitnami/nginx")),
        (("docker.io",), ("nginx", "library/nginx", "docker.io/library/nginx", "bitnami/nginx")),
    ):
        for image in images:
            assert not _fired(image, allowed), f"{image} should come from {allowed[0]}"
    # And the narrowing still narrows: an organisation is not every organisation.
    for image in ("bitnami/nginx", "docker.io/bitnami/nginx", "nginx"):
        assert _fired(image, ("docker.io/other",)), image


def test_the_repository_is_the_path_a_runtime_would_pull() -> None:
    from kube_noob.audit.rules import image_repository

    for image, repository in (
        ("nginx", "library/nginx"),
        ("nginx:1.27", "library/nginx:1.27"),
        ("library/nginx", "library/nginx"),
        ("docker.io/library/nginx", "library/nginx"),
        ("bitnami/nginx", "bitnami/nginx"),
        ("quay.io/my-org/app:1", "my-org/app:1"),
        ("quay.io/app", "app"),
        ("registry.local:5000/team/app", "team/app"),
        ("gcr.io/proj/img@sha256:" + "a" * 64, "proj/img"),
    ):
        assert image_repository(image) == repository, image


def test_a_whitespace_only_allowlist_is_not_a_configured_policy() -> None:
    """It reached `analyze` programmatically and reported every image against an allowlist of "  " (G245)."""
    from kube_noob import admission as adm
    from kube_noob.errors import KubeNoobError

    report = _report("quay.io/app", ("  ", "\n"))
    assert not [f for f in report.findings if f.rule_id == "KN-S036"]
    assert "KN-S036" not in report.evaluated_rules, "a declined rule must not be recorded as checked and clean"
    with pytest.raises((adm.AdmissionConfigError, KubeNoobError)):
        adm.Config.build(enforce=["KN-S036"], allowed_registries=["  "])


def test_a_fullwidth_digit_port_is_refused_everywhere() -> None:
    """`\\d` matches U+FF10..U+FF19, and no runtime pulls from `quay.io:\uff15\uff10\uff10\uff10` (G245)."""
    from kube_noob.config import load_settings
    from kube_noob.errors import ConfigError
    from kube_noob.generate.policies import registry_cel

    entry = "quay.io:\uff15\uff10\uff10\uff10"
    assert registry_cel((entry,)) is None
    with pytest.raises(ConfigError):
        load_settings(overrides={"audit": {"allowedRegistries": [entry]}})


def test_the_chart_schema_refuses_what_the_configuration_refuses() -> None:
    """Both gates, one answer: otherwise `helm install` succeeds and every pod crash-loops at config load."""
    import json
    import re
    from pathlib import Path

    from pydantic import ValidationError

    from kube_noob.config import AuditSettings

    root = Path(__file__).resolve().parent.parent
    schema = json.loads((root / "deploy" / "helm" / "kube-noob" / "values.schema.json").read_text())
    pattern = schema["properties"]["audit"]["properties"]["allowedRegistries"]["items"]["pattern"]
    entries = (
        "quay.io",
        "quay.io/my-org",
        "localhost",
        "localhost:5000",
        "localhost:5000/app",
        "localhostx",
        "registry.example.com:5000/team",
        "registry.local:5000",
        "sub.domain.example.io/a/b/c",
        "1.2.3.4:5000/x",
        "myregistry",
        "a",
        "MyRegistry",
        "quay.io/My-Org",
        "quay.io/",
        "quay.io:",
        "quay.io//a",
        "-quay.io",
        "quay.io-/a",
        "quay.io:\uff15\uff10\uff10\uff10",
        "quay.io/my-org'; true || '",
    )
    for entry in entries:
        by_schema = re.fullmatch(pattern, entry) is not None
        try:
            AuditSettings(allowed_registries=[entry])
            by_config = True
        except ValidationError:
            by_config = False
        assert by_schema == by_config, f"{entry!r}: schema={by_schema} config={by_config}"
    # The one difference, and it is deliberate: the settings strip surrounding whitespace off a YAML value
    # before matching, and a JSON Schema pattern cannot strip. Both end up with the same entry.
    assert re.fullmatch(pattern, "quay.io\n") is None
    assert AuditSettings(allowed_registries=["quay.io\n"]).allowed_registries == ["quay.io"]
