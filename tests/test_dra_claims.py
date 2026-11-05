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


# =====================================================================================================
# The cross-object half, and adminAccess (G193)
# =====================================================================================================

_CLAIM = """
apiVersion: resource.k8s.io/v1
kind: ResourceClaim
metadata: {{name: {name}, namespace: {ns}}}
spec:
  devices:
    requests:
    - name: gpu
      exactly:
        deviceClassName: example.com-gpu
        allocationMode: ExactCount
        count: 1
"""

_TEMPLATE = """
apiVersion: resource.k8s.io/v1
kind: ResourceClaimTemplate
metadata: {{name: {name}, namespace: {ns}}}
spec:
  spec:
    devices:
      requests:
      - name: gpu
        exactly:
          deviceClassName: example.com-gpu
          allocationMode: ExactCount
          count: 1
          {extra}
"""

_POD = """
apiVersion: v1
kind: Pod
metadata: {{name: inference, namespace: {ns}}}
spec:
  resourceClaims:
  - name: gpu
    {source}: {target}
  containers:
  - name: serve
    image: registry.example.com/s@sha256:1a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f809
    resources:
      claims:
      - name: gpu
"""


def test_a_claim_in_the_bundle_clears_the_reference_and_an_absent_one_does_not() -> None:
    pod = _POD.format(ns="ml", source="resourceClaimName", target="gpu-pool")
    together = pod + "---\n" + _CLAIM.format(name="gpu-pool", ns="ml")
    assert len(list(yaml.safe_load_all(together))) == 2, "the two documents must parse as two"
    assert _findings(together, "KN-C015") == []
    found = _findings(pod, "KN-C015")
    assert len(found) == 1 and "'gpu-pool'" in found[0].message, found


def test_the_reference_is_namespaced() -> None:
    """A ResourceClaim is namespaced, so one of the same name in another namespace does not satisfy it."""
    pod = _POD.format(ns="ml", source="resourceClaimName", target="gpu-pool")
    elsewhere = pod + "---\n" + _CLAIM.format(name="gpu-pool", ns="other")
    found = _findings(elsewhere, "KN-C015")
    assert len(found) == 1 and "namespace ml" in found[0].message, found


def test_a_template_reference_needs_a_template_not_a_claim() -> None:
    pod = _POD.format(ns="ml", source="resourceClaimTemplateName", target="gpu-pool")
    # A ResourceClaim of that name is the wrong kind to satisfy a template reference.
    wrong_kind = _findings(pod + "---\n" + _CLAIM.format(name="gpu-pool", ns="ml"), "KN-C015")
    assert len(wrong_kind) == 1 and "ResourceClaimTemplate" in wrong_kind[0].message, wrong_kind
    right_kind = pod + "---\n" + _TEMPLATE.format(name="gpu-pool", ns="ml", extra="")
    assert len(list(yaml.safe_load_all(right_kind))) == 2
    assert _findings(right_kind, "KN-C015") == []


def test_a_partial_bundle_cannot_tell_an_absent_claim_from_one_you_did_not_pass() -> None:
    pod = _POD.format(ns="ml", source="resourceClaimName", target="gpu-pool")
    assert [f for f in analyze(pod, "kubernetes", partial_bundle=True).findings if f.rule_id == "KN-C015"] == []


def test_admin_access_is_reported_on_a_claim_and_on_a_template() -> None:
    bad = _fixture("KN-S031")["bad"]
    found = _findings(bad, "KN-S031")
    assert len(found) == 1 and found[0].severity >= Severity.HIGH
    assert "adminAccess" in found[0].message and found[0].path.endswith(
        "spec.devices.requests[0].exactly.adminAccess"
    ), found[0].path
    assert _findings(_fixture("KN-S031")["good"], "KN-S031") == []
    template = _TEMPLATE.format(name="gpu-pool", ns="ml", extra="adminAccess: true")
    tf = _findings(template, "KN-S031")
    assert len(tf) == 1 and tf[0].path.endswith("spec.spec.devices.requests[0].exactly.adminAccess"), tf[0].path


def test_admin_access_false_is_not_a_finding() -> None:
    """Upstream: admin access is disabled if the field is unset or set to false."""
    assert _findings(_fixture("KN-S031")["bad"].replace("adminAccess: true", "adminAccess: false"), "KN-S031") == []


def test_a_namespace_in_the_bundle_without_the_label_makes_it_a_refusal_not_a_warning() -> None:
    """`resource.kubernetes.io/admin-access: "true"` on the namespace is what permits adminAccess at all."""
    ns = "apiVersion: v1\nkind: Namespace\nmetadata: {name: ml}\n---\n"
    refused = _findings(ns + _fixture("KN-S031")["bad"], "KN-S031")
    assert len(refused) == 1 and "refuse" in refused[0].message, refused
    labelled = (
        "apiVersion: v1\nkind: Namespace\nmetadata:\n  name: ml\n  labels:\n"
        '    resource.kubernetes.io/admin-access: "true"\n---\n'
    )
    allowed = _findings(labelled + _fixture("KN-S031")["bad"], "KN-S031")
    assert len(allowed) == 1 and "refuse" not in allowed[0].message, allowed


def test_admin_access_survives_a_non_mapping_request_tree() -> None:
    for text in (
        "apiVersion: resource.k8s.io/v1\nkind: ResourceClaim\nmetadata: {name: c, namespace: ml}\nspec: notamap\n",
        "apiVersion: resource.k8s.io/v1\nkind: ResourceClaim\nmetadata: {name: c, namespace: ml}\n"
        "spec: {devices: {requests: notalist}}\n",
        "apiVersion: resource.k8s.io/v1\nkind: ResourceClaim\nmetadata: {name: c, namespace: ml}\n"
        "spec: {devices: {requests: [7]}}\n",
        "apiVersion: resource.k8s.io/v1\nkind: ResourceClaim\nmetadata: {name: c, namespace: ml}\n"
        "spec: {devices: {requests: [{name: a, exactly: notamap}]}}\n",
    ):
        assert _findings(text, "KN-S031") == [], text


def test_admin_access_is_not_read_from_a_firstavailable_subrequest() -> None:
    """DeviceSubRequest deliberately omits adminAccess, so a key of that name there is not the API field."""
    text = (
        "apiVersion: resource.k8s.io/v1\nkind: ResourceClaim\nmetadata: {name: c, namespace: ml}\n"
        "spec:\n  devices:\n    requests:\n    - name: gpu\n      firstAvailable:\n"
        "      - name: big\n        deviceClassName: example.com-gpu\n        adminAccess: true\n"
    )
    assert _findings(text, "KN-S031") == []


# =====================================================================================================
# Red team, 2026-11-05 (G195)
# =====================================================================================================

_BETA1 = """
apiVersion: resource.k8s.io/v1beta1
kind: ResourceClaim
metadata: {name: gpu-pool, namespace: ml}
spec:
  devices:
    requests:
    - name: gpu
      deviceClassName: example.com-gpu
      allocationMode: ExactCount
      count: 1
      adminAccess: true
"""


def test_admin_access_is_found_in_the_v1beta1_flattened_shape() -> None:
    """v1beta1 has no `exactly`: adminAccess sits directly on the request, and the bundle still serves it."""
    found = _findings(_BETA1, "KN-S031")
    assert len(found) == 1, found
    assert found[0].path.endswith("spec.devices.requests[0].adminAccess"), found[0].path


def test_the_v1beta1_template_shape_is_found_too() -> None:
    text = _BETA1.replace("kind: ResourceClaim", "kind: ResourceClaimTemplate").replace(
        "spec:\n  devices:", "spec:\n  spec:\n    devices:\n"
    )
    # Rebuild the nesting properly rather than by indentation surgery.
    text = """
apiVersion: resource.k8s.io/v1beta1
kind: ResourceClaimTemplate
metadata: {name: gpu-tpl, namespace: ml}
spec:
  spec:
    devices:
      requests:
      - name: gpu
        deviceClassName: example.com-gpu
        adminAccess: true
"""
    found = _findings(text, "KN-S031")
    assert len(found) == 1 and found[0].path.endswith("spec.spec.devices.requests[0].adminAccess"), found


def test_a_flattened_admin_access_is_not_read_on_v1_where_the_field_cannot_live() -> None:
    """On v1 the request has only exactly/firstAvailable/name, so a key there is a schema error, not the field."""
    text = _BETA1.replace("resource.k8s.io/v1beta1", "resource.k8s.io/v1")
    assert _findings(text, "KN-S031") == []


def test_an_empty_source_name_counts_as_set_so_both_is_reported() -> None:
    """Upstream tests the pointer: "" decodes to a non-nil *string, so this is "at most one of"."""
    text = """
apiVersion: v1
kind: Pod
metadata: {name: p, namespace: ml}
spec:
  resourceClaims:
  - name: gpu
    resourceClaimName: ""
    resourceClaimTemplateName: gpu-tpl
  containers:
  - {name: c, image: i, resources: {claims: [{name: gpu}]}}
"""
    found = _findings(text, "KN-V021")
    assert len(found) == 1 and "both" in found[0].message, found


def test_an_explicit_null_source_really_is_unset() -> None:
    text = """
apiVersion: v1
kind: Pod
metadata: {name: p, namespace: ml}
spec:
  resourceClaims:
  - name: gpu
    resourceClaimName: null
    resourceClaimTemplateName: gpu-tpl
  containers:
  - {name: c, image: i, resources: {claims: [{name: gpu}]}}
"""
    assert _findings(text, "KN-V021") == []


def test_an_empty_source_name_on_its_own_is_reported_as_empty_not_as_missing() -> None:
    text = """
apiVersion: v1
kind: Pod
metadata: {name: p, namespace: ml}
spec:
  resourceClaims:
  - name: gpu
    resourceClaimName: ""
  containers:
  - {name: c, image: i, resources: {claims: [{name: gpu}]}}
"""
    found = _findings(text, "KN-V021")
    assert len(found) == 1, found
    assert "empty" in found[0].message and "neither" not in found[0].message, found[0].message


def test_a_duplicate_pod_claim_name_is_reported() -> None:
    """Upstream refuses it (field.Duplicate), and nothing reported it before."""
    text = """
apiVersion: v1
kind: Pod
metadata: {name: p, namespace: ml}
spec:
  resourceClaims:
  - {name: gpu, resourceClaimTemplateName: t}
  - {name: gpu, resourceClaimTemplateName: t2}
  containers:
  - {name: c, image: i}
"""
    found = _findings(text, "KN-V021")
    assert len(found) == 1 and "more than once" in found[0].message, found
    assert found[0].path.endswith("resourceClaims[1]"), found[0].path


def test_an_object_the_api_server_refuses_is_not_also_narrated_as_admitted() -> None:
    """KN-V021 owns a refused entry; KN-C015 must not say the Pod 'is admitted and then stays Pending'."""
    both = """
apiVersion: v1
kind: Pod
metadata: {name: p, namespace: ml}
spec:
  resourceClaims:
  - name: gpu
    resourceClaimName: gpu-pool
    resourceClaimTemplateName: gpu-tpl
  containers:
  - {name: c, image: i, resources: {claims: [{name: gpu}]}}
"""
    assert len(_findings(both, "KN-V021")) == 1
    assert _findings(both, "KN-C015") == [], "a refused object is not a Pending object"
    duplicate = """
apiVersion: v1
kind: Pod
metadata: {name: p, namespace: ml}
spec:
  resourceClaims:
  - {name: gpu, resourceClaimTemplateName: t}
  - {name: gpu, resourceClaimTemplateName: t2}
  containers:
  - {name: c, image: i}
"""
    assert _findings(duplicate, "KN-C015") == [], "duplicate names are refused; KN-V021 owns that"


def test_two_absent_claims_under_distinct_names_keep_distinct_identities() -> None:
    text = """
apiVersion: v1
kind: Pod
metadata: {name: p, namespace: ml}
spec:
  resourceClaims:
  - {name: a, resourceClaimTemplateName: t}
  - {name: b, resourceClaimTemplateName: t2}
  containers:
  - {name: c, image: i}
"""
    found = _findings(text, "KN-C015")
    assert len(found) == 2
    assert len({f.fingerprint() for f in found}) == 2, "a baseline entry for one would suppress the other"


def test_the_admission_webhook_does_not_run_the_cross_bundle_claim_rule() -> None:
    """The webhook never fetches ResourceClaims, so with lookups on it used to warn on every valid DRA Pod."""
    from kube_noob.admission import CROSS_OBJECT, SKIPPED_RULES

    assert "KN-C015" in SKIPPED_RULES, "without this the webhook warns about a claim it never looked for"
    assert "KN-C015" not in CROSS_OBJECT, "SKIPPED_RULES already stops it; listing both is a second answer"
