"""The under-served set: quota and limits, a paused pool, and an operator that upgrades itself (G203).

Every semantic here is from the upstream type, not from documentation prose: `MachineConfigPool.spec.paused`
("stops generating new desiredMachineConfig and update of machines") from openshift/api, and OLM's
`Approval` enum plus `Subscription.GetInstallPlanApproval`, which returns Manual ONLY when the field says
Manual -- so an absent field chooses automatic upgrades.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from kube_noob.audit.engine import analyze
from kube_noob.audit.model import Severity

ROOT = Path(__file__).resolve().parents[1]
FIX = ROOT / "tests" / "fixtures" / "rules"


def _f(text: str, rule_id: str, platform: str = "openshift", version: str | None = "4.22") -> list:
    return [x for x in analyze(text, platform, version).findings if x.rule_id == rule_id]


def _fixture(rule_id: str) -> dict[str, str]:
    return yaml.safe_load((FIX / f"{rule_id}.yaml").read_text(encoding="utf-8"))


@pytest.mark.parametrize("rule_id", ["KN-C016", "KN-S033", "KN-S034"])
def test_each_fixture_fires_and_clears(rule_id: str) -> None:
    data = _fixture(rule_id)
    assert _f(data["bad"], rule_id), f"{rule_id} did not fire on its bad fixture"
    assert _f(data["good"], rule_id) == [], f"{rule_id} fired on its good fixture"


# -- KN-C016 ------------------------------------------------------------------------------------------


def test_quota_rule_names_which_of_the_two_is_missing() -> None:
    found = _f(_fixture("KN-C016")["bad"], "KN-C016")
    assert len(found) == 1
    assert "ResourceQuota or LimitRange" in found[0].message, found[0].message
    assert "cannot show that" in found[0].message, "a cluster default may cover it; say so"


def test_only_the_missing_one_is_named() -> None:
    bad = _fixture("KN-C016")["bad"]
    quota = (
        "---\napiVersion: v1\nkind: ResourceQuota\nmetadata: {name: q, namespace: shop}\n"
        "spec: {hard: {requests.cpu: '4'}}\n"
    )
    found = _f(bad + quota, "KN-C016")
    assert len(found) == 1
    assert "no LimitRange in this bundle" in found[0].message, found[0].message


def test_one_finding_per_namespace_not_per_workload() -> None:
    bad = _fixture("KN-C016")["bad"]
    assert len(_f(bad + "---\n" + bad.replace("name: api", "name: api2"), "KN-C016")) == 1


def test_the_quota_rule_declines_to_decide_on_a_partial_bundle() -> None:
    """A quota in a file you did not pass is not a missing quota (G186), and it is not clean either (G202)."""
    rep = analyze(_fixture("KN-C016")["bad"], "openshift", "4.22", partial_bundle=True)
    assert [f for f in rep.findings if f.rule_id == "KN-C016"] == []
    assert "KN-C016" not in rep.evaluated_rules


# -- KN-S033 ------------------------------------------------------------------------------------------


def test_a_paused_pool_says_what_stops() -> None:
    found = _f(_fixture("KN-S033")["bad"], "KN-S033")
    assert len(found) == 1 and found[0].severity is Severity.MEDIUM
    assert found[0].path.endswith("spec.paused")
    assert "worker" in found[0].message
    for word in ("OS", "kubelet", "until it is unpaused"):
        assert word in found[0].message, word


@pytest.mark.parametrize("value", ["false", "null"])
def test_a_pool_that_is_not_paused_is_silent(value: str) -> None:
    text = _fixture("KN-S033")["bad"].replace("paused: true", f"paused: {value}")
    assert _f(text, "KN-S033") == []


def test_an_absent_paused_field_is_silent() -> None:
    kept = [line for line in _fixture("KN-S033")["bad"].splitlines() if "paused:" not in line]
    text = "\n".join(kept)
    assert _f(text, "KN-S033") == []


def test_the_pool_rule_survives_a_non_mapping_spec() -> None:
    for spec in ("notamap", "[a, b]", "{paused: 'true'}", "{paused: 1}"):
        text = (
            "apiVersion: machineconfiguration.openshift.io/v1\nkind: MachineConfigPool\n"
            f"metadata: {{name: w}}\nspec: {spec}\n"
        )
        assert _f(text, "KN-S033") == [], spec


# -- KN-S034 ------------------------------------------------------------------------------------------


def test_an_absent_approval_field_is_reported_because_absent_means_automatic() -> None:
    """Upstream's GetInstallPlanApproval returns Manual only when the field says Manual."""
    text = "\n".join(line for line in _fixture("KN-S034")["bad"].splitlines() if "installPlanApproval" not in line)
    found = _f(text, "KN-S034")
    assert len(found) == 1, "omitting the field chooses automatic upgrades"
    assert "no installPlanApproval" in found[0].message
    assert "Absent, the field means Automatic" in found[0].message
    assert found[0].path == "spec", found[0].path


def test_the_channel_is_named_when_it_is_known() -> None:
    found = _f(_fixture("KN-S034")["bad"], "KN-S034")
    assert len(found) == 1 and "channel stable" in found[0].message
    assert found[0].path.endswith("spec.installPlanApproval")


def test_an_unknown_approval_value_is_reported_rather_than_assumed_safe() -> None:
    text = _fixture("KN-S034")["bad"].replace("installPlanApproval: Automatic", "installPlanApproval: manual")
    found = _f(text, "KN-S034")
    assert len(found) == 1, "the enum is case-sensitive: 'manual' is not Manual"


def test_a_subscription_from_another_api_group_is_not_an_olm_subscription() -> None:
    text = (
        "apiVersion: messaging.example.com/v1\nkind: Subscription\n"
        "metadata: {name: topic-sub, namespace: apps}\nspec: {topic: orders}\n"
    )
    assert _f(text, "KN-S034") == []


def test_the_subscription_rule_survives_a_non_mapping_spec() -> None:
    for spec in ("notamap", "[a]", "{installPlanApproval: 7}"):
        text = f"apiVersion: operators.coreos.com/v1alpha1\nkind: Subscription\nmetadata: {{name: s}}\nspec: {spec}\n"
        _f(text, "KN-S034")  # must not raise
