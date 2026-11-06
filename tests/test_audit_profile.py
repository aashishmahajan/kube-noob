"""KN-S035: the cluster's audit configuration, and the one honest logging check a read-only client can make.

Two ChatGPT reviews of kube-noob both put audit logging and SIEM at the top of the missing-coverage list, and
both then proposed about twelve rules for it. Eleven of those twelve need credentials for a system this project
holds none for, so they could only ever answer "not evaluated" -- coverage theatre rather than coverage. This is
the twelfth: OpenShift keeps its audit settings in a cluster-scoped `APIServer` singleton that ordinary
read-only RBAC can read, so the question is decidable (G226).
"""

from __future__ import annotations

from kube_noob.audit.engine import analyze

CLUSTER = "apiVersion: config.openshift.io/v1\nkind: APIServer\nmetadata: {name: cluster}\nspec:\n  audit:\n"


def _rule_ids(text: str, platform: str = "openshift") -> list[str]:
    return [f.rule_id for f in analyze(text, platform, None).findings if f.rule_id == "KN-S035"]


def test_an_audit_profile_of_none_is_a_finding() -> None:
    report = analyze(CLUSTER + "    profile: None\n", "openshift", None)
    found = [f for f in report.findings if f.rule_id == "KN-S035"]
    assert len(found) == 1
    assert "records no requests at all" in found[0].message


def test_a_custom_rule_that_logs_nothing_for_one_group_is_a_finding() -> None:
    """The one worth having. `customRules` is evaluated top to bottom and the first match takes precedence over
    `spec.audit.profile`, so a cluster reporting `Default` can log nothing for a named group: it looks audited
    and is not. A reader who checks only the top-level profile is reading the reassuring half."""
    text = (
        CLUSTER + "    profile: Default\n    customRules:\n"
        "    - {group: 'system:authenticated:oauth', profile: WriteRequestBodies}\n"
        "    - {group: 'system:serviceaccounts:prod', profile: None}\n"
    )
    found = [f for f in analyze(text, "openshift", None).findings if f.rule_id == "KN-S035"]
    assert len(found) == 1
    assert "system:serviceaccounts:prod" in found[0].message
    assert "overrides" in found[0].message


def test_a_healthy_profile_is_not_a_finding() -> None:
    assert _rule_ids(CLUSTER + "    profile: WriteRequestBodies\n") == []
    assert _rule_ids("apiVersion: config.openshift.io/v1\nkind: APIServer\nmetadata: {name: cluster}\nspec: {}\n") == []


def test_a_bundle_without_the_object_declines_rather_than_passing() -> None:
    """On OpenShift the singleton always exists, so its absence means it was not collected -- not that auditing
    is on. Counting that clean is the defect this project keeps finding in its own output (G202, G216)."""
    report = analyze("apiVersion: v1\nkind: ConfigMap\nmetadata: {name: a}\n", "openshift", None)
    assert "KN-S035" not in report.evaluated_rules
    assert not [f for f in report.findings if f.rule_id == "KN-S035"]


def test_the_rule_is_evidence_about_the_audit_controls_and_nothing_else() -> None:
    from kube_noob.audit.controls import RULE_CONTROLS, TITLES

    assert RULE_CONTROLS["KN-S035"] == ("AU-2", "AU-12")
    assert TITLES["AU-2"] == "Event Logging"
    assert TITLES["AU-12"] == "Audit Record Generation"


def test_the_indicators_it_reaches_say_which_one_it_is_actually_about() -> None:
    """One rule moved three MLA indicators off the unevidenced list, and it has business claiming exactly one of
    them. `KSI-MLA-LET` asks which event types are logged -- that is this rule's subject. `KSI-MLA-OSM` asks
    whether a SIEM is operated and `KSI-MLA-RVL` whether logs are reviewed; both arrive only because FedRAMP and
    kube-noob both name `au-2`. Marking them off-subject is the whole discipline: adding a rule honestly made
    the coverage claim smaller, not larger (G219, G226)."""
    from kube_noob.audit import fedramp

    for ind in ("KSI-MLA-LET", "KSI-MLA-OSM", "KSI-MLA-RVL"):
        assert fedramp.indicator_rules(ind) == ("KN-S035",), ind
        assert ind in fedramp.EVIDENCE, ind
    assert fedramp.EVIDENCE["KSI-MLA-LET"]["onSubject"] is True
    assert fedramp.EVIDENCE["KSI-MLA-OSM"]["onSubject"] is False
    assert fedramp.EVIDENCE["KSI-MLA-RVL"]["onSubject"] is False
    rows = {r["id"]: r for r in fedramp.summary([])["indicators"]}
    assert rows["KSI-MLA-OSM"]["warning"]
    assert rows["KSI-MLA-RVL"]["warning"]
    assert "warning" not in rows["KSI-MLA-LET"]


def test_the_cluster_reader_knows_the_resource() -> None:
    """Verified against openshift/api config/v1 types_apiserver.go on 2026-11-06: group config.openshift.io,
    version v1, cluster-scoped, plural apiservers."""
    from kube_noob.debug.cluster import ALLOWED_RESOURCES

    r = ALLOWED_RESOURCES["apiservers"]
    assert r.group_version == "config.openshift.io/v1"
    assert r.plural == "apiservers"
    assert r.namespaced is False
