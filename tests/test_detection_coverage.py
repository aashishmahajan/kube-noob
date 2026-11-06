"""R4: what this cluster's audit configuration can and cannot record (G244).

The eleven proposed `AUD-*` checks (docs/ideation-review.md) all needed a credential kube-noob does not have.
This is the part that is decidable from a read-only bundle: `spec.audit` on the `config.openshift.io`
`APIServer` singleton, projected into categories of API activity.

The table below is the point of the test. Every row is the field documentation of `Audit` in openshift/api
`config/v1` (`types_apiserver.go`, read from master on 2026-11-06) written out independently of the
implementation, so a wrong edit to the module fails here rather than shipping a coverage claim that is not
true of the cluster.
"""

from __future__ import annotations

from typing import Any

import pytest
import yaml

from kube_noob.audit import detection
from kube_noob.audit.engine import analyze
from kube_noob.yamlio import load_documents

#: profile -> the categories that profile records. Read straight from the API documentation:
#: None logs nothing at all; Default logs MetaData for everything except events (never) and the two OAuth
#: token kinds (RequestBody); WriteRequestBodies adds write payloads; AllRequestBodies adds read payloads.
EXPECTED: dict[str, set[str]] = {
    "None": set(),
    "Default": {"request-metadata", "oauth-token-bodies"},
    "WriteRequestBodies": {"request-metadata", "oauth-token-bodies", "write-bodies"},
    "AllRequestBodies": {"request-metadata", "oauth-token-bodies", "write-bodies", "read-bodies"},
}


def _apiserver(audit: Any = None, name: str = "cluster", group: str = "config.openshift.io/v1") -> str:
    spec = {} if audit is None else {"audit": audit}
    return yaml.safe_dump({"apiVersion": group, "kind": "APIServer", "metadata": {"name": name}, "spec": spec})


def _coverage(audit: Any, **kw: Any) -> dict[str, Any]:
    cov = detection.coverage(load_documents(_apiserver(audit, **kw)))
    assert cov is not None
    return cov


def _recorded(cov: dict[str, Any]) -> set[str]:
    return {r["id"] for r in cov["records"] if r["recorded"] == "yes"}


@pytest.mark.parametrize("profile", sorted(EXPECTED))
def test_each_profile_records_what_the_api_documentation_says(profile: str) -> None:
    cov = _coverage({"profile": profile})
    assert _recorded(cov) == EXPECTED[profile], profile
    assert not [r for r in cov["records"] if r["recorded"] == "unknown"]
    assert cov["profile"] == profile and cov["profileAssumed"] is False


def test_events_are_recorded_under_no_profile_at_all() -> None:
    """The one category that is never recorded, and the one a reader assumes is: a deleted Event leaves no trace."""
    for profile in EXPECTED:
        assert "events" not in _recorded(_coverage({"profile": profile})), profile


def test_an_absent_profile_is_the_api_servers_default_and_says_so() -> None:
    for audit in ({}, {"profile": ""}, {"customRules": []}):
        cov = _coverage(audit)
        assert cov["profile"] == "Default" and cov["profileAssumed"] is True
        assert "unset, so the API server's default" in cov["statement"]
    # No `audit` block at all is the same case: the field default is Default, not "nothing configured".
    cov = _coverage(None)
    assert cov["profile"] == "Default" and cov["profileAssumed"] is True


def test_a_profile_this_build_does_not_know_is_undecidable_rather_than_empty() -> None:
    """A later OpenShift could add one. Reporting it as 'records nothing' is a confident wrong answer."""
    cov = _coverage({"profile": "SomethingNewer"})
    assert {r["recorded"] for r in cov["records"]} == {"unknown"}
    assert "'SomethingNewer'" in cov["statement"] and "not a profile this build knows" in cov["statement"]


def test_a_custom_rule_overrides_the_top_level_profile_for_its_group() -> None:
    cov = _coverage(
        {
            "profile": "AllRequestBodies",
            "customRules": [
                {"group": "system:authenticated:oauth", "profile": "None"},
                {"group": "noisy-controllers", "profile": "Default"},
                "not-a-mapping",
            ],
        }
    )
    assert _recorded(cov) == EXPECTED["AllRequestBodies"]
    groups = cov["groups"]
    assert [g["group"] for g in groups] == ["system:authenticated:oauth", "noisy-controllers"]
    assert [g["precedence"] for g in groups] == [0, 1]
    assert _recorded(groups[0]) == set() and _recorded(groups[1]) == EXPECTED["Default"]
    assert "No request from system:authenticated:oauth is recorded" in groups[0]["statement"]
    # Precedence is a property of the list, and it is what a reader gets wrong: the FIRST match applies, so a
    # user in both groups is not covered by the stricter entry.
    assert any("several of these groups" in w for w in cov["cannotSay"])


def test_a_custom_rule_without_a_group_or_profile_still_reports_something() -> None:
    cov = _coverage({"customRules": [{"profile": "None"}, {"group": "g"}]})
    assert cov["groups"][0]["group"] == "(unnamed group)" and _recorded(cov["groups"][0]) == set()
    # An entry with no profile: the field is required by the API, but a file is a file. The documented default
    # is Default, which is what a cluster would apply.
    assert cov["groups"][1]["profile"] == "Default" and _recorded(cov["groups"][1]) == EXPECTED["Default"]


def test_it_says_nothing_when_the_object_was_not_collected() -> None:
    """The singleton always exists on OpenShift, so its absence means nobody collected it (the KN-S035 shape)."""
    assert detection.coverage(load_documents("")) is None
    pod = yaml.safe_dump({"apiVersion": "v1", "kind": "Pod", "metadata": {"name": "p"}})
    assert detection.coverage(load_documents(pod)) is None
    # An APIServer in another group is a different resource that happens to share a name.
    assert detection.coverage(load_documents(_apiserver({"profile": "None"}, group="example.com/v1"))) is None


def test_two_objects_name_the_second_rather_than_silently_picking_one() -> None:
    text = _apiserver({"profile": "None"}) + "---\n" + _apiserver({"profile": "Default"}, name="other")
    cov = detection.coverage(load_documents(text))
    assert cov is not None and cov["profile"] == "None" and cov["alsoPresent"] == ["APIServer/other"]


def test_the_report_carries_it_only_when_the_object_is_there() -> None:
    with_object = analyze(_apiserver({"profile": "None"}), platform="openshift", version="4.20").as_dict()
    assert with_object["detectionCoverage"]["profile"] == "None"
    pod = yaml.safe_dump(
        {
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "p", "namespace": "shop"},
            "spec": {"containers": [{"name": "c", "image": "quay.io/o/a:1"}]},
        }
    )
    assert "detectionCoverage" not in analyze(pod, platform="openshift", version="4.20").as_dict()


def test_it_agrees_with_the_rule_that_reports_the_same_object() -> None:
    """KN-S035 reports the two settings that record nothing; this says what the others do record.

    They are two readings of one field, so they cannot disagree: wherever the statement is that nothing is
    recorded -- cluster-wide or for one group -- the rule must have reported it, and wherever the rule is
    silent, something must be recorded.
    """
    cases: list[tuple[Any, bool]] = [
        ({"profile": "None"}, True),
        ({"profile": "Default"}, False),
        ({"profile": "AllRequestBodies"}, False),
        ({"profile": "Default", "customRules": [{"group": "g", "profile": "None"}]}, True),
        ({"profile": "Default", "customRules": [{"group": "g", "profile": "WriteRequestBodies"}]}, False),
        ({}, False),
    ]
    for audit, reported in cases:
        text = _apiserver(audit)
        findings = [f for f in analyze(text, platform="openshift", version="4.20").findings if f.rule_id == "KN-S035"]
        cov = _coverage(audit)
        nothing = not _recorded(cov) or any(not _recorded(g) for g in cov.get("groups", ()))
        assert bool(findings) == reported, audit
        assert nothing == reported, f"{audit}: coverage and KN-S035 disagree"


def test_the_text_block_prints_every_row_and_every_limit() -> None:
    cov = _coverage({"profile": "Default", "customRules": [{"group": "g", "profile": "None"}]})
    out = detection.render_text(cov)
    for row in cov["records"]:
        assert row["what"] in out
    for limit in cov["cannotSay"]:
        assert limit in out
    assert "group g (customRules[0], profile None)" in out
    assert out.endswith("\n") and "\n\n\n" not in out


def test_the_category_table_cannot_name_a_profile_that_does_not_exist() -> None:
    """A typo in `yes_for` would make a category silently unrecorded under every profile."""
    for cid, _what, yes_for, because in detection.CATEGORIES:
        assert set(yes_for) <= set(detection.PROFILES), cid
        assert because and not because.endswith("."), cid
    assert detection.DEFAULT_PROFILE in detection.PROFILES
    assert set(EXPECTED) == set(detection.PROFILES)
    ids = [c[0] for c in detection.CATEGORIES]
    assert len(ids) == len(set(ids))
