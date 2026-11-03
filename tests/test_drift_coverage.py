"""An object kube-noob could not read is not an object that went away.

`collect_live` returns what it could not read, and `snapshot`, `diff` and `markdown` never received it. So when a
service account lost `list networkpolicies` between two runs, the objects simply vanished from the second
snapshot and the report said they had been **removed** and their findings **fixed**. An RBAC regression was
published as a security improvement, in the one artefact an operator reads every morning.

`attack_paths` already carries its `notRead` into its output and `build/oci` does the same, so this was drift
being the exception rather than a gap nobody had thought about.
"""

from __future__ import annotations

from typing import Any

from kube_noob import drift

NETPOL = {
    "apiVersion": "networking.k8s.io/v1",
    "kind": "NetworkPolicy",
    "metadata": {"name": "allow-all", "namespace": "prod", "resourceVersion": "1"},
    "spec": {"podSelector": {}, "ingress": [{}], "policyTypes": ["Ingress"]},
}
DEPLOY = {
    "apiVersion": "apps/v1",
    "kind": "Deployment",
    "metadata": {"name": "web", "namespace": "prod", "resourceVersion": "1"},
    "spec": {"template": {"spec": {"containers": [{"name": "c", "image": "web@sha256:" + "a" * 64}]}}},
}


def _snap(objects: list[dict[str, Any]], when: str, not_read: list[str] | None = None) -> dict[str, Any]:
    import datetime as dt

    return drift.snapshot(
        objects,
        source="live",
        platform="kubernetes",
        taken_at=dt.datetime.fromisoformat(when),
        not_read=not_read or [],
    )


def test_the_snapshot_keeps_what_it_could_not_read() -> None:
    """Without this the record dies in `collect_live`'s return value: the CLI prints the first five to stderr and
    the scheduled job logs the first three, and nothing durable holds it."""
    snap = _snap([DEPLOY], "2026-11-01T00:00:00+00:00", ["networkpolicies in prod: forbidden"])
    assert snap["notRead"] == ["networkpolicies in prod: forbidden"]
    assert _snap([DEPLOY], "2026-11-01T00:00:00+00:00")["notRead"] == []


def test_an_object_that_could_not_be_read_is_not_reported_as_removed() -> None:
    """The headline case. Run 1 reads the NetworkPolicy; run 2 is refused it. The object must not appear under
    'removed', because kube-noob does not know whether it is gone."""
    before = _snap([NETPOL, DEPLOY], "2026-11-01T00:00:00+00:00")
    after = _snap([DEPLOY], "2026-11-02T00:00:00+00:00", ["networkpolicies in prod: forbidden"])
    report = drift.diff(before, after)
    removed = report["objects"]["removed"]
    assert not any("NetworkPolicy" in k for k in removed), removed
    undetermined = report["objects"]["undetermined"]
    assert any("NetworkPolicy" in k for k in undetermined), undetermined


def test_a_finding_on_an_unreadable_object_is_not_reported_as_fixed() -> None:
    """Worse than the removal: `allow-all` trips a real rule, so the old report claimed a finding had been fixed
    when nothing had been fixed and kube-noob had merely lost permission to look."""
    before = _snap([NETPOL, DEPLOY], "2026-11-01T00:00:00+00:00")
    assert before["findings"], "the fixture must trip at least one rule for this test to mean anything"
    after = _snap([DEPLOY], "2026-11-02T00:00:00+00:00", ["networkpolicies in prod: forbidden"])
    report = drift.diff(before, after)
    fixed = [r["resource"] for r in report["findings"]["fixed"]]
    assert not any("NetworkPolicy" in r for r in fixed), fixed
    undet = [r["resource"] for r in report["findings"]["undetermined"]]
    assert any("NetworkPolicy" in r for r in undet), undet


def test_a_genuinely_deleted_object_is_still_reported_as_removed() -> None:
    """The fix must not turn every removal into an unknown: when nothing was unreadable, a gone object is gone."""
    before = _snap([NETPOL, DEPLOY], "2026-11-01T00:00:00+00:00")
    after = _snap([DEPLOY], "2026-11-02T00:00:00+00:00")
    report = drift.diff(before, after)
    assert any("NetworkPolicy" in k for k in report["objects"]["removed"])
    assert report["objects"]["undetermined"] == []
    assert any("NetworkPolicy" in r["resource"] for r in report["findings"]["fixed"])


def test_an_unreadable_resource_does_not_launder_an_unrelated_removal() -> None:
    """Only the kinds that could not be read become undetermined. A Deployment that really went away while
    `networkpolicies` was refused is still a removal."""
    before = _snap([NETPOL, DEPLOY], "2026-11-01T00:00:00+00:00")
    after = _snap([], "2026-11-02T00:00:00+00:00", ["networkpolicies in prod: forbidden"])
    report = drift.diff(before, after)
    assert any("Deployment" in k for k in report["objects"]["removed"]), report["objects"]
    assert any("NetworkPolicy" in k for k in report["objects"]["undetermined"]), report["objects"]


def test_the_report_says_out_loud_that_it_could_not_read_everything() -> None:
    """A record in the JSON that the Markdown does not print is a record nobody sees: the operator reads the
    rendered report, and the summary line is what they read first."""
    before = _snap([NETPOL, DEPLOY], "2026-11-01T00:00:00+00:00")
    after = _snap([DEPLOY], "2026-11-02T00:00:00+00:00", ["networkpolicies in prod: forbidden"])
    text = drift.markdown(drift.diff(before, after))
    assert "could not be read" in text.lower(), text
    assert "networkpolicies in prod" in text
    assert "## Fixed findings" not in text, text
