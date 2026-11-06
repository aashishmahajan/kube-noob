"""N14: one bundle, two views, one set of numbers (G246).

`audit_manifests` and `fedramp_ksi` are two readings of the same audit, and until now each ran its own: the KSI
view took no exception list, so a signed-off finding was counted open on a compliance page, and it audited at
INFO while `audit` defaults to `low`, so the same files produced two different figures depending on which tool
asked. Each was internally honest, which is why the fix was a decision rather than a patch: **the KSI view is a
projection of one audit**, so it takes the audit's threshold and the audit's exceptions, and anything a
threshold removed is reported as `withheld` rather than as clean.

What is asserted here is the agreement, not either number on its own.
"""

from __future__ import annotations

import datetime as dt
import json
import pathlib
import subprocess
import sys
from typing import Any

import pytest
import yaml

ROOT = pathlib.Path(__file__).resolve().parent.parent

#: One container that is clean except for an unpinned (INFO) image and a privileged flag (HIGH), so the bundle
#: has a finding on either side of the default threshold and one worth excepting.
BUNDLE = yaml.safe_dump(
    {
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": {"name": "web", "namespace": "shop"},
        "spec": {
            "replicas": 2,
            "selector": {"matchLabels": {"app": "web"}},
            "template": {
                "metadata": {"labels": {"app": "web"}},
                "spec": {
                    "containers": [
                        {
                            "name": "web",
                            "image": "quay.io/my-org/web:1.4.2",
                            "securityContext": {
                                "privileged": True,
                                "allowPrivilegeEscalation": False,
                                "runAsNonRoot": True,
                                "runAsUser": 1001,
                                "readOnlyRootFilesystem": True,
                                "capabilities": {"drop": ["ALL"]},
                                "seccompProfile": {"type": "RuntimeDefault"},
                            },
                            "resources": {
                                "requests": {"cpu": "10m", "memory": "32Mi"},
                                "limits": {"memory": "64Mi"},
                            },
                        }
                    ]
                },
            },
        },
    }
)


def _exceptions(rule: str = "KN-S001") -> str:
    expires = (dt.date.today() + dt.timedelta(days=120)).isoformat()
    return yaml.safe_dump(
        {
            "apiVersion": "kube-noob.io/v1",
            "kind": "ExceptionList",
            "exceptions": [
                {
                    "id": "EXC-001",
                    "rule": rule,
                    "scope": {"kind": "Deployment", "namespace": "shop", "name": "web"},
                    "owner": "team-web",
                    "reason": "the legacy agent needs it until the sidecar rewrite lands",
                    "expires": expires,
                }
            ],
        }
    )


def _kit() -> Any:
    from kube_noob.config import Settings
    from kube_noob.toolkit import Toolkit

    return Toolkit(Settings())


def _views(**kw: Any) -> tuple[dict[str, Any], dict[str, Any]]:
    """The audit and the KSI page for one bundle, with the bundle shape stated to both.

    `partial_bundle` is the one input whose DEFAULT differs between the two tools, deliberately: a pasted
    fragment is not a directory, and a rule that fires because another object is absent cannot tell a real gap
    from an object the caller did not paste. The reconciliation N14 is about is that given the same inputs the
    two views report the same numbers, so the tests state it rather than relying on either default.
    """
    import kube_noob.toolkit as tk

    kw.setdefault("partial_bundle", False)
    kit = _kit()
    audit = kit.audit(tk.AuditIn(manifests=BUNDLE, platform="kubernetes", **kw))
    ksi = kit.fedramp_ksi(tk.KsiIn(manifests=BUNDLE, platform="kubernetes", **kw))
    return audit, ksi


def _indicators_of(rule_id: str) -> set[str]:
    from kube_noob.audit.controls import RULE_CONTROLS
    from kube_noob.audit.fedramp import BY_CONTROL

    return {i for c in RULE_CONTROLS.get(rule_id, ()) for i in BY_CONTROL.get(c, ())}


def _mapped(rule_ids: set[str]) -> set[str]:
    """The rules that reach at least one indicator: the rest are reported under `findingsNotMapped`."""
    return {r for r in rule_ids if _indicators_of(r)}


def _counts_from(findings: list[dict[str, Any]]) -> dict[str, int]:
    """How many of these findings each indicator should be shown, derived from the audit's own output."""
    out: dict[str, int] = {}
    for f in findings:
        for ind in _indicators_of(str(f["ruleId"])):
            out[ind] = out.get(ind, 0) + 1
    return out


def _assert_rows_match(audit: dict[str, Any], ksi: dict[str, Any]) -> None:
    """Every indicator row's counts, recomputed from the audit report it is a projection of."""
    findings = _counts_from(audit["findings"])
    excepted = _counts_from(audit.get("excepted", []))
    for row in ksi["indicators"]:
        if not row["evidenced"]:
            assert "findings" not in row, row["id"]
            continue
        assert row["findings"] == findings.get(row["id"], 0), row["id"]
        # `excepted` is absent rather than zero when no list was passed, the same way the audit's control rows
        # leave it out: a column of zeroes reads as "nothing was excepted here", which is a claim.
        if "excepted" in audit:
            assert row["excepted"] == excepted.get(row["id"], 0), row["id"]
        else:
            assert "excepted" not in row, row["id"]


def test_the_two_views_report_the_same_exception_state() -> None:
    audit, ksi = _views(exceptions=_exceptions())
    assert audit["exceptions"] == ksi["exceptions"]
    assert [f["ruleId"] for f in audit["excepted"]] == [f["ruleId"] for f in ksi["excepted"]] == ["KN-S001"]
    # And the excepted rule is counted apart on both, not dropped from either: an owned, expiring decision about
    # a control has to stay visible, or it reads as a control nothing ever evaluated.
    assert any(c["id"] == "SC-39" and c.get("excepted") for c in audit["controlSummary"]["controls"])
    assert any(r.get("excepted") for r in ksi["indicators"])
    assert "KN-S001" not in {f["ruleId"] for f in audit["findings"]}
    # `rulesFired` is what fired, not what is open -- an excepted finding did fire, and the row counts it under
    # `excepted` rather than `findings`, which is how the audit's control rows read too.
    rows = [r for r in ksi["indicators"] if r["id"] in _indicators_for("SC-39")]
    assert rows and all("KN-S001" in r["rulesFired"] for r in rows)
    assert all(r["excepted"] >= 1 for r in rows)
    _assert_rows_match(audit, ksi)


def test_the_two_views_report_the_same_findings() -> None:
    audit, ksi = _views()
    open_rules = {f["ruleId"] for f in audit["findings"]}
    fired = {r for row in ksi["indicators"] for r in row["rulesFired"]}
    unmapped = {row["ruleId"] for row in ksi.get("findingsNotMapped", [])}
    assert fired == _mapped(open_rules), (fired, open_rules)
    assert unmapped == open_rules - _mapped(open_rules)
    _assert_rows_match(audit, ksi)


def test_a_finding_a_threshold_hid_is_withheld_on_both_and_clean_on_neither() -> None:
    """The INFO finding (an unpinned image) is below the default threshold on both views."""
    audit, ksi = _views()
    assert "KN-S012" not in {f["ruleId"] for f in audit["findings"]}
    assert "KN-S012" in audit["fired_rules"] if "fired_rules" in audit else True
    cm2 = next(c for c in audit["controlSummary"]["controls"] if c["id"] == "CM-2")
    assert cm2["withheld"] >= 1 and not cm2["findings"]
    rows = [r for r in ksi["indicators"] if r["id"] in _indicators_for("CM-2")]
    assert rows and all(r["withheld"] >= 1 for r in rows), rows
    assert all("KN-S012" not in r["rulesFired"] for r in rows)
    # At INFO both show it as a finding instead, and neither calls it withheld.
    audit_info, ksi_info = _views(min_severity="info")
    assert "KN-S012" in {f["ruleId"] for f in audit_info["findings"]}
    rows_info = [r for r in ksi_info["indicators"] if r["id"] in _indicators_for("CM-2")]
    assert all("KN-S012" in r["rulesFired"] for r in rows_info)


def _indicators_for(control: str) -> set[str]:
    from kube_noob.audit.fedramp import BY_CONTROL

    return set(BY_CONTROL.get(control, ()))


def test_the_ksi_default_threshold_is_the_audits_default() -> None:
    """The defect was a default, so the default is what the test pins."""
    import kube_noob.toolkit as tk

    kit = _kit()
    plain = kit.fedramp_ksi(tk.KsiIn(manifests=BUNDLE, platform="kubernetes"))
    low = kit.fedramp_ksi(tk.KsiIn(manifests=BUNDLE, platform="kubernetes", min_severity="low"))
    assert plain == low
    assert tk.KsiIn(manifests=BUNDLE).min_severity == tk.AuditIn(manifests=BUNDLE).min_severity
    # And the one default that still differs is the bundle shape, which is a fact about the input rather than
    # about the view: a pasted fragment is not a directory. It is documented on the field, not silent.
    assert tk.KsiIn(manifests=BUNDLE).partial_bundle is True
    assert tk.AuditIn(manifests=BUNDLE).partial_bundle is False
    assert "N14" in tk.KsiIn.model_fields["partial_bundle"].description


def _cli(*args: str, stdin: str) -> tuple[int, str]:
    r = subprocess.run(
        [sys.executable, "-m", "kube_noob.cli", *args],
        capture_output=True,
        text=True,
        cwd=ROOT,
        input=stdin,
        env={"PATH": "/usr/bin:/bin", "PYTHONPATH": str(ROOT / "src"), "HOME": "/tmp"},
        check=False,
    )
    return r.returncode, r.stdout + r.stderr


def test_the_command_and_the_tool_are_one_implementation(tmp_path: pathlib.Path) -> None:
    """Two implementations of one view is what N14 was, so the command now delegates to the tool."""
    exceptions = tmp_path / "exceptions.yaml"
    exceptions.write_text(_exceptions(), encoding="utf-8")
    code, out = _cli(
        "ksi",
        "-f",
        "-",
        "--platform",
        "kubernetes",
        "--exceptions",
        str(exceptions),
        "--format",
        "json",
        stdin=BUNDLE,
    )
    assert code == 0, out
    page = json.loads(out)
    _, tool = _views(exceptions=_exceptions(), partial_bundle=True)  # stdin is one document, so the CLI says partial
    assert page["exceptions"] == tool["exceptions"]
    assert [f["ruleId"] for f in page["excepted"]] == [f["ruleId"] for f in tool["excepted"]]
    assert page["indicators"] == tool["indicators"]


def test_a_refused_exception_is_refused_the_same_way_on_both() -> None:
    """An expiry too far out is refused by the reviewer, and a KSI page must not quietly count it active."""
    import kube_noob.toolkit as tk

    far = yaml.safe_load(_exceptions())
    far["exceptions"][0]["expires"] = "2099-01-01"
    text = yaml.safe_dump(far)
    kit = _kit()
    audit = kit.audit(tk.AuditIn(manifests=BUNDLE, platform="kubernetes", exceptions=text))
    ksi = kit.fedramp_ksi(tk.KsiIn(manifests=BUNDLE, platform="kubernetes", exceptions=text))
    assert audit["exceptions"]["counts"]["refused"] == ksi["exceptions"]["counts"]["refused"] == 1
    assert audit["exceptions"]["gate"] is False and ksi["exceptions"]["gate"] is False
    assert "KN-S001" in {f["ruleId"] for f in audit["findings"]}
    assert "KN-S001" in {r for row in ksi["indicators"] for r in row["rulesFired"]}


@pytest.mark.parametrize("severity", ["info", "low", "medium", "high"])
def test_every_threshold_keeps_the_two_views_in_step(severity: str) -> None:
    audit, ksi = _views(min_severity=severity)
    open_rules = {f["ruleId"] for f in audit["findings"]}
    fired = {r for row in ksi["indicators"] for r in row["rulesFired"]}
    assert fired == _mapped(open_rules), severity
    _assert_rows_match(audit, ksi)
    audit_x, ksi_x = _views(min_severity=severity, exceptions=_exceptions())
    _assert_rows_match(audit_x, ksi_x)
