"""kube-noob is an MCP server, so every result lands in a model's context window.

Two results were far larger than the information in them. `audit` repeated each rule's `title`, `severity`,
`stage`, `category`, `remediation`, `citations`, `stackroxPolicies` and `controls` on every finding -- 37 findings
over 13 distinct rules on one bundled example, so each constant appeared about three times. And
`policy generate` returned its whole rendered policy set as one 358 KB YAML string, about 96 000 tokens, with no
way to write it to a file instead.

Neither is a correctness bug. Both are a caller's context spent on bytes that carry nothing, which for an MCP
server is the same kind of waste as a wrong answer is a wrong answer: the caller pays and gets nothing back.
"""

from __future__ import annotations

import json
from pathlib import Path

from kube_noob.audit.compact import PER_RULE, compact_report, expand_report

EXAMPLE = Path(__file__).resolve().parent.parent / "examples" / "netpol-shop.yaml"


def _report() -> dict:
    from kube_noob.audit.engine import analyze
    from kube_noob.yamlio import load_documents

    return analyze(load_documents(EXAMPLE.read_text(encoding="utf-8"))).as_dict()


def test_compacting_hoists_each_rule_constant_out_of_every_finding() -> None:
    rep = _report()
    out = compact_report(rep)
    assert out["ruleInfo"], "the per-rule constants must be collected"
    for finding in out["findings"]:
        for key in ("title", "remediation", "citations", "severity", "controls"):
            assert key not in finding, f"{key} is a property of the rule, not of each finding"
        assert finding["ruleId"] in out["ruleInfo"]
        # what actually varies per finding has to survive
        assert "resource" in finding and "message" in finding


def test_compacting_is_lossless() -> None:
    """The point of hoisting rather than dropping: a caller rehydrates by ruleId and gets the original back."""
    rep = _report()
    assert expand_report(compact_report(rep)) == rep


def test_compacting_is_a_real_saving_on_a_bundled_example() -> None:
    """Asserted as a ratio rather than a byte count, so the test does not break when a rule's text is edited."""
    rep = _report()
    before = len(json.dumps(rep, separators=(",", ":")))
    after = len(json.dumps(compact_report(rep), separators=(",", ":")))
    assert after < before * 0.8, f"expected a meaningful saving, got {before} -> {after}"


def test_compacting_a_report_with_no_findings_changes_nothing_material() -> None:
    rep = {"findings": [], "summary": {}}
    out = compact_report(rep)
    assert out["findings"] == [] and out["ruleInfo"] == {}
    assert expand_report(out) == rep


def test_one_finding_per_rule_still_round_trips() -> None:
    """The worst case for the idea: nothing repeats, so hoisting can only add the map. It must still be lossless,
    and it must not claim a saving."""
    rep = _report()
    seen: set[str] = set()
    unique = [f for f in rep["findings"] if not (f["ruleId"] in seen or seen.add(f["ruleId"]))]
    rep = {**rep, "findings": unique}
    assert expand_report(compact_report(rep)) == rep


def test_asking_for_a_file_does_not_also_inline_the_whole_policy_set(tmp_path: Path, capsys) -> None:
    """`policy generate -o FILE` wrote the file and still returned all 358 KB of YAML in the JSON -- so the result
    was LARGER with `-o` than without, because it added the path on top. A caller that names a file has said where
    it wants the bytes."""
    from kube_noob.cli import main

    out = tmp_path / "policies.yaml"
    assert main(["--format", "json", "policy", "generate", "--platform", "openshift", "-o", str(out)]) == 0
    result = json.loads(capsys.readouterr().out)
    assert "yaml" not in result, "the YAML went to the file; inlining it as well spends the caller's context twice"
    assert result["output"] == str(out)
    assert result["bytes"] == out.stat().st_size, "say how big the file is, so a caller knows what it asked for"
    assert out.stat().st_size > 1000, "and the file must actually have the policies in it"
    # the structured summary a caller reasons over is still there
    assert result["generated"] and result["documents"]


def test_without_a_file_the_policy_set_is_still_returned_inline() -> None:
    """The flag changes where the bytes go, not whether they are available: with no `-o` there is nowhere else
    to put them."""
    from kube_noob.generate import policies

    g = policies.generate(platform="openshift", engines=policies.ENGINES, mode="audit")
    head = policies.header(g, platform="openshift", platform_version=None, mode="audit", engines=policies.ENGINES)
    assert g.yaml(head)


def test_the_audit_tool_hoists_when_asked_and_not_otherwise() -> None:
    """The saving has to be reachable through the MCP/REST tool, not only from the module. It is opt-in: the
    flat shape is what every existing caller of `/v1/audit` parses, so the default must not move under them."""
    from kube_noob import toolkit as tk

    kit = tk.Toolkit(tk.Settings())
    manifests = EXAMPLE.read_text(encoding="utf-8")
    flat = kit.audit(tk.AuditIn(manifests=manifests, platform="openshift"))
    assert "ruleInfo" not in flat, "the default shape stays flat"
    assert all("severity" in f for f in flat["findings"])

    small = kit.audit(tk.AuditIn(manifests=manifests, platform="openshift", compact=True))
    assert small["ruleInfo"], "compact=True must hoist the per-rule constants"
    assert all("severity" not in f for f in small["findings"])
    assert expand_report(small) == flat, "the tool's compact result must rehydrate to exactly the flat one"


def test_the_audit_tool_keeps_the_rule_ids_it_counts_for_telemetry() -> None:
    """`Toolkit.audit` observes `rule:<id>` per finding. Hoisting removes the rule's *constants*, never the id
    that says which rule fired, so the counters cannot be silently zeroed by turning compaction on."""
    from kube_noob import toolkit as tk

    kit = tk.Toolkit(tk.Settings())
    small = kit.audit(tk.AuditIn(manifests=EXAMPLE.read_text(encoding="utf-8"), platform="openshift", compact=True))
    assert small["findings"], "the example has findings"
    assert all(f.get("ruleId") for f in small["findings"])


def test_audit_compact_on_the_cli_changes_the_shape_but_not_the_verdict(capsys) -> None:
    """A gate reads the exit code. Compaction moves `severity` off the findings, so if the exit code were
    computed from the emitted shape instead of the audit, `--compact` would turn every failing gate green."""
    from kube_noob.cli import main

    args = ["--format", "json", "audit", "-f", str(EXAMPLE), "--platform", "openshift"]
    plain_code = main(args)
    plain = json.loads(capsys.readouterr().out)
    compact_code = main([*args, "--compact"])
    small = json.loads(capsys.readouterr().out)

    assert compact_code == plain_code, "the flag must not change the verdict a gate acts on"
    assert small["ruleInfo"], "--compact must hoist"
    assert "ruleInfo" not in plain
    assert expand_report(small) == plain, "and the hoisted report must rehydrate to the plain one"
    assert len(json.dumps(small)) < len(json.dumps(plain)) * 0.9


# --- the excepted list ---------------------------------------------------------------------------------------
# The first version of this module compacted `findings` and nothing else. `Toolkit.audit` puts the findings an
# exceptions file accepted in a separate top-level `excepted` list, so every caller with an exceptions file --
# which is every CI caller -- got the duplication straight back, and a report whose two finding lists had
# different shapes. The tests above missed it because they call `analyze(...).as_dict()` directly and so never
# produce an `excepted` key at all; these go through the tool the way a caller does.

EXCEPTION_LIST = """apiVersion: kube-noob.io/v1
kind: ExceptionList
exceptions:
- id: EXC-001
  rule: KN-N001
  scope: {namespace: web, kind: Deployment, name: frontend}
  owner: team-net
  reason: North-south traffic is handled at the edge gateway; reviewed with security
  expires: 2027-06-30
"""


def _audit(compact: bool) -> dict:
    from kube_noob.config import Settings
    from kube_noob.toolkit import AuditIn, Toolkit

    return Toolkit(Settings()).audit(
        AuditIn(manifests=EXAMPLE.read_text(encoding="utf-8"), exceptions=EXCEPTION_LIST, compact=compact)
    )


def test_the_excepted_findings_are_compacted_too() -> None:
    out = _audit(compact=True)
    assert out["excepted"], "the exception must have matched, or this test proves nothing"
    for entry in out["excepted"]:
        for key in PER_RULE:
            assert key not in entry, f"{key} is a property of the rule; it must not stay inline on an excepted one"
        assert entry["ruleId"] in out["ruleInfo"]
        assert "exception" in entry, "the exception block is per-finding and must survive"


def test_a_report_with_exceptions_round_trips_through_the_tool() -> None:
    assert expand_report(_audit(compact=True)) == _audit(compact=False)


def test_both_finding_lists_end_up_the_same_shape() -> None:
    """One report must not hold hoisted findings beside un-hoisted ones."""
    out = _audit(compact=True)
    keys: set[str] = set()
    for f in out["findings"] + out["excepted"]:
        keys |= set(f)
    assert not keys & set(PER_RULE)
