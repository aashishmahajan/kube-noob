"""Hoist each rule's constants out of every finding, so one result is not three copies of the same text.

kube-noob is an MCP server: every result it returns is spent out of a caller's context window. An audit of one
bundled example produces 37 findings over 13 distinct rules, and each finding carried that rule's ``title``,
``severity``, ``stage``, ``category``, ``remediation``, ``citations``, ``stackroxPolicies`` and ``controls`` --
so each of those appeared about three times, for about 37% of the serialized result.

The fix is a hoist, not a trim: the constants move into a ``ruleInfo`` map keyed by rule id, and the findings keep
only what varies between them (which object, where in the file, what the message said). ``expand_report`` puts it
back exactly, so nothing is lost and a caller that wants the flat shape can have it in one call. That is the whole
reason to hoist rather than drop fields a model "probably does not need": dropping is a guess about the caller,
and this is not.

Both finding lists are hoisted against the same map. ``Toolkit.audit`` puts the findings an exceptions file
accepted in a separate top-level ``excepted`` list, and the first version of this module compacted ``findings``
alone -- so any caller with an exceptions file, which is every CI caller, got the duplication straight back in
``excepted`` and two finding lists of different shapes in one report.
"""

from __future__ import annotations

from typing import Any

# Properties of the rule, identical on every finding that rule produces.
PER_RULE: tuple[str, ...] = (
    "title",
    "severity",
    "stage",
    "category",
    "remediation",
    "citations",
    "stackroxPolicies",
    "controls",
)

# The finding lists a report can carry. `excepted` entries also hold an `exception` block, which is per-finding
# and so is never hoisted.
FINDING_LISTS: tuple[str, ...] = ("findings", "excepted")


def _compact_list(findings: list[dict[str, Any]], rule_info: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    """Strip the per-rule fields from each finding, collecting them into the shared ``rule_info``."""
    out: list[dict[str, Any]] = []
    for finding in findings:
        rule_id = str(finding.get("ruleId"))
        hoisted = {k: finding[k] for k in PER_RULE if k in finding}
        existing = rule_info.get(rule_id)
        if existing is None:
            rule_info[rule_id] = hoisted
        elif existing != hoisted:
            # Two findings of one rule disagreed about a field this module calls constant. Rather than silently
            # keep the first and lose the second, leave the differing fields on the finding itself.
            differing = {k: v for k, v in hoisted.items() if existing.get(k) != v}
            out.append({k: v for k, v in finding.items() if k not in PER_RULE or k in differing})
            continue
        out.append({k: v for k, v in finding.items() if k not in PER_RULE})
    return out


def compact_report(report: dict[str, Any]) -> dict[str, Any]:
    """``report`` with each rule's constants collected into ``ruleInfo`` and removed from the findings.

    Every finding list in the report is compacted against one shared map, so a rule that fired both in the open
    findings and in the excepted ones is described once. The findings keep their order and their per-finding
    fields. A report with no findings gets an empty map rather than no key, so a caller never has to test for the
    key's presence.
    """
    rule_info: dict[str, dict[str, Any]] = {}
    lists = {k: _compact_list(report.get(k) or [], rule_info) for k in FINDING_LISTS if k in report}
    rest = {k: v for k, v in report.items() if k not in FINDING_LISTS}
    return {**rest, "ruleInfo": rule_info, **lists}


def expand_report(report: dict[str, Any]) -> dict[str, Any]:
    """The inverse of :func:`compact_report`: every finding carries its rule's fields again.

    A field left on a finding by the disagreement branch above wins over the map, so a round trip is exact even
    where the "constant" was not one.
    """
    rule_info = report.get("ruleInfo") or {}
    # Put the keys back in the order `Finding.as_dict` writes them, so a diff of the two shapes is empty.
    order = ("ruleId", "title", "severity", "stage", "category")

    def restore(f: dict[str, Any]) -> dict[str, Any]:
        merged = {**{k: v for k, v in (rule_info.get(str(f.get("ruleId"))) or {}).items() if k not in f}, **f}
        return {**{k: merged[k] for k in order if k in merged}, **{k: v for k, v in merged.items() if k not in order}}

    lists = {k: [restore(f) for f in (report.get(k) or [])] for k in FINDING_LISTS if k in report}
    rest = {k: v for k, v in report.items() if k not in FINDING_LISTS and k != "ruleInfo"}
    return {**rest, **lists}
