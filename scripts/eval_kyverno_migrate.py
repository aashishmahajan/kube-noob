#!/usr/bin/env python3
"""Measure ``policy migrate-check`` against kyverno/policies: does its verdict agree with what upstream converted?

kyverno/policies removed its legacy samples after the 1.19 branch and recorded every one of them in
``.github/legacy-policy-migration.json`` on main: its status (``equivalent``: a CEL sample covers it, ``partial``: a CEL
sample with gaps, ``missing``: none yet), the CEL kind it should become (``desiredKind``) and the CEL files that replace
it. This script runs migrate-check on each legacy sample (from a clone of the release-1.19 branch) and compares:

- kind: the CEL kinds migrate-check names for the policy against ``desiredKind`` (all samples) and against the kinds of
  the upstream CEL files (equivalent samples);
- feasibility: an upstream conversion exists (equivalent), so migrate-check should not call any of its rules blocked;
- lookups: a rule migrate-check calls manual because of a context lookup (apiCall, configMap, globalReference,
  imageRegistry) should be one whose upstream CEL uses a lookup library (resource., http., globalContext.,
  image.GetMetadata);
- draft scope: the resources a draft matches should be among the resources the upstream CEL policy matches.

Missing samples say nothing either way (upstream has not converted them yet); their verdicts are reported as counts.
Nothing from either clone is copied into the repository.

Usage:
  git clone --depth 1 --branch release-1.19 https://github.com/kyverno/policies <legacy>
  git clone --depth 1 https://github.com/kyverno/policies <main>
  python scripts/eval_kyverno_migrate.py --legacy <legacy> --main <main> [--json <file>]
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any

import yaml

from kube_noob import kyverno_migrate as km

# The lookup functions of cel-libraries.mdx (Resource, HTTP, GlobalContext and ImageData libraries).
LOOKUPS = (
    "resource.Get",
    "resource.List",
    "resource.Post",
    "http.Get",
    "http.Post",
    "globalContext.Get",
    "image.GetMetadata",
)
LOOKUP_KEYS = (".apiCall", ".configMap", ".globalReference", ".imageRegistry")


def _base(kind: str) -> str:
    return kind.removeprefix("Namespaced")


def _cel_docs(main: Path, paths: list[str]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for rel in paths:
        for doc in yaml.safe_load_all((main / rel).read_text(encoding="utf-8")):
            # apiVersion is <group>/<version>: compare the API group whole, not as a string prefix
            group, sep, _version = (
                str(doc.get("apiVersion", "")).partition("/") if isinstance(doc, dict) else ("", "", "")
            )
            if sep and group == "policies.kyverno.io":
                out.append(doc)
    return out


def _resources(spec: dict[str, Any]) -> set[str]:
    rules = (spec.get("matchConstraints") or {}).get("resourceRules") or []
    return {r for rule in rules if isinstance(rule, dict) for r in rule.get("resources") or []}


def evaluate(legacy: Path, main: Path) -> dict[str, Any]:
    audit = json.loads((main / ".github" / "legacy-policy-migration.json").read_text(encoding="utf-8"))
    rows: list[dict[str, Any]] = []
    for sample in audit["samples"]:
        text = (legacy / sample["path"]).read_text(encoding="utf-8")
        report = km.check(text)
        ref = f"{sample['kind']}/{sample['name']}"
        found = [p for p in report["policies"] if p["policy"] == ref]
        if not found:
            rows.append({"path": sample["path"], "status": sample["status"], "error": "policy not found"})
            continue
        p = found[0]
        cel = _cel_docs(main, sample["equivalents"])
        cel_text = json.dumps(cel)
        lookup_rules = [
            r["rule"] for r in p["rules"] if any(k in f["path"] for f in r["findings"] for k in LOOKUP_KEYS)
        ]
        draft_resources: set[str] = set()
        for r in p["rules"]:
            if "draft" in r:
                draft_resources |= _resources(yaml.safe_load(r["draft"].split("---\n", 1)[1])["spec"])
        rows.append(
            {
                "path": sample["path"],
                "status": sample["status"],
                "desired": sorted(k.strip() for k in sample["desiredKind"].split("+")),
                "upstreamKinds": sorted({str(d["kind"]) for d in cel}),
                "verdict": p["verdict"],
                "ruleVerdicts": [r["verdict"] for r in p["rules"]],
                "targets": sorted({_base(t) for t in p["targets"]}),
                "lookupRules": lookup_rules,
                "upstreamLookup": any(fn in cel_text for fn in LOOKUPS),
                "draftResources": sorted(draft_resources),
                "upstreamResources": sorted({r for d in cel for r in _resources(d.get("spec") or {})}),
                "drafts": sum(1 for r in p["rules"] if "draft" in r),
            }
        )
    return {"source": {k: audit[k] for k in ("sourceRepository", "sourceRevision", "upstreamIssue")}, "rows": rows}


def summarise(result: dict[str, Any]) -> dict[str, Any]:
    rows = [r for r in result["rows"] if "error" not in r]
    eq = [r for r in rows if r["status"] == "equivalent"]
    kind_all = sum(r["targets"] == r["desired"] for r in rows)
    kind_eq = sum(r["targets"] == r["upstreamKinds"] for r in eq)
    feasible = [r for r in eq if r["verdict"] != "blocked"]
    lookups = [r for r in rows if r["status"] in ("equivalent", "partial") and r["upstreamKinds"] and r["lookupRules"]]
    drafted = [r for r in eq if r["drafts"]]
    scope = [r for r in drafted if set(r["draftResources"]) <= set(r["upstreamResources"])]
    by_status = {
        status: dict(Counter(r["verdict"] for r in rows if r["status"] == status))
        for status in ("equivalent", "partial", "missing")
    }
    rules = Counter(v for r in rows for v in r["ruleVerdicts"])
    return {
        "samples": len(result["rows"]),
        "errors": [r for r in result["rows"] if "error" in r],
        "kindAgreesWithDesiredKind": f"{kind_all}/{len(rows)}",
        "kindAgreesWithUpstreamFiles": f"{kind_eq}/{len(eq)}",
        "convertedUpstreamNotBlocked": f"{len(feasible)}/{len(eq)}",
        "blockedButConverted": [r["path"] for r in eq if r["verdict"] == "blocked"],
        "lookupPoliciesWhereUpstreamUsesALookup": f"{sum(r['upstreamLookup'] for r in lookups)}/{len(lookups)}",
        "draftScopeWithinUpstream": f"{len(scope)}/{len(drafted)}",
        "draftScopeOutside": [
            (r["path"], r["draftResources"], r["upstreamResources"]) for r in drafted if r not in scope
        ],
        "policyVerdictsByUpstreamStatus": by_status,
        "ruleVerdicts": dict(rules),
        "kindDisagreements": [(r["path"], r["targets"], r["desired"]) for r in rows if r["targets"] != r["desired"]],
    }


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--legacy", required=True, type=Path, help="clone of kyverno/policies, branch release-1.19")
    ap.add_argument("--main", required=True, type=Path, help="clone of kyverno/policies, branch main")
    ap.add_argument("--json", type=Path, help="write every row and the summary here")
    a = ap.parse_args(argv)
    result = evaluate(a.legacy, a.main)
    summary = summarise(result)
    if a.json:
        a.json.write_text(json.dumps({**result, "summary": summary}, indent=1), encoding="utf-8")
    short = {k: v for k, v in summary.items() if k not in ("kindDisagreements", "draftScopeOutside")}
    print(json.dumps(short, indent=1))
    print(
        f"kind disagreements: {len(summary['kindDisagreements'])}; draft scope outside: "
        f"{len(summary['draftScopeOutside'])}"
    )
    return 1 if summary["errors"] else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
