"""Deterministic check DSL shared by learning exercises, the eval benchmark and the training reward.

A check spec is a mapping (YAML/JSON):

    platform: openshift          # target used for the audit
    version: "4.20"              # optional platform version
    kinds: [Deployment, Service] # kinds that must be present
    schemaValid: true            # no KN-V007 findings
    maxSeverity: medium          # no finding above this severity
    forbidRules: [KN-S001]       # these rule ids must not fire (INFO-level advisories are ignored)
    minScore: 80                 # audit posture score threshold (0-100)
    assertions:                  # field assertions on the first object of a kind
      - {kind: Deployment, path: spec.replicas, gte: 2}
      - {kind: Route, path: spec.tls.termination, in: [edge, reencrypt]}
      - {kind: PodDisruptionBudget, exists: true}
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from kube_noob.audit.engine import analyze
from kube_noob.audit.model import Report, Severity
from kube_noob.errors import ManifestError
from kube_noob.yamlio import Document, load_documents

_FENCE = re.compile(r"```(?:ya?ml|yml)?\s*\n(.*?)```", re.DOTALL | re.IGNORECASE)
_PATH_TOKEN = re.compile(r"([^.\[\]]+)|\[(\d+)\]")


@dataclass
class CheckOutcome:
    name: str
    passed: bool
    detail: str
    weight: float = 1.0

    def as_dict(self) -> dict[str, Any]:
        return {"check": self.name, "passed": self.passed, "detail": self.detail, "weight": self.weight}


@dataclass
class Evaluation:
    outcomes: list[CheckOutcome]
    report: Report | None
    parsed: bool

    @property
    def score(self) -> float:
        total = sum(o.weight for o in self.outcomes)
        return 0.0 if total == 0 else sum(o.weight for o in self.outcomes if o.passed) / total

    @property
    def passed(self) -> bool:
        return self.parsed and all(o.passed for o in self.outcomes)

    def as_dict(self) -> dict[str, Any]:
        return {
            "passed": self.passed,
            "score": round(self.score, 4),
            "checks": [o.as_dict() for o in self.outcomes],
            "audit": self.report.as_dict()["summary"] if self.report else None,
            "findings": [f.as_dict() for f in self.report.findings if f.severity >= Severity.MEDIUM][:25]
            if self.report
            else [],
        }


def extract_yaml(answer: str) -> str:
    """Accept raw YAML or Markdown with fenced YAML blocks (model completions)."""
    blocks = _FENCE.findall(answer)
    if blocks:
        return "\n---\n".join(b.strip() for b in blocks)
    return answer


def get_dotted(obj: Any, path: str) -> tuple[bool, Any]:
    cur = obj
    for m in _PATH_TOKEN.finditer(path):
        key, idx = m.group(1), m.group(2)
        if idx is not None:
            if not isinstance(cur, list) or int(idx) >= len(cur):
                return False, None
            cur = cur[int(idx)]
        else:
            if not isinstance(cur, dict) or key not in cur:
                return False, None
            cur = cur[key]
    return True, cur


def _assert(docs: list[Document], a: dict[str, Any]) -> CheckOutcome:
    kind = a.get("kind")
    path = a.get("path")
    name = f"{kind}{('.' + path) if path else ''}"
    cands = [d for d in docs if d.kind == kind]
    if not cands:
        return CheckOutcome(f"assert {name}", False, f"no {kind} object found")
    if not path:
        return CheckOutcome(f"assert {name}", bool(a.get("exists", True)), f"{kind} present")
    found, val = False, None
    for d in cands:
        found, val = get_dotted(d.data, path)
        if found:
            break
    if "exists" in a:
        ok = found == bool(a["exists"])
        return CheckOutcome(f"assert {name} exists={a['exists']}", ok, f"found={found}")
    if not found:
        return CheckOutcome(f"assert {name}", False, f"{path} not set")
    if "equals" in a:
        return CheckOutcome(f"assert {name} == {a['equals']!r}", val == a["equals"], f"got {val!r}")
    if "in" in a:
        return CheckOutcome(f"assert {name} in {a['in']!r}", val in a["in"], f"got {val!r}")
    if "gte" in a:
        ok = isinstance(val, int | float) and val >= a["gte"]
        return CheckOutcome(f"assert {name} >= {a['gte']}", ok, f"got {val!r}")
    if "contains" in a:
        ok = isinstance(val, list | str) and a["contains"] in val
        return CheckOutcome(f"assert {name} contains {a['contains']!r}", ok, f"got {val!r}")
    if "matches" in a:
        ok = isinstance(val, str) and re.search(str(a["matches"]), val) is not None
        return CheckOutcome(f"assert {name} matches {a['matches']!r}", ok, f"got {val!r}")
    return CheckOutcome(f"assert {name}", True, "present")


def evaluate(answer: str, spec: dict[str, Any]) -> Evaluation:
    text = extract_yaml(answer)
    try:
        docs = load_documents(text)
    except ManifestError as exc:
        return Evaluation([CheckOutcome("parse", False, str(exc), weight=2.0)], None, parsed=False)
    docs = [d for d in docs if isinstance(d.data, dict)]
    if not docs:
        return Evaluation([CheckOutcome("parse", False, "no Kubernetes objects found", weight=2.0)], None, False)
    report = analyze(docs, platform=spec.get("platform", "kubernetes"), version=spec.get("version"))
    outcomes: list[CheckOutcome] = [CheckOutcome("parse", True, f"{len(docs)} object(s)", weight=1.0)]
    present = {d.kind for d in docs}
    for k in spec.get("kinds") or []:
        outcomes.append(CheckOutcome(f"kind {k}", k in present, "present" if k in present else "missing"))
    if spec.get("schemaValid"):
        errs = [f for f in report.findings if f.rule_id in {"KN-V007", "KN-V001", "KN-V002", "KN-V010"}]
        outcomes.append(
            CheckOutcome("schema valid", not errs, "; ".join(f.message for f in errs[:3]) or "ok", weight=2.0)
        )
    if spec.get("maxSeverity"):
        limit = Severity.parse(spec["maxSeverity"])
        over = [f for f in report.findings if f.severity > limit]
        outcomes.append(
            CheckOutcome(
                f"no findings above {limit.name.lower()}",
                not over,
                "; ".join(f"{f.rule_id} {f.message}" for f in over[:4]) or "ok",
                weight=2.0,
            )
        )
    for rid in spec.get("forbidRules") or []:
        hits = [f for f in report.findings if f.rule_id == rid and f.severity >= Severity.LOW]
        outcomes.append(
            CheckOutcome(f"rule {rid} not triggered", not hits, hits[0].message if hits else "ok", weight=1.5)
        )
    if "minScore" in spec:
        outcomes.append(
            CheckOutcome(
                f"posture score >= {spec['minScore']}",
                report.score() >= float(spec["minScore"]),
                f"score {report.score():.0f}",
                weight=1.5,
            )
        )
    for a in spec.get("assertions") or []:
        outcomes.append(_assert(docs, a))
    return Evaluation(outcomes, report, parsed=True)
