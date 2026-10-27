"""Finding / report data model shared by validation, audit, calibration and red-team stages."""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import Any

from kube_noob.audit.controls import controls_for
from kube_noob.audit.controls import summary as control_summary
from kube_noob.catalog import SOURCES, Citation


class Severity(enum.IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def parse(cls, value: str | int | Severity) -> Severity:
        if isinstance(value, Severity):
            return value
        if isinstance(value, int):
            return cls(value)
        try:
            return cls[value.strip().upper()]
        except KeyError as exc:
            raise ValueError(f"Unknown severity {value!r}; use one of {[s.name.lower() for s in cls]}") from exc


class Stage(enum.Enum):
    VALIDATE = "validate"
    AUDIT = "audit"
    CALIBRATE = "calibrate"
    RED_TEAM = "red-team"


@dataclass
class Finding:
    rule_id: str
    title: str
    severity: Severity
    stage: Stage
    category: str
    resource: str
    message: str
    remediation: str
    path: str = ""
    line: int | None = None
    doc_index: int | None = None
    citations: list[str] = field(default_factory=list)
    stackrox_policies: list[str] = field(default_factory=list)

    def citation_objects(self) -> list[Citation]:
        return [SOURCES[c] for c in self.citations if c in SOURCES]

    def as_dict(self) -> dict[str, Any]:
        return {
            "ruleId": self.rule_id,
            "title": self.title,
            "severity": self.severity.name.lower(),
            "stage": self.stage.value,
            "category": self.category,
            "resource": self.resource,
            "docIndex": self.doc_index,
            "path": self.path,
            "line": self.line,
            "message": self.message,
            "remediation": self.remediation,
            "citations": [c.as_dict() for c in self.citation_objects()],
            "stackroxPolicies": self.stackrox_policies,
            "controls": controls_for(self.rule_id),
        }


@dataclass
class RedTeamScenario:
    scenario_id: str
    question: str
    verdict: str  # "exposed" | "mitigated" | "not-applicable"
    severity: Severity
    evidence: list[str]
    blast_radius: str
    safeguards: list[str]
    verification: list[str]

    def as_dict(self) -> dict[str, Any]:
        return {
            "scenarioId": self.scenario_id,
            "question": self.question,
            "verdict": self.verdict,
            "severity": self.severity.name.lower(),
            "evidence": self.evidence,
            "blastRadius": self.blast_radius,
            "safeguards": self.safeguards,
            "verification": self.verification,
        }


@dataclass
class Report:
    platform: str
    kubernetes_version: str
    platform_version: str | None
    resources: list[str]
    findings: list[Finding] = field(default_factory=list)
    scenarios: list[RedTeamScenario] = field(default_factory=list)
    assumptions: list[str] = field(default_factory=list)

    def max_severity(self) -> Severity | None:
        return max((f.severity for f in self.findings), default=None)

    def counts(self) -> dict[str, int]:
        out = {s.name.lower(): 0 for s in Severity}
        for f in self.findings:
            out[f.severity.name.lower()] += 1
        return out

    def score(self) -> float:
        """0..100 posture score. Deterministic; used by the learning grader and the training reward."""
        weights = {Severity.CRITICAL: 25.0, Severity.HIGH: 10.0, Severity.MEDIUM: 4.0, Severity.LOW: 1.0}
        penalty = sum(weights.get(f.severity, 0.0) for f in self.findings)
        return max(0.0, 100.0 - penalty)

    def as_dict(self) -> dict[str, Any]:
        return {
            "platform": self.platform,
            "platformVersion": self.platform_version,
            "kubernetesVersion": self.kubernetes_version,
            "resources": self.resources,
            "summary": {
                "counts": self.counts(),
                "maxSeverity": top.name.lower() if (top := self.max_severity()) is not None else None,
                "score": round(self.score(), 1),
            },
            "assumptions": self.assumptions,
            "findings": [f.as_dict() for f in sorted(self.findings, key=_sort_key)],
            "controlSummary": control_summary([f.rule_id for f in self.findings]),
            "redTeam": [s.as_dict() for s in self.scenarios],
        }


def _sort_key(f: Finding) -> tuple[int, int, int, str]:
    return (-int(f.severity), f.doc_index if f.doc_index is not None else -1, f.line or 0, f.rule_id)
