"""Weekly risk review: pure decision logic (network calls are thin wrappers and not exercised here)."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import ModuleType

ROOT = Path(__file__).resolve().parents[1]


def _load() -> ModuleType:
    spec = importlib.util.spec_from_file_location("risk_review", ROOT / "scripts" / "risk_review.py")
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules["risk_review"] = mod
    spec.loader.exec_module(mod)
    return mod


rr = _load()

PIP_AUDIT = {
    "dependencies": [
        {"name": "httpx", "version": "0.28.1", "vulns": []},
        {"name": "jinja2", "version": "3.1.4", "vulns": [{"id": "GHSA-x", "fix_versions": ["3.1.6"], "aliases": []}]},
        {"name": "nofix", "version": "1.0", "vulns": [{"id": "PYSEC-1", "fix_versions": [], "aliases": []}]},
    ]
}

TRIVY = {
    "Results": [
        {
            "Target": "img",
            "Vulnerabilities": [
                {"VulnerabilityID": "CVE-1", "Severity": "CRITICAL", "FixedVersion": "1.2", "PkgName": "openssl"},
                {"VulnerabilityID": "CVE-2", "Severity": "HIGH", "FixedVersion": "", "PkgName": "glibc"},
                {"VulnerabilityID": "CVE-3", "Severity": "MEDIUM", "FixedVersion": "2.0", "PkgName": "zlib"},
            ],
        }
    ]
}


def test_parsers() -> None:
    vulns = rr.parse_pip_audit(PIP_AUDIT)
    assert [(v.package, v.fixable) for v in vulns] == [("jinja2", True), ("nofix", False)]
    image = rr.parse_trivy(TRIVY)
    assert image == {"fixableHighCritical": 1, "unfixedHighCritical": 1, "ids": ["CVE-1"]}
    assert rr.parse_trivy({}) == {"fixableHighCritical": 0, "unfixedHighCritical": 0, "ids": []}


def test_latest_stable_ignores_prereleases_and_other_majors() -> None:
    tags = ["v1.36.4", "v1.37.0", "v1.38.0-rc.1", "v1.37.1", "junk"]
    assert rr.latest_stable(tags) == (1, 37, 1)
    assert rr.latest_stable(["v3.22.1", "v4.3.1", "v4.4.0-rc.1"], major=3) == (3, 22, 1)
    assert rr.latest_stable(["5.0.0-rc.4", "4.11.6", "4.11.5"]) == (4, 11, 6)
    assert rr.latest_stable([]) is None


def test_knowledge_drift_compares_minor_or_patch_as_declared() -> None:
    baseline = {"kubernetes": "1.37", "openshift": "4.22", "helm4": "4.3.1", "stackrox": "4.11.6"}
    upstream = {"kubernetes": "1.38", "openshift": "4.22", "helm4": "4.3.2", "stackrox": "4.11.6"}
    drift = rr.knowledge_drift(baseline, upstream)
    assert {d["component"] for d in drift} == {"kubernetes", "helm4"}
    assert rr.knowledge_drift(baseline, {"kubernetes": "1.37.9"}) == []  # minor-level baseline ignores patches
    assert rr.knowledge_drift(baseline, {"openshift": None}) == []  # unknown upstream is not drift


def test_decision_rule() -> None:
    clean = rr.decide(vulns=[], image=rr.parse_trivy({}), drift=[], sdk=[])
    assert clean.release_recommended is False and clean.reasons == []
    fixable = rr.decide(vulns=rr.parse_pip_audit(PIP_AUDIT), image=rr.parse_trivy({}), drift=[], sdk=[])
    assert fixable.release_recommended and any("jinja2" in r for r in fixable.reasons)
    image = rr.decide(vulns=[], image=rr.parse_trivy(TRIVY), drift=[], sdk=[])
    assert image.release_recommended and any("rebuild" in r for r in image.reasons)
    drift_only = rr.decide(vulns=[], image=rr.parse_trivy({}), drift=[{"component": "kubernetes"}], sdk=[])
    assert drift_only.release_recommended and drift_only.review_required


def test_markdown_report_is_stable() -> None:
    d = rr.decide(vulns=rr.parse_pip_audit(PIP_AUDIT), image=rr.parse_trivy(TRIVY), drift=[], sdk=[])
    md = rr.render_markdown(d, week="2026-W44")
    assert md.startswith("# Weekly risk review 2026-W44")
    assert "Release recommended: **yes**" in md and "jinja2 3.1.4 -> 3.1.6" in md and "CVE-1" in md
