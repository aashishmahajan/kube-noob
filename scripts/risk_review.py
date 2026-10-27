#!/usr/bin/env python3
"""Weekly risk review: decide whether kube-noob needs an upgrade release.

Signals (each is cheap and deterministic):
  1. Python dependency vulnerabilities  - pip-audit JSON for requirements.lock
  2. Released image vulnerabilities      - Trivy JSON for the latest published image (optional before first release)
  3. Knowledge drift                     - upstream Kubernetes / OpenShift / Helm / StackRox releases newer than the
                                           versions the built-in knowledge and rules were verified against
  4. SDK drift                           - newer `mcp` / `anthropic` releases than the lock pins

Usage (CI): python scripts/risk_review.py --pip-audit pip-audit.json [--trivy trivy.json] --out report
Writes report.json and report.md and prints `release_recommended=<true|false>` for the workflow.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import re
import subprocess
import urllib.request
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
BASELINE = ROOT / "scripts" / "risk_baseline.json"
_SEMVER = re.compile(r"^v?(\d+)\.(\d+)\.(\d+)$")

# component -> (git repo, tag/branch source, major filter)
UPSTREAM = {
    "kubernetes": ("https://github.com/kubernetes/kubernetes.git", "tags", None),
    "helm4": ("https://github.com/helm/helm.git", "tags", 4),
    "helm3": ("https://github.com/helm/helm.git", "tags", 3),
    "stackrox": ("https://github.com/stackrox/stackrox.git", "tags", None),
    "openshift": ("https://github.com/openshift/openshift-docs.git", "enterprise-branches", None),
}
SDKS = ("mcp", "anthropic")


@dataclass
class Vuln:
    package: str
    version: str
    vuln_id: str
    fix_versions: list[str]

    @property
    def fixable(self) -> bool:
        return bool(self.fix_versions)


@dataclass
class Decision:
    release_recommended: bool
    review_required: bool
    reasons: list[str] = field(default_factory=list)
    vulns: list[Vuln] = field(default_factory=list)
    image: dict[str, Any] = field(default_factory=dict)
    drift: list[dict[str, Any]] = field(default_factory=list)
    sdk: list[dict[str, Any]] = field(default_factory=list)


def parse_pip_audit(data: dict[str, Any]) -> list[Vuln]:
    out = []
    for dep in data.get("dependencies", []):
        for v in dep.get("vulns", []) or []:
            out.append(Vuln(dep["name"], dep.get("version", "?"), v.get("id", "?"), list(v.get("fix_versions") or [])))
    return out


def parse_trivy(data: dict[str, Any]) -> dict[str, Any]:
    fixable, unfixed = [], 0
    for result in data.get("Results", []) or []:
        for v in result.get("Vulnerabilities", []) or []:
            if v.get("Severity") not in {"HIGH", "CRITICAL"}:
                continue
            if v.get("FixedVersion"):
                fixable.append(v["VulnerabilityID"])
            else:
                unfixed += 1
    ids = sorted(set(fixable))
    return {"fixableHighCritical": len(ids), "unfixedHighCritical": unfixed, "ids": ids}


def latest_stable(tags: list[str], major: int | None = None) -> tuple[int, int, int] | None:
    versions = []
    for t in tags:
        m = _SEMVER.match(t.strip())
        if m:
            v = (int(m.group(1)), int(m.group(2)), int(m.group(3)))
            if major is None or v[0] == major:
                versions.append(v)
    return max(versions) if versions else None


def _parts(v: str) -> tuple[int, ...]:
    return tuple(int(x) for x in v.split("."))


def knowledge_drift(baseline: dict[str, str], upstream: dict[str, str | None]) -> list[dict[str, Any]]:
    """Upstream newer than baseline, compared at the precision the baseline declares (1.37 = minor, 4.3.1 = patch)."""
    out = []
    for comp, known in baseline.items():
        seen = upstream.get(comp)
        if not seen or comp.startswith("_"):
            continue
        n = len(_parts(known))
        if _parts(seen)[:n] > _parts(known):
            out.append({"component": comp, "baseline": known, "upstream": seen})
    return out


def decide(
    vulns: list[Vuln], image: dict[str, Any], drift: list[dict[str, Any]], sdk: list[dict[str, Any]]
) -> Decision:
    reasons = []
    for v in vulns:
        if v.fixable:
            reasons.append(f"dependency {v.package} {v.version} -> {v.fix_versions[0]} fixes {v.vuln_id}")
    if image.get("fixableHighCritical", 0):
        reasons.append(f"image rebuild: {image['fixableHighCritical']} fixable HIGH/CRITICAL CVEs in the base image")
    for d in drift:
        reasons.append(f"knowledge drift: {d['component']} upstream {d.get('upstream')} > verified {d.get('baseline')}")
    for s in sdk:
        reasons.append(f"SDK update available: {s['package']} {s['locked']} -> {s['latest']} (review changelog)")
    security = any(v.fixable for v in vulns) or bool(image.get("fixableHighCritical", 0))
    return Decision(
        release_recommended=security or bool(drift),
        review_required=bool(drift or sdk or any(not v.fixable for v in vulns)),
        reasons=reasons,
        vulns=vulns,
        image=image,
        drift=drift,
        sdk=sdk,
    )


def render_markdown(d: Decision, week: str) -> str:
    lines = [
        f"# Weekly risk review {week}",
        "",
        f"Release recommended: **{'yes' if d.release_recommended else 'no'}**  ",
        f"Human/agent review required: **{'yes' if d.review_required else 'no'}**",
        "",
        "## Reasons",
        *(f"- {r}" for r in d.reasons or ["none - no action needed this week"]),
        "",
        "## Python dependencies (pip-audit)",
    ]
    lines += [
        f"- {v.package} {v.version}: {v.vuln_id} (fix: {', '.join(v.fix_versions) or 'none yet'})" for v in d.vulns
    ]
    if not d.vulns:
        lines.append("- no known vulnerabilities")
    img = d.image
    lines += [
        "",
        "## Released image (Trivy, HIGH/CRITICAL)",
        f"- fixable: {img.get('fixableHighCritical', 'n/a')} {' '.join(img.get('ids', [])[:20])}",
        f"- no fix yet: {img.get('unfixedHighCritical', 'n/a')}",
        "",
        "## Knowledge drift",
    ]
    lines += [f"- {x['component']}: verified {x['baseline']}, upstream {x['upstream']}" for x in d.drift] or ["- none"]
    lines += ["", "## SDKs", *([f"- {s['package']}: {s['locked']} -> {s['latest']}" for s in d.sdk] or ["- current"])]
    lines += ["", "Runbook: docs/operations.md"]
    return "\n".join(lines) + "\n"


# -- thin network wrappers ---------------------------------------------------------------------------------
def _git_refs(url: str, kind: str) -> list[str]:
    flag = "--tags" if kind == "tags" else "--heads"
    out = subprocess.run(["git", "ls-remote", flag, url], capture_output=True, text=True, timeout=120, check=True)  # noqa: S607
    refs = [line.split("\t")[1] for line in out.stdout.splitlines() if "\t" in line]
    return [r.rsplit("/", 1)[-1].removesuffix("^{}") for r in refs]


def upstream_versions() -> dict[str, str | None]:
    found: dict[str, str | None] = {}
    for comp, (url, kind, major) in UPSTREAM.items():
        try:
            refs = _git_refs(url, "heads" if kind == "enterprise-branches" else "tags")
        except (subprocess.SubprocessError, OSError):
            found[comp] = None
            continue
        if kind == "enterprise-branches":
            minors = [int(m.group(1)) for r in refs if (m := re.fullmatch(r"enterprise-4\.(\d+)", r))]
            found[comp] = f"4.{max(minors)}" if minors else None
        else:
            v = latest_stable(refs, major)
            found[comp] = ".".join(map(str, v)) if v else None
    return found


def sdk_drift(lock: Path) -> list[dict[str, Any]]:
    pins = dict(re.findall(r"^([a-z0-9_.-]+)==([^\s\\]+)", lock.read_text(), re.MULTILINE))
    out = []
    for pkg in SDKS:
        try:
            with urllib.request.urlopen(f"https://pypi.org/pypi/{pkg}/json", timeout=30) as r:
                latest = json.load(r)["info"]["version"]
        except OSError:
            continue
        if pkg in pins and _parts_safe(latest) > _parts_safe(pins[pkg]):
            out.append({"package": pkg, "locked": pins[pkg], "latest": latest})
    return out


def _parts_safe(v: str) -> tuple[int, ...]:
    return tuple(int(x) for x in re.findall(r"\d+", v)[:3])


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--pip-audit", type=Path, required=True)
    ap.add_argument("--trivy", type=Path)
    ap.add_argument("--out", type=Path, default=Path("report"))
    ap.add_argument("--offline", action="store_true", help="skip upstream and SDK lookups")
    a = ap.parse_args()
    vulns = parse_pip_audit(json.loads(a.pip_audit.read_text()))
    image = parse_trivy(json.loads(a.trivy.read_text())) if a.trivy and a.trivy.is_file() else {}
    baseline = json.loads(BASELINE.read_text())
    drift = [] if a.offline else knowledge_drift(baseline, upstream_versions())
    sdk = [] if a.offline else sdk_drift(ROOT / "requirements.lock")
    d = decide(vulns, image, drift, sdk)
    week = dt.date.today().strftime("%G-W%V")
    a.out.mkdir(parents=True, exist_ok=True)
    (a.out / "report.md").write_text(render_markdown(d, week))
    (a.out / "report.json").write_text(json.dumps({"week": week, **asdict(d)}, indent=2, default=str))
    print(f"release_recommended={'true' if d.release_recommended else 'false'}")
    print(f"review_required={'true' if d.review_required else 'false'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
