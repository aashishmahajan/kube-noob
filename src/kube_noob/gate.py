"""The CI gate before deploy (requirements R4.3): one command over manifests, rendered charts and Containerfiles.

``kube-noob gate`` runs the audit rules (with an exception list when given), says for every finding whether the
generated admission policy would refuse it in enforce mode, lists open reported issues in the target OpenShift
release that mention a kind the manifests deploy, audits Containerfiles, and fails at ``--fail-on``. It writes SARIF
2.1.0 (GitHub code scanning), a Markdown summary (``$GITHUB_STEP_SUMMARY``, merge request notes) and GitLab's code
quality JSON. Findings in a rendered Helm chart point at the template file (``# Source:`` comments) when
``--chart-path`` names the chart in the repository.

Everything is offline: no cluster, no network, no model. Vulnerability checks need scanner input and are listed as
not run until the scanner reader (requirements R5.1) is built.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from kube_noob import __version__
from kube_noob.audit.model import Severity

MAX_FILES = 2_000
MAX_TOTAL = 5_000_000
SEVERITIES = ("info", "low", "medium", "high", "critical")
_SOURCE = re.compile(r"^# Source: ([\w.-]{1,200})/(.{1,400})$")
_KIND = re.compile(r"^kind:\s{0,5}([A-Z][A-Za-z0-9]{1,62})\s*$", re.M)
# Kinds whose names are distinctive enough to search release notes for (Route, Service or Pod are everyday words).
_DISTINCT_KIND = re.compile(r"^[A-Z][a-z0-9]+(?:[A-Z][a-z0-9]+)+$")
SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
INFO_URI = "https://github.com/aashishmahajan/kube-noob"


class GateError(ValueError):
    """Nothing to check, too much input, or a file that cannot be read."""


@dataclass
class Source:
    uri: str
    text: str
    chart: str | None = None  # the chart directory this was rendered from (findings point at its templates)
    skip: str | None = None  # why the file is not audited (not a manifest, a Helm template)
    start: int = 0  # first line of this file in the combined input (1-based)
    lines: int = 0


def _classify(path: Path | None, text: str) -> str | None:
    """Why a YAML file found in a directory is not a manifest to audit, or None when it is one.

    Only files picked up from a directory are classified; a file named on the command line is always audited, so a
    broken manifest cannot slip through as "not a manifest"."""
    if path is not None and any(_in_chart_templates(path, parent) for parent in path.parents):
        return "a Helm template: render the chart with --chart"
    try:
        docs = [d for d in yaml.safe_load_all(text) if d is not None]
    except yaml.YAMLError:
        return None  # audited, so the parse error is reported
    if not any(isinstance(d, dict) and "apiVersion" in d and "kind" in d for d in docs):
        return "not a Kubernetes manifest (no document with apiVersion and kind)"
    return None


def _in_chart_templates(path: Path, parent: Path) -> bool:
    return parent.name == "templates" and (parent.parent / "Chart.yaml").is_file() and path.is_relative_to(parent)


def render(charts: list[str], values: list[str], namespace: str) -> list[Source]:
    """``helm template`` each chart (the helm binary must be on PATH)."""
    from kube_noob.generate.helm import render_chart

    out = []
    for chart in charts:
        text = render_chart(chart, values, namespace=namespace, release="kube-noob-gate")
        out.append(Source(f"{chart.rstrip('/')}/(rendered)", text, chart=chart.rstrip("/")))
    return out


def _uri(path: Path) -> str:
    """Relative to the working directory (the repository root in CI) when the file is under it."""
    try:
        return path.resolve().relative_to(Path.cwd().resolve()).as_posix()
    except ValueError:
        return path.resolve().as_posix()


def collect(paths: list[str], read: Any) -> list[Source]:
    """Manifest files from paths (directories: their *.yaml and *.yml, sorted), ``-`` for stdin."""
    out: list[Source] = []
    total = 0
    for raw in paths:
        items: list[tuple[str, str, str | None]]
        if raw == "-":
            items = [("stdin", read("-"), None)]
        else:
            p = Path(raw)
            if p.is_dir():
                files = sorted(
                    f
                    for f in p.rglob("*")
                    if f.suffix in {".yaml", ".yml"}
                    and not any(part.startswith(".") for part in f.relative_to(p).parts)  # .git, .github, ..data
                    and f.is_file()
                )
                items = []
                for f in files:
                    text = f.read_text(encoding="utf-8", errors="replace")
                    items.append((_uri(f), text, _classify(f, text)))
            elif p.is_file():
                items = [(_uri(p), p.read_text(encoding="utf-8", errors="replace"), None)]
            else:
                raise GateError(f"{raw}: no such file or directory")
        for uri, text, why in items:
            total += len(text)
            out.append(Source(uri, text, skip=why))
            if len(out) > MAX_FILES or total > MAX_TOTAL:
                raise GateError(f"more than {MAX_FILES} files or {MAX_TOTAL:,} characters: gate one release at a time")
    return out


def _combine(sources: list[Source]) -> str:
    parts: list[str] = []
    line = 1
    for s in sources:
        text = s.text if s.text.endswith("\n") else s.text + "\n"
        s.start, s.lines = line, text.count("\n")
        parts.append(text)
        line += s.lines + 1  # the separator line
    return "---\n".join(parts)


def _where(sources: list[Source], line: int | None, chart_path: str | None) -> tuple[str, int | None]:
    if line is None:
        return (sources[0].uri if len(sources) == 1 else "manifests"), None
    for s in sources:
        if s.start <= line < s.start + s.lines:
            local = line - s.start + 1
            chart = s.chart or chart_path
            if chart:
                tpl = _template_for(s.text, local, chart)
                if tpl:
                    return tpl, None
            return s.uri, local
    return sources[-1].uri, None


def _template_for(text: str, line: int, chart_path: str) -> str | None:
    """The chart template a rendered line came from (``helm template`` writes ``# Source: <chart>/<path>``)."""
    source = None
    for n, raw in enumerate(text.splitlines()[:line], 1):
        m = _SOURCE.match(raw.strip())
        if m:
            source = m.group(2)
        if n == line:
            break
    if source is None or ".." in source.split("/"):
        return None
    return f"{chart_path.rstrip('/')}/{source}"


def _admission(platform: str, version: str | None) -> tuple[dict[str, str], dict[str, str]]:
    """Rules generated as admission policies (with their limitation, if any) and the reasons for the others."""
    from kube_noob.generate import policies

    checks, skipped = policies._checks(platform, version)
    return {r: c.limitation for r, c in checks.items()}, {**policies.NOT_GENERATED, **skipped}


def _admission_text(rule: str, severity: str, enforced: dict[str, str], not_generated: dict[str, str]) -> str:
    if rule not in enforced:
        return f"not an admission policy: {not_generated.get(rule, 'needs other objects')}"
    if severity == "info":
        return "not refused: the admission policies refuse low severity and above"
    return "refused in enforce mode" + (f" (partly: {enforced[rule]})" if enforced[rule] else "")


def _known(kinds: set[str], platform: str, version: str | None, data_dir: Path | None) -> list[dict[str, Any]]:
    """Open reported issues in the target release whose text names a kind these manifests deploy."""
    from kube_noob.catalog import OPENSHIFT_FAMILY
    from kube_noob.known_issues import get_index, vkey

    if platform not in OPENSHIFT_FAMILY or not version:
        return []
    minor = ".".join(version.split(".")[:2])
    out: list[dict[str, Any]] = []
    for issue in get_index(data_dir).issues:
        if issue.kind != "known" or issue.minor != minor:
            continue
        if issue.fixed_in and vkey(version) >= vkey(issue.fixed_in):
            continue
        named = sorted(k for k in kinds if _DISTINCT_KIND.match(k) and re.search(rf"\b{k}s?\b", issue.text))
        if named:
            out.append({**issue.as_dict(version, 1.0), "kinds": named})
    return out[:20]


def run(
    sources: list[Source],
    *,
    containerfiles: list[tuple[str, str]] | None = None,
    platform: str = "kubernetes",
    version: str | None = None,
    exceptions: str | None = None,
    fail_on: str = "high",
    chart_path: str | None = None,
    data_dir: Path | None = None,
    scanner_reports: list[tuple[str, str]] | None = None,
    vex_paths: list[Path] | None = None,
    kev_path: Path | None = None,
    trust_report_vex: bool = False,
) -> dict[str, Any]:
    from kube_noob.audit import exceptions as exc
    from kube_noob.audit.engine import analyze

    containerfiles = containerfiles or []
    scanner_reports = scanner_reports or []
    skipped = [{"file": s.uri, "why": s.skip} for s in sources if s.skip]
    sources = [s for s in sources if not s.skip]
    if not sources and not containerfiles and not scanner_reports:
        raise GateError(
            "nothing to check: pass manifests with -f, Containerfiles with --containerfile, or --scanner-report"
        )
    findings: list[dict[str, Any]] = []
    failures: list[str] = []
    combined = _combine(sources) if sources else ""
    review = exc.review(exceptions) if exceptions else None
    enforced, not_generated = _admission(platform, version)
    excepted = 0
    kinds: set[str] = set()
    if sources:
        report = analyze(combined, platform, version)
        kinds = set(_KIND.findall(combined))
        for f in report.findings:
            if review is not None and exc.match(review, f.rule_id, f.resource) is not None:
                excepted += 1
                continue
            uri, line = _where(sources, f.line, chart_path)
            findings.append(
                {
                    "ruleId": f.rule_id,
                    "title": f.title,
                    "severity": f.severity.name.lower(),
                    "message": f.message,
                    "resource": f.resource,
                    "path": f.path,
                    "uri": uri,
                    "line": line,
                    "remediation": f.remediation,
                    "admission": _admission_text(f.rule_id, f.severity.name.lower(), enforced, not_generated),
                    "helpUri": next((c.url for c in f.citation_objects()), INFO_URI),
                }
            )
        if review is not None and not review.summary()["gate"]:
            failures.append("the exception list has expired or refused entries (kube-noob exceptions check)")
    for uri, text in containerfiles:
        from kube_noob.build import containerfile as cf
        from kube_noob.build import image

        try:
            rep = image.audit(text, manifests=combined or None)
        except cf.ContainerfileError as err:
            failures.append(f"{uri}: {err}")
            continue
        for f in rep["findings"]:
            findings.append(
                {
                    "ruleId": f["ruleId"],
                    "title": f["title"],
                    "severity": f["severity"],
                    "message": f["message"],
                    "resource": "Containerfile",
                    "path": "",
                    "uri": uri,
                    "line": f.get("line"),
                    "remediation": f["fix"],
                    "admission": "a build check, not an admission policy",
                    "helpUri": (f.get("sources") or [{"url": INFO_URI}])[0]["url"],
                }
            )
    vulns = _vulnerabilities(scanner_reports, combined, vex_paths or [], kev_path, data_dir, fail_on, trust_report_vex)
    findings.extend(vulns["findings"])
    if vulns["failing"]:
        failures.append(
            f"{vulns['failing']} vulnerability finding(s) at {fail_on} or above that are fixable or known exploited"
        )
    order = {s: i for i, s in enumerate(SEVERITIES)}
    findings.sort(key=lambda r: (-order[r["severity"]], r["uri"], r.get("line") or 0, r["ruleId"]))
    counts = {s: sum(1 for r in findings if r["severity"] == s) for s in reversed(SEVERITIES)}
    if fail_on != "never":
        floor = Severity.parse(fail_on)
        over = [r for r in findings if Severity.parse(r["severity"]) >= floor and not r.get("vulnerability")]
        if over:
            failures.append(f"{len(over)} finding(s) at {fail_on} or above")
    known = _known(kinds, platform, version, data_dir)
    return {
        "tool": {"name": "kube-noob", "version": __version__},
        "platform": platform,
        "version": version,
        "failOn": fail_on,
        "passed": not failures,
        "failures": failures,
        "files": [s.uri for s in sources],
        "skipped": skipped,
        "containerfiles": [u for u, _ in containerfiles],
        "counts": counts,
        "excepted": excepted,
        "findings": findings,
        "admission": {
            "refusedInEnforceMode": sum(1 for r in findings if r["admission"].startswith("refused in enforce mode")),
            "command": f"kube-noob policy generate --platform {platform}"
            + (f" --version {version}" if version else "")
            + " --mode enforce",
        },
        "knownIssues": known,
        "vulnerabilities": vulns["summary"],
        "notRun": []
        if scanner_reports
        else [
            "vulnerability checks: pass the images' scanner output with --scanner-report (Trivy or Grype JSON, a "
            "CycloneDX or SPDX SBOM, or an RHACS image scan)"
        ],
    }


_VULN_SEVERITY = {"critical": "critical", "high": "high", "medium": "medium", "low": "low", "negligible": "info"}


def _vulnerabilities(
    reports: list[tuple[str, str]],
    manifests: str,
    vex_paths: list[Path],
    kev_path: Path | None,
    data_dir: Path | None,
    fail_on: str,
    trust_report_vex: bool = False,
) -> dict[str, Any]:
    """Scanner findings as gate findings: VEX applied, KEV marked, ranked against the manifests. A finding fails the
    gate at ``fail_on`` only when it is fixable or known exploited (an unfixable finding is reported, not blocked)."""
    if not reports:
        return {"findings": [], "failing": 0, "summary": None}
    from kube_noob.attack_paths import Inventory as PathInventory
    from kube_noob.attack_paths import workload_reach
    from kube_noob.vuln import assess
    from kube_noob.vuln import kev as kevmod
    from kube_noob.vuln import reports as rep
    from kube_noob.vuln import vex as vexmod
    from kube_noob.yamlio import load_documents

    try:
        parsed = [rep.parse(text, uri) for uri, text in reports]
        index = vexmod.load(data_dir, vex_paths)
        kev = kevmod.load(kev_path) if kev_path else None
        reach = (
            workload_reach(PathInventory.from_documents(d.data for d in load_documents(manifests)))
            if manifests
            else None
        )
        out = assess.assess(parsed, vex=index, kev=kev, reach=reach, top=200, trust_report_vex=trust_report_vex)
    except (rep.ReportError, vexmod.VexError, kevmod.KevError, assess.AssessError) as exc:
        raise GateError(str(exc)) from exc
    uri_of: dict[str, str] = {}
    for (uri, _), one in zip(reports, parsed, strict=True):
        uri_of.setdefault(one.image.label, uri)
    ranked = {(x["image"], x["finding"]["id"]): x for x in out["ranking"]["ranked"]}
    findings: list[dict[str, Any]] = []
    failing = 0
    floor = Severity.parse(fail_on) if fail_on != "never" else None
    from kube_noob.vuln.reports import gating_severity

    for f in out["findings"]:
        sev = _VULN_SEVERITY.get(gating_severity(f["severity"], f["cvss"], f["knownExploited"]), "medium")
        r = ranked.get((f["image"], f["id"]))
        where = f"; ranked {r['rank']} (score {r['score']}): {r['attackPath']['summary']}" if r else ""
        fix = f["fixVersion"] or "no fix yet"
        findings.append(
            {
                "ruleId": f["cve"],
                "title": f"{f['cve']} in {f['package']['name']}",
                "severity": sev,
                "message": f"{f['cve']} in {f['package']['name']} {f['package']['version']} (fix: {fix}) in image "
                f"{f['image']}" + (" - known exploited (CISA KEV)" if f["knownExploited"] else "") + where,
                "resource": ", ".join(r["workloads"][:3]) if r and r["workloads"] else f["image"],
                "path": "",
                "uri": uri_of.get(f["image"], reports[0][0]),
                "line": None,
                "remediation": f"update {f['package']['name']} to {f['fixVersion']} and rebuild the image"
                if f["fixVersion"]
                else "no fixed version yet: reduce exposure and privileges of the workloads that run it",
                "admission": "a vulnerability in the image, not an admission policy",
                "vulnerability": True,
                "helpUri": f"https://access.redhat.com/security/cve/{f['cve']}"
                if f["package"]["ecosystem"] == "rpm"
                else f"https://www.cve.org/CVERecord?id={f['cve']}",
            }
        )
        if floor is not None and Severity.parse(sev) >= floor and (f["fixVersion"] or f["knownExploited"]):
            failing += 1
    summary = {
        **out["counts"],
        "images": [i["image"]["name"] for i in out["images"]],
        "vex": out["vex"]["sources"],
        "kev": out["kev"]["catalog"],
    }
    return {"findings": findings, "failing": failing, "summary": summary}


# -- output formats ----------------------------------------------------------------------------------------------

_LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}
_SCORE = {"critical": "9.5", "high": "8.0", "medium": "5.5", "low": "3.0", "info": "0.0"}
_CODEQUALITY = {"critical": "blocker", "high": "critical", "medium": "major", "low": "minor", "info": "info"}


def _fingerprint(r: dict[str, Any]) -> str:
    key = "\x1f".join(str(r.get(k) or "") for k in ("ruleId", "uri", "resource", "path", "message"))
    return hashlib.sha256(key.encode("utf-8")).hexdigest()[:32]


def sarif(report: dict[str, Any]) -> dict[str, Any]:
    rules: dict[str, dict[str, Any]] = {}
    results = []
    for r in report["findings"]:
        if r["ruleId"] not in rules:
            rules[r["ruleId"]] = {
                "id": r["ruleId"],
                "name": re.sub(r"[^A-Za-z0-9]+", "", r["title"].title())[:100] or r["ruleId"],
                "shortDescription": {"text": r["title"]},
                "fullDescription": {"text": r["remediation"][:1000]},
                "help": {"text": r["remediation"][:2000]},
                "helpUri": r["helpUri"],
                "defaultConfiguration": {"level": _LEVEL[r["severity"]]},
                "properties": {"security-severity": _SCORE[r["severity"]], "tags": ["security", "kubernetes"]},
            }
        uri = str(r["uri"])
        artifact = {"uri": Path(uri).as_uri()} if uri.startswith("/") else {"uri": uri, "uriBaseId": "%SRCROOT%"}
        loc: dict[str, Any] = {"artifactLocation": artifact}
        if r.get("line"):
            loc["region"] = {"startLine": int(r["line"])}
        results.append(
            {
                "ruleId": r["ruleId"],
                "ruleIndex": list(rules).index(r["ruleId"]),
                "level": _LEVEL[r["severity"]],
                "message": {"text": f"{r['resource']}: {r['message']}" if r["resource"] else r["message"]},
                "locations": [{"physicalLocation": loc}],
                "partialFingerprints": {"kubeNoob/v1": _fingerprint(r)},
            }
        )
    return {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "kube-noob",
                        "version": report["tool"]["version"],
                        "informationUri": INFO_URI,
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
                "columnKind": "unicodeCodePoints",
            }
        ],
    }


def codequality(report: dict[str, Any]) -> list[dict[str, Any]]:
    """GitLab's code quality report (a list of CodeClimate issues)."""
    return [
        {
            "description": f"{r['ruleId']} {r['resource']}: {r['message']}"[:2000],
            "check_name": r["ruleId"],
            "fingerprint": _fingerprint(r),
            "severity": _CODEQUALITY[r["severity"]],
            "location": {"path": r["uri"], "lines": {"begin": int(r.get("line") or 1)}},
        }
        for r in report["findings"]
    ]


_CONTROL = re.compile(r"[\x00-\x1f\x7f\u2028\u2029]+")
_MD_ESCAPE = {"&": "&amp;", "<": "&lt;", ">": "&gt;", "|": "\\|"} | {c: "\\" + c for c in "\\`*_[]!#~"}


def _cell(text: Any, limit: int = 300) -> str:
    """One line of Markdown text from untrusted input (an image name or package from a scanner report, a manifest
    path): control characters and line breaks become spaces so nothing starts a new heading or table row, HTML
    is entity-escaped and link, image, emphasis and code syntax is backslash-escaped, so a report cannot render as
    a different verdict, an image or a link in the job summary (red team, VUL1)."""
    flat = _CONTROL.sub(" ", str(text))[:limit]
    return "".join(_MD_ESCAPE.get(c, c) for c in flat)


def markdown(report: dict[str, Any], top: int = 25) -> str:
    verdict = "passed" if report["passed"] else "failed"
    target = _cell(report["platform"] + (f" {report['version']}" if report["version"] else ""), 60)
    lines = [
        f"## kube-noob gate {verdict}",
        "",
        f"{len(report['files'])} manifest file(s) and {len(report['containerfiles'])} Containerfile(s) checked for "
        f"{target}, failing at {report['failOn']}. kube-noob {report['tool']['version']}, offline.",
        "",
        "| Severity | Findings |",
        "|---|---|",
        *[f"| {sev} | {n} |" for sev, n in report["counts"].items()],
        "",
    ]
    if report["failures"]:
        lines += ["### Why it failed", "", *[f"- {_cell(f)}" for f in report["failures"]], ""]
    if report["findings"]:
        lines += ["### Findings", "", "| Severity | Rule | Where | Finding | Admission |", "|---|---|---|---|---|"]
        for r in report["findings"][:top]:
            where = f"{r['uri']}:{r['line']}" if r.get("line") else r["uri"]
            lines.append(
                f"| {r['severity']} | {_cell(r['ruleId'], 80)} | {_cell(where)} "
                f"| {_cell(r['resource'] + ': ' + r['message'])} | {_cell(r['admission'])} |"
            )
        if len(report["findings"]) > top:
            lines.append(f"\n{len(report['findings']) - top} more in the SARIF file.")
        lines.append("")
    adm = report["admission"]
    lines += [
        f"{adm['refusedInEnforceMode']} of {len(report['findings'])} findings would be refused at admission by "
        f"`{adm['command']}`.",
        "",
    ]
    if report["excepted"]:
        lines += [f"{report['excepted']} finding(s) accepted by the exception list.", ""]
    v = report.get("vulnerabilities")
    if v:
        lines += [
            f"Vulnerabilities in {_cell(', '.join(v['images']), 600)}: {v['reported']} reported, "
            f"{v['excludedByVex']} excluded by VEX, {v['findings']} findings, {v['fixable']} fixable, "
            f"{v['knownExploited']} known exploited.",
            "",
        ]
    if report["knownIssues"]:
        lines += ["### Reported issues in this release (informational)", ""]
        for k in report["knownIssues"]:
            lines.append(f"- [{_cell(k['id'], 40)}]({k['url']}) ({', '.join(k['kinds'])}): {_cell(k['summary'])}")
        lines.append("")
    if report.get("skipped"):
        lines += ["### Skipped", "", *[f"- {_cell(x['file'])}: {_cell(x['why'])}" for x in report["skipped"][:50]], ""]
    lines += ["### Not run", "", *[f"- {_cell(n)}" for n in report["notRun"]], ""]
    return "\n".join(lines)


def write(report: dict[str, Any], *, sarif_path: str | None, summary: str | None, quality: str | None) -> None:
    if sarif_path:
        Path(sarif_path).write_text(json.dumps(sarif(report), indent=1) + "\n", encoding="utf-8")
    if summary:
        Path(summary).write_text(markdown(report), encoding="utf-8")
    if quality:
        Path(quality).write_text(json.dumps(codequality(report), indent=1) + "\n", encoding="utf-8")
