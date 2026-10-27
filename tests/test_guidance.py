"""docs/guidance.md is the contract: every rule names its checks, and every named check must exist."""

from __future__ import annotations

import ast
import re
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
ROW = re.compile(r"^\| (G\d{2}) \| (.+?) \| (.+) \|$")
REF = re.compile(r"`([^`]+)`")


def _rows() -> list[tuple[str, str, list[str]]]:
    rows = []
    for line in (ROOT / "docs/guidance.md").read_text().splitlines():
        m = ROW.match(line)
        if m:
            refs = [r for r in REF.findall(m.group(3)) if r.startswith(("tests/", "ci:"))]
            rows.append((m.group(1), m.group(2), refs))
    return rows


def _tests_in(path: Path) -> set[str]:
    tree = ast.parse(path.read_text())
    return {n.name for n in tree.body if isinstance(n, ast.FunctionDef | ast.AsyncFunctionDef)}


def _ci_names() -> set[str]:
    names: set[str] = set()
    for wf in (ROOT / ".github/workflows").glob("*.yml"):
        doc = yaml.safe_load(wf.read_text())
        for job_id, job in (doc.get("jobs") or {}).items():
            names.add(job_id)
            names.update(str(s["name"]) for s in job.get("steps", []) if "name" in s)
    return names


def test_every_rule_has_existing_checks() -> None:
    rows = _rows()
    assert len(rows) >= 20
    ids = [r[0] for r in rows]
    assert len(ids) == len(set(ids)), "duplicate guidance ids"
    ci = _ci_names()
    missing = []
    for gid, _, refs in rows:
        assert refs, f"{gid} has no enforcing check"
        for ref in refs:
            if ref.startswith("ci:"):
                if ref[3:] not in ci:
                    missing.append(f"{gid}: CI step/job {ref[3:]!r}")
                continue
            file, _, name = ref.partition("::")
            path = ROOT / file
            if not path.is_file() or name not in _tests_in(path):
                missing.append(f"{gid}: {ref}")
    assert missing == []


def test_docs_are_concise_and_linked() -> None:
    readme = (ROOT / "README.md").read_text()
    assert len(readme.split()) < 600
    for doc in ("docs/use-cases.md", "docs/learning.md", "docs/guidance.md"):
        assert (ROOT / doc).is_file() and doc in readme, doc
    assert "kube-noob demo" in readme and "kube-noob doctor" in readme
    use_cases = (ROOT / "docs/use-cases.md").read_text()
    assert all(f"kube-noob demo {d}" in use_cases for d in ("learn", "audit", "diagnose", "posture"))
    assert "getting_started" in use_cases


_AI_CLAIMS = [
    re.compile(r"(?i)\boffline AI\b"),
    re.compile(r"(?i)\bkube-noob (is|as) an? [^.\n|]{0,60}?\b(assistant|chatbot|agent|AI)\b"),
    re.compile(r"(?i)\b(debugging|audit|learning) agent\b"),
    re.compile(r"(?i)\bmine runs\b"),
]


def test_positioning_says_no_ai_inside_and_never_claims_otherwise() -> None:
    """kube-noob calls no model; the AI is the client (Claude, Lightspeed) or the optional `kube-noob ask`."""
    for doc in ("README.md", "plugin/kube-noob/README.md", "docs/use-cases.md", "PRIVACY.md"):
        assert "no AI inside" in (ROOT / doc).read_text().replace("No AI inside", "no AI inside"), doc
    copy = [
        ROOT / "README.md",
        ROOT / "PRIVACY.md",
        ROOT / "pyproject.toml",
        ROOT / "server.json",
        ROOT / ".claude-plugin" / "marketplace.json",
        ROOT / "plugin" / "kube-noob" / ".claude-plugin" / "plugin.json",
        ROOT / "plugin" / "kube-noob" / "README.md",
        ROOT / "src" / "kube_noob" / "__init__.py",
        ROOT / "src" / "kube_noob" / "cli.py",
        *sorted((ROOT / "docs").glob("*.md")),
        *sorted((ROOT / "plugin" / "kube-noob" / "skills").glob("*/SKILL.md")),
        *sorted((ROOT / "demos").glob("*.md")),
        *sorted((ROOT / "demos" / "video").glob("*.html")),
    ]
    found = [
        f"{path.relative_to(ROOT)}: {m.group(0)!r}"
        for path in copy
        for rx in _AI_CLAIMS
        for m in rx.finditer(path.read_text())
    ]
    assert found == []


def test_privacy_policy_lists_every_destination() -> None:
    from kube_noob.config import DEFAULT_ALLOWED_DOMAINS

    privacy = (ROOT / "PRIVACY.md").read_text()
    for domain in DEFAULT_ALLOWED_DOMAINS:
        assert re.search(rf"(?<![\w.-]){re.escape(domain)}(?![\w-])", privacy), domain
    for destination in ("API server", "The model you configure", "Public GitHub", "Jira"):
        assert destination in privacy, destination
    assert "no telemetry" in privacy.lower() and "uv.lock" in privacy
