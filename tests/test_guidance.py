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
