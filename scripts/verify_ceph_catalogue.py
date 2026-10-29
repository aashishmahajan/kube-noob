#!/usr/bin/env python3
"""Check the Ceph health catalogue (src/kube_noob/data/ceph_health.yaml) against checkouts of the sources it cites.

Usage: python scripts/verify_ceph_catalogue.py --ceph DIR --rook DIR --odf DIR

DIR are checkouts of github.com/ceph/ceph, github.com/rook/rook and github.com/red-hat-storage/ocs-operator at the
commits the catalogue pins (shallow, sparse clones of the cited files are enough). For every code: its doc line is the
heading of its section (or names the code), each source line emits it, and the literal wording of each summary is in
a cited source file (or its words are next to a cited line). For every alert: the rule line declares it, a `health`
rule's expression names the codes it watches (or its `expr`), and an ODF rule carries the runbook the catalogue
gives. Alerts in the rule files that the catalogue leaves out are listed, not failed. Exit 1 on any mismatch.
"""

from __future__ import annotations

import argparse
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "src" / "kube_noob" / "data" / "ceph_health.yaml"
NEARBY = 40  # lines around a cited source line where a summary's words may be composed (" OSD(s)" + its suffix)


def _lines(path: Path) -> list[str]:
    return path.read_text(encoding="utf-8", errors="replace").split("\n")


def _head(repo: Path) -> str:
    git = shutil.which("git")
    if git is None:
        return ""
    out = subprocess.run([git, "-C", str(repo), "rev-parse", "HEAD"], capture_output=True, text=True, check=False)
    return out.stdout.strip()


def _pieces(summary: str) -> list[str]:
    return [p.strip() for p in re.split(r"\{[a-z]+\}", summary) if len(p.strip()) >= 4]


def check_codes(doc: dict[str, Any], ceph: Path, problems: list[str]) -> None:
    files = doc["sources"]["ceph"]["files"]
    texts = {key: _lines(ceph / path) for key, path in files.items()}
    for c in doc["codes"]:
        code = c["code"]
        if c.get("doc"):
            key, line = c["doc"].split(":")
            lines = texts[key]
            n = int(line) - 1
            heading = lines[n] if n < len(lines) else ""
            underline = lines[n + 1] if n + 1 < len(lines) else ""
            wanted = c.get("section") or code
            is_heading = bool(re.fullmatch(r"[_\-~=]{3,}", underline)) and wanted in heading.replace("``", "")
            if not (is_heading or code in heading):
                problems.append(f"{code}: {c['doc']} is not its section ({heading.strip()[:80]!r})")
        cited: list[tuple[str, int]] = []
        for cite in c.get("src", []):
            key, line = cite.split(":")
            n = int(line) - 1
            window = "\n".join(texts[key][max(0, n - 2) : n + 3])
            names = [code, *c.get("also", [])]
            if not any(name in window for name in names) and not (code.startswith("OSD_") and '"_DOWN"' in window):
                problems.append(f"{code}: {cite} does not emit it")
            cited.append((key, n))
        for summary in c.get("summary", []):
            for piece in _pieces(summary):
                if any(piece in "\n".join(texts[key]) for key, _ in cited):
                    continue
                words = re.findall(r"[A-Za-z]{3,}", piece)
                near = "\n".join("\n".join(texts[key][max(0, n - NEARBY) : n + NEARBY]) for key, n in cited)
                if not words or not all(w in near for w in words):
                    problems.append(f"{code}: summary wording {piece!r} not found near its source")


def _rules(path: Path) -> dict[str, dict[str, Any]]:
    doc = yaml.safe_load(path.read_text(encoding="utf-8"))
    groups = doc["spec"]["groups"] if "spec" in doc else doc["groups"]
    return {r["alert"]: r for g in groups for r in g.get("rules", []) if "alert" in r}


def check_alerts(doc: dict[str, Any], repos: dict[str, Path], problems: list[str]) -> list[str]:
    rule_files = {s: repos[s] / doc["sources"][s]["files"]["rules"] for s in ("rook", "odf")}
    lines = {s: _lines(p) for s, p in rule_files.items()}
    rules = {s: _rules(p) for s, p in rule_files.items()}
    catalogued = {a["alert"] for a in doc["alerts"]}
    for a in doc["alerts"]:
        name = a["alert"]
        exprs: list[str] = []
        for cite in a["rules"]:
            source, line = cite.split(":")
            text = lines[source][int(line) - 1] if int(line) <= len(lines[source]) else ""
            if not re.search(r"alert:\s*\"?" + re.escape(name) + r"\"?\s*\Z", text):
                problems.append(f"{name}: {cite} does not declare it ({text.strip()[:80]!r})")
                continue
            rule = rules[source].get(name, {})
            exprs.append(str(rule.get("expr", "")))
            if source == "odf":
                runbook = (rule.get("annotations") or {}).get("runbook_url")
                if runbook != a.get("runbook"):
                    problems.append(f"{name}: runbook {a.get('runbook')!r} is not the rule's {runbook!r}")
        if a["how"] == "health":  # each code is read by one of the alert's rules (Rook's and ODF's may differ)
            for code in a.get("expr") or a.get("watches", []):
                named = re.compile(r"name=~?\"[A-Z0-9_|]*\b" + code + r"\b")
                if not any(named.search(e) or f"healthcheck_{code.lower()}" in e for e in exprs):
                    problems.append(f"{name}: no rule's expression reads {code}")
    return sorted({n for s in rules for n in rules[s]} - catalogued)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--ceph", required=True, type=Path)
    ap.add_argument("--rook", required=True, type=Path)
    ap.add_argument("--odf", required=True, type=Path)
    a = ap.parse_args(argv)
    doc = yaml.safe_load(DATA.read_text(encoding="utf-8"))
    repos = {"ceph": a.ceph, "rook": a.rook, "odf": a.odf}
    problems: list[str] = []
    for source, repo in repos.items():
        if _head(repo) != doc["sources"][source]["commit"]:
            problems.append(f"{source}: checkout is at {_head(repo) or '?'}, the catalogue pins the commit it cites")
    check_codes(doc, a.ceph, problems)
    left_out = check_alerts(doc, repos, problems)
    print(f"{len(doc['codes'])} codes, {len(doc['alerts'])} alerts checked")
    if left_out:
        print(f"not catalogued ({len(left_out)}): {', '.join(left_out)}")
    for p in problems:
        print(f"MISMATCH {p}")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
