#!/usr/bin/env python3
"""Refresh the bundled OpenShift update risks (src/kube_noob/data/upgrade_risks/) from the public update graph data.

Usage: python scripts/vendor_upgrade_risks.py --repo DIR [--min-minor 4.18]
       python scripts/vendor_upgrade_risks.py --check     exit 1 if a shard is too large, unreadable or malformed

DIR is a local clone of https://github.com/openshift/cincinnati-graph-data (Apache-2.0), made outside this repository,
for example ``git clone --depth 1 https://github.com/openshift/cincinnati-graph-data /tmp/graph-data``. The script
reads ``blocked-edges/*.yaml`` and keeps, for every declaration whose target (``to``) is an x.y.z release of OpenShift
``--min-minor`` or later, only ``to``, ``from``, ``url``, ``name``, ``message``, ``fixedIn`` and ``matchingRules``,
plus the file's path; each shard records the upstream commit, its date and what was kept and skipped. Pre-release
targets (``4.21.0-rc.1``) are skipped: kube-noob looks up updates between x.y.z releases. Shards are split by target
minor into parts under PART_LIMIT bytes, so every file stays readable text well under the Claude plugin directory's
256 KiB limit.

The format was checked against the repository's own README.md ("Block Edges": ``to``, ``from``, ``url``, ``name``,
``fixedIn``, ``autoExtend``, ``message``, ``matchingRules``; schema ``version`` 1.1.0) at commit
7572174a551561c30e07e9b5ca6f156ef5cd513c (2026-10-29):
https://github.com/openshift/cincinnati-graph-data/blob/7572174a551561c30e07e9b5ca6f156ef5cd513c/README.md
A consumer that understands schema x.y.0 may read x.y'.0 for y' <= y (README "Schema Version"); the script stops on a
newer schema. Needs git (to read the commit) and no network.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "src" / "kube_noob" / "data" / "upgrade_risks"
PART_LIMIT = 200_000  # bytes per shard; the plugin directory refuses files over 256 KiB
MAX_FILE = 64 * 1024  # a blocked-edges file larger than this is skipped as malformed
MAX_FIELD = 8_000  # characters in any one kept string (message, PromQL)
SCHEMA_MAJOR, SCHEMA_MINOR = 1, 1  # the graph-data schema this script and kube_noob.upgrade_risks understand
SOURCE = "https://github.com/openshift/cincinnati-graph-data"
ATTRIBUTION = f"OpenShift update graph data (c) Red Hat, Inc. and contributors, Apache-2.0, {SOURCE}"
_RELEASE = re.compile(r"(0|[1-9][0-9]{0,3})\.(0|[1-9][0-9]{0,3})\.(0|[1-9][0-9]{0,5})\Z")
_LEADING = re.compile(r"([0-9]+)\.([0-9]+)\.")
_COMMIT = re.compile(r"[0-9a-f]{40}\Z")
sys.path.insert(0, str(ROOT / "src"))


def _git(repo: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-C", str(repo), *args],  # noqa: S607 - git from PATH, fixed arguments, a local path
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def _string(value: Any) -> bool:
    return isinstance(value, str) and len(value) <= MAX_FIELD


def _rules(value: Any) -> list[dict[str, Any]] | None:
    """``matchingRules`` as upstream wrote them (each a mapping with a string ``type``), or None when malformed."""
    if not isinstance(value, list) or len(value) > 20:
        return None
    out = []
    for raw in value:
        if not isinstance(raw, dict) or not _string(raw.get("type")):
            return None
        rule = raw
        if raw["type"] == "PromQL":
            promql = raw.get("promql")
            if not isinstance(promql, dict) or not _string(promql.get("promql")):
                return None
            rule = {"type": "PromQL", "promql": {"promql": promql["promql"].strip()}}  # YAML's trailing newline
        if len(json.dumps(rule)) > MAX_FIELD:
            return None
        out.append(rule)
    return out


def record(path: Path, doc: Any) -> dict[str, Any] | None:
    """The kept fields of one blocked-edges file, or None when it is malformed."""
    if not isinstance(doc, dict) or not isinstance(doc.get("to"), str) or not _string(doc.get("from")):
        return None
    r: dict[str, Any] = {"to": doc["to"], "from": doc["from"]}
    for key in ("name", "url", "message", "fixedIn"):
        if key in doc:
            if not _string(doc[key]):
                return None
            r[key] = doc[key].strip()
    if "matchingRules" in doc:
        rules = _rules(doc["matchingRules"])
        if rules is None:
            return None
        r["matchingRules"] = rules
    r["source"] = f"blocked-edges/{path.name}"
    return r


def _vkey(version: str) -> tuple[int, ...]:
    return tuple(int(p) for p in version.split("."))


def collect(repo: Path, min_minor: tuple[int, int]) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    edges = repo / "blocked-edges"
    kept: list[dict[str, Any]] = []
    older = pre_release = 0
    malformed: list[str] = []
    for path in sorted(edges.glob("*.yaml")):
        if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_FILE:
            malformed.append(path.name)
            continue
        doc = yaml.safe_load(path.read_text(encoding="utf-8"))
        r = record(path, doc)
        if r is None:
            malformed.append(path.name)
            continue
        lead = _LEADING.match(r["to"])
        if not lead or (int(lead.group(1)), int(lead.group(2))) < min_minor:
            older += 1
            continue
        if not _RELEASE.match(r["to"]):
            pre_release += 1
            continue
        kept.append(r)
    kept.sort(key=lambda r: (_vkey(r["to"]), r["source"]))
    scope = {
        "minTarget": f"{min_minor[0]}.{min_minor[1]}",
        "targets": "x.y.z releases only",
        "kept": len(kept),
        "skippedOlderTargets": older,
        "skippedPreReleaseTargets": pre_release,
        "skippedMalformed": malformed,
    }
    return kept, scope


def write_parts(records: list[dict[str, Any]], meta: dict[str, Any]) -> list[Path]:
    OUT.mkdir(parents=True, exist_ok=True)
    for old in OUT.glob("*.json"):
        old.unlink()
    groups: dict[str, list[dict[str, Any]]] = {}
    for r in records:
        groups.setdefault(".".join(r["to"].split(".")[:2]), []).append(r)
    head = json.dumps(meta, ensure_ascii=False, separators=(",", ":"))[:-1]
    written: list[Path] = []
    for minor, recs in sorted(groups.items(), key=lambda kv: _vkey(kv[0])):
        parts: list[list[str]] = [[]]
        size = len(head) + 64
        for r in recs:
            line = json.dumps(r, ensure_ascii=False, separators=(",", ":"))
            if parts[-1] and size + len(line.encode()) + 2 > PART_LIMIT:
                parts.append([])
                size = len(head) + 64
            parts[-1].append(line)
            size += len(line.encode()) + 2
        for n, lines in enumerate(parts, start=1):
            path = OUT / f"openshift-{minor}-{n}.json"
            body = ",\n".join(lines)
            path.write_text(f'{head},"records":[\n{body}\n]}}\n', encoding="utf-8")
            written.append(path)
    return written


def check() -> int:
    from kube_noob.upgrade_risks import PatternError, compile_from

    bad: list[str] = []
    files = sorted(OUT.glob("*.json"))
    unsupported = 0
    total = 0
    for f in files:
        raw = f.read_bytes()
        if len(raw) >= PART_LIMIT:
            bad.append(f"{f.name}: {len(raw)} bytes (limit {PART_LIMIT})")
        doc = json.loads(raw.decode("utf-8"))
        if not _COMMIT.match(str(doc.get("commit", ""))) or doc.get("license") != "Apache-2.0":
            bad.append(f"{f.name}: no upstream commit or license")
        for r in doc.get("records", []):
            total += 1
            if not _RELEASE.match(str(r.get("to", ""))) or not str(r.get("source", "")).startswith("blocked-edges/"):
                bad.append(f"{f.name}: malformed record {r.get('source')}")
            try:
                compile_from(str(r.get("from", "")))
            except PatternError:
                unsupported += 1
    if not files:
        bad.append(f"no shards in {OUT}: run with --repo")
    if bad:
        print("\n".join(bad))
        return 1
    print(
        f"{len(files)} upgrade-risk files, {total} risks, each file under {PART_LIMIT} bytes and valid JSON; "
        f"{unsupported} 'from' patterns outside the safe regex subset"
    )
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--repo", type=Path, help="a local clone of openshift/cincinnati-graph-data")
    ap.add_argument("--min-minor", default="4.18", help="keep targets of this OpenShift minor and later")
    ap.add_argument("--check", action="store_true")
    a = ap.parse_args()
    if a.check:
        return check()
    if a.repo is None:
        ap.error("--repo is required (a clone of cincinnati-graph-data made outside this repository)")
    repo = a.repo.resolve()
    if repo == ROOT or ROOT in repo.parents:
        ap.error("clone cincinnati-graph-data outside this repository")
    if not (repo / "blocked-edges").is_dir():
        ap.error(f"{repo} has no blocked-edges/ directory")
    schema = (repo / "version").read_text(encoding="utf-8").strip()
    major, minor = (int(p) for p in schema.split(".")[:2])
    if major != SCHEMA_MAJOR or minor > SCHEMA_MINOR:
        print(f"graph-data schema {schema} is newer than {SCHEMA_MAJOR}.{SCHEMA_MINOR}.0: review the README first")
        return 1
    m = re.fullmatch(r"([0-9]+)\.([0-9]+)", a.min_minor)
    if not m:
        ap.error("--min-minor is a minor version such as 4.18")
    commit = _git(repo, "rev-parse", "HEAD")
    if not _COMMIT.match(commit):
        print(f"unexpected commit id {commit!r}")
        return 1
    records, scope = collect(repo, (int(m.group(1)), int(m.group(2))))
    meta = {
        "retrievedAt": datetime.now(UTC).date().isoformat(),
        "source": SOURCE,
        "commit": commit,
        "commitDate": _git(repo, "log", "-1", "--format=%cI"),
        "schemaVersion": schema,
        "license": "Apache-2.0",
        "attribution": ATTRIBUTION,
        "scope": scope,
    }
    files = write_parts(records, meta)
    print(
        f"{len(records)} risks for OpenShift {scope['minTarget']}+ targets from {SOURCE}@{commit[:12]} -> "
        f"{len(files)} files in {OUT}; skipped {scope['skippedOlderTargets']} older and "
        f"{scope['skippedPreReleaseTargets']} pre-release targets, {len(scope['skippedMalformed'])} malformed"
    )
    for name in scope["skippedMalformed"]:
        print(f"  malformed: {name}")
    return check()


if __name__ == "__main__":
    raise SystemExit(main())
