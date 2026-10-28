"""CI check of the live Red Hat VEX step (db-image job): the output, the shard, and diagnostics when either is off.

Usage: python scripts/vex_ci_check.py OUTPUT_JSON SHARD_JSONL RAW_DOC_JSON

OUTPUT_JSON is `kube-noob corpus advisories --format json`, SHARD_JSONL the shard it wrote, RAW_DOC_JSON one raw
CSAF VEX document downloaded by the step (read only to explain a failure). Passes when statements were kept, none is
malformed, at least one record names an OpenShift product, and the only fetch failures are documents over the size
cap (reported and skipped by design: Red Hat's CVE-2023-44487 document is larger than 25 MB). Every result is
printed as a GitHub annotation, because the runner's log host is not reachable from where the loop reads results.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any


def _annotate(level: str, title: str, message: str) -> None:
    text = " ".join(message.split())[:1800]
    print(f"::{level} title={title}::{text}")


def _cpes(raw: Any) -> list[str]:
    out: list[str] = []

    def walk(node: Any) -> None:
        if isinstance(node, dict):
            helper = node.get("product_identification_helper")
            if isinstance(helper, dict) and isinstance(helper.get("cpe"), str):
                out.append(helper["cpe"])
            for value in node.values():
                walk(value)
        elif isinstance(node, list):
            for value in node:
                walk(value)

    walk(raw.get("product_tree") if isinstance(raw, dict) else None)
    return out


def diagnose(raw_path: Path) -> str:
    try:
        raw = json.loads(raw_path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        return f"raw document unreadable: {type(exc).__name__}: {exc}"
    cpes = _cpes(raw)
    prefixes = sorted({":".join(c.split(":")[:4]) for c in cpes})
    vulns = raw.get("vulnerabilities") if isinstance(raw, dict) else None
    status_keys = sorted({k for v in vulns or [] if isinstance(v, dict) for k in (v.get("product_status") or {})})
    return (
        f"raw: {len(cpes)} CPEs, {len(prefixes)} prefixes: {prefixes[:25]}; vulnerabilities "
        f"{len(vulns or [])}; product_status keys {status_keys}"
    )


def main(argv: list[str]) -> int:
    if len(argv) != 4:
        _annotate("error", "VEX check usage", "python scripts/vex_ci_check.py OUTPUT_JSON SHARD_JSONL RAW_DOC_JSON")
        return 2
    out_path, shard_path, raw_path = (Path(x) for x in argv[1:])
    problems: list[str] = []
    try:
        out = json.loads(out_path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        _annotate("error", "Red Hat VEX output", f"{type(exc).__name__}: {exc}")
        return 1
    summary = {k: out.get(k) for k in ("documents", "kept", "malformed", "cves", "requests", "failed", "notPublished")}
    if not (isinstance(out.get("kept"), int) and out["kept"] >= 1):
        problems.append("no statement kept for the default products")
    if out.get("malformed"):
        problems.append(f"{out['malformed']} malformed")
    records: list[dict[str, Any]] = []
    if shard_path.exists():
        for line in shard_path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                records.append(json.loads(line))
    else:
        problems.append(f"no shard at {shard_path}")
    for failure in out.get("failed") or []:
        if "larger than" not in str(failure):  # a document over the size cap is reported and skipped, as designed
            problems.append(f"fetch failed: {failure}")
    rows: list[str] = []
    openshift = False
    for rec in records:
        products = sorted({str(st.get("product")) for st in rec.get("statements", [])})
        statuses = sorted({str(st.get("status")) for st in rec.get("statements", [])})
        openshift = openshift or any("OpenShift" in prod for prod in products)
        rows.append(f"{rec.get('cve')}: {len(rec.get('statements', []))} statements, {statuses}, {products[:4]}")
    if not openshift:
        problems.append(f"no record names an OpenShift product ({len(records)} records)")
    if problems:
        _annotate("error", "Red Hat VEX live", f"{'; '.join(problems)}; output {summary}; {diagnose(raw_path)}")
        return 1
    _annotate("notice", "Red Hat VEX live", f"{' | '.join(rows)}; output {summary}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
