"""Corpus storage: JSONL shards plus a manifest with provenance, licenses and checksums."""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

REQUIRED = ("id", "title", "text", "sourceId", "license", "redistributable")


def corpus_dir(data_dir: Path) -> Path:
    d = data_dir / "corpus"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _validate(rec: dict[str, Any]) -> None:
    missing = [k for k in REQUIRED if k not in rec]
    if missing:
        raise ValueError(f"corpus record {rec.get('id')!r} missing {missing}")
    if not isinstance(rec["redistributable"], bool):
        raise ValueError(f"corpus record {rec['id']!r}: redistributable must be a bool")


def write_shard(data_dir: Path, shard: str, records: list[dict[str, Any]]) -> dict[str, Any]:
    """Atomically replace ``corpus/<shard>.jsonl`` and update the manifest."""
    if not shard.replace("-", "").replace("_", "").isalnum():
        raise ValueError(f"invalid shard name {shard!r}")
    cdir = corpus_dir(data_dir)
    for r in records:
        _validate(r)
        r.setdefault("sha256", hashlib.sha256(r["text"].encode("utf-8")).hexdigest())
    target = cdir / f"{shard}.jsonl"
    fd, tmp = tempfile.mkstemp(dir=cdir, prefix=f".{shard}.", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            for r in records:
                fh.write(json.dumps(r, ensure_ascii=False, sort_keys=True) + "\n")
        os.replace(tmp, target)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise
    digest = hashlib.sha256(target.read_bytes()).hexdigest()
    entry = {
        "shard": shard,
        "file": target.name,
        "records": len(records),
        "sha256": digest,
        "licenses": dict(Counter(r["license"] for r in records)),
        "redistributable": all(r["redistributable"] for r in records),
        "sources": sorted({r["sourceId"] for r in records}),
        "writtenAt": datetime.now(UTC).isoformat(timespec="seconds"),
    }
    manifest_path = cdir / "MANIFEST.json"
    manifest: dict[str, Any] = {"shards": {}}
    if manifest_path.is_file():
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest.setdefault("shards", {})[shard] = entry
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return entry


def read_manifest(data_dir: Path) -> dict[str, Any]:
    p = data_dir / "corpus" / "MANIFEST.json"
    return json.loads(p.read_text(encoding="utf-8")) if p.is_file() else {"shards": {}}


def iter_records(data_dir: Path, include_restricted: bool = True) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    cdir = data_dir / "corpus"
    if not cdir.is_dir():
        return out
    for f in sorted(cdir.glob("*.jsonl")):
        with f.open(encoding="utf-8") as fh:
            for line in fh:
                if line.strip():
                    rec = json.loads(line)
                    if include_restricted or rec.get("redistributable"):
                        out.append(rec)
    return out


def verify(data_dir: Path) -> list[str]:
    """Return problems: checksum mismatches, shards missing from the manifest, invalid records."""
    problems: list[str] = []
    manifest = read_manifest(data_dir)
    cdir = data_dir / "corpus"
    for name, entry in manifest.get("shards", {}).items():
        f = cdir / entry["file"]
        if not f.is_file():
            problems.append(f"{name}: file {entry['file']} missing")
            continue
        if hashlib.sha256(f.read_bytes()).hexdigest() != entry["sha256"]:
            problems.append(f"{name}: checksum mismatch (modified outside kube-noob?)")
    if cdir.is_dir():
        listed = {e["file"] for e in manifest.get("shards", {}).values()}
        problems.extend(f"{f.name}: not in MANIFEST.json" for f in cdir.glob("*.jsonl") if f.name not in listed)
    return problems
