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


def import_corpus(source: Path, data_dir: Path) -> dict[str, Any]:
    """Import shards from a directory or .tgz produced by ``corpus build`` / the corpus-refresh workflow.

    Only files listed in the source MANIFEST.json are copied, names are validated, and every checksum must match.
    """
    import shutil
    import tarfile

    data_dir.mkdir(parents=True, exist_ok=True)
    # extract next to the data, not in /tmp: a Jira snapshot is gigabytes and the chart's /tmp holds 256 MiB
    with tempfile.TemporaryDirectory(dir=data_dir, prefix=".import-") as tmp:
        root = source
        if source.is_file():
            with tarfile.open(source, "r:gz") as tf:
                tf.extractall(tmp, filter="data")  # rejects absolute paths, '..', links outside, devices
            candidates = list(Path(tmp).rglob("MANIFEST.json"))
            if not candidates:
                raise ValueError(f"{source}: no MANIFEST.json inside the archive")
            root = candidates[0].parent
        manifest_file = root / "MANIFEST.json"
        if not manifest_file.is_file():
            raise ValueError(f"{root}: MANIFEST.json not found")
        manifest = json.loads(manifest_file.read_text(encoding="utf-8"))
        from kube_noob.sources.jira_snapshot import check_extras, restore_extras

        checked = check_extras(root, manifest, data_dir)  # a Jira snapshot: validated before anything is copied
        target = corpus_dir(data_dir)
        current = read_manifest(data_dir)
        imported: list[str] = []
        for name, entry in manifest.get("shards", {}).items():
            fname = str(entry.get("file", ""))
            if not fname.endswith(".jsonl") or "/" in fname or "\\" in fname or fname.startswith("."):
                raise ValueError(f"refusing suspicious shard file name {fname!r}")
            src = root / fname
            if not src.is_file():
                continue  # e.g. redistributable-only bundles omit restricted shards
            if hashlib.sha256(src.read_bytes()).hexdigest() != entry.get("sha256"):
                raise ValueError(f"{fname}: checksum mismatch, refusing to import")
            with src.open(encoding="utf-8") as fh:  # a checksum proves integrity, not well-formedness
                for lineno, line in enumerate(fh, 1):
                    if not line.strip():
                        continue
                    try:
                        rec = json.loads(line)
                    except json.JSONDecodeError as exc:
                        raise ValueError(f"{fname} line {lineno}: invalid JSON ({exc.msg})") from exc
                    if not isinstance(rec, dict):
                        raise ValueError(f"{fname} line {lineno}: record must be a JSON object")
                    _validate(rec)
            shutil.copyfile(src, target / fname)
            current.setdefault("shards", {})[name] = entry
            imported.append(name)
        (target / "MANIFEST.json").write_text(json.dumps(current, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        extras = restore_extras(checked, data_dir) if checked else {}  # its sync state and change log
    return {"imported": imported, "dataDir": str(data_dir), **({"jira": extras} if extras else {})}


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
