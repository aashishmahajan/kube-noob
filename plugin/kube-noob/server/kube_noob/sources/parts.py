"""Which files belong to one corpus shard.

Nothing in this module imports the rest of ``sources``. The plugin reads VEX from these
paths, and importing ``corpus`` from there would also ship the Jira client.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def _manifest(data_dir: Path) -> dict[str, Any]:
    path = data_dir / "corpus" / "MANIFEST.json"
    if not path.is_file():
        return {"shards": {}}
    loaded = json.loads(path.read_text(encoding="utf-8"))
    return loaded if isinstance(loaded, dict) else {"shards": {}}


def shard_paths(data_dir: Path, shard: str) -> list[Path]:
    """Every file of ``shard``, in part order. A large shard is ``<shard>.jsonl`` then ``<shard>-2.jsonl``.

    The manifest decides which parts are current, so a leftover file from a larger previous write is not read.
    A file with no manifest entry is still read: that is how a single shard written before parts existed is found.
    """
    cdir = data_dir / "corpus"
    shards = _manifest(data_dir).get("shards") or {}
    ordered: list[tuple[int, str]] = []
    primary = shards.get(shard)
    if isinstance(primary, dict) and primary.get("file"):
        ordered.append((1, str(primary["file"])))
    for key, entry in shards.items():
        tail = key[len(shard) + 1 :] if key.startswith(f"{shard}-") else ""
        if tail.isdigit() and isinstance(entry, dict) and entry.get("file"):
            ordered.append((int(tail), str(entry["file"])))
    if ordered:
        return [cdir / name for _, name in sorted(ordered) if (cdir / name).is_file()]
    one = cdir / f"{shard}.jsonl"
    return [one] if one.is_file() else []
