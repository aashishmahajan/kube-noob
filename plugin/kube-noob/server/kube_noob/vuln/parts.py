"""Which files belong to one corpus shard.

This stays out of ``sources``. The plugin reads VEX from these paths, and anything under
``sources`` is refused: that package is how the Jira client would get bundled.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from kube_noob.sanitize import loads_bounded


def _manifest(data_dir: Path) -> dict[str, Any]:
    path = data_dir / "corpus" / "MANIFEST.json"
    if not path.is_file():
        return {"shards": {}}
    loaded = loads_bounded(path.read_text(encoding="utf-8"))
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
