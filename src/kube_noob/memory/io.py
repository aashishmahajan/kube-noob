"""Reading and writing memory entries: one YAML file per entry at ``<repo>/entries/MEM-<n>.yaml``.

Reading is bounded like every other parser (256 KB per file, the YAML node, depth and alias budgets of
``kube_noob.yamlio``), refuses duplicate keys and more than one document, and the file name must match the id.
Writing is deterministic: the model's field order, camelCase keys, versions always quoted, empty fields left out.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from kube_noob.memory.model import MemoryEntry

MAX_FILE = 256_000
ENTRIES_DIR = "entries"


def parse_entry(text: str) -> MemoryEntry:
    """One entry from YAML text. Raises ``ValueError`` (or pydantic's ``ValidationError``) with the reason."""
    from kube_noob.yamlio import fmt_path, load_documents

    if len(text.encode("utf-8", errors="replace")) > MAX_FILE:
        raise ValueError(f"a memory entry is limited to {MAX_FILE} bytes")
    docs = load_documents(text)
    if len(docs) != 1:
        raise ValueError(f"a memory entry file holds one entry (found {len(docs)} YAML documents)")
    doc = docs[0]
    if doc.duplicate_keys:
        path, line = doc.duplicate_keys[0]
        raise ValueError(f"duplicate key {fmt_path(path)} at line {line}: YAML would keep only the last one")
    if not isinstance(doc.data, dict):
        raise ValueError("a memory entry is a YAML mapping (id, status, kind, symptom, ...)")
    return MemoryEntry.model_validate(doc.data)


def load_entry(path: Path) -> MemoryEntry:
    if path.stat().st_size > MAX_FILE:
        raise ValueError(f"{path.name}: a memory entry is limited to {MAX_FILE} bytes")
    entry = parse_entry(path.read_text(encoding="utf-8"))
    if path.name != f"{entry.id}.yaml":
        raise ValueError(f"{path.name} holds {entry.id}: name the file {entry.id}.yaml")
    return entry


class _Dumper(yaml.SafeDumper):
    def ignore_aliases(self, data: Any) -> bool:
        return True  # the same date twice is written twice, never as an &anchor / *alias pair


def _str(dumper: yaml.SafeDumper, data: str) -> yaml.ScalarNode:
    if "\n" in data:
        return dumper.represent_scalar("tag:yaml.org,2002:str", data, style="|")
    if data.replace(".", "").isdigit():  # versions stay strings when someone edits the file: '4.20', not 4.2
        return dumper.represent_scalar("tag:yaml.org,2002:str", data, style="'")
    return dumper.represent_scalar("tag:yaml.org,2002:str", data)


_Dumper.add_representer(str, _str)


def _prune(value: Any) -> Any:
    if isinstance(value, dict):
        return {k: _prune(v) for k, v in value.items() if v not in (None, [], {})}
    if isinstance(value, list):
        return [_prune(v) for v in value]
    return value


def dump_entry(entry: MemoryEntry) -> str:
    data = _prune(entry.model_dump(by_alias=True, mode="python"))
    return yaml.dump(data, Dumper=_Dumper, sort_keys=False, default_flow_style=False, width=120, allow_unicode=True)


def entry_path(repo: Path, entry: MemoryEntry) -> Path:
    return repo / ENTRIES_DIR / f"{entry.id}.yaml"
