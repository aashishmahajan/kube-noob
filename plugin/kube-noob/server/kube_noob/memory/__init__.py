"""Fixes-as-code memory: what a team learned about a problem, kept as reviewed YAML in the team's own repository.

``model`` defines the entry and its content rules, ``io`` reads and writes ``entries/MEM-<n>.yaml``. The JSON Schema
shipped at ``kube_noob/data/memory/entry.schema.json`` describes the shape for editors and CI; content rules (the
classifier's labels, credential and log detection) are enforced by the model.

Memory content is the team's own and is never redistributable: kube-noob never bundles, publishes or exports it as
training data.
"""

from __future__ import annotations

from typing import Any

from kube_noob.memory.io import ENTRIES_DIR, MAX_FILE, dump_entry, entry_path, load_entry, parse_entry
from kube_noob.memory.model import (
    Command,
    Evidence,
    Fix,
    MemoryEntry,
    OperatorRange,
    Outcome,
    RiskAccepted,
    SignalRef,
    Versions,
)

__all__ = [
    "ENTRIES_DIR",
    "MAX_FILE",
    "Command",
    "Evidence",
    "Fix",
    "MemoryEntry",
    "OperatorRange",
    "Outcome",
    "RiskAccepted",
    "SignalRef",
    "Versions",
    "dump_entry",
    "entry_path",
    "json_schema",
    "load_entry",
    "parse_entry",
]


def json_schema() -> dict[str, Any]:
    """The entry's JSON Schema (draft 2020-12), as shipped in ``data/memory/entry.schema.json``."""
    schema = MemoryEntry.model_json_schema(by_alias=True, mode="validation")
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "title": "kube-noob memory entry",
        "description": "One file per entry at entries/MEM-<n>.yaml. Shape only: `kube-noob memory validate` also "
        "checks content (command labels, credentials, raw logs, the fix verifier).",
        **{k: v for k, v in schema.items() if k not in {"title", "description"}},
    }
