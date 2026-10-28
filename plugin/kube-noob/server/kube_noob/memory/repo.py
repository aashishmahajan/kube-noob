"""A memory repository on disk: ``README.md``, ``entry.schema.json``, ``entries/MEM-<n>.yaml`` and CI templates.

kube-noob writes only what a person asks for (``init``, ``add``, ``outcome``, ``migrate-learning``) and never runs
git: reviewing and committing an entry is the team's step. New files are created exclusively (two ``add`` runs never
take the same id) and rewrites are atomic (a temporary file, then ``os.replace``).
"""

from __future__ import annotations

import os
import re
import tempfile
from dataclasses import dataclass
from datetime import date
from importlib import resources
from pathlib import Path
from string import Template
from typing import Any

from kube_noob.memory.io import ENTRIES_DIR, dump_entry, load_entry
from kube_noob.memory.model import MemoryEntry

MAX_ENTRIES = 10_000
_ENTRY_FILE = re.compile(r"^MEM-[1-9]\d{0,6}\.yaml$")


@dataclass(frozen=True)
class Loaded:
    path: Path
    entry: MemoryEntry | None
    error: str | None = None


def is_repo(root: Path) -> bool:
    return (root / ENTRIES_DIR).is_dir()


def require_repo(root: Path) -> Path:
    if not is_repo(root):
        raise ValueError(f"{root} is not a memory repository (no {ENTRIES_DIR}/): run kube-noob memory init {root}")
    return root


def entry_files(root: Path) -> list[Path]:
    """Entry files in id order. Files that are not ``MEM-<n>.yaml`` are reported by ``validate``, not read."""
    files = [p for p in (root / ENTRIES_DIR).iterdir() if p.is_file() and p.suffix in {".yaml", ".yml"}]
    if len(files) > MAX_ENTRIES:
        raise ValueError(f"{root}: more than {MAX_ENTRIES} entry files; split the repository")
    return sorted(files, key=lambda p: (int(p.stem.split("-", 1)[1]) if _ENTRY_FILE.match(p.name) else 10**9, p.name))


def load_repo(root: Path) -> list[Loaded]:
    """Every entry file, loaded or with the reason it could not be."""
    require_repo(root)
    out: list[Loaded] = []
    for path in entry_files(root):
        if not _ENTRY_FILE.match(path.name):
            out.append(Loaded(path, None, f"{path.name}: entry files are named MEM-<n>.yaml"))
            continue
        try:
            out.append(Loaded(path, load_entry(path)))
        except Exception as exc:  # noqa: BLE001 - every problem is reported with its file, none stops the rest
            out.append(Loaded(path, None, _reason(exc)))
    return out


def _reason(exc: Exception) -> str:
    from pydantic import ValidationError

    if isinstance(exc, ValidationError):
        parts = []
        for err in exc.errors()[:5]:
            where = ".".join(str(x) for x in err.get("loc", ()))
            msg = str(err.get("msg", "")).removeprefix("Value error, ")
            parts.append(f"{where}: {msg}" if where else msg)
        return "; ".join(parts)
    return str(exc)


def approved(root: Path) -> list[MemoryEntry]:
    return [x.entry for x in load_repo(root) if x.entry is not None and x.entry.status == "approved"]


def next_number(root: Path) -> int:
    nums = [int(p.stem.split("-", 1)[1]) for p in entry_files(root) if _ENTRY_FILE.match(p.name)]
    return max(nums, default=0) + 1


def _write_new(path: Path, text: str) -> bool:
    try:
        with open(path, "x", encoding="utf-8") as fh:
            fh.write(text)
    except FileExistsError:
        return False
    return True


def write_atomic(path: Path, text: str) -> None:
    fd, tmp = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(text)
        os.replace(tmp, path)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise


# --------------------------------------------------------------------------------------------------- init


def _template(name: str, **values: str) -> str:
    raw = resources.files("kube_noob").joinpath("data", "memory", name).read_text(encoding="utf-8")
    return Template(raw).substitute(**values)


def init_repo(root: Path) -> dict[str, list[str]]:
    """Scaffold a repository. Existing files are kept, never overwritten."""
    from kube_noob import __version__
    from kube_noob.memory import json_schema

    files: dict[str, str] = {
        "README.md": _template("README.md.tmpl", version=__version__),
        "entry.schema.json": _schema_text(json_schema()),
        f"{ENTRIES_DIR}/.gitkeep": "",
        ".github/workflows/kube-noob-memory.yml": _template("kube-noob-memory.yml.tmpl", version=__version__),
        "scripts/validate-memory.sh": _template("validate-memory.sh.tmpl", version=__version__),
    }
    created, kept = [], []
    for rel, text in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        if _write_new(path, text):
            created.append(rel)
            if rel.endswith(".sh"):
                path.chmod(0o755)
        else:
            kept.append(rel)
    return {"created": created, "kept": kept}


def _schema_text(schema: dict[str, Any]) -> str:
    import json

    return json.dumps(schema, indent=2) + "\n"


# --------------------------------------------------------------------------------------------------- add


def add_entry(
    root: Path, fields: dict[str, Any], today: date | None = None, created: date | None = None
) -> tuple[Path, MemoryEntry]:
    """Write a new ``proposed`` entry with the next free id. ``fields`` are the entry's fields without id, status and
    dates; ``created`` backdates the entry to when the lesson was learned (an imported ticket's resolution date).
    The entry is validated before anything is written."""
    require_repo(root)
    day = today or date.today()
    born = min(created or day, day)
    for _ in range(100):
        number = next_number(root)
        entry = MemoryEntry.model_validate(
            {**fields, "id": f"MEM-{number}", "status": "proposed", "created": born, "updated": day}
        )
        path = root / ENTRIES_DIR / f"{entry.id}.yaml"
        if _write_new(path, dump_entry(entry)):
            return path, entry
    raise RuntimeError("could not reserve a new entry id; is another process adding entries?")


def find_entry(root: Path, entry_id: str) -> Path:
    if not re.fullmatch(r"MEM-[1-9]\d{0,6}", entry_id):
        raise ValueError(f"{entry_id!r} is not an entry id (MEM-<n>)")
    path = require_repo(root) / ENTRIES_DIR / f"{entry_id}.yaml"
    if not path.is_file():
        raise ValueError(f"no entry {entry_id} in {root}")
    return path


def add_outcome(
    root: Path,
    entry_id: str,
    result: str,
    ticket: str | None = None,
    cluster: str | None = None,
    day: date | None = None,
) -> MemoryEntry:
    """Record that the entry was applied once, and how it went; ``updated`` becomes that day."""
    path = find_entry(root, entry_id)
    entry = load_entry(path)
    when = day or date.today()
    outcome: dict[str, Any] = {"date": when, "result": result}
    if ticket:
        outcome["ticket"] = ticket
    if cluster:
        outcome["cluster"] = cluster
    data = entry.model_dump(by_alias=True)
    data["outcomes"] = [*data.get("outcomes", []), outcome]
    data["updated"] = max(when, entry.updated)
    updated = MemoryEntry.model_validate(data)
    write_atomic(path, dump_entry(updated))
    return updated


# --------------------------------------------------------------------------------------------------- learning


def migrate_learning(
    root: Path, notes: list[dict[str, Any]], owner: str, default_platform: str, today: date | None = None
) -> dict[str, list[dict[str, str]]]:
    """Turn confirmed learning notes into proposed entries, once: an entry that already cites a note's
    ``kn:local-<n>#0`` is not created again. The note's words give the signals."""
    from kube_noob.signals import for_text

    require_repo(root)
    cited: dict[str, str] = {}
    for item in load_repo(root):
        if item.entry:
            for ev in item.entry.evidence:
                if ev.kind == "citation":
                    cited[ev.ref.strip("[]")] = item.entry.id
    created: list[dict[str, str]] = []
    skipped: list[dict[str, str]] = []
    for note in notes:
        if not note.get("confirmed", True):
            continue
        citation = f"kn:{note['id']}#0"
        if citation in cited:
            skipped.append({"note": note["id"], "reason": f"already {cited[citation]}"})
            continue
        found = for_text(f"{note['symptom']}\n{note['cause']}")
        signals = [{"kind": s.kind, "name": s.name} for s in found if s.kind != "error_template"][:20]
        fields: dict[str, Any] = {
            "kind": "fix",
            "signals": signals,
            "symptom": note["symptom"],
            "platform": note.get("platform") or default_platform,
            "cause": note["cause"],
            "fix": {"text": note["fix"]},
            "evidence": [{"kind": "citation", "ref": citation}],
            "owners": [owner],
        }
        try:
            _, entry = add_entry(root, fields, today)
        except Exception as exc:  # noqa: BLE001 - one bad note never stops the rest
            skipped.append({"note": note["id"], "reason": _reason(exc)})
            continue
        created.append({"note": note["id"], "entry": entry.id})
    return {"created": created, "skipped": skipped}
