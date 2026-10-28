"""Reconciling the local Red Hat Jira copy: what changed since a date, and what is still open.

Every sync records each ticket whose status, status category, resolution or fix versions changed
(``<dataDir>/jira/changes.jsonl``, written by ``kube_noob.sources.jira``). This module reads that log and the ticket
index: tickets fixed (and in which versions), closed without a fix (not a bug, won't fix, duplicate...), reopened,
given a fix version, or opened since a date; and the open tickets per project and verdict. Local data only: nothing
here is shipped or sent anywhere.
"""

from __future__ import annotations

import json
import re
import sqlite3
from collections import Counter
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

OPEN_VERDICTS = ("open", "fix-in-progress", "fix-proposed")
KINDS = (
    "fixed",
    "done",
    "closed",
    "not-a-bug",
    "wont-fix",
    "duplicate",
    "cannot-reproduce",
    "obsolete",
    "reopened",
    "fix-in-progress",
    "fix-proposed",
    "fix-version",
    "opened",
    "open",
    "status",
)
MAX_READ = 50_000_000  # bytes of change log read


def changes_path(data_dir: Path) -> Path:
    """The change log every sync appends to (``kube_noob.sources.jira.append_changes``)."""
    return data_dir / "jira" / "changes.jsonl"


def sync_state(data_dir: Path) -> dict[str, Any]:
    """The sync state (``jira/state.json``) read without the sync code, so the MCP plugin needs no Jira client."""
    path = data_dir / "jira" / "state.json"
    try:
        doc = json.loads(path.read_text(encoding="utf-8")) if path.is_file() else {}
    except (OSError, ValueError):
        return {}
    return doc if isinstance(doc, dict) else {}


def parse_since(text: str, now: datetime | None = None) -> datetime:
    """``2d``, ``36h``, ``90m`` or a date (``2026-10-25``) as an aware datetime."""
    now = now or datetime.now(UTC)
    m = re.fullmatch(r"\s*(\d{1,4})\s*([dhm])\s*", text)
    if m:
        n, unit = int(m.group(1)), m.group(2)
        return now - {"d": timedelta(days=n), "h": timedelta(hours=n), "m": timedelta(minutes=n)}[unit]
    try:
        t = datetime.fromisoformat(text.strip())
    except ValueError as exc:
        raise ValueError(f"--since {text!r}: use 2d, 36h, 90m or a date such as 2026-10-25") from exc
    return t if t.tzinfo else t.replace(tzinfo=UTC)


def _when(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        t = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return t if t.tzinfo else t.replace(tzinfo=UTC)


def _events(data_dir: Path) -> list[dict[str, Any]]:
    path = changes_path(data_dir)
    if not path.is_file():
        return []
    out: list[dict[str, Any]] = []
    with path.open(encoding="utf-8") as fh:
        read = 0
        for line in fh:
            read += len(line)
            if read > MAX_READ:
                break
            try:
                e = json.loads(line)
            except ValueError:
                continue
            if isinstance(e, dict) and isinstance(e.get("key"), str) and isinstance(e.get("kind"), str):
                out.append(e)
    return out


def _titles(data_dir: Path, keys: list[str]) -> dict[str, tuple[str, str]]:
    from kube_noob import tickets

    db = tickets.ensure_index(data_dir)
    if db is None or not keys:
        return {}
    out: dict[str, tuple[str, str]] = {}
    con = sqlite3.connect(f"{db.as_uri()}?mode=ro", uri=True)
    try:
        for i in range(0, len(keys), 500):
            chunk = keys[i : i + 500]
            marks = ",".join("?" * len(chunk))
            for key, title, url in con.execute(f"SELECT key, title, url FROM tickets WHERE key IN ({marks})", chunk):  # noqa: S608
                out[key] = (title, url)
    finally:
        con.close()
    return out


def last_sync(data_dir: Path) -> str | None:
    projects = sync_state(data_dir).get("projects")
    stamps = [
        str(p.get("lastSyncAt"))
        for p in (projects.values() if isinstance(projects, dict) else [])
        if isinstance(p, dict) and p.get("lastSyncAt")
    ]
    return max(stamps) if stamps else None


def changes(
    data_dir: Path,
    since: datetime | None = None,
    project: str | None = None,
    kinds: list[str] | None = None,
    limit: int = 200,
) -> dict[str, Any]:
    """Change events since ``since`` (default: 2 days), newest first, with each ticket's title and link."""
    since = since or datetime.now(UTC) - timedelta(days=2)
    wanted = {k.lower() for k in kinds or []}
    rows = []
    for e in _events(data_dir):
        at = _when(e.get("at"))
        if at is None or at < since:
            continue
        if project and str(e.get("project", "")).upper() != project.upper():
            continue
        if wanted and e["kind"] not in wanted:
            continue
        rows.append(e)
    latest: dict[str, dict[str, Any]] = {}
    for e in rows:  # the log is oldest first: keep each ticket's latest change, counted once
        latest[e["key"]] = e
    ordered = sorted(latest.values(), key=lambda e: (str(e.get("at")), e["key"]), reverse=True)
    titles = _titles(data_dir, [e["key"] for e in ordered[:limit]])
    out_rows = []
    for e in ordered[:limit]:
        title, url = titles.get(e["key"], ("", ""))
        row = {k: e.get(k) for k in ("key", "project", "kind", "at", "type")}
        row.update(title=title, url=url, to=e.get("to"))
        if e.get("from"):
            row["from"] = e["from"]
        out_rows.append(row)
    return {
        "since": since.isoformat(timespec="seconds"),
        "lastSync": last_sync(data_dir),
        "counts": dict(sorted(Counter(e["kind"] for e in ordered).items())),
        "tickets": len(ordered),
        "changes": out_rows,
        **({"truncated": len(ordered) - limit} if len(ordered) > limit else {}),
        **(
            {}
            if out_rows or _events(data_dir)
            else {
                "note": "No changes recorded yet: they are recorded from the "
                "second sync of a copy on (kube-noob corpus jira --online)."
            }
        ),
    }


def open_summary(data_dir: Path, project: str | None = None, top: int = 10) -> dict[str, Any]:
    """Open tickets in the copy: per project and verdict (open, fix in progress, fix proposed), and the busiest
    components."""
    from kube_noob import tickets

    db = tickets.ensure_index(data_dir)
    if db is None:
        return {"available": False, "note": "No local Jira copy: kube-noob corpus jira --online, or corpus import."}
    con = sqlite3.connect(f"{db.as_uri()}?mode=ro", uri=True)
    try:
        marks = ",".join("?" * len(OPEN_VERDICTS))
        where = f"verdict IN ({marks})" + (" AND project = ?" if project else "")
        args: list[Any] = [*OPEN_VERDICTS, *([project.upper()] if project else [])]
        per = con.execute(
            f"SELECT project, verdict, count(*) FROM tickets WHERE {where} GROUP BY project, verdict ORDER BY 1, 2",  # noqa: S608
            args,
        ).fetchall()
        comps: Counter[str] = Counter()
        for (raw,) in con.execute(f"SELECT components FROM tickets WHERE {where}", args):  # noqa: S608
            try:
                names = json.loads(raw or "[]")
            except ValueError:
                continue
            comps.update(str(c) for c in names if isinstance(c, str))
    finally:
        con.close()
    projects: dict[str, dict[str, int]] = {}
    for proj, verdict, n in per:
        projects.setdefault(proj, {})[verdict] = n
    return {
        "available": True,
        "lastSync": last_sync(data_dir),
        "open": sum(n for _, _, n in per),
        "byProject": projects,
        "topComponents": comps.most_common(top),
    }
