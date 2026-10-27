"""Local, upgrade-safe learning file: ``<dataDir>/learning.json``.

What it keeps
- ``profile``: the user's platform, versions and naming/ops conventions, set explicitly.
- ``notes``: symptom -> cause -> fix records the user confirmed. They are searchable and citable as
  ``[kn:local-<n>#0]`` and are never exported as training data.
- ``counters``: how often each playbook, audit rule, platform and version comes up. These are ids only, never content.

What it never keeps: raw logs, manifests, credentials, cluster object payloads or model conversations.

Upgrade safety
- The file lives in the data directory, outside the installed package, so upgrading or reinstalling the CLI, plugin or
  container image (with a persistent data dir) keeps it.
- ``schemaVersion`` is migrated forward on load, and unknown keys written by newer versions are preserved.
- A file from a newer schema is opened read-only. A corrupt file is moved aside, never overwritten.
"""

from __future__ import annotations

import json
import logging
import os
import re
import tempfile
import threading
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from kube_noob.debug.cluster import redact_text

SCHEMA_VERSION = 1
FILE_NAME = "learning.json"
MAX_NOTES = 500
MAX_COUNTERS = 2000
PLATFORMS = ("kubernetes", "openshift", "rosa-classic", "rosa-hcp")
VERSION_KEYS = ("kubernetes", "openshift", "helm", "rhacs", "rosa")
_LIMITS = {"symptom": 400, "cause": 600, "fix": 1200}
_MAX_LINES = 8
_VERSION = re.compile(r"^\d+\.\d+(\.\d+)?$")
_COUNTER = re.compile(r"^[a-z][a-z-]*:[A-Za-z0-9._-]{1,80}$")
_TAG = re.compile(r"^[a-z0-9][a-z0-9-]{0,39}$")
_MANIFEST = re.compile(r"(?m)^\s*(apiVersion|kind|metadata|spec|data|stringData)\s*:")
_LOG_LINE = re.compile(r"(?m)^\s*(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}|[IWEF]\d{4} \d{2}:\d{2}|\[\d+\.\d+\])")
_EXTRA_SECRETS = (
    re.compile(r"(?i)\b(ghp|gho|ghs|ghu|github_pat)_[A-Za-z0-9_]{20,}"),
    re.compile(r"\bsk-[A-Za-z0-9-]{20,}"),
    re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{16,}"),
)

_log = logging.getLogger("kube_noob.learning")
_lock = threading.Lock()


def _now() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def check_text(field: str, value: str, limit: int) -> str:
    """Reject anything that is not a short human summary: credentials, manifests, raw log excerpts."""
    v = value.strip()
    if not v:
        raise ValueError(f"{field} is empty")
    if len(v) > limit:
        raise ValueError(f"{field} is longer than {limit} characters; store a summary, not raw output")
    if redact_text(v) != v or any(p.search(v) for p in _EXTRA_SECRETS):
        raise ValueError(f"{field} looks like it contains a credential; learning notes never store secrets")
    if len(_MANIFEST.findall(v)) >= 2:
        raise ValueError(f"{field} looks like a manifest; describe the fix in words and keep manifests in Git")
    if v.count("\n") >= _MAX_LINES or len(_LOG_LINE.findall(v)) >= 3:
        raise ValueError(f"{field} looks like raw log or command output; summarise it in a sentence or two")
    return v


class LearningStore:
    def __init__(self, data_dir: Path) -> None:
        self.path = data_dir / FILE_NAME
        self._read_only_reason: str | None = None
        self._stamp: tuple[int, int] | None = None
        self._cache: dict[str, Any] = self._default()

    @property
    def _data(self) -> dict[str, Any]:
        """Re-read when the file changed on disk (another process, the CLI, an upgrade) so writes never lose edits."""
        try:
            st = self.path.stat()
            stamp: tuple[int, int] | None = (st.st_mtime_ns, st.st_size)
        except OSError:
            stamp = None
        if stamp != self._stamp or stamp is None:
            self._read_only_reason = None
            self._cache = self._load()
            self._stamp = stamp if self.path.is_file() else None
        return self._cache

    # -- persistence -------------------------------------------------------------------------------------------
    def _default(self) -> dict[str, Any]:
        return {"schemaVersion": SCHEMA_VERSION, "profile": {}, "notes": [], "counters": {}, "updated": None}

    def _load(self) -> dict[str, Any]:
        if not self.path.is_file():
            return self._default()
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
            if not isinstance(raw, dict):
                raise ValueError("top level is not an object")
        except (OSError, ValueError) as exc:
            aside = self.path.with_name(f"{FILE_NAME}.corrupt-{datetime.now(UTC):%Y%m%dT%H%M%SZ}")
            try:
                self.path.rename(aside)
                _log.warning("learning file %s was unreadable (%s); moved to %s", self.path, exc, aside)
            except OSError:
                self._read_only_reason = f"{self.path} is unreadable and could not be moved aside"
            return self._default()
        version = raw.get("schemaVersion", 0)
        if not isinstance(version, int) or version > SCHEMA_VERSION:
            self._read_only_reason = (
                f"{self.path} was written by a newer kube-noob (schemaVersion {version}); "
                "upgrade kube-noob to change it"
            )
            return {**self._default(), **raw}
        return self._migrate(raw, version)

    def _migrate(self, raw: dict[str, Any], version: int) -> dict[str, Any]:
        data = {**self._default(), **raw}
        if version < 1:
            notes = []
            for i, n in enumerate(raw.get("notes") or [], 1):
                if isinstance(n, dict) and all(isinstance(n.get(k), str) for k in ("symptom", "cause", "fix")):
                    notes.append({"id": n.get("id") or f"local-{i}", "created": n.get("created") or _now(), **n})
            data["notes"] = notes
            data["profile"] = raw.get("profile") if isinstance(raw.get("profile"), dict) else {}
            data["counters"] = {
                k: v for k, v in (raw.get("counters") or {}).items() if isinstance(v, int) and _COUNTER.match(k)
            }
        data["schemaVersion"] = SCHEMA_VERSION
        return data

    def _save(self) -> None:
        if self._read_only_reason:
            raise ValueError(self._read_only_reason)
        self._cache["updated"] = _now()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=self.path.parent, prefix=".learning.", suffix=".tmp")
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(self._cache, fh, indent=2, sort_keys=True)
            os.replace(tmp, self.path)
            st = self.path.stat()
            self._stamp = (st.st_mtime_ns, st.st_size)
        except BaseException:
            Path(tmp).unlink(missing_ok=True)
            raise

    # -- notes ---------------------------------------------------------------------------------------------------
    def add_note(
        self, symptom: str, cause: str, fix: str, platform: str | None = None, tags: list[str] | None = None
    ) -> dict[str, Any]:
        note: dict[str, Any] = {
            "symptom": check_text("symptom", symptom, _LIMITS["symptom"]),
            "cause": check_text("cause", cause, _LIMITS["cause"]),
            "fix": check_text("fix", fix, _LIMITS["fix"]),
        }
        if platform is not None:
            if platform not in PLATFORMS:
                raise ValueError(f"platform must be one of {', '.join(PLATFORMS)}")
            note["platform"] = platform
        clean_tags = sorted({t.strip().lower() for t in (tags or []) if t.strip()})
        bad = [t for t in clean_tags if not _TAG.match(t)]
        if bad or len(clean_tags) > 8:
            raise ValueError("tags are up to 8 short lowercase words (a-z, 0-9, '-')")
        if clean_tags:
            note["tags"] = clean_tags
        with _lock:
            notes: list[dict[str, Any]] = self._data["notes"]
            if self._read_only_reason:
                raise ValueError(self._read_only_reason)
            if len(notes) >= MAX_NOTES:
                raise ValueError(f"learning file holds {MAX_NOTES} notes; forget old ones first")
            nums = [int(n["id"].split("-", 1)[1]) for n in notes if re.fullmatch(r"local-\d+", str(n.get("id")))]
            note = {"id": f"local-{max(nums, default=0) + 1}", "created": _now(), "confirmed": True, **note}
            notes.append(note)
            self._save()
        return note

    def forget(self, note_id: str) -> bool:
        with _lock:
            data = self._data
            before = len(data["notes"])
            data["notes"] = [n for n in data["notes"] if n.get("id") != note_id]
            if len(data["notes"]) == before:
                return False
            self._save()
            return True

    def notes(self) -> list[dict[str, Any]]:
        return list(self._data["notes"])

    # -- profile -------------------------------------------------------------------------------------------------
    def set_profile(
        self,
        platform: str | None = None,
        versions: dict[str, str] | None = None,
        conventions: list[str] | None = None,
    ) -> dict[str, Any]:
        prof: dict[str, Any] = dict(self._data.get("profile") or {})
        if self._read_only_reason:
            raise ValueError(self._read_only_reason)
        if platform is not None:
            if platform not in PLATFORMS:
                raise ValueError(f"platform must be one of {', '.join(PLATFORMS)}")
            prof["platform"] = platform
        if versions:
            merged = dict(prof.get("versions") or {})
            for k, v in versions.items():
                if k not in VERSION_KEYS or not _VERSION.match(v):
                    raise ValueError(f"versions keys are {', '.join(VERSION_KEYS)} with values like 4.22 or 1.35.1")
                merged[k] = v
            prof["versions"] = merged
        if conventions is not None:
            if len(conventions) > 20:
                raise ValueError("keep at most 20 conventions")
            prof["conventions"] = [check_text("convention", c, 200) for c in conventions]
        with _lock:
            self._data["profile"] = prof
            self._save()
        return prof

    def profile(self) -> dict[str, Any]:
        return dict(self._data.get("profile") or {})

    # -- counters ------------------------------------------------------------------------------------------------
    def bump(self, keys: list[str]) -> None:
        """Count pattern ids (``playbook:DBG-X``, ``rule:KN-SEC-001``, ``platform:openshift``). Best effort."""
        valid = [k for k in keys if _COUNTER.match(k)]
        if not valid:
            return
        with _lock:
            counters: dict[str, int] = self._data["counters"]
            if self._read_only_reason:
                return
            for k in valid:
                if k in counters or len(counters) < MAX_COUNTERS:
                    counters[k] = counters.get(k, 0) + 1
            try:
                self._save()
            except (OSError, ValueError) as exc:
                _log.warning("learning counters not saved: %s", exc)

    # -- views ---------------------------------------------------------------------------------------------------
    def summary(self, top: int = 10) -> dict[str, Any]:
        data = self._data
        counters: dict[str, int] = data.get("counters") or {}
        ranked = sorted(counters.items(), key=lambda kv: (-kv[1], kv[0]))[:top]
        return {
            "path": str(self.path),
            "schemaVersion": SCHEMA_VERSION,
            "readOnly": self._read_only_reason,
            "profile": self.profile(),
            "notes": len(data["notes"]),
            "recentNotes": [
                {"id": n["id"], "symptom": n["symptom"], "citation": f"[kn:{n['id']}#0]"}
                for n in reversed(data["notes"][-5:])
            ],
            "counters": dict(ranked),
            "updated": data.get("updated"),
        }

    def note_documents(self) -> list[dict[str, Any]]:
        """Notes rendered as knowledge documents (title + markdown body) for the local search index."""
        docs = []
        for n in self._data["notes"]:
            body = f"Symptom: {n['symptom']}\n\nCause: {n['cause']}\n\nFix: {n['fix']}"
            if n.get("platform"):
                body += f"\n\nPlatform: {n['platform']}"
            if n.get("tags"):
                body += f"\n\nTags: {', '.join(n['tags'])}"
            docs.append(
                {"id": n["id"], "title": f"Team note: {n['symptom'][:80]}", "body": body, "created": n.get("created")}
            )
        return docs

    def profile_prompt(self) -> str:
        """One line of environment context for an agent's system prompt (profile only, no notes)."""
        prof = self.profile()
        if not prof:
            return ""
        parts = []
        if prof.get("platform"):
            parts.append(f"platform {prof['platform']}")
        parts += [f"{k} {v}" for k, v in sorted((prof.get("versions") or {}).items())]
        parts += [f"convention: {c}" for c in prof.get("conventions") or []]
        return "Known environment (user-provided profile): " + "; ".join(parts) + "."
