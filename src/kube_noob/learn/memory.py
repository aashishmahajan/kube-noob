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
- A file from a newer schema is opened read-only. A corrupt file is moved aside under a unique name, never
  overwritten; a file that cannot be read (permissions, I/O) makes learning read-only instead.
- Every write is a read-modify-write under an advisory file lock, so the CLI, the MCP server and other replicas
  sharing the data directory never lose each other's notes or counts.
"""

from __future__ import annotations

import contextlib
import json
import logging
import math
import os
import re
import tempfile
import threading
import uuid
from collections import Counter
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

try:  # POSIX advisory lock so the CLI, the MCP server and other replicas never lose each other's writes
    import fcntl
except ImportError:  # pragma: no cover - Windows
    fcntl = None  # type: ignore[assignment]

from kube_noob.debug.cluster import redact_text

SCHEMA_VERSION = 1
FILE_NAME = "learning.json"
MAX_NOTES = 500
MAX_COUNTERS = 2000
PLATFORMS = ("kubernetes", "openshift", "rosa-classic", "rosa-hcp")
VERSION_KEYS = ("kubernetes", "openshift", "helm", "rhacs", "rosa")
_LIMITS = {"symptom": 400, "cause": 600, "fix": 1200}
_MAX_LINES = 5
_VERSION = re.compile(r"^\d+\.\d+(\.\d+)?$")
_COUNTER = re.compile(r"^[a-z][a-z-]*:[A-Za-z0-9._-]{1,80}$")
_TAG = re.compile(r"^[a-z0-9][a-z0-9-]{0,39}$")
_NOTE_ID = re.compile(r"^local-\d{1,6}$")
_MANIFEST_KEYS = re.compile(r"(?m)^\s*[\"']?(apiVersion|kind|metadata|spec|data|stringData)[\"']?\s*:")
_API_VERSION = re.compile(r"[\"']?\bapiVersion\b[\"']?\s*[:=]")
_KIND = re.compile(r"[\"']?\bkind\b[\"']?\s*[:=]")
_LOG_LINE = re.compile(r"(?m)^\s*(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}|[IWEF]\d{4} \d{2}:\d{2}|\[\d+\.\d+\])")
_STACK = re.compile(
    r"(?m)(goroutine \d+ \[|Traceback \(most recent call last\)|^\s+at [\w.$<>]+\(|^panic: |\.go:\d+ \+0x)"
)
_EXTRA_SECRETS = (
    re.compile(r"(?i)\b(ghp|gho|ghs|ghu|github_pat)_[A-Za-z0-9_]{20,}"),
    re.compile(r"\bsk-[A-Za-z0-9-]{20,}"),
    re.compile(r"\bglpat-[A-Za-z0-9_-]{20,}"),
    re.compile(r"(?i)\b(Bearer|Basic)\s+[A-Za-z0-9._~+/=-]{12,}"),
    re.compile(r"(?i)[\w-]*(key|certificate|token)-data\s*[:=]"),
    re.compile(r"(?i)(secret[_-]?access[_-]?key|access[_-]?key[_-]?id|session[_-]?token|client[_-]?secret)\s*[:=]"),
    re.compile(r"(?i)[\"']auths?[\"']\s*:"),
    re.compile(r"(?i)\b(password|passwd|passphrase|pwd|token|secret|api[ _-]?key)\s+(is|was|=|:)\s*\S{6,}"),
    re.compile(r"\bAIza[0-9A-Za-z_-]{30,}"),
    re.compile(r"\bsha256~[A-Za-z0-9_-]{20,}"),
    re.compile(r"-----BEGIN [A-Z ]*(PRIVATE KEY|CERTIFICATE|OPENSSH)[A-Z ]*-----"),
    re.compile(r"\b(AKIA|ASIA)[A-Z0-9]{12,}"),
)
_TOKENISH = re.compile(r"[A-Za-z0-9+/=_]{24,}")

_log = logging.getLogger("kube_noob.learning")
_lock = threading.Lock()


def _now() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _entropy(token: str) -> float:
    counts = Counter(token)
    return -sum(c / len(token) * math.log2(c / len(token)) for c in counts.values())


def _looks_like_secret_token(text: str) -> bool:
    """A long mixed-case alphanumeric run with high entropy (API keys, base64 credentials). Hex digests and
    hyphenated Kubernetes names do not qualify: they lack upper case or are split by '-'."""
    for tok in _TOKENISH.findall(text):
        has_mix = any(c.isupper() for c in tok) and any(c.islower() for c in tok) and any(c.isdigit() for c in tok)
        if has_mix and _entropy(tok) >= 3.5:
            return True
    return False


def check_text(field: str, value: str, limit: int) -> str:
    """Reject anything that is not a short human summary: credentials, manifests, raw log excerpts."""
    v = value.strip()
    if not v:
        raise ValueError(f"{field} is empty")
    if len(v) > limit:
        raise ValueError(f"{field} is longer than {limit} characters; store a summary, not raw output")
    if redact_text(v) != v or any(p.search(v) for p in _EXTRA_SECRETS) or _looks_like_secret_token(v):
        raise ValueError(f"{field} looks like it contains a credential; learning notes never store secrets")
    if len(_MANIFEST_KEYS.findall(v)) >= 2 or (_API_VERSION.search(v) and _KIND.search(v)):
        raise ValueError(f"{field} looks like a manifest; describe the fix in words and keep manifests in Git")
    if v.count("\n") >= _MAX_LINES or len(_LOG_LINE.findall(v)) >= 3 or _STACK.search(v):
        raise ValueError(f"{field} looks like raw log or command output; summarise it in a sentence or two")
    return v


def _valid_note(n: Any) -> bool:
    return (
        isinstance(n, dict)
        and isinstance(n.get("id"), str)
        and bool(_NOTE_ID.match(n["id"]))
        and all(isinstance(n.get(k), str) and n[k].strip() for k in ("symptom", "cause", "fix"))
    )


def _normalize(data: dict[str, Any]) -> dict[str, Any]:
    """Keep only well-formed entries so a hand-edited, truncated or newer file can never break search or audit."""
    notes = data.get("notes")
    data["notes"] = [n for n in notes if _valid_note(n)] if isinstance(notes, list) else []
    counters = data.get("counters")
    data["counters"] = (
        {k: v for k, v in counters.items() if isinstance(k, str) and _COUNTER.match(k) and type(v) is int and v >= 0}
        if isinstance(counters, dict)
        else {}
    )
    prof = data.get("profile")
    data["profile"] = prof if isinstance(prof, dict) else {}
    return data


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
            text = self.path.read_text(encoding="utf-8")
        except OSError as exc:  # permissions, I/O: never move a file we merely could not read
            self._read_only_reason = f"{self.path} cannot be read ({exc}); learning is read-only"
            return self._default()
        try:
            raw = json.loads(text)
            if not isinstance(raw, dict):
                raise ValueError("top level is not an object")
        except (ValueError, RecursionError) as exc:
            # Unique name: a second corrupt load in the same second must not overwrite the first backup.
            aside = self.path.with_name(
                f"{FILE_NAME}.corrupt-{datetime.now(UTC):%Y%m%dT%H%M%SZ}-{uuid.uuid4().hex[:8]}"
            )
            try:
                if aside.exists():
                    raise FileExistsError(aside)
                self.path.rename(aside)
                _log.warning("learning file %s was corrupt (%s); moved to %s", self.path, exc, aside)
            except OSError:
                self._read_only_reason = f"{self.path} is corrupt and could not be moved aside"
            return self._default()
        version = raw.get("schemaVersion", 0)
        if type(version) is not int or version > SCHEMA_VERSION:
            self._read_only_reason = (
                f"{self.path} was written by a newer kube-noob (schemaVersion {version}); "
                "upgrade kube-noob to change it"
            )
            return _normalize({**self._default(), **raw})
        return _normalize(self._migrate(raw, version))

    @contextlib.contextmanager
    def _mutate(self) -> Iterator[dict[str, Any]]:
        """Read-modify-write under a thread lock and an advisory file lock, always from a fresh read."""
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with _lock, open(self.path.with_name(FILE_NAME + ".lock"), "a", encoding="utf-8") as lock_fh:
            if fcntl is not None:
                fcntl.flock(lock_fh.fileno(), fcntl.LOCK_EX)
            try:
                self._read_only_reason = None
                self._cache = self._load()
                if self._read_only_reason:
                    raise ValueError(self._read_only_reason)
                yield self._cache
                self._save()
            finally:
                if fcntl is not None:
                    fcntl.flock(lock_fh.fileno(), fcntl.LOCK_UN)

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
        with self._mutate() as data:
            notes: list[dict[str, Any]] = data["notes"]
            if len(notes) >= MAX_NOTES:
                raise ValueError(f"learning file holds {MAX_NOTES} notes; forget old ones first")
            nums = [int(n["id"].split("-", 1)[1]) for n in notes]
            note = {"id": f"local-{max(nums, default=0) + 1}", "created": _now(), "confirmed": True, **note}
            notes.append(note)
        return note

    def forget(self, note_id: str) -> bool:
        if not any(n["id"] == note_id for n in self._data["notes"]):
            return False
        with self._mutate() as data:
            data["notes"] = [n for n in data["notes"] if n["id"] != note_id]
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
        updates: dict[str, Any] = {}
        if platform is not None:
            if platform not in PLATFORMS:
                raise ValueError(f"platform must be one of {', '.join(PLATFORMS)}")
            updates["platform"] = platform
        for k, v in (versions or {}).items():
            if k not in VERSION_KEYS or not _VERSION.match(v):
                raise ValueError(f"versions keys are {', '.join(VERSION_KEYS)} with values like 4.22 or 1.35.1")
        if conventions is not None:
            if len(conventions) > 20:
                raise ValueError("keep at most 20 conventions")
            updates["conventions"] = [check_text("convention", c, 200) for c in conventions]
        with self._mutate() as data:
            prof: dict[str, Any] = data["profile"]
            prof.update(updates)
            if versions:
                current = prof.get("versions")
                prof["versions"] = {
                    **(current if isinstance(current, dict) else {}),
                    **versions,
                }
        return dict(prof)

    def profile(self) -> dict[str, Any]:
        return dict(self._data.get("profile") or {})

    # -- counters ------------------------------------------------------------------------------------------------
    def bump(self, keys: list[str]) -> None:
        """Count pattern ids (``playbook:DBG-X``, ``rule:KN-SEC-001``, ``platform:openshift``). Best effort."""
        valid = [k for k in keys if isinstance(k, str) and _COUNTER.match(k)]
        if not valid:
            return
        try:
            with self._mutate() as data:
                counters: dict[str, int] = data["counters"]
                for k in valid:
                    if k in counters or len(counters) < MAX_COUNTERS:
                        counters[k] = counters.get(k, 0) + 1
        except Exception as exc:  # noqa: BLE001 - counting is best effort and must never break a tool call
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
        if prof.get("platform") in PLATFORMS:
            parts.append(f"platform {prof['platform']}")
        raw_versions = prof.get("versions")
        versions: dict[str, Any] = raw_versions if isinstance(raw_versions, dict) else {}
        parts += [f"{k} {v}" for k, v in sorted(versions.items()) if k in VERSION_KEYS and isinstance(v, str)]
        raw_conventions = prof.get("conventions")
        conventions: list[Any] = raw_conventions if isinstance(raw_conventions, list) else []
        parts += [f"convention: {c}" for c in conventions if isinstance(c, str)]
        if not parts:
            return ""
        return "Known environment (user-provided profile): " + "; ".join(parts) + "."
