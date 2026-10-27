"""Is this a reported issue? Match an error or symptom against the issues Red Hat lists in the OpenShift release notes.

The index holds every known issue (open in a release) and every fixed issue (fixed in a release or update) that the
release notes link to an issue id, for the minor releases in the bundled snapshot. A match is returned only when the
text shares several rare words with the issue, so a generic error (OOMKilled, ImagePullBackOff) does not pull in an
unrelated bug. Each match carries the issue link, the release-notes file it came from, whether a fix exists, and
what that means for the version the user runs.

Data: ``kube_noob/data/known_issues/*.json`` (refreshed with ``scripts/vendor_known_issues.py``) plus, when present,
a newer copy in ``<dataDir>/known_issues/`` written by ``kube-noob corpus known-issues --online``.
"""

from __future__ import annotations

import json
import re
import threading
from dataclasses import dataclass
from importlib import resources
from pathlib import Path
from typing import Any

from kube_noob.catalog import OPENSHIFT_FAMILY
from kube_noob.knowledge.store import Chunk, KnowledgeStore, builtin_chunks, tokenize

MIN_RARE_TERMS = 3  # rare words shared with the issue text before it counts as a match
RARE_SHARE = 0.03  # a word in at most 3% of issues is rare
MIN_SCORE = 20.0  # BM25 score floor, set from tests/test_known_issues.py
GENERAL_SHARE = 0.02  # and in at most 2% of the bundled Kubernetes and OpenShift docs
RELATIVE_FLOOR = 0.75  # further matches must score at least 75% of the best one
_SENTENCE = re.compile(r"(?<=[.!?])\s+(?=[A-Z(`])")
_lock = threading.Lock()
_cache: dict[str, Index] = {}
_general: dict[str, KnowledgeStore] = {}


def vkey(version: str) -> tuple[int, ...]:
    return tuple(int(p) for p in re.findall(r"\d+", version))


def _minor(version: str) -> str:
    return ".".join(version.split(".")[:2])


@dataclass(frozen=True)
class Issue:
    id: str
    ids: tuple[str, ...]
    kind: str  # "known" (open in `minor`) or "fixed" (fixed in `version`)
    minor: str
    version: str
    text: str
    source: str
    issued: str | None
    fixed_in: str | None

    @property
    def summary(self) -> str:
        first = _SENTENCE.split(self.text, maxsplit=1)[0]
        return first if len(first) <= 280 else first[:277].rsplit(" ", 1)[0] + "..."

    @property
    def workaround(self) -> str | None:
        if self.kind != "known":
            return None
        for sentence in _SENTENCE.split(self.text):
            if re.match(r"(?i)(as a workaround|to work around|you can avoid|to avoid this|workaround:)", sentence):
                return sentence
        return "There is no supported workaround." if re.search(r"(?i)no (supported )?workaround", self.text) else None

    @property
    def url(self) -> str:
        return f"https://issues.redhat.com/browse/{self.id}"

    def status(self, running: str | None) -> str:
        if self.kind == "known":
            if self.fixed_in:
                msg = f"Known issue in OpenShift {self.minor}; fixed in {self.fixed_in}."
                if running and vkey(running) < vkey(self.fixed_in):
                    msg += f" You run {running}: updating to {self.fixed_in} or later fixes it."
                return msg
            return f"Known issue in OpenShift {self.minor}; the release notes list no fix yet."
        msg = f"Reported and fixed in OpenShift {self.version}."
        if running and vkey(running) < vkey(self.version):
            msg += f" You run {running}: updating to {self.version} or later fixes it."
        return msg

    def as_dict(self, running: str | None, score: float) -> dict[str, Any]:
        return {
            "id": self.id,
            "url": self.url,
            "kind": self.kind,
            "foundIn": self.minor if self.kind == "known" else None,
            "fixedIn": self.fixed_in if self.kind == "known" else self.version,
            "status": self.status(running),
            "summary": self.summary,
            "workaround": self.workaround,
            "source": self.source,
            "score": round(score, 2),
        }


class Index:
    def __init__(self, issues: list[Issue], meta: dict[str, Any]) -> None:
        self.issues = issues
        self.meta = meta
        self.store = KnowledgeStore(
            Chunk(
                chunk_id=f"{i.id}@{i.version}#{n}",
                doc_id=i.id,
                title=i.summary,
                heading="",
                text=i.text,
                url=i.url,
                license="Apache-2.0",
                origin="known-issues",
                source_id=f"release-notes:{i.minor}",
                version=i.version,
            )
            for n, i in enumerate(issues)
        )
        self.by_chunk = {f"{i.id}@{i.version}#{n}": i for n, i in enumerate(issues)}

    def knowledge(self) -> dict[str, Any]:
        minors = sorted({i.minor for i in self.issues}, key=vkey)
        return {
            "knownIssuesAsOf": self.meta.get("retrievedAt"),
            "openshiftReleases": minors,
            "issues": len(self.issues),
        }

    def _rare_shared(self, query_tokens: set[str], issue: Issue) -> list[str]:
        """Words the text and the issue share that are rare among issues and in general Kubernetes writing, so
        `spec`, `pod` or `securitycontext` never make a match on their own."""
        doc = set(tokenize(f"{issue.summary} {issue.text}"))
        general = _general_store()
        return sorted(
            t
            for t in query_tokens & doc
            if len(t) > 2 and self.store.doc_frequency(t) <= RARE_SHARE and general.doc_frequency(t) <= GENERAL_SHARE
        )

    def match(
        self, text: str, platform: str | None = None, version: str | None = None, limit: int = 3
    ) -> dict[str, Any]:
        out: dict[str, Any] = {"knowledge": self.knowledge(), "matches": []}
        if platform and platform not in OPENSHIFT_FAMILY:
            out["note"] = "The index holds OpenShift release-note issues; it does not apply to plain Kubernetes."
            return out
        running = version if version and re.fullmatch(r"\d+\.\d+(\.\d+)?", version) else None
        q = set(tokenize(text))
        seen: set[str] = set()
        top = 0.0
        for hit in self.store.search(text, limit=40):
            issue = self.by_chunk[hit.chunk.chunk_id]
            if hit.score < MIN_SCORE or issue.id in seen or (top and hit.score < RELATIVE_FLOOR * top):
                continue
            if running and not self._applies(issue, running):
                continue
            rare = self._rare_shared(q, issue)
            if len(rare) < MIN_RARE_TERMS:
                continue
            seen.add(issue.id)
            top = top or hit.score
            out["matches"].append({**issue.as_dict(running, hit.score), "sharedTerms": rare[:8]})
            if len(out["matches"]) >= limit:
                break
        if not out["matches"]:
            out["note"] = (
                "No reported issue in the OpenShift release notes matches this text closely. "
                f"The index covers OpenShift {', '.join(out['knowledge']['openshiftReleases'])} "
                f"as of {out['knowledge']['knownIssuesAsOf']}."
            )
        return out

    @staticmethod
    def _applies(issue: Issue, running: str) -> bool:
        """Could this issue affect a cluster on `running`? Known: same or earlier minor and not yet fixed there.
        Fixed: the fix is in the same minor and the cluster is older than it."""
        if issue.kind == "known":
            if vkey(_minor(running)) < vkey(issue.minor):
                return False
            return not (issue.fixed_in and vkey(running) >= vkey(issue.fixed_in))
        if _minor(issue.version) != _minor(running):
            return False
        return vkey(running) < vkey(issue.version)


def _general_store() -> KnowledgeStore:
    """The bundled general docs, to tell everyday Kubernetes words from words specific to one issue."""
    with _lock:
        if "__general__" not in _general:
            _general["__general__"] = KnowledgeStore(builtin_chunks())
        return _general["__general__"]


def _parse(doc: dict[str, Any]) -> list[Issue]:
    commits = doc.get("commits", {})
    out = []
    for r in doc.get("records", []):
        source = r["source"]
        if not source.startswith("http"):
            commit = commits.get(r["minor"], f"enterprise-{r['minor']}")
            source = f"https://github.com/openshift/openshift-docs/blob/{commit}/{source}"
        out.append(
            Issue(
                id=r["id"],
                ids=tuple(r.get("ids") or [r["id"]]),
                kind=r["kind"],
                minor=r["minor"],
                version=r["version"],
                text=r["text"],
                source=source,
                issued=r.get("issued"),
                fixed_in=r.get("fixedIn"),
            )
        )
    return out


def _read_parts(files: list[Any]) -> tuple[list[Issue], dict[str, Any]]:
    issues: list[Issue] = []
    meta: dict[str, Any] = {}
    for f in sorted(files, key=lambda p: p.name):
        doc = json.loads(f.read_text(encoding="utf-8"))
        issues.extend(_parse(doc))
        meta = {k: v for k, v in doc.items() if k != "records"} or meta
    return issues, meta


def bundled() -> tuple[list[Issue], dict[str, Any]]:
    root = resources.files("kube_noob").joinpath("data", "known_issues")
    return _read_parts([f for f in root.iterdir() if f.name.endswith(".json")])


def get_index(data_dir: Path | None = None) -> Index:
    """The bundled snapshot, or a newer one in ``<dataDir>/known_issues`` (from ``corpus known-issues``)."""
    key = str(data_dir) if data_dir else ""
    with _lock:
        if key not in _cache:
            issues, meta = bundled()
            local = data_dir / "known_issues" if data_dir else None
            if local and local.is_dir():
                files = sorted(local.glob("*.json"))
                if files:
                    l_issues, l_meta = _read_parts(files)
                    if l_issues and str(l_meta.get("retrievedAt", "")) >= str(meta.get("retrievedAt", "")):
                        issues, meta = l_issues, l_meta
            _cache[key] = Index(issues, meta)
        return _cache[key]


def match(
    text: str, platform: str | None = None, version: str | None = None, limit: int = 3, data_dir: Path | None = None
) -> dict[str, Any]:
    return get_index(data_dir).match(text, platform, version, limit)
