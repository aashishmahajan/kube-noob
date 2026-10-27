"""Local knowledge base: built-in curated docs + ingested corpus, searched with BM25.

Every chunk carries provenance (source URL, license, version, retrieval time) so answers can credit their sources
("source attribution credits"). Chunk ids are stable: ``kn:<doc-id>#<n>``.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
import threading
from collections import Counter
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from importlib import resources
from pathlib import Path
from typing import Any

import yaml

_TOKEN = re.compile(r"[a-z0-9][a-z0-9._/-]*[a-z0-9]|[a-z0-9]")
_STOP = frozenset(
    [
        "a",
        "an",
        "and",
        "are",
        "as",
        "at",
        "be",
        "by",
        "for",
        "from",
        "has",
        "have",
        "how",
        "i",
        "in",
        "is",
        "it",
        "its",
        "of",
        "on",
        "or",
        "that",
        "the",
        "this",
        "to",
        "was",
        "what",
        "when",
        "where",
        "which",
        "who",
        "why",
        "will",
        "with",
        "you",
        "your",
        "can",
        "do",
        "does",
        "not",
        "no",
    ]
)
MAX_CHUNK_CHARS = 1600
CITATION_RE = re.compile(r"\[(kn:[A-Za-z0-9._/-]+#\d+)\]")


def tokenize(text: str) -> list[str]:
    out: list[str] = []
    for tok in _TOKEN.findall(text.lower()):
        if tok in _STOP:
            continue
        out.append(tok)
        if any(ch in tok for ch in "-./"):
            out.extend(p for p in re.split(r"[-./]", tok) if p and p not in _STOP)
    return out


@dataclass
class Chunk:
    chunk_id: str
    doc_id: str
    title: str
    heading: str
    text: str
    url: str | None
    license: str
    origin: str  # builtin | corpus
    source_id: str
    version: str | None = None
    redistributable: bool = True
    extra: dict[str, Any] = field(default_factory=dict)

    def citation(self) -> dict[str, Any]:
        return {
            "chunkId": self.chunk_id,
            "title": self.title + (f" > {self.heading}" if self.heading and self.heading != self.title else ""),
            "url": self.url,
            "license": self.license,
            "sourceId": self.source_id,
            "version": self.version,
            "origin": self.origin,
        }


def _split_markdown(body: str) -> Iterator[tuple[str, str]]:
    heading = ""
    buf: list[str] = []
    for line in body.splitlines():
        m = re.match(r"^(#{1,3})\s+(.*)$", line)
        if m:
            if "".join(buf).strip():
                yield heading, "\n".join(buf).strip()
            heading, buf = m.group(2).strip(), []
        else:
            buf.append(line)
    if "".join(buf).strip():
        yield heading, "\n".join(buf).strip()


def _size_split(text: str) -> Iterator[str]:
    if len(text) <= MAX_CHUNK_CHARS:
        yield text
        return
    paras = re.split(r"\n\s*\n", text)
    cur = ""
    for p in paras:
        if len(cur) + len(p) + 2 > MAX_CHUNK_CHARS and cur:
            yield cur.strip()
            cur = ""
        rest = p
        while len(rest) > MAX_CHUNK_CHARS:
            yield rest[:MAX_CHUNK_CHARS]
            rest = rest[MAX_CHUNK_CHARS:]
        cur += rest + "\n\n"
    if cur.strip():
        yield cur.strip()


def parse_front_matter(raw: str) -> tuple[dict[str, Any], str]:
    if raw.startswith("---\n"):
        end = raw.find("\n---", 4)
        if end != -1:
            meta = yaml.safe_load(raw[4:end]) or {}
            return (meta if isinstance(meta, dict) else {}), raw[end + 4 :].lstrip("\n")
    return {}, raw


def chunk_document(
    doc_id: str,
    title: str,
    body: str,
    *,
    url: str | None,
    license_: str,
    origin: str,
    source_id: str,
    version: str | None = None,
    redistributable: bool = True,
    extra: dict[str, Any] | None = None,
) -> list[Chunk]:
    chunks: list[Chunk] = []
    n = 0
    for heading, section in _split_markdown(body):
        for piece in _size_split(section):
            chunks.append(
                Chunk(
                    f"kn:{doc_id}#{n}",
                    doc_id,
                    title,
                    heading or title,
                    piece,
                    url,
                    license_,
                    origin,
                    source_id,
                    version,
                    redistributable,
                    dict(extra or {}),
                )
            )
            n += 1
    return chunks


@dataclass
class Hit:
    chunk: Chunk
    score: float

    def as_dict(self, max_chars: int = 700) -> dict[str, Any]:
        text = self.chunk.text
        return {
            **self.chunk.citation(),
            "score": round(self.score, 3),
            "text": text if len(text) <= max_chars else text[:max_chars].rsplit(" ", 1)[0] + " ...",
        }


class KnowledgeStore:
    """BM25 (k1=1.5, b=0.75) over chunks. Thread-safe lazy build."""

    def __init__(self, chunks: Iterable[Chunk]) -> None:
        self.chunks: list[Chunk] = list(chunks)
        self.by_id: dict[str, Chunk] = {c.chunk_id: c for c in self.chunks}
        self._tf: list[Counter[str]] = []
        self._len: list[int] = []
        self._df: Counter[str] = Counter()
        for c in self.chunks:
            toks = tokenize(f"{c.title} {c.heading} {c.heading} {c.text}")
            tf = Counter(toks)
            self._tf.append(tf)
            self._len.append(len(toks))
            self._df.update(tf.keys())
        self._avg = (sum(self._len) / len(self._len)) if self._len else 0.0

    def search(
        self,
        query: str,
        limit: int = 5,
        origin: str | None = None,
        source_prefix: str | None = None,
        include_restricted: bool = True,
    ) -> list[Hit]:
        q = tokenize(query)
        if not q or not self.chunks:
            return []
        n = len(self.chunks)
        scores: list[tuple[float, int]] = []
        for i, c in enumerate(self.chunks):
            if origin and c.origin != origin:
                continue
            if source_prefix and not c.source_id.startswith(source_prefix):
                continue
            if not include_restricted and not c.redistributable:
                continue
            tf = self._tf[i]
            s = 0.0
            for t in q:
                f = tf.get(t)
                if not f:
                    continue
                df = self._df[t]
                idf = math.log(1 + (n - df + 0.5) / (df + 0.5))
                s += idf * (f * 2.5) / (f + 1.5 * (1 - 0.75 + 0.75 * self._len[i] / (self._avg or 1)))
            if s > 0:
                scores.append((s, i))
        scores.sort(reverse=True)
        return [Hit(self.chunks[i], s) for s, i in scores[:limit]]

    def get(self, chunk_id: str) -> Chunk | None:
        return self.by_id.get(chunk_id)

    def doc(self, doc_id: str) -> list[Chunk]:
        return [c for c in self.chunks if c.doc_id == doc_id]

    def doc_ids(self) -> list[dict[str, Any]]:
        seen: dict[str, dict[str, Any]] = {}
        for c in self.chunks:
            if c.doc_id not in seen:
                seen[c.doc_id] = {
                    "docId": c.doc_id,
                    "title": c.title,
                    "origin": c.origin,
                    "sourceId": c.source_id,
                    "url": c.url,
                    "license": c.license,
                    "chunks": 0,
                }
            seen[c.doc_id]["chunks"] += 1
        return list(seen.values())

    def stats(self) -> dict[str, Any]:
        by_origin = Counter(c.origin for c in self.chunks)
        by_source = Counter(c.source_id.split(":")[0] for c in self.chunks)
        return {
            "chunks": len(self.chunks),
            "documents": len({c.doc_id for c in self.chunks}),
            "byOrigin": dict(by_origin),
            "bySource": dict(by_source.most_common(20)),
        }


def builtin_chunks() -> list[Chunk]:
    out: list[Chunk] = []
    root = resources.files("kube_noob").joinpath("data", "knowledge")
    if not root.is_dir():
        return out
    for f in sorted(root.iterdir(), key=lambda p: p.name):
        if not f.name.endswith(".md"):
            continue
        meta, body = parse_front_matter(f.read_text(encoding="utf-8"))
        doc_id = str(meta.get("id") or f.name[:-3])
        srcs = meta.get("sources") or []
        url = srcs[0].get("url") if srcs and isinstance(srcs[0], dict) else None
        out.extend(
            chunk_document(
                doc_id,
                str(meta.get("title") or doc_id),
                body,
                url=url,
                license_=str(meta.get("license", "Apache-2.0")),
                origin="builtin",
                source_id=f"builtin:{doc_id}",
                version=str(meta.get("updated")) if meta.get("updated") else None,
                extra={"sources": srcs, "tags": meta.get("tags") or [], "platforms": meta.get("platforms") or []},
            )
        )
    return out


def corpus_chunks(data_dir: Path) -> list[Chunk]:
    out: list[Chunk] = []
    cdir = data_dir / "corpus"
    if not cdir.is_dir():
        return out
    for f in sorted(cdir.glob("*.jsonl")):
        with f.open(encoding="utf-8") as fh:
            for line in fh:
                if not line.strip():
                    continue
                rec = json.loads(line)
                out.extend(
                    chunk_document(
                        rec["id"],
                        rec.get("title") or rec["id"],
                        rec.get("text", ""),
                        url=rec.get("url"),
                        license_=rec.get("license", "unknown"),
                        origin="corpus",
                        source_id=rec.get("sourceId", f.stem),
                        version=rec.get("version"),
                        redistributable=bool(rec.get("redistributable", False)),
                        extra={
                            k: rec[k]
                            for k in (
                                "retrievedAt",
                                "sha256",
                                "labels",
                                "status",
                                "fixVersions",
                                "affectsVersions",
                                "updated",
                                "issueType",
                                "priority",
                            )
                            if k in rec
                        },
                    )
                )
    return out


_lock = threading.Lock()
_store: KnowledgeStore | None = None
_store_key: str | None = None


def get_store(data_dir: Path | None = None) -> KnowledgeStore:
    """Process-wide store; rebuilt when the corpus directory changes."""
    global _store, _store_key  # noqa: PLW0603
    key = "builtin"
    if data_dir is not None:
        cdir = data_dir / "corpus"
        if cdir.is_dir():
            h = hashlib.sha256()
            for f in sorted(cdir.glob("*.jsonl")):
                st = f.stat()
                h.update(f"{f.name}:{st.st_size}:{st.st_mtime_ns}".encode())
            key = h.hexdigest()
    with _lock:
        if _store is None or _store_key != key:
            chunks = builtin_chunks()
            if data_dir is not None:
                chunks.extend(corpus_chunks(data_dir))
            _store = KnowledgeStore(chunks)
            _store_key = key
        return _store


def extract_citations(text: str) -> list[str]:
    return list(dict.fromkeys(CITATION_RE.findall(text)))
