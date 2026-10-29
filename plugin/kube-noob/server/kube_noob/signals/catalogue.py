"""The signal catalogue (``kube_noob/data/signals.yaml``): canonical alert names and reasons, the phrases people use
for them, the words that expand a search, components and playbooks. Every name cites the upstream file it comes
from; ``tests/test_signal_catalogue.py`` keeps the file consistent with the code."""

from __future__ import annotations

import functools
import re
from dataclasses import dataclass
from importlib import resources
from typing import Any

import yaml

from kube_noob.signals.core import Signal

KINDS = ("alert", "event_reason", "pod_reason")
_ID = re.compile(r"^(alert|event_reason|pod_reason):([A-Za-z][A-Za-z0-9_]{1,127})\Z")


@dataclass(frozen=True)
class Entry:
    id: str
    kind: str
    name: str
    aliases: tuple[str, ...]
    terms: tuple[str, ...]
    components: tuple[str, ...]
    playbooks: tuple[str, ...]
    sources: tuple[str, ...]


def _strs(value: Any) -> tuple[str, ...]:
    return tuple(str(v) for v in value) if isinstance(value, list) else ()


@functools.cache
def entries() -> tuple[Entry, ...]:
    raw = resources.files("kube_noob").joinpath("data", "signals.yaml").read_text(encoding="utf-8")
    doc = yaml.safe_load(raw)
    urls: dict[str, str] = doc.get("sources") or {}
    out: list[Entry] = []
    for item in doc.get("signals") or []:
        m = _ID.match(str(item.get("id", "")))
        if not m:
            raise ValueError(f"signals.yaml: bad id {item.get('id')!r}")
        out.append(
            Entry(
                id=m.group(0),
                kind=m.group(1),
                name=m.group(2),
                aliases=_strs(item.get("aliases")),
                terms=_strs(item.get("terms")),
                components=_strs(item.get("components")),
                playbooks=_strs(item.get("playbooks")),
                sources=tuple(urls.get(s, s) for s in _strs(item.get("sources"))),
            )
        )
    return tuple(out)


@functools.cache
def _by_key() -> dict[tuple[str, str], Entry]:
    return {(e.kind, e.name): e for e in entries()}


def get(kind: str, name: str) -> Entry | None:
    return _by_key().get((kind, name))


@functools.cache
def _alias_patterns() -> tuple[tuple[re.Pattern[str], Entry, str], ...]:
    out = []
    for e in entries():
        for alias in e.aliases:
            out.append((re.compile(r"(?<![a-z0-9])" + re.escape(alias) + r"(?![a-z0-9])"), e, alias))
    return tuple(out)


@functools.cache
def _alert_names() -> dict[str, Entry]:
    return {e.name: e for e in entries() if e.kind == "alert"}


def infer(text: str, limit: int = 20) -> list[Signal]:
    """Signals a text implies without naming them: catalogue alert names written as words, and the phrases people
    use for a signal ("leader changed frequently" means etcdHighNumberOfLeaderChanges)."""
    text = text[:200_000]
    found: dict[str, Signal] = {}
    names = _alert_names()
    for word in set(re.findall(r"[A-Za-z][A-Za-z0-9_]{2,127}", text)):
        e = names.get(word)
        if e:
            found.setdefault(e.id, Signal(e.kind, e.name, "", "catalogue: name"))
    lower = text.lower()
    for rx, e, alias in _alias_patterns():
        if e.id not in found and rx.search(lower):
            found[e.id] = Signal(e.kind, e.name, alias, "catalogue: phrase")
    return sorted(found.values(), key=lambda s: (KINDS.index(s.kind), s.name))[:limit]


def terms_for(signals: list[Signal]) -> list[str]:
    """Search words for a set of signals: each catalogued signal's name, terms and components, de-duplicated."""
    out: list[str] = []
    for s in signals:
        e = get(s.kind, s.name)
        if e is None:
            continue
        for t in (*e.terms, *e.components):
            if t not in out:
                out.append(t)
    return out
