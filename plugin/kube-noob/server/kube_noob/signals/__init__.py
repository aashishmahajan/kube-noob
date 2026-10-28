"""Signals: the canonical names an error carries (alert names, event and condition reasons, container reasons,
admission rules, components and normalised error templates). They are the join key between an error, a known issue
and a past fix; text search is the fallback. See ``extract``; ``for_text`` adds the signals a text implies through
the catalogue, and ``playbooks_for`` says which playbooks those signals point at."""

from __future__ import annotations

from typing import Any

from kube_noob.signals.core import KINDS, Signal, extract, normalise_error

__all__ = ["KINDS", "Signal", "extract", "for_text", "normalise_error", "playbooks_for"]


def for_text(data: Any) -> list[Signal]:
    """The signals ``data`` carries (``extract``) followed by the ones its words imply (``catalogue.infer``: an alert
    name written in prose, "leader changed" for etcdHighNumberOfLeaderChanges), each name once."""
    from kube_noob.signals.catalogue import infer

    found = extract(data)
    seen = {(s.kind, s.name) for s in found}
    if isinstance(data, str):
        for s in infer(data):
            if (s.kind, s.name) not in seen:
                seen.add((s.kind, s.name))
                found.append(s)
    return sorted(found, key=lambda s: KINDS.index(s.kind))  # stable: extract's order within a kind, then implied


def playbooks_for(signals: list[Signal]) -> dict[str, list[Signal]]:
    """Playbook id -> the catalogued signals that point at it, in signal order."""
    from kube_noob.signals.catalogue import get

    out: dict[str, list[Signal]] = {}
    for s in signals:
        entry = get(s.kind, s.name)
        for pid in entry.playbooks if entry else ():
            if s not in out.setdefault(pid, []):
                out[pid].append(s)
    return out
