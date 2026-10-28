"""``kube-noob memory match`` and ``memory stats``: find a team's entries for an error, and count what they did.

Matching is signals first: an entry whose alert, reason, condition, admission or error-template signals appear in the
text (or in an Alertmanager payload) matches on them; components alone are too broad to match. Without a shared
signal, an entry matches on words: at least three distinctive words shared between the text and the entry's symptom,
cause and fix. Approved entries only, unless proposed ones are asked for.

What a match means depends on the entry and the version: ``fix`` and ``runbook`` entries are offered; ``negative``
entries are shown as "tried, did not work"; an entry whose ``fixedIn`` is at or below the given version is shown as
retired (history, not a fix). Each match carries its outcomes: "matched N times, resolved M".
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from kube_noob.catalog import OPENSHIFT_FAMILY
from kube_noob.memory.model import MemoryEntry, vkey
from kube_noob.memory.repo import load_repo, require_repo

MIN_SHARED_WORDS = 3
_STATE_ORDER = {"fix": 0, "runbook": 1, "tried, did not work": 2, "retired": 3}


def _words(text: str) -> set[str]:
    from kube_noob.knowledge.store import tokenize
    from kube_noob.tickets import GENERIC_WORDS

    return {t for t in tokenize(text[:200_000]) if len(t) >= 4 and not t.isdigit() and t not in GENERIC_WORDS}


def _applies(e: MemoryEntry, platform: str | None, version: str | None, operators: dict[str, str]) -> bool:
    same_family = platform in OPENSHIFT_FAMILY and e.platform in OPENSHIFT_FAMILY
    if platform and e.platform not in ("kubernetes", platform) and not same_family:
        return False
    if version and e.versions.introduced and vkey(version) < vkey(e.versions.introduced):
        return False
    for op in e.operators:
        have = operators.get(op.name)
        if have is not None and not op.contains(have):
            return False
    return True


def _outcomes(e: MemoryEntry) -> dict[str, Any]:
    results = [o.result for o in e.outcomes]
    plural = "s" if len(results) != 1 else ""
    clusters = sorted({o.cluster for o in e.outcomes if o.cluster})
    fixed_on = sorted({o.cluster for o in e.outcomes if o.cluster and o.result == "resolved"})
    summary = f"matched {len(results)} time{plural}, resolved {results.count('resolved')}"
    if clusters:
        summary += f"; seen on {len(clusters)} of your clusters, fixed on {len(fixed_on)}"
    return {
        "applied": len(results),
        "resolved": results.count("resolved"),
        "partial": results.count("partial"),
        "notResolved": results.count("not-resolved"),
        "clusters": clusters,
        "summary": summary,
    }


def _render(e: MemoryEntry, repo: Path, state: str, version: str | None) -> dict[str, Any]:
    out: dict[str, Any] = {
        "citation": f"[mem:{e.id}]",
        "id": e.id,
        "repository": str(repo),
        "file": f"entries/{e.id}.yaml",
        "status": e.status,
        "kind": e.kind,
        "state": state,
        "symptom": e.symptom,
        "cause": e.cause,
        "fix": {
            "text": e.fix.text,
            "commands": [{"command": c.command, "label": c.label} for c in e.fix.commands],
            **({"patch": e.fix.patch} if e.fix.patch else {}),
        },
        "platform": e.platform,
        "versions": e.versions.model_dump(by_alias=True, exclude_none=True),
        "outcomes": _outcomes(e),
        "owners": list(e.owners),
        "sources": list(e.sources),
        "evidence": [x.model_dump(exclude_none=True) for x in e.evidence],
    }
    if state == "retired" and e.versions.fixed_in:
        out["note"] = f"Fixed in {e.versions.fixed_in}; {version} already has the fix, so this entry is history there."
    if state == "tried, did not work":
        out["note"] = "Tried before and did not work: do not repeat it without a new reason."
    if e.risk_accepted:
        out["riskAccepted"] = {"owner": e.risk_accepted.owner, "reason": e.risk_accepted.reason}
    return out


def match(
    dirs: list[Path],
    text: str,
    version: str | None = None,
    platform: str | None = None,
    operators: dict[str, str] | None = None,
    include_proposed: bool = False,
    limit: int = 5,
) -> dict[str, Any]:
    from kube_noob.signals import alertmanager, for_text

    payload = alertmanager.parse(text)
    words_text = payload.symptoms if payload else text
    version_from = "argument" if version else None
    if not version and payload and payload.version:
        version, version_from = payload.version, payload.version_from
    signals = for_text(text)
    strong = {(s.kind, s.name) for s in signals if s.kind != "component"}
    components = {(s.kind, s.name) for s in signals if s.kind == "component"}
    query_words = _words(words_text)
    statuses = {"approved", "proposed"} if include_proposed else {"approved"}
    rows: list[tuple[int, float, int, str, dict[str, Any]]] = []
    skipped = {"notApproved": 0, "notApplicable": 0, "unreadable": 0}
    repos = []
    for repo in dirs:
        loaded = load_repo(require_repo(repo))
        repos.append({"path": str(repo), "entries": len(loaded)})
        for item in loaded:
            e = item.entry
            if e is None:
                skipped["unreadable"] += 1
                continue
            if e.status not in statuses:
                skipped["notApproved"] += 1
                continue
            if not _applies(e, platform, version, operators or {}):
                skipped["notApplicable"] += 1
                continue
            mine = {(s.kind, s.name) for s in e.signals}
            hit_strong = sorted(f"{k}:{n}" for k, n in mine & strong)
            hit_components = sorted(f"{k}:{n}" for k, n in mine & components)
            shared = sorted(query_words & _words(f"{e.symptom}\n{e.cause}\n{e.fix.text}"))
            if not hit_strong and len(shared) < MIN_SHARED_WORDS:
                continue
            if e.fixed_for(version):
                state = "retired"
            elif e.kind == "negative":
                state = "tried, did not work"
            else:
                state = "fix" if e.kind == "fix" else "runbook"
            rendered = _render(e, repo, state, version)
            rendered["matchedBy"] = {"signals": hit_strong + hit_components, "words": shared[:10]}
            score = 10.0 * len(hit_strong) + len(hit_components) + 0.5 * len(shared)
            rows.append((_STATE_ORDER[state], -score, e.number, str(repo), rendered))
    rows.sort(key=lambda r: r[:4])
    out: dict[str, Any] = {
        "query": {
            "version": version,
            **({"versionFrom": version_from} if version_from else {}),
            "platform": platform,
            "signals": sorted(f"{k}:{n}" for k, n in strong | components),
            **({"input": payload.summary()} if payload else {}),
        },
        "repositories": repos,
        "matches": [r[4] for r in rows[:limit]],
        "skipped": skipped,
    }
    if not rows:
        out["note"] = "No entry in your team's memory matches this text."
    return out


def stats(root: Path, by: str | None = None) -> dict[str, Any]:
    """Counts for a repository: entries by status and kind, outcomes by result, and, with ``by``, per cluster, signal
    or component (a component counts the entry's component signals and the catalogue components of its alerts)."""
    from kube_noob.signals.catalogue import get

    loaded = load_repo(require_repo(root))
    entries = [x.entry for x in loaded if x.entry is not None]
    out: dict[str, Any] = {
        "repository": str(root),
        "entries": len(loaded),
        "unreadable": sum(1 for x in loaded if x.entry is None),
        "byStatus": {s: sum(1 for e in entries if e.status == s) for s in ("approved", "proposed", "retired")},
        "byKind": {k: sum(1 for e in entries if e.kind == k) for k in ("fix", "negative", "runbook")},
        "outcomes": {
            r: sum(1 for e in entries for o in e.outcomes if o.result == r)
            for r in ("resolved", "partial", "not-resolved")
        },
    }
    if by is None:
        return out
    groups: dict[str, dict[str, Any]] = {}

    def bump(key: str, e: MemoryEntry, results: list[str]) -> None:
        g = groups.setdefault(key, {"entries": set(), "applied": 0, "resolved": 0, "partial": 0, "notResolved": 0})
        g["entries"].add(e.id)
        g["applied"] += len(results)
        g["resolved"] += results.count("resolved")
        g["partial"] += results.count("partial")
        g["notResolved"] += results.count("not-resolved")

    for e in entries:
        if by == "cluster":
            for cluster in sorted({o.cluster or "(no cluster)" for o in e.outcomes}):
                bump(cluster, e, [o.result for o in e.outcomes if (o.cluster or "(no cluster)") == cluster])
            continue
        keys: set[str] = set()
        for s in e.signals:
            if by == "signal":
                keys.add(f"{s.kind}:{s.name}")
            elif s.kind == "component":
                keys.add(s.name)
            else:
                entry = get(s.kind, s.name)
                keys.update(entry.components if entry else ())
        for key in sorted(keys):
            bump(key, e, [o.result for o in e.outcomes])
    out["by"] = by
    out["groups"] = [
        {"key": k, **{**g, "entries": sorted(g["entries"], key=lambda i: int(i.split("-")[1]))}}
        for k, g in sorted(groups.items(), key=lambda kv: (-kv[1]["applied"], -len(kv[1]["entries"]), kv[0]))
    ]
    return out
