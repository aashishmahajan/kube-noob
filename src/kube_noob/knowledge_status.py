"""What kube-noob knows, and up to when: stamped on every tool result and printed by `doctor`.

kube-noob ships with a fixed body of knowledge: audit rules and schemas for a Kubernetes version, playbooks and docs
reviewed on a date, and a snapshot of the issues listed in the OpenShift release notes. Anything newer reaches it only
through the opt-in web lookups (labelled as external) or a corpus you rebuild yourself.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from kube_noob.catalog import DEFAULT_K8S_VERSION, DEFAULT_OCP_VERSION, parse_minor

# The date the bundled rules, playbooks, docs and version tables were last reviewed. Raise it with every review.
KNOWLEDGE_REVIEWED = "2026-10-27"


def _corpus_as_of(data_dir: Path | None) -> str | None:
    manifest = data_dir / "corpus" / "MANIFEST.json" if data_dir else None
    if not manifest or not manifest.is_file():
        return None
    try:
        doc = json.loads(manifest.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    shards = (doc.get("shards") or {}).values()
    dates = [str(v.get("writtenAt") or "") for v in shards if isinstance(v, dict)]
    dates = [d for d in dates if d]
    return max(dates)[:10] if dates else None


def status(data_dir: Path | None = None) -> dict[str, Any]:
    from kube_noob.known_issues import get_index

    issues = get_index(data_dir).knowledge()
    out: dict[str, Any] = {
        "asOf": KNOWLEDGE_REVIEWED,
        "kubernetes": DEFAULT_K8S_VERSION,
        "openshift": DEFAULT_OCP_VERSION,
        "knownIssuesAsOf": issues["knownIssuesAsOf"],
        "knownIssueReleases": issues["openshiftReleases"],
        "note": (
            f"Built-in knowledge reviewed {KNOWLEDGE_REVIEWED} (Kubernetes up to {DEFAULT_K8S_VERSION}, OpenShift up "
            f"to {DEFAULT_OCP_VERSION}); release-note issues as of {issues['knownIssuesAsOf']}. Newer facts come "
            "only from web lookups you enable, and those are marked as external."
        ),
    }
    corpus = _corpus_as_of(data_dir)
    if corpus:
        out["corpusAsOf"] = corpus
    return out


def compare(kubernetes: str | None, openshift: str | None) -> dict[str, Any]:
    """Is the cluster newer than what kube-noob knows? Used with the live cluster version."""
    newer: list[str] = []
    try:
        if openshift and parse_minor(openshift) > parse_minor(DEFAULT_OCP_VERSION):
            newer.append(f"OpenShift {openshift} is newer than kube-noob's knowledge (up to {DEFAULT_OCP_VERSION})")
        if kubernetes and parse_minor(kubernetes) > parse_minor(DEFAULT_K8S_VERSION):
            newer.append(f"Kubernetes {kubernetes} is newer than kube-noob's knowledge (up to {DEFAULT_K8S_VERSION})")
    except ValueError:
        pass
    return {"newerThanKnowledge": bool(newer), "warnings": newer}


def line(data_dir: Path | None = None) -> str:
    s = status(data_dir)
    return (
        f"knowledge as of {s['asOf']} (Kubernetes {s['kubernetes']}, OpenShift {s['openshift']}); "
        f"release-note issues as of {s['knownIssuesAsOf']} for OpenShift {', '.join(s['knownIssueReleases'])}"
    )
