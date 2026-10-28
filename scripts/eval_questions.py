"""Evaluate kube-noob against a CSV of real-world questions (Stack Overflow, GitHub issues, Red Hat Jira, forums).

The CSV is the owner's (columns: id, question, body_excerpt, topic_category, platform_tags, source, url, item_type,
...). It is third-party text and never enters the repository: pass its path, write results outside the repo.

Every row is pasted into ``insight`` (title and excerpt, as a user would paste them), offline. Per row the script
records what kube-noob answered: the recognised input kinds, the playbook diagnoses, the reported issues, the
documents, and the top answer. It then scores what can be scored without reference answers:

- ground truth where the row names it: a Red Hat Jira row (``redhat-jira:OCPBUGS``, ``:ROX``) is a reported bug, so
  the reported-issue matcher should return that key (recall at 3; also split by whether the key is in the bundled
  release-note index at all, so "kube-noob could not know it" is told apart from "kube-noob missed it");
- answer coverage: the share of rows with a playbook diagnosis, a reported issue, documents only, or nothing;
- topic agreement: whether the top playbook belongs to the row's labelled topic (``PLAYBOOK_TOPICS``); the labels
  come from the dataset and are themselves noisy, so this is a signal, not a grade.

Usage:
  python scripts/eval_questions.py questions.csv --out <dir> [--limit N] [--sample-review 60] [--seed 7]

Writes ``<dir>/results.csv`` (one row per question, no question text), ``<dir>/summary.json`` and, with
``--sample-review``, ``<dir>/review.csv``: a stratified sample with the question, kube-noob's top answer and empty
``verdict`` / ``expected`` columns for a person to fill in.
"""

from __future__ import annotations

import argparse
import csv
import json
import random
import re
import sys
import time
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

# The playbooks' topics in the dataset's vocabulary (topic_category). A playbook may serve several topics.
PLAYBOOK_TOPICS: dict[str, set[str]] = {
    "DBG-CRASHLOOP": {"workloads-debugging", "containers-docker", "kubernetes-general"},
    "DBG-IMAGEPULL": {"image-pull", "aws-eks-ecr", "containers-docker"},
    "DBG-PULLSECRET": {"image-pull", "aws-eks-ecr"},
    "DBG-OOM": {"workloads-debugging", "containers-docker"},
    "DBG-CONFIGERR": {"workloads-debugging", "manifests-yaml"},
    "DBG-RUNASROOT": {"rbac-security", "openshift-specific", "containers-docker"},
    "DBG-SCC": {"rbac-security", "openshift-specific"},
    "DBG-PSA": {"rbac-security", "policy-kyverno-opa"},
    "DBG-PENDING-RESOURCES": {"workloads-debugging", "kubernetes-general"},
    "DBG-PENDING-PLACEMENT": {"workloads-debugging", "kubernetes-general"},
    "DBG-PVC-PENDING": {"storage-odf"},
    "DBG-MULTIATTACH": {"storage-odf"},
    "DBG-MOUNT": {"storage-odf", "workloads-debugging"},
    "DBG-PROBE": {"workloads-debugging"},
    "DBG-ROUTE-503": {"ingress-routing", "openshift-specific", "networking-ip"},
    "DBG-NO-ENDPOINTS": {"networking-ip", "ingress-routing"},
    "DBG-RBAC": {"rbac-security"},
    "DBG-WEBHOOK": {"policy-kyverno-opa", "rbac-security"},
    "DBG-STACKROX-ADMISSION": {"acs-scanning-threat", "policy-kyverno-opa"},
    "DBG-HELM-LOCK": {"helm"},
    "DBG-HELM-OWNERSHIP": {"helm"},
    "DBG-NO-MATCHES-KIND": {"upgrade", "manifests-yaml", "helm"},
    "DBG-EVICTED": {"workloads-debugging", "storage-odf"},
    "DBG-DNS": {"dns", "networking-ip"},
    "DBG-NETPOL": {"networking-ip", "policy-kyverno-opa"},
    "DBG-X509-CLIENT": {"rbac-security", "kubernetes-general", "etcd-control-plane"},
    "DBG-X509": {"rbac-security", "ingress-routing", "networking-ip"},
    "DBG-EXEC-FORMAT": {"containers-docker", "workloads-debugging"},
    "DBG-QUOTA": {"workloads-debugging", "policy-kyverno-opa"},
    "DBG-PDB-DRAIN": {"upgrade", "workloads-debugging"},
    "DBG-HPA": {"workloads-debugging", "kubernetes-general"},
    "DBG-JOB": {"workloads-debugging"},
    "DBG-CLUSTEROPERATOR": {"openshift-specific", "upgrade"},
    "DBG-ETCD": {"etcd-control-plane"},
    "DBG-ROSA-HCP-NODES": {"rosa-hcp-aws"},
    "DBG-ARBITRARY-UID": {"openshift-specific", "rbac-security", "storage-odf"},
    "DBG-IMMUTABLE-SELECTOR": {"manifests-yaml", "helm"},
    "DBG-NS-TERMINATING": {"kubernetes-general"},
    "DBG-POD-TERMINATING": {"workloads-debugging"},
    "DBG-EGRESSIP": {"networking-ip", "openshift-specific"},
}
_KEY = re.compile(r"/browse/((?:OCPBUGS|ROX)-\d{1,7})\b")


def _key(url: str) -> str:
    m = _KEY.search(url)
    return m.group(1) if m else ""


def _platform(tags: str) -> str | None:
    t = set(tags.split(";"))
    if "rosa-hcp" in t:
        return "rosa-hcp"
    if "openshift" in t or "ceph-rook-odf" in t or "acs-stackrox" in t:
        return "openshift"
    return None


def evaluate(rows: list[dict[str, str]], data_dir: Path) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    from kube_noob import known_issues
    from kube_noob import toolkit as tk
    from kube_noob.config import load_settings
    from kube_noob.insight import insight

    kit = tk.Toolkit(load_settings(overrides={"dataDir": str(data_dir), "learningEnabled": False}))
    indexed = {i.id for i in known_issues.get_index().issues}
    out: list[dict[str, Any]] = []
    started = time.monotonic()
    for r in rows:
        text = f"{r['question'].strip()}\n{r['body_excerpt'].strip()}".strip()
        platform = _platform(r.get("platform_tags", ""))
        res = insight(kit, text, platform=platform)
        f = res.get("findings", [])
        playbooks = [x["id"] for x in f if x.get("source") == "playbook"][:3]
        issues = [x["id"] for x in f if x.get("source") == "reported-issue"][:5]
        docs = [x["id"] for x in f if x.get("source") == "doc"][:3]
        key = _key(r.get("url", ""))
        direct: list[str] = []
        if key:  # the reported-issue matcher on its own, as `kube-noob known-issues` runs it
            direct = [m["id"] for m in known_issues.match(text, "openshift", None, 3)["matches"]]
        top = f[0] if f else {}
        out.append(
            {
                "id": r["id"],
                "topic": r.get("topic_category", ""),
                "platforms": r.get("platform_tags", ""),
                "source": r.get("source", ""),
                "itemType": r.get("item_type", ""),
                "url": r.get("url", ""),
                "kinds": ";".join(k["kind"] for k in res.get("kinds", [])),
                "answer": "playbook" if playbooks else "reported-issue" if issues else "docs" if docs else "none",
                "topSource": top.get("source", ""),
                "topId": top.get("id", ""),
                "topTitle": str(top.get("title", ""))[:160],
                "playbooks": ";".join(playbooks),
                "issues": ";".join(issues),
                "docs": ";".join(docs),
                "signals": len(res.get("signals", [])),
                "expectedKey": key,
                "keyIndexed": bool(key) and key in indexed,
                "hitInsight": bool(key) and key in issues[:3],
                "hitDirect": bool(key) and key in direct,
                "topicAgree": bool(playbooks)
                and r.get("topic_category", "") in PLAYBOOK_TOPICS.get(playbooks[0], set()),
            }
        )
    return out, {"seconds": round(time.monotonic() - started, 1), "indexedIssues": len(indexed)}


def summarise(res: list[dict[str, Any]], meta: dict[str, Any]) -> dict[str, Any]:
    n = len(res)

    def pct(a: int, b: int) -> float:
        return round(100.0 * a / b, 1) if b else 0.0

    answers = Counter(r["answer"] for r in res)
    by_topic: dict[str, Counter[str]] = defaultdict(Counter)
    for r in res:
        c = by_topic[r["topic"]]
        c["rows"] += 1
        c[r["answer"]] += 1
        c["topicAgree"] += r["topicAgree"]
    jira = [r for r in res if r["expectedKey"]]
    jira_idx = [r for r in jira if r["keyIndexed"]]
    misplaced = Counter(r["playbooks"].split(";")[0] for r in res if r["playbooks"] and not r["topicAgree"])
    return {
        "rows": n,
        "seconds": meta["seconds"],
        "answerCoverage": {k: {"rows": v, "pct": pct(v, n)} for k, v in answers.most_common()},
        "groundTruth": {
            "jiraRows": len(jira),
            "keyInBundledIndex": len(jira_idx),
            "recallAt3Insight": pct(sum(r["hitInsight"] for r in jira), len(jira)),
            "recallAt3Direct": pct(sum(r["hitDirect"] for r in jira), len(jira)),
            "recallAt3DirectWhenIndexed": pct(sum(r["hitDirect"] for r in jira_idx), len(jira_idx)),
            "indexedIssues": meta["indexedIssues"],
        },
        "topicAgreementWhenPlaybook": pct(sum(r["topicAgree"] for r in res), sum(1 for r in res if r["playbooks"])),
        "byTopic": {
            t: {
                "rows": c["rows"],
                "playbookPct": pct(c["playbook"], c["rows"]),
                "reportedIssuePct": pct(c["reported-issue"], c["rows"]),
                "docsPct": pct(c["docs"], c["rows"]),
                "nonePct": pct(c["none"], c["rows"]),
                "topicAgreePct": pct(c["topicAgree"], c["playbook"]),
            }
            for t, c in sorted(by_topic.items(), key=lambda kv: -kv[1]["rows"])
        },
        "playbooksOutsideTheirTopic": dict(misplaced.most_common(15)),
    }


def review_sample(rows: list[dict[str, str]], res: list[dict[str, Any]], k: int, seed: int) -> list[dict[str, Any]]:
    """``k`` rows stratified by topic, with the question and kube-noob's top answer, for a person to grade."""
    rng = random.Random(seed)  # noqa: S311 - a reproducible sample, not a secret
    by_topic: dict[str, list[int]] = defaultdict(list)
    for i, r in enumerate(rows):
        by_topic[r.get("topic_category", "")].append(i)
    picks: list[int] = []
    topics = sorted(by_topic)
    while len(picks) < k and any(by_topic.values()):
        for t in topics:
            if by_topic[t] and len(picks) < k:
                picks.append(by_topic[t].pop(rng.randrange(len(by_topic[t]))))
    out = []
    for i in picks:
        r, x = rows[i], res[i]
        out.append(
            {
                "id": r["id"],
                "topic": r.get("topic_category", ""),
                "question": r["question"][:300],
                "excerpt": r["body_excerpt"][:300],
                "url": r.get("url", ""),
                "kubeNoobAnswer": x["answer"],
                "kubeNoobTop": f"{x['topId']}: {x['topTitle']}" if x["topId"] else "",
                "playbooks": x["playbooks"],
                "issues": x["issues"],
                "docs": x["docs"],
                "verdict": "",
                "expected": "",
            }
        )
    return out


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("csv", type=Path)
    ap.add_argument("--out", type=Path, required=True)
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--sample-review", type=int, default=0)
    ap.add_argument("--seed", type=int, default=7)
    a = ap.parse_args(argv)
    csv.field_size_limit(10**8)
    with a.csv.open(newline="", encoding="utf-8", errors="replace") as f:
        rows = list(csv.DictReader(f))
    if a.limit:
        rows = random.Random(a.seed).sample(rows, min(a.limit, len(rows)))  # noqa: S311 - reproducible sample
    a.out.mkdir(parents=True, exist_ok=True)
    res, meta = evaluate(rows, a.out / "data")
    with (a.out / "results.csv").open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(res[0]))
        w.writeheader()
        w.writerows(res)
    summary = summarise(res, meta)
    (a.out / "summary.json").write_text(json.dumps(summary, indent=1) + "\n", encoding="utf-8")
    if a.sample_review:
        sample = review_sample(rows, res, a.sample_review, a.seed)
        with (a.out / "review.csv").open("w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=list(sample[0]))
            w.writeheader()
            w.writerows(sample)
    print(json.dumps({k: summary[k] for k in ("rows", "seconds", "answerCoverage", "groundTruth")}, indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
