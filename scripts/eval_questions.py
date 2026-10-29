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
  python scripts/eval_questions.py questions.csv --out <dir> [--limit N] [--sample-review 76] [--seed 7]
      [--grades docs/evals/community-questions-grades.csv --grades docs/evals/community-questions-heldout.csv]
      [--split all|train|test] [--retired docs/evals/community-questions-retired.csv] [--data-dir <dir>]

A CSV that also carries ``answer_text`` (an accepted answer or a Jira resolution) is scored against it: per row,
the share of the answer's specific words that kube-noob's top finding carries (``answerShare``) and whether that
reaches the agreement threshold (``answerAgrees``); ``summary.json`` -> ``referenceAnswers`` totals it per answer kind.
The answer text is never written out.

Writes ``<dir>/results.csv`` (one row per question, no question text), ``<dir>/summary.json`` and, with
``--sample-review``, ``<dir>/review.csv``: a stratified sample with the question, kube-noob's top answer and
``verdict`` / ``expected`` columns for a person to fill in.

``--grades`` reads earlier verdicts (id, answer, top, verdict; no question text, so the file can live in the repo).
A verdict carries over only while kube-noob still gives the same answer kind and the same top finding for that row;
a row whose answer changed is listed under ``graded.changed`` and its review row shows the old verdict in
``previousVerdict`` with ``verdict`` left empty, so a tuning change is re-graded where it moved an answer and
nowhere else.

``--split`` evaluates one fixed half (by a hash of the row id): tune on ``train``, report on ``test``, and per
technology (``byTechnology``). A test row whose grading informed a change is listed in the retired file (id, change,
date) and left out of ``--split test``.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
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
    "DBG-ENTRYPOINT-NOT-FOUND": {"workloads-debugging", "containers-docker", "aws-eks-ecr"},
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

# The technologies kube-noob supports, in the order a row is assigned to one (the most specific first), from the
# dataset's platform tags and source. "other" holds what kube-noob does not claim (Docker alone, EKS/AKS/GKE consoles,
# Argo CD, Istio...). See docs/evals/supported-technologies.md.
TECHNOLOGIES: tuple[tuple[str, frozenset[str], tuple[str, ...]], ...] = (
    ("rhacs", frozenset({"acs-stackrox"}), ("redhat-jira:ROX",)),
    ("rosa-hcp", frozenset({"rosa-hcp"}), ()),
    ("policy", frozenset({"kyverno", "opa-gatekeeper"}), ()),
    ("odf-storage", frozenset({"ceph-rook-odf"}), ("redhat-jira:DFBUGS",)),
    ("openshift", frozenset({"openshift"}), ("redhat-jira:",)),
    ("helm", frozenset({"helm"}), ()),
    ("kubernetes", frozenset({"kubernetes", "kubeadm"}), ()),
)


def technology(row: dict[str, str]) -> str:
    tags = set((row.get("platform_tags") or "").split(";"))
    source = row.get("source") or ""
    for name, wanted, sources in TECHNOLOGIES:
        if tags & wanted or any(source.startswith(s) for s in sources):
            return name
    return "other"


def split_of(row_id: str) -> str:
    """A fixed half of the rows to tune on and the other half to report on: the same row is always in the same half,
    whatever file it comes from."""
    return "test" if hashlib.sha256(row_id.encode()).digest()[0] % 2 else "train"


# What a person can say about one answer. "not-indexed": a Red Hat bug report whose key the bundled release-note
# index does not hold (a synced local Jira copy would); "out-of-scope": nothing an offline Kubernetes and OpenShift
# assistant should know (application code, Docker alone, another cloud's console, an upstream code bug).
VERDICTS = ("correct", "partial", "wrong", "missed", "not-indexed", "out-of-scope")
GRADE_COLUMNS = ("id", "topic", "source", "answer", "top", "verdict", "note")
MAX_GRADES = 5000
MAX_NOTE = 300


MAX_ANSWER = 20_000
# A top finding "agrees" with a reference answer when it carries at least this share of the answer's specific words
# and at least AGREE_MIN_SHARED of them (calibrated against graded rows; see docs/evals/community-questions.md).
AGREE_SHARE = 0.15
AGREE_MIN_SHARED = 3


def _shown_text(top: dict[str, Any], store: Any, playbook_text: dict[str, str]) -> str:
    """The text a person reads for kube-noob's top finding: the whole document section, the playbook's causes,
    checks and fixes, or the reported issue's summary."""
    if not top:
        return ""
    if top.get("source") == "doc":
        chunk = store.get(top.get("id", ""))
        return f"{top.get('title') or ''} {chunk.text if chunk else ''}"
    if top.get("source") == "playbook":
        return playbook_text.get(str(top.get("id")), str(top.get("title") or ""))
    return f"{top.get('id') or ''} {top.get('title') or ''}"


def answer_overlap(answer: str, shown: str) -> dict[str, Any]:
    """How much of a reference answer's specific vocabulary kube-noob's top finding carries. Lexical, so a signal to
    sort rows by and to calibrate against graded rows, not a verdict; the answer text itself is never written out."""
    from kube_noob.insight import _specific_terms

    want = _specific_terms(answer, kubernetes_words=True)
    have = _specific_terms(shown, kubernetes_words=True) if shown else set()
    shared = want & have
    share = round(len(shared) / len(want), 3) if want else 0.0
    return {
        "answerTerms": len(want),
        "answerShared": len(shared),
        "answerShare": share,
        "answerAgrees": bool(shown) and share >= AGREE_SHARE and len(shared) >= AGREE_MIN_SHARED,
    }


class GradesError(ValueError):
    """The grades file is malformed: the eval stops instead of scoring against it."""


def load_grades(path: Path) -> dict[str, dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        missing = [c for c in ("id", "answer", "top", "verdict") if c not in (reader.fieldnames or [])]
        if missing:
            raise GradesError(f"{path}: missing column(s) {', '.join(missing)}")
        grades: dict[str, dict[str, str]] = {}
        for n, row in enumerate(reader, start=2):
            if len(grades) >= MAX_GRADES:
                raise GradesError(f"{path}: more than {MAX_GRADES} graded rows")
            rid, verdict = (row.get("id") or "").strip(), (row.get("verdict") or "").strip()
            if not rid:
                raise GradesError(f"{path}:{n}: empty id")
            if verdict not in VERDICTS:
                raise GradesError(f"{path}:{n}: verdict {verdict!r} is not one of {', '.join(VERDICTS)}")
            if rid in grades:
                raise GradesError(f"{path}:{n}: id {rid} is graded twice")
            if len(row.get("note") or "") > MAX_NOTE:
                raise GradesError(f"{path}:{n}: note longer than {MAX_NOTE} characters")
            grades[rid] = {k: (row.get(k) or "").strip() for k in GRADE_COLUMNS}
    return grades


RETIRED_COLUMNS = ("id", "change", "date")
MAX_CHANGE = 200
RETIRED_DEFAULT = Path(__file__).resolve().parents[1] / "docs" / "evals" / "community-questions-retired.csv"


def load_retired(path: Path) -> dict[str, str]:
    """Test-half rows whose grading informed a change (id -> the change). They no longer measure that change, so
    ``--split test`` leaves them out; they stay in the train half."""
    with path.open(newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        missing = [c for c in RETIRED_COLUMNS if c not in (reader.fieldnames or [])]
        if missing:
            raise GradesError(f"{path}: missing column(s) {', '.join(missing)}")
        retired: dict[str, str] = {}
        for n, row in enumerate(reader, start=2):
            if len(retired) >= MAX_GRADES:
                raise GradesError(f"{path}: more than {MAX_GRADES} retired rows")
            rid, change = (row.get("id") or "").strip(), (row.get("change") or "").strip()
            if not rid:
                raise GradesError(f"{path}:{n}: empty id")
            if rid in retired:
                raise GradesError(f"{path}:{n}: id {rid} is retired twice")
            if len(change) > MAX_CHANGE:
                raise GradesError(f"{path}:{n}: change longer than {MAX_CHANGE} characters")
            retired[rid] = change
    return retired


def apply_grades(res: list[dict[str, Any]], grades: dict[str, dict[str, str]]) -> dict[str, Any]:
    """Carry each verdict over while the row's answer is unchanged; list the rows to re-grade."""
    by_id = {r["id"]: r for r in res}
    verdicts: Counter[str] = Counter()
    changed: list[dict[str, str]] = []
    not_run = 0
    for rid, g in grades.items():
        r = by_id.get(rid)
        if r is None:
            not_run += 1
            continue
        if r["answer"] == g["answer"] and r["topId"] == g["top"]:
            r["verdict"] = g["verdict"]
            verdicts[g["verdict"]] += 1
        else:
            r["previousVerdict"] = g["verdict"]
            changed.append(
                {
                    "id": rid,
                    "verdict": g["verdict"],
                    "was": f"{g['answer']} {g['top']}".strip(),
                    "now": f"{r['answer']} {r['topId']}".strip(),
                }
            )
    answered = verdicts["correct"] + verdicts["partial"] + verdicts["wrong"]
    return {
        "graded": len(grades),
        "unchanged": sum(verdicts.values()),
        "notRun": not_run,
        "verdicts": {v: verdicts[v] for v in VERDICTS},
        "helpfulWhenAnswered": round(100.0 * (verdicts["correct"] + verdicts["partial"]) / answered, 1)
        if answered
        else 0.0,
        "changed": changed,
    }


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
    from kube_noob.debug.playbooks import PLAYBOOKS

    playbook_text = {
        p.pid: " ".join((p.title, *p.root_causes, *p.checks, *p.fixes)) for p in PLAYBOOKS
    }  # what a person reads for that diagnosis
    store = kit.store()
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
                "technology": technology(r),
                "split": split_of(r["id"]),
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
        answer = (r.get("answer_text") or "")[:MAX_ANSWER]
        if answer.strip():
            shown = _shown_text(top, store, playbook_text)
            out[-1].update(answer_overlap(answer, shown))
            out[-1]["answerSource"] = r.get("answer_source_type", "")
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
        **_answer_summary(res),
    }


def _answer_summary(res: list[dict[str, Any]]) -> dict[str, Any]:
    """Against reference answers (rows whose CSV carries answer_text): how often the top finding agrees, per kind."""
    rows = [r for r in res if "answerShare" in r]
    if not rows:
        return {}
    by: dict[str, Counter[str]] = defaultdict(Counter)
    tech: dict[str, Counter[str]] = defaultdict(Counter)
    for r in rows:
        c = by[r["answer"]]
        c["rows"] += 1
        c["agrees"] += r["answerAgrees"]
        t = tech[r.get("technology", "other")]
        t["rows"] += 1
        t["answered"] += r["answer"] != "none"
        t["agrees"] += r["answerAgrees"]
    answered = [r for r in rows if r["answer"] != "none"]
    return {
        "referenceAnswers": {
            "rows": len(rows),
            "answered": len(answered),
            "agreesWhenAnswered": round(100.0 * sum(r["answerAgrees"] for r in answered) / len(answered), 1)
            if answered
            else 0.0,
            "agreesOfAll": round(100.0 * sum(r["answerAgrees"] for r in rows) / len(rows), 1),
            "byAnswer": {k: {"rows": v["rows"], "agrees": v["agrees"]} for k, v in sorted(by.items())},
            "byTechnology": {
                k: {"rows": v["rows"], "answered": v["answered"], "agrees": v["agrees"]}
                for k, v in sorted(tech.items())
            },
            "threshold": {"share": AGREE_SHARE, "minShared": AGREE_MIN_SHARED},
        }
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
                "verdict": x.get("verdict", ""),
                "previousVerdict": x.get("previousVerdict", ""),
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
    ap.add_argument(
        "--split",
        choices=("all", "train", "test"),
        default="all",
        help="evaluate one fixed half: tune on train, report on test (split by a hash of the row id)",
    )
    ap.add_argument(
        "--data-dir",
        type=Path,
        help="a kube-noob data dir to read (for example one with the optional docs corpus built); default: a fresh one",
    )
    ap.add_argument(
        "--grades",
        type=Path,
        action="append",
        default=[],
        help="earlier verdicts to carry over (id, answer, top, verdict); repeat for several files",
    )
    ap.add_argument(
        "--retired",
        type=Path,
        help="test-half rows that informed a change, left out of --split test (default: "
        "docs/evals/community-questions-retired.csv when it exists)",
    )
    a = ap.parse_args(argv)
    csv.field_size_limit(10**8)
    grades: dict[str, dict[str, str]] = {}
    retired: dict[str, str] = {}
    try:
        retired_path = a.retired or (RETIRED_DEFAULT if RETIRED_DEFAULT.is_file() else None)
        if retired_path is not None:
            retired = load_retired(retired_path)
        for path in a.grades:
            more = load_grades(path)
            twice = sorted(set(grades) & set(more))
            if twice:
                raise GradesError(f"{path}: id {twice[0]} is already graded in another grades file")
            grades.update(more)
    except (OSError, GradesError) as e:
        print(f"eval_questions: {e}", file=sys.stderr)
        return 2
    with a.csv.open(newline="", encoding="utf-8", errors="replace") as f:
        rows = list(csv.DictReader(f))
    retired_excluded = 0
    if a.split != "all":
        rows = [r for r in rows if split_of(r["id"]) == a.split]
    if a.split == "test" and retired:
        kept = [r for r in rows if r["id"] not in retired]
        retired_excluded, rows = len(rows) - len(kept), kept
    if a.limit:
        rows = random.Random(a.seed).sample(rows, min(a.limit, len(rows)))  # noqa: S311 - reproducible sample
    a.out.mkdir(parents=True, exist_ok=True)
    res, meta = evaluate(rows, a.data_dir or a.out / "data")
    graded = apply_grades(res, grades) if grades else None
    with (a.out / "results.csv").open("w", newline="", encoding="utf-8") as f:
        extra = ("answerTerms", "answerShared", "answerShare", "answerAgrees", "answerSource")
        base = [k for k in res[0] if k not in ("verdict", "previousVerdict", *extra)]
        if any("answerShare" in r for r in res):
            base += list(extra)
        w = csv.DictWriter(f, fieldnames=[*base, "verdict", "previousVerdict"], restval="")
        w.writeheader()
        w.writerows(res)
    summary = summarise(res, meta)
    if a.split == "test":
        summary["retiredExcluded"] = retired_excluded
    if graded is not None:
        summary["graded"] = graded
    (a.out / "summary.json").write_text(json.dumps(summary, indent=1) + "\n", encoding="utf-8")
    if a.sample_review:
        sample = review_sample(rows, res, a.sample_review, a.seed)
        with (a.out / "review.csv").open("w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=list(sample[0]))
            w.writeheader()
            w.writerows(sample)
    keys = ("rows", "seconds", "answerCoverage", "groundTruth", "graded", "referenceAnswers")
    print(json.dumps({k: summary[k] for k in keys if k in summary}, indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
