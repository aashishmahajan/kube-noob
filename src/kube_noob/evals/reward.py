"""Enforcer + credit system for model training and evaluation.

``grade(task, completion)`` returns a decomposed, deterministic reward:

    reward = 0.70 * task      (manifest checks via the audit engine, or QA must/must-not mention rules)
           + 0.20 * credit    (source attribution: share of cited [kn:...] chunks that exist in the local corpus;
                               uncited answers get 0 when citations are required, 0.5 otherwise)
           + 0.10 * format    (YAML parses / answer within length budget)
           - penalties        (fabricated citations, refusal to answer, runaway length)

No LLM is involved, so the reward cannot be gamed by flattering a judge and is safe to use as an RL signal.
``trl_reward`` adapts it to the TRL ``GRPOTrainer`` reward-function signature.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from functools import cache
from importlib import resources
from typing import Any

import yaml

from kube_noob.evals.checks import evaluate, extract_yaml
from kube_noob.knowledge.store import extract_citations, get_store

W_TASK, W_CREDIT, W_FORMAT = 0.70, 0.20, 0.10
MAX_COMPLETION_CHARS = 24_000
_REFUSAL = re.compile(r"(?i)\b(i can(no|')t help|as an ai|i am unable to|i'm unable to)\b")


@dataclass
class Grade:
    task_id: str
    reward: float
    task: float
    credit: float
    format: float
    penalties: list[str] = field(default_factory=list)
    details: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {
            "taskId": self.task_id,
            "reward": round(self.reward, 4),
            "components": {
                "task": round(self.task, 4),
                "credit": round(self.credit, 4),
                "format": round(self.format, 4),
            },
            "penalties": self.penalties,
            "details": self.details,
            "labelSource": "deterministic-grader",
        }


@cache
def benchmark() -> dict[str, dict[str, Any]]:
    raw = resources.files("kube_noob").joinpath("data", "evals", "tasks.yaml").read_text(encoding="utf-8")
    data = yaml.safe_load(raw) or {}
    return {t["id"]: t for t in data.get("tasks", [])}


def _completion_text(c: Any) -> str:
    """TRL passes strings (standard) or chat message lists (conversational)."""
    if isinstance(c, str):
        return c
    if isinstance(c, list):
        return "\n".join(str(m.get("content", "")) for m in c if isinstance(m, dict) and m.get("role") == "assistant")
    return str(c)


def _credit(text: str, required: bool) -> tuple[float, dict[str, Any], list[str]]:
    cites = extract_citations(text)
    store = get_store()
    valid = [c for c in cites if store.get(c) is not None]
    invalid = [c for c in cites if c not in valid]
    penalties = [f"fabricated citation {c}" for c in invalid]
    if not cites:
        score = 0.0 if required else 0.5
    else:
        score = len(valid) / len(cites)
    return score, {"cited": cites, "valid": valid, "invalid": invalid}, penalties


def _qa(text: str, task: dict[str, Any]) -> tuple[float, dict[str, Any]]:
    must = task.get("mustMention") or []
    must_not = task.get("mustNotMention") or []
    hits = [p for p in must if re.search(p, text, re.IGNORECASE)]
    bad = [p for p in must_not if re.search(p, text, re.IGNORECASE)]
    denom = len(must) + len(must_not)
    score = 1.0 if denom == 0 else (len(hits) + (len(must_not) - len(bad))) / denom
    return score, {"mentioned": hits, "missing": [p for p in must if p not in hits], "forbiddenHits": bad}


def grade(task: dict[str, Any], completion: Any) -> Grade:
    text = _completion_text(completion)
    penalties: list[str] = []
    details: dict[str, Any] = {}
    fmt = 1.0
    if len(text) > MAX_COMPLETION_CHARS:
        penalties.append("completion exceeds length budget")
        fmt = 0.0
        text = text[:MAX_COMPLETION_CHARS]
    if _REFUSAL.search(text) and len(text) < 400:
        penalties.append("refusal / non-answer")
    kind = task.get("type", "manifest")
    if kind == "manifest":
        ev = evaluate(text, task["checks"])
        task_score = ev.score if ev.parsed else 0.0
        if not ev.parsed:
            fmt = 0.0
        details["checks"] = ev.as_dict()
        if not extract_yaml(text).strip():
            fmt = 0.0
    elif kind == "qa":
        task_score, qa_details = _qa(text, task)
        details["qa"] = qa_details
    else:
        raise ValueError(f"unknown task type {kind!r}")
    credit, cdetails, cpen = _credit(text, bool(task.get("requireCitations")))
    details["attribution"] = cdetails
    penalties.extend(cpen)
    reward = W_TASK * task_score + W_CREDIT * credit + W_FORMAT * fmt
    reward -= 0.05 * len(cpen)
    if "refusal / non-answer" in penalties:
        reward -= 0.25
    reward = max(0.0, min(1.0, reward))
    return Grade(str(task.get("id", "adhoc")), reward, task_score, credit, fmt, penalties, details)


def grade_by_id(task_id: str, completion: str) -> Grade:
    task = benchmark().get(task_id)
    if task is None:
        raise KeyError(f"unknown task {task_id!r}")
    return grade(task, completion)


def trl_reward(completions: list[Any], task_id: list[str] | None = None, **kwargs: Any) -> list[float]:
    """TRL GRPOTrainer reward function. The dataset must carry a ``task_id`` column."""
    if task_id is None:
        raise ValueError("dataset must provide a 'task_id' column for kube-noob rewards")
    tasks = benchmark()
    return [grade(tasks[tid], c).reward for c, tid in zip(completions, task_id, strict=True)]
