"""Enforcer + credit system for model training and evaluation.

``grade(task, completion)`` returns a decomposed, deterministic reward:

    reward = 0.70 * task      (manifest checks via the audit engine and field assertions, or QA claims)
           + 0.20 * credit * task
                              (source attribution: share of cited [kn:...] chunks that exist in the local knowledge
                               store AND are relevant - a task-declared doc, a top hit for the prompt, or lexically
                               supporting the sentence that cites it; uncited answers get 0 when citations are
                               required, 0.5 otherwise)
           + 0.10 * format    (YAML parses / answer within length budget)
           - penalties        (fabricated citations, refusal to answer, runaway length)

QA claims are regexes that must match affirmatively: a match preceded by a negation in the same clause ("not EFS",
"never use efs-sc") does not count, any ``mustNotMention`` claim (a known wrong statement) zeroes the task score,
and answers shorter than ``minWords`` are scaled down so keyword lists do not pass.

No LLM is involved, so the reward cannot be gamed by flattering a judge. It is still a proxy: when training against it,
keep the benchmark held out and spot-check samples with the eval-only LLM judge.
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
from kube_noob.knowledge.store import CITATION_RE, KnowledgeStore, extract_citations, get_store, tokenize

W_TASK, W_CREDIT, W_FORMAT = 0.70, 0.20, 0.10
MAX_COMPLETION_CHARS = 24_000
_REFUSAL = re.compile(r"(?i)\b(i can(no|')t help|as an ai|i am unable to|i'm unable to)\b")
DEFAULT_MIN_WORDS = 20
RELEVANT_TOP_K = 8
MIN_SHARED_TERMS = 3
_NEGATORS = frozenset(
    [
        "not",
        "no",
        "never",
        "none",
        "cannot",
        "can't",
        "won't",
        "don't",
        "doesn't",
        "isn't",
        "aren't",
        "wasn't",
        "shouldn't",
        "mustn't",
        "avoid",
        "without",
    ]
)
# Negation scope ends at sentence punctuation, commas, dashes and contrastive conjunctions.
_CLAUSE_BOUNDARY = re.compile(r"[.;:!?\n,()]|\s[-\u2013\u2014]\s|\b(?:but|however|instead|whereas|rather)\b", re.I)
_WORD = re.compile(r"[A-Za-z0-9][A-Za-z0-9'._/-]*")


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


def _default_store() -> KnowledgeStore:
    """The same store the toolkit searches (built-in docs + local corpus), so valid corpus citations earn credit."""
    from kube_noob.config import load_settings
    from kube_noob.errors import ConfigError

    try:
        return get_store(load_settings().data_dir)
    except ConfigError:
        return get_store()


_SENTENCE_END = re.compile(r"[.!?](?=\s)|\n")


def _citing_context(text: str, citation: str) -> str:
    """The sentence (at most 300 chars) that ends with the citation marker; '4.10' is not a sentence break."""
    i = text.find(f"[{citation}]")
    if i < 0:
        return ""
    body = text[max(0, i - 300) : i].rstrip()
    if body.endswith((".", "!", "?")):  # "claim. [kn:x#0]" style: the cited sentence is the one just closed
        body = body[:-1]
    ends = list(_SENTENCE_END.finditer(body))
    sentence = body[ends[-1].end() :] if ends else body
    return CITATION_RE.sub(" ", sentence)


def _credit(
    text: str,
    required: bool,
    store: KnowledgeStore,
    prompt: str | None = None,
    cite_docs: list[str] | None = None,
) -> tuple[float, dict[str, Any], list[str]]:
    cites = extract_citations(text)
    valid = [c for c in cites if store.get(c) is not None]
    invalid = [c for c in cites if c not in valid]
    penalties = [f"fabricated citation {c}" for c in invalid]
    # Tasks that declare their supporting docs do not also get the looser "top hits for the prompt" allowance.
    top = {h.chunk.chunk_id for h in store.search(prompt, limit=RELEVANT_TOP_K)} if prompt and not cite_docs else set()
    relevant: list[str] = []
    for c in valid:
        chunk = store.get(c)
        assert chunk is not None  # noqa: S101
        if (cite_docs and chunk.doc_id in cite_docs) or c in top:
            relevant.append(c)
            continue
        shared = {t for t in tokenize(_citing_context(text, c)) if len(t) > 2} & set(
            tokenize(f"{chunk.title} {chunk.heading} {chunk.text}")
        )
        if len(shared) >= MIN_SHARED_TERMS:
            relevant.append(c)
    if not cites:
        score = 0.0 if required else 0.5
    else:
        score = len(relevant) / len(cites)
    details = {
        "cited": cites,
        "valid": valid,
        "relevant": relevant,
        "irrelevant": [c for c in valid if c not in relevant],
        "invalid": invalid,
    }
    return score, details, penalties


def _negated(text: str, start: int) -> bool:
    """True when one of the three words before ``start`` (within the same clause) is a negator."""
    head = text[:start]
    bounds = list(_CLAUSE_BOUNDARY.finditer(head))
    clause = head[bounds[-1].end() :] if bounds else head
    words = [w.lower().strip("'.") for w in _WORD.findall(clause)][-3:]
    return any(w in _NEGATORS or w.endswith("n't") for w in words)


def _claim(spec: Any) -> tuple[str, bool]:
    """A claim is a regex string or ``{pattern, negationCheck}`` (negationCheck false for patterns that contain the
    negation themselves, e.g. 'no 4\\.12')."""
    if isinstance(spec, dict):
        return str(spec["pattern"]), bool(spec.get("negationCheck", True))
    return str(spec), True


def _affirmed(text: str, spec: Any) -> bool:
    pattern, check_negation = _claim(spec)
    for m in re.finditer(pattern, text, re.IGNORECASE | re.MULTILINE):
        if not check_negation or not _negated(text, m.start()):
            return True
    return False


def _qa(text: str, task: dict[str, Any]) -> tuple[float, dict[str, Any]]:
    must = task.get("mustMention") or []
    must_not = task.get("mustNotMention") or []
    prose = CITATION_RE.sub(" ", text)
    hits = [m for m in must if _affirmed(prose, m)]
    bad = [m for m in must_not if _affirmed(prose, m)]
    coverage = 1.0 if not must else len(hits) / len(must)
    words = len(_WORD.findall(prose))
    min_words = int(task.get("minWords", DEFAULT_MIN_WORDS))
    length_factor = min(1.0, words / min_words) if min_words > 0 else 1.0
    score = 0.0 if bad else coverage * length_factor
    return score, {
        "mentioned": [_claim(m)[0] for m in hits],
        "missing": [_claim(m)[0] for m in must if m not in hits],
        "forbiddenHits": [_claim(m)[0] for m in bad],
        "words": words,
        "lengthFactor": round(length_factor, 3),
    }


def grade(task: dict[str, Any], completion: Any, store: KnowledgeStore | None = None) -> Grade:
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
    credit, cdetails, cpen = _credit(
        text,
        bool(task.get("requireCitations")),
        store if store is not None else _default_store(),
        prompt=task.get("prompt"),
        cite_docs=task.get("citeDocs"),
    )
    details["attribution"] = cdetails
    penalties.extend(cpen)
    # Attribution only earns credit in proportion to correctness: citations supporting a wrong answer are not credit.
    reward = W_TASK * task_score + W_CREDIT * credit * task_score + W_FORMAT * fmt
    reward -= 0.05 * len(cpen)
    if "refusal / non-answer" in penalties:
        reward -= 0.25
    reward = max(0.0, min(1.0, reward))
    return Grade(str(task.get("id", "adhoc")), reward, task_score, credit, fmt, penalties, details)


def grade_by_id(task_id: str, completion: str, store: KnowledgeStore | None = None) -> Grade:
    task = benchmark().get(task_id)
    if task is None:
        raise KeyError(f"unknown task {task_id!r}")
    return grade(task, completion, store)


def trl_reward(completions: list[Any], task_id: list[str] | None = None, **kwargs: Any) -> list[float]:
    """TRL GRPOTrainer reward function. The dataset must carry a ``task_id`` column."""
    if task_id is None:
        raise ValueError("dataset must provide a 'task_id' column for kube-noob rewards")
    tasks = benchmark()
    store = _default_store()
    return [grade(tasks[tid], c, store).reward for c, tid in zip(completions, task_id, strict=True)]
