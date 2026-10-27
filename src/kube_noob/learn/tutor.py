"""Self-sufficient learning module: tracks, lessons, graded exercises, quizzes and credits.

Content lives in ``kube_noob/data/curriculum.yaml``; lessons point at built-in knowledge docs. Grading is fully
offline and deterministic (the same check DSL as the training reward), so the module works air-gapped.
"""

from __future__ import annotations

import json
import os
import re
import tempfile
from dataclasses import dataclass
from datetime import UTC, datetime
from functools import cache
from importlib import resources
from pathlib import Path
from typing import Any

import yaml

from kube_noob.evals.checks import evaluate
from kube_noob.knowledge.store import get_store

_LEARNER = re.compile(r"^[A-Za-z0-9._@-]{1,64}$")


@cache
def curriculum() -> dict[str, Any]:
    raw = resources.files("kube_noob").joinpath("data", "curriculum.yaml").read_text(encoding="utf-8")
    data = yaml.safe_load(raw)
    if not isinstance(data, dict) or "tracks" not in data:
        raise RuntimeError("curriculum.yaml is malformed")
    return data


def _index(kind: str) -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    for t in curriculum()["tracks"]:
        for item in t.get(kind, []):
            out[item["id"]] = {**item, "track": t["id"]}
    return out


def lessons() -> dict[str, dict[str, Any]]:
    return _index("lessons")


def exercises() -> dict[str, dict[str, Any]]:
    return _index("exercises")


def quizzes() -> dict[str, dict[str, Any]]:
    return _index("quiz")


@dataclass
class Progress:
    learner: str
    credits: int
    completed_exercises: dict[str, dict[str, Any]]
    answered_quiz: dict[str, dict[str, Any]]
    lessons_read: list[str]

    def as_dict(self) -> dict[str, Any]:
        return {
            "learner": self.learner,
            "credits": self.credits,
            "completedExercises": self.completed_exercises,
            "answeredQuiz": self.answered_quiz,
            "lessonsRead": self.lessons_read,
        }


class Tutor:
    def __init__(self, data_dir: Path) -> None:
        self.dir = data_dir / "progress"

    def _path(self, learner: str) -> Path:
        if not _LEARNER.match(learner):
            raise ValueError("learner id must be 1-64 chars of letters, digits, '.', '_', '@' or '-'")
        return self.dir / f"{learner}.json"

    def load(self, learner: str) -> Progress:
        p = self._path(learner)
        if p.is_file():
            d = json.loads(p.read_text(encoding="utf-8"))
            return Progress(
                learner,
                int(d.get("credits", 0)),
                d.get("completedExercises", {}),
                d.get("answeredQuiz", {}),
                d.get("lessonsRead", []),
            )
        return Progress(learner, 0, {}, {}, [])

    def save(self, prog: Progress) -> None:
        self.dir.mkdir(parents=True, exist_ok=True)
        p = self._path(prog.learner)
        fd, tmp = tempfile.mkstemp(dir=self.dir, prefix=".progress.", suffix=".tmp")
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(prog.as_dict(), fh, indent=2, sort_keys=True)
        os.replace(tmp, p)

    # -- browsing -----------------------------------------------------------------------------------------
    def tracks(self, learner: str | None = None) -> list[dict[str, Any]]:
        prog = self.load(learner) if learner else None
        out = []
        for t in curriculum()["tracks"]:
            ex_ids = [e["id"] for e in t.get("exercises", [])]
            entry = {
                "id": t["id"],
                "title": t["title"],
                "summary": t.get("summary", ""),
                "lessons": [{"id": les["id"], "title": les["title"]} for les in t.get("lessons", [])],
                "exercises": [
                    {"id": e["id"], "title": e["title"], "points": e.get("points", 10)} for e in t.get("exercises", [])
                ],
                "quizQuestions": len(t.get("quiz", [])),
            }
            if prog:
                entry["completedExercises"] = sum(
                    1 for e in ex_ids if prog.completed_exercises.get(e, {}).get("passed")
                )
            out.append(entry)
        return out

    def lesson(self, lesson_id: str, learner: str | None = None) -> dict[str, Any]:
        les = lessons().get(lesson_id)
        if les is None:
            raise KeyError(f"unknown lesson {lesson_id!r}; available: {', '.join(sorted(lessons()))}")
        store = get_store()
        body: list[str] = []
        citations: list[dict[str, Any]] = []
        for doc_id in les.get("docs", []):
            chunks = store.doc(doc_id)
            if not chunks:
                raise RuntimeError(f"lesson {lesson_id} references missing knowledge doc {doc_id}")
            for c in chunks:
                body.append(f"## {c.heading}\n\n{c.text}" if c.heading else c.text)
            citations.append(chunks[0].citation())
            src = chunks[0].extra.get("sources") or []
            citations.extend(
                {"title": s.get("title"), "url": s.get("url"), "license": s.get("license")}
                for s in src
                if isinstance(s, dict)
            )
        if learner:
            prog = self.load(learner)
            if lesson_id not in prog.lessons_read:
                prog.lessons_read.append(lesson_id)
                self.save(prog)
        return {
            "id": lesson_id,
            "track": les["track"],
            "title": les["title"],
            "objectives": les.get("objectives", []),
            "content": "\n\n".join(body),
            "keyPoints": les.get("keyPoints", []),
            "tryIt": les.get("tryIt", []),
            "exercises": les.get("exercises", []),
            "citations": citations,
        }

    def exercise(self, exercise_id: str) -> dict[str, Any]:
        ex = exercises().get(exercise_id)
        if ex is None:
            raise KeyError(f"unknown exercise {exercise_id!r}; available: {', '.join(sorted(exercises()))}")
        return {
            "id": ex["id"],
            "track": ex["track"],
            "title": ex["title"],
            "prompt": ex["prompt"],
            "platform": ex["checks"].get("platform", "kubernetes"),
            "starter": ex.get("starter", ""),
            "hints": ex.get("hints", []),
            "points": ex.get("points", 10),
            "checks": [k for k in ex["checks"] if k not in {"platform", "version"}],
        }

    def submit(self, exercise_id: str, answer: str, learner: str = "local") -> dict[str, Any]:
        ex = exercises().get(exercise_id)
        if ex is None:
            raise KeyError(f"unknown exercise {exercise_id!r}; available: {', '.join(sorted(exercises()))}")
        ev = evaluate(answer, ex["checks"])
        points = int(ex.get("points", 10))
        earned = round(points * ev.score) if ev.parsed else 0
        prog = self.load(learner)
        prev = prog.completed_exercises.get(exercise_id, {})
        best = max(int(prev.get("bestPoints", 0)), earned)
        prog.credits += best - int(prev.get("bestPoints", 0))
        prog.completed_exercises[exercise_id] = {
            "passed": bool(prev.get("passed")) or ev.passed,
            "bestPoints": best,
            "attempts": int(prev.get("attempts", 0)) + 1,
            "lastAttempt": datetime.now(UTC).isoformat(timespec="seconds"),
        }
        self.save(prog)
        feedback = []
        if ev.report:
            for f in ev.report.findings:
                if f.severity.value >= 2:
                    feedback.append(
                        {
                            "ruleId": f.rule_id,
                            "severity": f.severity.name.lower(),
                            "message": f.message,
                            "fix": f.remediation,
                            "line": f.line,
                        }
                    )
        return {
            "exercise": exercise_id,
            "passed": ev.passed,
            "score": round(ev.score, 3),
            "pointsEarned": earned,
            "bestPoints": best,
            "totalCredits": prog.credits,
            "checks": [o.as_dict() for o in ev.outcomes],
            "feedback": feedback[:20],
            "hints": [] if ev.passed else ex.get("hints", []),
        }

    def quiz_question(self, qid: str) -> dict[str, Any]:
        q = quizzes().get(qid)
        if q is None:
            raise KeyError(f"unknown quiz question {qid!r}; available: {', '.join(sorted(quizzes()))}")
        return {"id": qid, "track": q["track"], "question": q["question"], "choices": q["choices"]}

    def answer_quiz(self, qid: str, choice: int, learner: str = "local") -> dict[str, Any]:
        q = quizzes().get(qid)
        if q is None:
            raise KeyError(f"unknown quiz question {qid!r}; available: {', '.join(sorted(quizzes()))}")
        if not 0 <= choice < len(q["choices"]):
            raise ValueError(f"choice must be 0..{len(q['choices']) - 1}")
        correct = choice == int(q["answer"])
        prog = self.load(learner)
        first = qid not in prog.answered_quiz
        if correct and first:
            prog.credits += int(q.get("points", 2))
        prog.answered_quiz.setdefault(qid, {"correct": correct, "at": datetime.now(UTC).isoformat(timespec="seconds")})
        self.save(prog)
        return {
            "id": qid,
            "correct": correct,
            "answer": int(q["answer"]),
            "explanation": q.get("explanation", ""),
            "source": q.get("source"),
            "creditsAwarded": int(q.get("points", 2)) if correct and first else 0,
            "totalCredits": prog.credits,
        }

    def progress(self, learner: str) -> dict[str, Any]:
        prog = self.load(learner)
        total_points = sum(int(e.get("points", 10)) for e in exercises().values()) + sum(
            int(q.get("points", 2)) for q in quizzes().values()
        )
        return {**prog.as_dict(), "maxCredits": total_points}
