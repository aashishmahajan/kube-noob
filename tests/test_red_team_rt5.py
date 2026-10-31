"""Red team RT5: shared-mode write tools.

The HTTP server is one process with one static bearer token serving many callers. A tool that writes per-caller
state there has no identity to key that state on: the learner id comes from the caller, so anybody can write and
read anybody's. The filter that was meant to keep write tools off a shared server was a denylist of three names,
and three others had been added since.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from kube_noob import toolkit as tk
from kube_noob.config import load_settings


def _kits(tmp_path: Path) -> tuple[tk.Toolkit, tk.Toolkit]:
    s = load_settings(overrides={"dataDir": str(tmp_path / "data")})
    return tk.Toolkit(s), tk.Toolkit(s, shared=True)


def test_a_shared_server_offers_nothing_that_writes(tmp_path: Path) -> None:
    """RT5-1. The filter was a denylist, so a write tool added later is exposed by default -- and three had been:
    learn_lesson, learn_submit and learn_quiz all wrote a progress file. The filter is now the read_only flag the
    tools already carry, which excludes a new one by construction."""
    _, shared = _kits(tmp_path)
    writers = [t.name for t in shared.specs() if not t.read_only]
    assert writers == [], f"a shared server offers these write tools: {writers}"


def test_the_local_server_keeps_every_tool(tmp_path: Path) -> None:
    """The counterpart: one person on stdio owns their own data dir, so nothing is taken away there."""
    local, shared = _kits(tmp_path)
    local_names = {t.name for t in local.specs()}
    assert {"learning_note_add", "incident_confirm", "learn_submit", "learn_quiz", "learn_lesson"} <= local_names
    assert {t.name for t in shared.specs()} < local_names


def test_grading_still_works_on_a_shared_server_without_recording_anything(tmp_path: Path) -> None:
    """RT5-2. Dropping the tools entirely would take the learning tracks off the in-cluster service. Everything
    they return -- lesson text, grading feedback, whether an answer was right -- is computable without state; only
    the credit tally needs the file. So a shared server teaches and grades, records nothing, and says so, rather
    than keeping a tally any caller could have written."""
    _, shared = _kits(tmp_path)
    names = {t.name for t in shared.specs()}
    assert {"learn_tracks", "learn_exercise", "learn_progress"} <= names, "the read-only half stays"

    out = shared.quiz(tk.QuizIn(question_id=_a_quiz_id(), choice=0))
    assert "correct" in out
    assert out.get("recorded") is False
    assert "shared" in str(out.get("note", "")).lower()
    assert not (tmp_path / "data" / "progress").exists(), "nothing was written"


def test_a_shared_progress_read_does_not_hand_over_someone_elses_tally(tmp_path: Path) -> None:
    """RT5-3. A learner id is not an identity: with one static bearer token, any caller can name any id. Returning
    a tally anyone could have written, to anyone who asks for it, is worse than returning none."""
    local, shared = _kits(tmp_path)
    local.quiz(tk.QuizIn(question_id=_a_quiz_id(), choice=0, learner="alice@corp.example"))
    theirs = local.progress(tk.LearnerIn(learner="alice@corp.example"))
    assert theirs["credits"] >= 0
    mine = shared.progress(tk.LearnerIn(learner="alice@corp.example"))
    assert mine.get("recorded") is False
    assert "shared" in str(mine.get("note", "")).lower()
    assert "credits" not in mine or mine["credits"] == 0


def test_concurrent_answers_on_the_local_server_do_not_lose_each_other(tmp_path: Path) -> None:
    """RT5-4. Tutor.load and Tutor.save took no lock, so fifteen concurrent answers stored between two and eight of
    them. One person on stdio can still have two clients open, and a lost credit is a silent wrong answer."""
    local, _ = _kits(tmp_path)
    ids = _quiz_ids()[:8]
    assert len(ids) >= 4, "the test needs several questions"
    with ThreadPoolExecutor(max_workers=len(ids)) as pool:
        list(pool.map(lambda q: local.quiz(tk.QuizIn(question_id=q, choice=0, learner="bob")), ids))
    answered = local.progress(tk.LearnerIn(learner="bob")).get("answeredQuiz") or {}
    assert len(answered) == len(ids), f"stored {len(answered)} of {len(ids)} answers"


def _quiz_ids() -> list[str]:
    from kube_noob.learn.tutor import quizzes

    return sorted(quizzes())


def _a_quiz_id() -> str:
    return _quiz_ids()[0]
