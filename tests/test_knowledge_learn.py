from __future__ import annotations

from pathlib import Path

import pytest

from kube_noob.evals.checks import evaluate
from kube_noob.generate.blueprint import Blueprint
from kube_noob.generate.manifests import generate
from kube_noob.knowledge.store import extract_citations, get_store, tokenize
from kube_noob.learn.tutor import Tutor, curriculum, exercises, lessons, quizzes


def test_builtin_knowledge_loaded() -> None:
    store = get_store()
    stats = store.stats()
    assert stats["documents"] >= 28 and stats["byOrigin"] == {"builtin": stats["chunks"]}
    top = store.search("ReadWriteMany gp3-csi pending EFS", limit=3)
    assert top[0].chunk.doc_id in {"rosa-efs", "storage-access-modes", "rosa-hcp"}
    route = store.search("Route apiVersion route.openshift.io reencrypt", limit=1)[0]
    assert route.chunk.doc_id == "ocp-routes"


def test_tokenizer_keeps_compound_terms() -> None:
    toks = tokenize("gp3-csi route.openshift.io/v1")
    assert "gp3-csi" in toks and "gp3" in toks and "route.openshift.io/v1" in toks


def test_curriculum_integrity() -> None:
    store = get_store()
    ex_ids = set(exercises())
    for les in lessons().values():
        for d in les.get("docs", []):
            assert store.doc(d), f"lesson {les['id']} -> missing doc {d}"
        for e in les.get("exercises", []):
            assert e in ex_ids, f"lesson {les['id']} -> missing exercise {e}"
    for q in quizzes().values():
        assert 0 <= q["answer"] < len(q["choices"])
        assert store.get(q["source"]) is not None, q["source"]
    assert len(curriculum()["tracks"]) == 5


@pytest.mark.parametrize("ex_id", [e for e, x in exercises().items() if x.get("reference")])
def test_reference_solutions_pass(ex_id: str) -> None:
    ex = exercises()[ex_id]
    y = generate(Blueprint.model_validate(ex["reference"])).yaml()
    ev = evaluate(y, ex["checks"])
    assert ev.passed, [o.as_dict() for o in ev.outcomes if not o.passed]


@pytest.mark.parametrize("ex_id", [e for e, x in exercises().items() if x.get("starter")])
def test_starters_fail(ex_id: str) -> None:
    ex = exercises()[ex_id]
    assert not evaluate(ex["starter"], ex["checks"]).passed


def test_tutor_flow_and_credits(tmp_path: Path) -> None:
    t = Tutor(tmp_path)
    ex = exercises()["ocp-ex-secure-route"]
    answer = "```yaml\n" + generate(Blueprint.model_validate(ex["reference"])).yaml() + "```"
    r1 = t.submit("ocp-ex-secure-route", answer, learner="ana")
    assert r1["passed"] and r1["pointsEarned"] == 15 and r1["totalCredits"] == 15
    r2 = t.submit("ocp-ex-secure-route", answer, learner="ana")
    assert r2["totalCredits"] == 15  # best score counted once
    q = t.answer_quiz("ocp-q-route-group", 1, learner="ana")
    assert q["correct"] and q["totalCredits"] == 17
    assert t.answer_quiz("ocp-q-route-group", 1, learner="ana")["creditsAwarded"] == 0
    lesson = t.lesson("ocp-102-scc", learner="ana")
    assert "restricted-v2" in lesson["content"] and lesson["citations"]
    assert t.progress("ana")["lessonsRead"] == ["ocp-102-scc"]
    with pytest.raises(ValueError):
        t.progress("../../etc/passwd")


def test_citation_extraction() -> None:
    assert extract_citations("see [kn:ocp-scc#0] and [kn:ocp-scc#0], [kn:rosa-hcp#2]") == [
        "kn:ocp-scc#0",
        "kn:rosa-hcp#2",
    ]
