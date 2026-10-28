"""The cause-level set (tests/fixtures/triage) holds: an item that names its labelled cause keeps naming it."""

from __future__ import annotations

from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def _eval():  # type: ignore[no-untyped-def]
    import importlib.util

    spec = importlib.util.spec_from_file_location("eval_triage", ROOT / "scripts" / "eval_triage.py")
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_the_committed_triage_set_holds() -> None:
    ev = _eval()
    items = ev.load(ROOT / "tests" / "fixtures" / "triage")
    assert len(items) >= 100 and {i["kind"] for i in items} >= {"typed", "pasted"}
    res = ev.run(items)
    assert res["regressed"] == [], res["regressed"]
    assert res["total"]["causeRight"] >= sum(1 for i in items if i.get("status") == "pass")


def test_the_training_set_is_separate_from_the_held_out_set() -> None:
    ev = _eval()
    train = ev.load(ROOT / "tests" / "fixtures" / "triage-train")
    held = ev.load(ROOT / "tests" / "fixtures" / "triage")
    assert len(train) >= 150 and not {i["id"] for i in train} & {i["id"] for i in held}
    assert not {i["text"].strip() for i in train} & {i["text"].strip() for i in held}


def test_a_malformed_triage_item_stops_the_run(tmp_path: Path) -> None:
    ev = _eval()
    (tmp_path / "x.yaml").write_text("- {id: a, playbook: DBG-OOM, cause: one, text: x}\n")
    with pytest.raises(ValueError):
        ev.load(tmp_path)
    (tmp_path / "x.yaml").write_text("- {id: a, playbook: DBG-OOM, cause: 0, text: x, extra: 1}\n")
    with pytest.raises(ValueError):
        ev.load(tmp_path)
