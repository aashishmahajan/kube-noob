"""The golden question set (tests/fixtures/golden): original questions written from each supported technology's
official documentation, graded against kube-noob. Items that pass must keep passing and out-of-scope items must
stay unanswered; misses are counted (scripts/eval_golden.py)."""

from __future__ import annotations

import importlib.util
import sys
import tempfile
from pathlib import Path
from typing import Any

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
GOLDEN = ROOT / "tests" / "fixtures" / "golden"


def _mod() -> Any:
    spec = importlib.util.spec_from_file_location("eval_golden", ROOT / "scripts" / "eval_golden.py")
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules["eval_golden"] = mod
    spec.loader.exec_module(mod)
    return mod


def _item(**over: Any) -> dict[str, Any]:
    base = {
        "id": "t-001",
        "technology": "kubernetes",
        "kind": "error",
        "question": "pod stuck with 0/3 nodes are available: 3 Insufficient memory",
        "answer": "requests exceed what the nodes have free",
        "source": {"repo": "kubernetes/website", "path": "x.md", "commit": "abc", "url": "https://kubernetes.io/x"},
        "outOfScope": False,
        "status": "pass",
        "expect": ["DBG-PENDING-RESOURCES"],
    }
    base.update(over)
    return base


def test_the_committed_golden_set_holds() -> None:
    mod = _mod()
    items = mod.load(GOLDEN)
    techs = {i["technology"] for i in items}
    assert {"kubernetes", "helm", "openshift", "rosa-hcp", "rhacs", "policy"} <= techs
    from kube_noob import toolkit as tk
    from kube_noob.config import load_settings

    with tempfile.TemporaryDirectory() as data:
        kit = tk.Toolkit(load_settings(overrides={"dataDir": data, "learningEnabled": False}))
        result = mod.score(items, kit)
    assert result["regressions"] == [], result["regressions"]
    for item in items:
        if not item["outOfScope"]:
            assert item["source"]["url"].startswith("https://")


def test_scoring_counts_pass_abstain_and_miss(tmp_path: Path) -> None:
    mod = _mod()
    items = [
        _item(),
        _item(
            id="t-002",
            outOfScope=True,
            status="abstain",
            source={},
            expect=None,
            kind="out-of-scope",
            question="How do I tune the JVM heap of my Spring Boot jar?",
        ),
        _item(id="t-003", status="miss", expect=None, gap="doc: something", question="zzqx unknown words"),
    ]
    (tmp_path / "k.yaml").write_text(yaml.safe_dump([{k: v for k, v in i.items() if v is not None} for i in items]))
    loaded = mod.load(tmp_path)
    from kube_noob import toolkit as tk
    from kube_noob.config import load_settings

    kit = tk.Toolkit(load_settings(overrides={"dataDir": str(tmp_path / "d"), "learningEnabled": False}))
    result = mod.score(loaded, kit)
    s = result["byTechnology"]["kubernetes"]
    assert s["answeredRight"] == 1 and s["abstainedRight"] == 1 and s["misses"] == 1
    assert result["regressions"] == []


@pytest.mark.parametrize(
    ("over", "message"),
    [
        ({"status": "maybe"}, "is not one of"),
        ({"expect": None}, "needs expect"),
        ({"status": "abstain"}, "only out-of-scope"),
        ({"source": {}}, "needs its documentation source"),
        ({"colour": "red"}, "unknown"),
    ],
)
def test_a_malformed_golden_item_stops_the_run(tmp_path: Path, over: dict[str, Any], message: str) -> None:
    mod = _mod()
    item = {k: v for k, v in _item(**over).items() if v is not None}
    (tmp_path / "k.yaml").write_text(yaml.safe_dump([item]))
    with pytest.raises(mod.GoldenError, match=message):
        mod.load(tmp_path)
