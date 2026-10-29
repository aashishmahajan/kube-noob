"""Run kube-noob on the golden question set and score it per technology.

The golden set (``tests/fixtures/golden/<technology>.yaml``) is original text: realistic questions written from the
official documentation of each supported technology (Kubernetes, Helm, OpenShift, ROSA HCP, RHACS, admission
policy engines), each with a paraphrased reference answer and the documentation page it comes from, plus questions
about other products that kube-noob should leave unanswered. Unlike the community-questions eval it can live in the
repository and run in CI.

Each item carries a ``status`` decided by grading kube-noob's answer against the reference answer:

- ``pass``: kube-noob's top finding (or, with ``expectAny``, any of its first three) is one of ``expect``;
- ``abstain``: an out-of-scope item that must get no playbook, reported issue or document;
- ``miss``: kube-noob does not answer it yet; ``gap`` says what it needs. Misses are counted, not failed, and a
  miss that starts passing is reported so its status can be raised.

Usage:
  python scripts/eval_golden.py [--dir tests/fixtures/golden] [--out <dir>] [--json]

Exit status 1 when a ``pass`` or ``abstain`` item regressed (the CI gate), else 0.
"""

from __future__ import annotations

import argparse
import json
import sys
import tempfile
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[1]
STATUSES = ("pass", "abstain", "miss")
KEYS = {"id", "technology", "kind", "question", "answer", "source", "outOfScope", "status"}
OPTIONAL = {"expect", "expectAny", "gap", "platform"}
ANSWER_SOURCES = ("playbook", "reported-issue", "doc", "team-memory", "policy", "rule", "build", "ceph-health")
MAX_ITEMS = 2000


class GoldenError(ValueError):
    """The golden set is malformed: the run stops instead of scoring against it."""


def load(directory: Path) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    seen: set[str] = set()
    for path in sorted(directory.glob("*.yaml")):
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
        if not isinstance(data, list):
            raise GoldenError(f"{path.name}: expected a list of items")
        for n, item in enumerate(data):
            where = f"{path.name}[{n}]"
            if not isinstance(item, dict):
                raise GoldenError(f"{where}: not a mapping")
            missing = KEYS - set(item)
            extra = set(item) - KEYS - OPTIONAL
            if missing or extra:
                raise GoldenError(f"{where}: missing {sorted(missing)} unknown {sorted(extra)}")
            if item["id"] in seen:
                raise GoldenError(f"{where}: duplicate id {item['id']}")
            seen.add(item["id"])
            if item["status"] not in STATUSES:
                raise GoldenError(f"{where}: status {item['status']!r} is not one of {', '.join(STATUSES)}")
            if item["status"] == "pass" and not item.get("expect"):
                raise GoldenError(f"{where}: a pass item needs expect")
            if item["status"] == "abstain" and not item["outOfScope"]:
                raise GoldenError(f"{where}: only out-of-scope items abstain")
            if not item["outOfScope"] and not (isinstance(item["source"], dict) and item["source"].get("url")):
                raise GoldenError(f"{where}: an in-scope item needs its documentation source")
            items.append(item)
            if len(items) > MAX_ITEMS:
                raise GoldenError(f"more than {MAX_ITEMS} items")
    return items


def answers(kit: Any, item: dict[str, Any]) -> list[str]:
    """kube-noob's findings for the question, in rank order, ids only."""
    from kube_noob import toolkit as tk

    out = kit.insight(tk.InsightIn(text=item["question"], platform=item.get("platform")))
    return [str(f["id"]) for f in out.get("findings", []) if f.get("source") in ANSWER_SOURCES]


def score(items: list[dict[str, Any]], kit: Any) -> dict[str, Any]:
    by_tech: dict[str, Counter[str]] = defaultdict(Counter)
    regressions: list[dict[str, Any]] = []
    newly_passing: list[str] = []
    rows: list[dict[str, Any]] = []
    for item in items:
        got = answers(kit, item)
        expect = {str(e) for e in item.get("expect") or []}
        window = got[:3] if item.get("expectAny") else got[:1]
        hit = bool(expect & set(window))
        abstained = not got
        status = item["status"]
        c = by_tech[item["technology"]]
        c["items"] += 1
        c[status] += 1
        ok = (status == "pass" and hit) or (status == "abstain" and abstained) or status == "miss"
        if status == "miss" and expect and hit:
            newly_passing.append(item["id"])
        if not ok:
            regressions.append({"id": item["id"], "status": status, "got": got[:3], "expect": sorted(expect)})
            c["regressed"] += 1
        if not item["outOfScope"]:
            c["inScope"] += 1
            c["answeredRight"] += status == "pass" and hit
        else:
            c["outOfScope"] += 1
            c["abstainedRight"] += abstained
        rows.append({"id": item["id"], "technology": item["technology"], "status": status, "got": got[:3]})
    summary = {
        t: {
            "items": c["items"],
            "inScope": c["inScope"],
            "answeredRight": c["answeredRight"],
            "answeredRightPct": round(100.0 * c["answeredRight"] / c["inScope"], 1) if c["inScope"] else 0.0,
            "outOfScope": c["outOfScope"],
            "abstainedRight": c["abstainedRight"],
            "misses": c["miss"],
            "regressed": c["regressed"],
        }
        for t, c in sorted(by_tech.items())
    }
    return {"byTechnology": summary, "regressions": regressions, "newlyPassing": newly_passing, "rows": rows}


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--dir", type=Path, default=ROOT / "tests" / "fixtures" / "golden")
    ap.add_argument("--out", type=Path, help="write golden-results.json here")
    ap.add_argument("--json", action="store_true", help="print the whole result as JSON")
    a = ap.parse_args(argv)
    try:
        items = load(a.dir)
    except (OSError, GoldenError, yaml.YAMLError) as e:
        print(f"eval_golden: {e}", file=sys.stderr)
        return 2
    from kube_noob import toolkit as tk
    from kube_noob.config import load_settings

    with tempfile.TemporaryDirectory() as data:
        kit = tk.Toolkit(load_settings(overrides={"dataDir": data, "learningEnabled": False}))
        result = score(items, kit)
    if a.out:
        a.out.mkdir(parents=True, exist_ok=True)
        (a.out / "golden-results.json").write_text(json.dumps(result, indent=1) + "\n", encoding="utf-8")
    if a.json:
        print(json.dumps(result, indent=1))
    else:
        for t, s in result["byTechnology"].items():
            print(
                f"{t:12s} in scope {s['answeredRight']}/{s['inScope']} right ({s['answeredRightPct']}%), "
                f"out of scope {s['abstainedRight']}/{s['outOfScope']} left unanswered, "
                f"misses {s['misses']}, regressed {s['regressed']}"
            )
        for r in result["regressions"]:
            print(f"REGRESSED {r['id']} ({r['status']}): got {r['got']} expected {r['expect']}")
        for i in result["newlyPassing"]:
            print(f"NOW PASSING {i}: raise its status to pass")
    return 1 if result["regressions"] else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
