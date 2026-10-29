"""Score which cause kube-noob shows, not only which playbook: for each labelled input, does the answer name the
expected playbook, and does that finding show the expected root cause?

The set (``tests/fixtures/triage/*.yaml``) is original text written by an agent that saw only each playbook's list of
root causes (not the patterns or code that pick one), one typed question and one pasted error per cause, each
labelled with its playbook and cause index. ``status: pass`` items must keep passing (``tests/test_triage.py``).
Patterns are tuned on the separate training set (``tests/fixtures/triage-train``, written the same way) and never on
the held-out set.

    python scripts/eval_triage.py [--dir tests/fixtures/triage] [--out triage-results.json] [--json]
    python scripts/eval_triage.py --dir tests/fixtures/triage-train
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
FIELDS = {"id", "playbook", "cause", "kind", "platform", "text", "status", "note"}
MAX_TEXT = 4000


def load(directory: Path) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    seen: set[str] = set()
    for path in sorted(directory.glob("*.yaml")):
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or []
        if not isinstance(data, list):
            raise ValueError(f"{path.name}: a list of items expected")
        for it in data:
            if not isinstance(it, dict) or set(it) - FIELDS or not {"id", "playbook", "cause", "text"} <= set(it):
                raise ValueError(f"{path.name}: malformed item {it!r:.120}")
            if it["id"] in seen:
                raise ValueError(f"{path.name}: duplicate id {it['id']}")
            if not isinstance(it["cause"], int) or not isinstance(it["text"], str) or len(it["text"]) > MAX_TEXT:
                raise ValueError(f"{path.name}: {it['id']}: cause must be an int and text at most {MAX_TEXT} chars")
            if it.get("status") not in (None, "pass", "miss"):
                raise ValueError(f"{path.name}: {it['id']}: status must be pass or miss")
            seen.add(it["id"])
            items.append(it)
    return items


def _prefix(cause: str) -> str:
    """The part of a root cause before its first placeholder: the shown cause has the input's names filled in."""
    return cause.split("{", 1)[0].strip()[:60]


def run(items: list[dict[str, Any]]) -> dict[str, Any]:
    from kube_noob import toolkit as tk
    from kube_noob.config import load_settings
    from kube_noob.debug.playbooks import PLAYBOOKS

    causes = {p.pid: p.root_causes for p in PLAYBOOKS}
    rows: list[dict[str, Any]] = []
    with tempfile.TemporaryDirectory() as data:
        kit = tk.Toolkit(load_settings(overrides={"dataDir": data, "learningEnabled": False}))
        for it in items:
            pid, idx = it["playbook"], it["cause"]
            if pid not in causes or not 0 <= idx < len(causes[pid]):
                raise ValueError(f"{it['id']}: unknown playbook or cause index")
            out = kit.insight(tk.InsightIn(text=it["text"], platform=it.get("platform")))
            playbooks = [f for f in out["findings"] if f["source"] == "playbook"]
            mine = next((f for f in playbooks if f["id"] == pid), None)
            shown = str((mine or {}).get("cause") or "")
            right = bool(mine) and shown.startswith(_prefix(causes[pid][idx]))
            rows.append(
                {
                    "id": it["id"],
                    "playbook": pid,
                    "kind": it.get("kind"),
                    "top1": bool(playbooks) and playbooks[0]["id"] == pid,
                    "found": mine is not None,
                    "causeRight": right,
                    "status": it.get("status"),
                    "regressed": it.get("status") == "pass" and not right,
                }
            )
    per: dict[str, Counter[str]] = defaultdict(Counter)
    for r in rows:
        c = per[r["playbook"]]
        c["items"] += 1
        c["found"] += r["found"]
        c["top1"] += r["top1"]
        c["causeRight"] += r["causeRight"]
    total = Counter[str]()
    for c in per.values():
        total.update(c)
    return {
        "items": len(rows),
        "total": dict(total),
        "perPlaybook": {k: dict(v) for k, v in sorted(per.items())},
        "regressed": [r["id"] for r in rows if r["regressed"]],
        "rows": rows,
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--dir", type=Path, default=ROOT / "tests" / "fixtures" / "triage")
    ap.add_argument("--out", type=Path)
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)
    res = run(load(args.dir))
    if args.out:
        args.out.write_text(json.dumps(res, indent=1))
    if args.json:
        print(json.dumps(res, indent=1))
        return 0
    for pid, c in res["perPlaybook"].items():
        print(f"{pid:<24} cause right {c['causeRight']}/{c['items']}, playbook found {c['found']}, first {c['top1']}")
    t = res["total"]
    print(f"{'all':<24} cause right {t['causeRight']}/{t['items']}, playbook found {t['found']}, first {t['top1']}")
    if res["regressed"]:
        print("REGRESSED: " + ", ".join(res["regressed"]))
    return 1 if res["regressed"] else 0


if __name__ == "__main__":
    sys.exit(main())
