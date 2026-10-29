"""Write docs/scorecard.md: what kube-noob answers, what it leaves unanswered and where it is weak, measured by running
the code in this repository.

Everything is deterministic and comes from committed sources: the golden question set (``scripts/eval_golden.py``),
the held-out and training triage sets (``scripts/eval_triage.py``), ``kube-noob selftest``, counts taken from the
code, and the community-question tables of ``docs/evals/supported-technologies.md``, which are quoted line for line
and never computed. The engine runs in a neutral environment (no configuration file, no KUBE_NOOB_* variable, a
throwaway data directory, learning off), so the same code gives the same document on any machine.

Usage:
  python scripts/scorecard.py            write docs/scorecard.md
  python scripts/scorecard.py --check    exit 1 when the committed file differs from what the code produces
"""

from __future__ import annotations

import contextlib
import importlib.util
import os
import sys
import tempfile
from collections import Counter
from collections.abc import Iterable, Iterator, Sequence
from pathlib import Path
from types import ModuleType
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "docs" / "scorecard.md"
SUPPORTED = ROOT / "docs" / "evals" / "supported-technologies.md"
GOLDEN_DIR = ROOT / "tests" / "fixtures" / "golden"
HELD_OUT_DIR = ROOT / "tests" / "fixtures" / "triage"
TRAIN_DIR = ROOT / "tests" / "fixtures" / "triage-train"

# The two sections of the linked document whose tables are quoted. Their numbers come from graders reading the
# answers to third-party questions that are not in this repository, so the scorecard can only repeat them.
COMMUNITY_HEADINGS = (
    "## How well it answers: measured per technology",
    "## The owner's by-technology file (QA9",
)

TECHNOLOGIES = {
    "kubernetes": "Kubernetes",
    "helm": "Helm 3",
    "openshift": "OpenShift",
    "rosa-hcp": "ROSA HCP",
    "rhacs": "RHACS",
    "policy": "Admission policy engines",
}
QUESTION_CHARS = 110


class ScorecardError(Exception):
    """The scorecard cannot be produced faithfully (a quoted heading or table moved): it stops instead of guessing."""


def _script(name: str) -> ModuleType:
    """Load scripts/<name>.py by path, so this file works from any directory and under pytest."""
    key = f"_scorecard_{name}"
    if key in sys.modules:
        return sys.modules[key]
    spec = importlib.util.spec_from_file_location(key, ROOT / "scripts" / f"{name}.py")
    if spec is None or spec.loader is None:
        raise ScorecardError(f"scripts/{name}.py cannot be loaded")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[key] = mod
    spec.loader.exec_module(mod)
    return mod


@contextlib.contextmanager
def neutral_environment() -> Iterator[Path]:
    """No user configuration reaches the engine: every KUBE_NOOB_* variable is dropped and KUBE_NOOB_CONFIG names a
    file that does not exist, which also stops the lookup of the user's and the system's config. Restored on exit."""
    saved = dict(os.environ)
    with tempfile.TemporaryDirectory() as tmp:
        try:
            for name in [n for n in os.environ if n.startswith("KUBE_NOOB_")]:
                del os.environ[name]
            os.environ["KUBE_NOOB_CONFIG"] = str(Path(tmp) / "no-such-config.yaml")
            yield Path(tmp)
        finally:
            os.environ.clear()
            os.environ.update(saved)


# -- measuring -------------------------------------------------------------------------------------------------------


def _order(tech: str) -> tuple[int, str]:
    known = list(TECHNOLOGIES)
    return (known.index(tech) if tech in known else len(known), tech)


def _golden(mod: ModuleType, items: list[dict[str, Any]], kit: Any) -> dict[str, Any]:
    result = mod.score(items, kit)
    got = {r["id"]: r["got"] for r in result["rows"]}
    technologies = []
    for tech in sorted(result["byTechnology"], key=_order):
        s = result["byTechnology"][tech]
        mine = [i for i in items if i["technology"] == tech]
        technologies.append(
            {
                "id": tech,
                "inScope": s["inScope"],
                "right": s["answeredRight"],
                "rightFirst": sum(
                    1
                    for i in mine
                    if i["status"] == "pass" and {str(e) for e in i.get("expect") or []} & set(got[i["id"]][:1])
                ),
                "inScopeMisses": sum(1 for i in mine if i["status"] == "miss" and not i["outOfScope"]),
                "outOfScopeMisses": sum(1 for i in mine if i["status"] == "miss" and i["outOfScope"]),
                "outOfScope": s["outOfScope"],
                "unanswered": s["abstainedRight"],
            }
        )

    def entry(item: dict[str, Any]) -> dict[str, Any]:
        return {
            "id": item["id"],
            "technology": item["technology"],
            "question": item["question"],
            "gap": item.get("gap") or "no gap recorded",
            "got": got[item["id"]],
        }

    ranked = sorted(items, key=lambda i: (_order(i["technology"]), i["id"]))
    return {
        "technologies": technologies,
        "misses": [entry(i) for i in ranked if i["status"] == "miss" and not i["outOfScope"]],
        "misfires": [entry(i) for i in ranked if i["outOfScope"] and got[i["id"]]],
        "regressions": result["regressions"],
        "newlyPassing": result["newlyPassing"],
    }


def _triage(mod: ModuleType, directory: Path) -> dict[str, Any]:
    result = mod.run(mod.load(directory))
    total = result["total"]
    kinds: dict[str, Counter[str]] = {}
    for r in result["rows"]:
        c = kinds.setdefault(str(r["kind"] or "unlabelled"), Counter())
        c["items"] += 1
        c["causeRight"] += bool(r["causeRight"])
    weak = [
        {"playbook": pid, **{k: c.get(k, 0) for k in ("items", "found", "top1", "causeRight")}}
        for pid, c in result["perPlaybook"].items()
        if c.get("causeRight", 0) < c["items"]
    ]
    weak.sort(key=lambda w: (w["causeRight"] - w["items"], w["playbook"]))
    return {
        "items": result["items"],
        "found": total.get("found", 0),
        "top1": total.get("top1", 0),
        "causeRight": total.get("causeRight", 0),
        "playbooks": len(result["perPlaybook"]),
        "regressed": result["regressed"],
        "byKind": {k: dict(v) for k, v in sorted(kinds.items())},
        "weak": weak,
    }


def _counts(golden: int, held_out: int, train: int) -> dict[str, Any]:
    from kube_noob import known_issues
    from kube_noob.audit.engine import list_rules
    from kube_noob.debug.playbooks import PLAYBOOKS
    from kube_noob.evals import selftest
    from kube_noob.knowledge.store import builtin_chunks

    rules = list_rules()
    chunks = builtin_chunks()
    return {
        "rules": len(rules),
        "rulesByStage": dict(sorted(Counter(str(r["stage"]) for r in rules).items())),
        "playbooks": len(PLAYBOOKS),
        "rootCauses": sum(len(p.root_causes) for p in PLAYBOOKS),
        "knowledgeSections": len(chunks),
        "knowledgeDocuments": len({c.doc_id for c in chunks}),
        "reportedIssues": len({issue.id for issue in known_issues.bundled()[0]}),  # one bug can sit in several minors
        "selftestCases": len(selftest.cases()),
        "goldenQuestions": golden,
        "triageHeldOut": held_out,
        "triageTrain": train,
    }


def collect() -> dict[str, Any]:
    """Run everything and return plain data. The only slow step of the scorecard (about fifteen seconds)."""
    from kube_noob import toolkit as tk
    from kube_noob.config import Settings
    from kube_noob.evals import selftest

    golden_mod, triage_mod = _script("eval_golden"), _script("eval_triage")
    with neutral_environment() as tmp:
        data_dir = tmp / "data"
        data_dir.mkdir()
        settings = Settings.model_validate({"dataDir": str(data_dir), "learningEnabled": False})
        items = golden_mod.load(GOLDEN_DIR)
        golden = _golden(golden_mod, items, tk.Toolkit(settings))
        held_out = _triage(triage_mod, HELD_OUT_DIR)
        train = _triage(triage_mod, TRAIN_DIR)
        st = selftest.run(settings)
    return {
        "counts": _counts(len(items), held_out["items"], train["items"]),
        "golden": golden,
        "triage": {"heldOut": held_out, "train": train},
        "selftest": {k: st[k] for k in ("passed", "total", "byCategory", "failures")},
        "community": {"blocks": [quote_section(SUPPORTED.read_text(encoding="utf-8"), h) for h in COMMUNITY_HEADINGS]},
    }


# -- quoting the linked document -------------------------------------------------------------------------------------


def quote_section(text: str, heading: str) -> dict[str, Any]:
    """The paragraphs before the first table of a section, the table, and the paragraph right after it, unchanged."""
    lines = text.splitlines()
    start = next((n for n, line in enumerate(lines) if line.startswith(heading)), None)
    if start is None:
        raise ScorecardError(f"heading {heading!r} is not in {SUPPORTED.name}: update COMMUNITY_HEADINGS")
    level = len(lines[start]) - len(lines[start].lstrip("#"))
    end = next(
        (
            n
            for n in range(start + 1, len(lines))
            if lines[n].startswith("#" * level + " ") or lines[n].startswith("# ")
        ),
        len(lines),
    )
    body = lines[start + 1 : end]
    first = next((n for n, line in enumerate(body) if line.startswith("|")), None)
    if first is None:
        raise ScorecardError(f"the section {heading!r} has no table: update COMMUNITY_HEADINGS")
    last = first
    while last + 1 < len(body) and body[last + 1].startswith("|"):
        last += 1
    return {
        "heading": lines[start].lstrip("# ").strip(),
        "before": _paragraphs(body[:first]),
        "table": body[first : last + 1],
        "after": _paragraphs(body[last + 1 :])[:1],
    }


def _paragraphs(lines: Sequence[str]) -> list[str]:
    out: list[str] = []
    current: list[str] = []
    for line in [*lines, ""]:
        if line.strip():
            current.append(line.strip())
        elif current:
            out.append(" ".join(current))
            current = []
    return out


# -- the document ----------------------------------------------------------------------------------------------------


def _text(value: str, limit: int | None = None) -> str:
    """Plain text for a table cell: one line, cut at ``limit``, and nothing that markdown would act on."""
    value = " ".join(str(value).split())
    if limit is not None and len(value) > limit:
        value = value[: limit - 3].rstrip() + "..."
    for raw, safe in (("\\", "\\\\"), ("|", "\\|"), ("`", "\\`"), ("*", "\\*"), ("<", "&lt;"), (">", "&gt;")):
        value = value.replace(raw, safe)
    return value


def _code_list(items: Iterable[str]) -> str:
    return ", ".join(f"`{i}`" for i in items) or "none"


def _table(header: Sequence[str], rows: Iterable[Sequence[str]]) -> list[str]:
    return [
        "| " + " | ".join(header) + " |",
        "|" + "---|" * len(header),
        *("| " + " | ".join(row) + " |" for row in rows),
    ]


def _pct(part: int, whole: int) -> str:
    return f"{round(100 * part / whole)}%" if whole else "n/a"


def _of(part: int, whole: int) -> str:
    return f"{part} of {whole}"


def _name(tech: str) -> str:
    return TECHNOLOGIES.get(tech, tech)


def _intro(counts: dict[str, Any]) -> list[str]:
    return [
        "# Scorecard",
        "",
        "What kube-noob answers, what it leaves unanswered and where it is weak, measured by running the code in this "
        "repository. Generated by `scripts/scorecard.py`; do not edit it. `python scripts/scorecard.py` rewrites it, "
        "and `python scripts/scorecard.py --check` and `tests/test_scorecard.py` fail when it no longer matches the "
        "code. Every number comes from the command next to it, run on committed fixtures with no model, no network, "
        "no configuration file and no KUBE_NOOB_* variable, so a rerun gives the same numbers.",
        "",
        "## How to read it",
        "",
        f"- The golden set (`tests/fixtures/golden`, {counts['goldenQuestions']} questions) was written from each "
        "technology's official documentation, and the gaps it showed were then closed by adding what the graders "
        "named for each miss. Its score shows that nothing regressed; it is a regression test. As "
        "[supported-technologies.md](evals/supported-technologies.md) puts it, the rise is a fit to those questions, "
        '"not evidence that kube-noob generalises".',
        "- The held-out triage set (`tests/fixtures/triage`) was never used to tune a pattern; the training set "
        "(`tests/fixtures/triage-train`) was. Compare the two to see what tuning on a set buys, and quote the "
        "held-out number.",
        "- The community questions (last section) are real posts. They are third-party text kept outside this "
        "repository, so their tables are quoted unchanged from "
        "[docs/evals/supported-technologies.md](evals/supported-technologies.md) and are not recomputed here. They "
        "are the numbers to trust for real posts.",
        "- Counts here are mechanical: a golden question is right when the expected finding is first (among the first "
        "three where the item says so) and a triage question when the answer shows the labelled cause. The graded "
        "tables in the linked document read the answers instead, so the two can differ by a few items.",
        "",
    ]


def _headline(data: dict[str, Any]) -> list[str]:
    g, t, st, c = data["golden"]["technologies"], data["triage"], data["selftest"], data["counts"]
    right, in_scope = sum(x["right"] for x in g), sum(x["inScope"] for x in g)
    unanswered, out_of_scope = sum(x["unanswered"] for x in g), sum(x["outOfScope"] for x in g)
    eval_golden, eval_triage = "python scripts/eval_golden.py", "python scripts/eval_triage.py"

    def count(label: str, value: int, expression: str) -> tuple[str, str, str]:
        return label, f"{value}", f'`python -c "{expression}"`'

    rows = [
        ("Golden questions in scope answered right", _of(right, in_scope), f"`{eval_golden}`"),
        ("Golden questions out of scope left unanswered", _of(unanswered, out_of_scope), f"`{eval_golden}`"),
        (
            "Held-out triage questions that name the labelled cause",
            _of(t["heldOut"]["causeRight"], t["heldOut"]["items"]),
            f"`{eval_triage}`",
        ),
        (
            "Training triage questions that name the labelled cause",
            _of(t["train"]["causeRight"], t["train"]["items"]),
            f"`{eval_triage} --dir tests/fixtures/triage-train`",
        ),
        ("Self-test cases passed", _of(st["passed"], st["total"]), "`kube-noob selftest`"),
        count("Audit rules", c["rules"], "from kube_noob.audit.engine import RULES; print(len(RULES))"),
        count(
            "Diagnosis playbooks",
            c["playbooks"],
            "from kube_noob.debug.playbooks import PLAYBOOKS; print(len(PLAYBOOKS))",
        ),
        count(
            "Knowledge documents",
            c["knowledgeDocuments"],
            "from kube_noob.knowledge.store import builtin_chunks; print(len({c.doc_id for c in builtin_chunks()}))",
        ),
        count(
            "Knowledge sections",
            c["knowledgeSections"],
            "from kube_noob.knowledge.store import builtin_chunks; print(len(builtin_chunks()))",
        ),
        count(
            "Reported issues bundled (distinct bugs)",
            c["reportedIssues"],
            "from kube_noob.known_issues import bundled; print(len({i.id for i in bundled()[0]}))",
        ),
        count("Self-test cases", c["selftestCases"], "from kube_noob.evals.selftest import cases; print(len(cases()))"),
    ]
    return [
        "## Headline numbers",
        "",
        *_table(("What", "Result", "Command"), rows),
        "",
        "The community-question numbers are quoted in the last section; their command needs the owner's question "
        "file, which is not in this repository.",
        "",
    ]


def _weak(data: dict[str, Any]) -> list[str]:
    golden, held, train = data["golden"], data["triage"]["heldOut"], data["triage"]["train"]
    techs = sorted(golden["technologies"], key=lambda x: (x["right"] / x["inScope"] if x["inScope"] else 1.0, x["id"]))
    right, in_scope = sum(x["right"] for x in techs), sum(x["inScope"] for x in techs)
    unanswered, out_of_scope = sum(x["unanswered"] for x in techs), sum(x["outOfScope"] for x in techs)
    by_kind = ", ".join(
        f"{kind} {_of(k['causeRight'], k['items'])}" for kind, k in held["byKind"].items() if k["items"]
    )
    lines = [
        "## Where it is weak",
        "",
        f"- Golden questions: {_of(right, in_scope)} in-scope questions are answered right, and this is the set "
        "the gaps were closed on. By technology, weakest first: "
        + "; ".join(f"{_name(x['id'])} {_of(x['right'], x['inScope'])}" for x in techs)
        + f". {len(golden['misses'])} in-scope questions get no right answer; each is listed below with what it needs.",
    ]
    if golden["misfires"]:
        lines.append(
            f"- Out of scope: {_of(unanswered, out_of_scope)} questions about another product are left unanswered. "
            f"{len(golden['misfires'])} got an answer anyway ({_code_list(m['id'] for m in golden['misfires'])}); "
            "each is listed below with what should have kept it silent."
        )
    else:
        lines.append(f"- Out of scope: all {out_of_scope} questions about another product are left unanswered.")
    lines.append(
        f"- Cause choice: on questions the patterns were not tuned on, the answer names the labelled cause for "
        f"{_of(held['causeRight'], held['items'])} ({_pct(held['causeRight'], held['items'])}); on the set they were "
        f"tuned on, for {_of(train['causeRight'], train['items'])} ({_pct(train['causeRight'], train['items'])}). The "
        f"held-out number is the one to quote. Held-out by kind of input: {by_kind}. The right playbook is among the "
        f"findings for {_of(held['found'], held['items'])} and first for {_of(held['top1'], held['items'])}."
    )
    lines.append(
        "- Neither set measures how well kube-noob generalises to real posts: the golden questions shaped the "
        "content, and the triage questions were written from the playbooks' own root causes. The community tables "
        "in the last section do."
    )
    baseline = data["community"]["blocks"][-1]["after"]  # the plain statement under the by-technology baseline
    if baseline:
        lines.append(f"- On real posts, in the words of the linked document's by-technology baseline: {baseline[0]}")
    lines.append(
        "- The self-test runs bundled examples. A pass shows the install works and the bundled content still answers "
        "them; it says nothing about questions outside it."
    )
    return [*lines, ""]


def _carries(counts: dict[str, Any]) -> list[str]:
    stages = ", ".join(f"{n} {stage}" for stage, n in counts["rulesByStage"].items())
    return [
        "## What it carries",
        "",
        f"- {counts['rules']} audit rules ({stages}).",
        f"- {counts['playbooks']} diagnosis playbooks with {counts['rootCauses']} root causes.",
        f"- {counts['knowledgeSections']} knowledge sections in {counts['knowledgeDocuments']} documents.",
        f"- {counts['reportedIssues']} reported issues from the bundled OpenShift release notes.",
        f"- {counts['selftestCases']} self-test cases, {counts['goldenQuestions']} golden questions, "
        f"{counts['triageHeldOut']} held-out and {counts['triageTrain']} training triage questions.",
        "",
        "What is bundled for each technology is listed in "
        "[supported-technologies.md](evals/supported-technologies.md).",
        "",
    ]


def _entries(rows: Sequence[dict[str, Any]], missing_header: str) -> list[str]:
    return _table(
        ("Id", "Technology", "Question", missing_header, "kube-noob returned"),
        [
            (
                f"`{r['id']}`",
                _text(_name(r["technology"])),
                _text(r["question"], QUESTION_CHARS),
                _text(r["gap"]),
                _code_list(r["got"]),
            )
            for r in rows
        ],
    )


def _golden_section(golden: dict[str, Any]) -> list[str]:
    techs = golden["technologies"]
    rows = [
        (
            _text(_name(x["id"])),
            str(x["inScope"]),
            f"{x['right']} ({_pct(x['right'], x['inScope'])})",
            str(x["rightFirst"]),
            str(x["inScopeMisses"]),
            str(x["outOfScope"]),
            str(x["unanswered"]),
        )
        for x in techs
    ]
    total = [
        sum(x[k] for x in techs)
        for k in ("inScope", "right", "rightFirst", "inScopeMisses", "outOfScope", "unanswered")
    ]
    rows.append(
        (
            "**All**",
            f"**{total[0]}**",
            f"**{total[1]} ({_pct(total[1], total[0])})**",
            f"**{total[2]}**",
            f"**{total[3]}**",
            f"**{total[4]}**",
            f"**{total[5]}**",
        )
    )
    lines = [
        "## Golden questions, per technology",
        "",
        "`python scripts/eval_golden.py` prints the same table. An item counts as right when the expected finding is "
        'first, or among the first three where the item says so; "first" counts only the former. A miss is an '
        "in-scope question the item itself records as unanswered, with what it needs.",
        "",
        *_table(
            (
                "Technology",
                "In scope",
                "Right",
                "Right as the first finding",
                "Misses",
                "Out of scope",
                "Left unanswered",
            ),
            rows,
        ),
        "",
        "### Golden questions kube-noob does not answer",
        "",
    ]
    if golden["misses"]:
        lines += [*_entries(golden["misses"], "What it needs"), ""]
    else:
        lines += ["No in-scope golden question is unanswered.", ""]
    lines += ["### Out-of-scope questions that got an answer", ""]
    if golden["misfires"]:
        lines += [*_entries(golden["misfires"], "Why it is wrong"), ""]
    else:
        lines += ["No out-of-scope golden question got an answer.", ""]
    for r in golden["regressions"]:
        lines.append(
            f"REGRESSED `{r['id']}` ({r['status']}): returned {_code_list(r['got'])}, "
            f"expected {_code_list(r['expect'])}."
        )
    if golden["newlyPassing"]:
        lines.append(f"Now passing, status can be raised: {_code_list(golden['newlyPassing'])}.")
    if golden["regressions"] or golden["newlyPassing"]:
        lines.append("")
    return lines


def _triage_section(triage: dict[str, Any]) -> list[str]:
    held, train = triage["heldOut"], triage["train"]
    rows = [
        (
            name,
            str(part["items"]),
            f"{part['found']} ({_pct(part['found'], part['items'])})",
            f"{part['top1']} ({_pct(part['top1'], part['items'])})",
            f"{part['causeRight']} ({_pct(part['causeRight'], part['items'])})",
        )
        for name, part in (("Held-out (never tuned on)", held), ("Training (tuned on)", train))
    ]
    lines = [
        "## Cause choice (triage)",
        "",
        "For each labelled question, does the answer name the labelled playbook, and does that finding show the "
        "labelled root cause? One typed question and one pasted error were written per cause. "
        "`python scripts/eval_triage.py` prints the held-out set per playbook and "
        "`python scripts/eval_triage.py --dir tests/fixtures/triage-train` the training set.",
        "",
        *_table(("Set", "Questions", "Playbook found", "Playbook first", "Names the labelled cause"), rows),
        "",
        "### Held-out: playbooks where the cause is not always right",
        "",
    ]
    if held["weak"]:
        lines += _table(
            ("Playbook", "Questions", "Found", "First", "Cause right"),
            [
                (f"`{w['playbook']}`", str(w["items"]), str(w["found"]), str(w["top1"]), str(w["causeRight"]))
                for w in held["weak"]
            ],
        )
        lines.append("")
    else:
        lines += ["Every held-out question names its labelled cause.", ""]
    for part, name in ((held, "held-out"), (train, "training")):
        if part["regressed"]:
            lines.append(f"REGRESSED ({name}): {_code_list(part['regressed'])}.")
            lines.append("")
    return lines


def _selftest_section(st: dict[str, Any]) -> list[str]:
    lines = [
        "## Self-test",
        "",
        "`kube-noob selftest` runs bundled examples through search, diagnosis, audit and the protocol, offline. It "
        "proves an install answers the questions it claims to; it is not a measure of coverage.",
        "",
        *_table(
            ("Category", "Passed", "Of"),
            [(_text(cat), str(c["passed"]), str(c["total"])) for cat, c in st["byCategory"].items()],
        ),
        "",
    ]
    if st["failures"]:
        for f in st["failures"]:
            lines.append(f"REGRESSED `{f['id']}` ({f['category']}, {f['kind']}): {_text(f['detail'])}.")
        lines.append("")
    else:
        lines += ["No self-test case fails.", ""]
    return lines


def _community_section(community: dict[str, Any]) -> list[str]:
    lines = [
        "## Community questions (quoted, not recomputed)",
        "",
        "These come from real posts (Stack Overflow, Server Fault, forums and Red Hat Jira resolutions), graded by "
        "independent agents against the accepted answers. The posts are third-party text and stay outside this "
        "repository, so the tables below are copied line for line from "
        "[docs/evals/supported-technologies.md](evals/supported-technologies.md), which holds the method, the dates "
        "and the changes since. Nothing here is computed from them.",
        "",
    ]
    for block in community["blocks"]:
        lines += [f"### {block['heading']}", ""]
        for para in block["before"]:
            lines += [f"> {para}", ">"]
        lines += [f"> {row}" for row in block["table"]]
        for para in block["after"]:
            lines += [">", f"> {para}"]
        lines.append("")
    return lines


def render(data: dict[str, Any]) -> str:
    lines = [
        *_intro(data["counts"]),
        *_headline(data),
        *_weak(data),
        *_carries(data["counts"]),
        *_golden_section(data["golden"]),
        *_triage_section(data["triage"]),
        *_selftest_section(data["selftest"]),
        *_community_section(data["community"]),
    ]
    while lines and not lines[-1]:
        lines.pop()
    return "\n".join(lines) + "\n"


def main(argv: list[str]) -> int:
    if argv not in ([], ["--check"]):
        print(__doc__)
        return 2
    try:
        text = render(collect())
    except ScorecardError as exc:
        print(f"scorecard: {exc}", file=sys.stderr)
        return 1
    if argv == ["--check"]:
        if not OUT.is_file() or OUT.read_text(encoding="utf-8") != text:
            shown = OUT.relative_to(ROOT) if OUT.is_relative_to(ROOT) else OUT
            print(f"{shown} is stale: run python scripts/scorecard.py", file=sys.stderr)
            return 1
        print("docs/scorecard.md matches the code")
        return 0
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(text, encoding="utf-8")
    print(f"wrote {OUT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
