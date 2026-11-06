#!/usr/bin/env python3
"""Generate the measured numbers the documents quote, from the code that produces them.

Four of these were wrong at once on 2026-11-05, all of them the same defect `docs/compliance.md` had before
`scripts/compliance_doc.py` (G206): a number somebody typed, beside code that moved. `docs/limits.md` published
"47 generated / 31 not generated" for Kubernetes and "54 / 24" for OpenShift -- both pairs summing to 78, the rule
count this project retired, because the generated column was updated and the other was not. `docs/use-cases.md`
sold the compact report as "105 findings over 19 rules ... 118 631 to 54 694 bytes" when it was 115 over 21 and
141 349 to 69 936.

It happened again on 2026-11-06, in the one file that measures the whole product: `docs/roadmap.md` said "91
rules" and "28 of NIST SP 800-53 Rev. 5's controls" the day the catalogue reached 92 and the thirtieth control
got a rule, and its "105 commands" matched no counting method at all. Those sentences are generated now too.

Four regions are rewritten and nothing else:

- the platform table in `docs/limits.md`, from `kube_noob.generate.policies.generate` for each platform the table
  lists, with its own `policy generate` header as the authority a reader can reproduce;
- the compaction sentence in `docs/use-cases.md`, from an actual audit of `examples/` and an actual compaction of
  that report;
- the "Measured <date>, not estimated" sentence in `docs/roadmap.md`, from the files and registries themselves;
- the control sentence under that file's "honest ceiling" heading, from `kube_noob.audit.controls`.

Every measurement is deterministic: fixed inputs, same bytes every run, which is what makes `--check` meaningful
rather than flaky. What each number counts, so a reader can reproduce it and a later change cannot quietly
redefine it:

- lines and modules: every `*.py` under `src/kube_noob` and under `tests`, counted as lines of text;
- rules: `audit.engine.list_rules`, the catalogue the audit actually runs;
- MCP tools: `Toolkit(load_settings()).specs()`, the same call `docs/website-updates.md` publishes;
- commands: every subcommand node in the CLI parser, at any depth (`posture` and `posture scan` are two), which
  is the only definition that does not change with how deeply a command is nested;
- chart templates: `*.yaml` under the chart's `templates/`;
- controls: the NIST controls at least one rule names (`RULE_CONTROLS`), out of the titled catalogue.

    python scripts/doc_numbers.py --check    # exit 1 when a document is stale
    python scripts/doc_numbers.py            # rewrite the two regions
"""

from __future__ import annotations

import argparse
import re
import sys
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
LIMITS = ROOT / "docs" / "limits.md"
USE_CASES = ROOT / "docs" / "use-cases.md"
ROADMAP = ROOT / "docs" / "roadmap.md"

#: The platforms the limits table reports, with the version each row is measured at. A row is only honest with its
#: version, because a rule can generate on one minor and not another.
PLATFORMS: tuple[tuple[str, str, str | None], ...] = (
    ("kubernetes", "kubernetes", "1.35"),
    ("openshift 4.20", "openshift", "4.20"),
)

_TABLE = re.compile(
    r"^\| Platform \| Rules generated \| Not generated \|\n\|[ -|]+\|\n(?:\| [^|]+ \| \d+ \| \d+ \|\n)+", re.M
)
_COMPACTION = re.compile(
    r"that is \d[\d   ]* findings over \d+ rules, and the JSON goes from [\d   ]+ to\n"
    r"[\d   ]+ bytes"
)

#: The roadmap's two measured sentences. The date is kept as written -- it says when somebody last looked at the
#: file, which is not something this script can measure -- and only the figures are rewritten. This file groups
#: thousands with a comma, unlike the two above, so it keeps its own convention rather than being normalised. The
#: two line counts are rounded to the nearest thousand deliberately: reported exactly, every commit that adds a
#: test would make the committed document stale and fail `--check`, which trains people to ignore the gate.
_MEASURED = re.compile(
    r"(The engine is\s+about )[\d,]+( lines across )\d+( modules with about )[\d,]+"
    r"( lines of tests \(both to the nearest thousand, because a[\s\S]{0,120}?and exactly )\d+"
    r"( rules,\s+)\d+( MCP tools,\s+)\d+( commands and )\d+( chart templates\.)"
)
_CEILING = re.compile(r"(kube-noob names )\d+( of NIST SP 800-53 Rev\. 5's controls across its )\d+( rules)")
_CEILING_EVIDENCE = re.compile(r"(bearing on these )\d+( controls)")


@dataclass(frozen=True)
class Row:
    label: str
    platform: str
    version: str | None
    generated: int
    not_generated: int


@dataclass(frozen=True)
class Measured:
    engine_lines: int
    modules: int
    test_lines: int
    rules: int
    mcp_tools: int
    commands: int
    chart_templates: int
    controls: int


@dataclass(frozen=True)
class Compaction:
    findings: int
    rules: int
    flat_bytes: int
    compact_bytes: int


def thousands(n: int) -> str:
    """A thin space between groups, as the documents already write these numbers (118 631, not 118,631)."""
    return f"{n:,}".replace(",", " ")


def policy_rows() -> list[Row]:
    from kube_noob.generate import policies

    rows = []
    for label, platform, version in PLATFORMS:
        g = policies.generate(platform=platform, platform_version=version, engines=policies.ENGINES, mode="audit")
        generated = {str(r["ruleId"]) for r in g.generated}
        skipped = {str(r["ruleId"]) for r in g.skipped}
        rows.append(Row(label, platform, version, len(generated), len(skipped)))
    return rows


def compaction() -> Compaction:
    """Run the command the document prints, both ways, and measure what it writes.

    Through the CLI rather than through `Toolkit.audit` in process, because the sentence is about the bytes
    `kube-noob --format json audit -f examples/ --compact` produces, and the CLI adds keys of its own (it reports
    `unreadable` on the file path). Reconstructing the shape in here gave a number 20 bytes off the command's, and
    a measurement a reader cannot reproduce from the paragraph above it is not worth printing.
    """
    import json
    import subprocess

    def run(*extra: str) -> bytes:
        cmd = [sys.executable, "-m", "kube_noob", "--format", "json", "audit", "-f", "examples/", *extra]
        out = subprocess.run(cmd, capture_output=True, cwd=ROOT, check=False)
        if not out.stdout:
            raise SystemExit(f"{' '.join(cmd)} wrote nothing: {out.stderr.decode()[:400]}")
        return out.stdout

    flat_bytes = run()
    compact_bytes = run("--compact")
    flat = json.loads(flat_bytes)
    return Compaction(
        findings=len(flat["findings"]),
        rules=len({str(f["ruleId"]) for f in flat["findings"]}),
        flat_bytes=len(flat_bytes),
        compact_bytes=len(compact_bytes),
    )


def _k(n: int) -> str:
    """To the nearest thousand, with the file's comma grouping: 59,573 -> "60,000"."""
    return f"{round(n, -3):,}"


def _lines(paths: list[Path]) -> int:
    return sum(len(p.read_text(encoding="utf-8").splitlines()) for p in paths)


def _command_nodes() -> int:
    """Every subcommand node in the CLI parser, at any depth.

    Built from the parser rather than from the help text, so a command that is added without a help string is
    still counted, and `posture` and `posture scan` count as two -- a reader can reproduce it with this function
    and nothing else.
    """
    import argparse as ap

    from kube_noob.cli import build_parser

    def walk(parser: ap.ArgumentParser) -> int:
        total = 0
        for action in parser._actions:
            if isinstance(action, ap._SubParsersAction):
                for sub in action.choices.values():
                    total += 1 + walk(sub)
        return total

    return walk(build_parser())


def measured() -> Measured:
    from kube_noob.audit.controls import RULE_CONTROLS
    from kube_noob.audit.engine import list_rules
    from kube_noob.config import load_settings
    from kube_noob.toolkit import Toolkit

    src = sorted((ROOT / "src" / "kube_noob").rglob("*.py"))
    tests = sorted((ROOT / "tests").rglob("*.py"))
    return Measured(
        engine_lines=_lines(src),
        modules=len(src),
        test_lines=_lines(tests),
        rules=len(list_rules()),
        mcp_tools=len(Toolkit(load_settings()).specs()),
        commands=_command_nodes(),
        chart_templates=len(sorted((ROOT / "deploy" / "helm" / "kube-noob" / "templates").glob("*.yaml"))),
        controls=len({c for cs in RULE_CONTROLS.values() for c in cs}),
    )


def _table() -> str:
    head = "| Platform | Rules generated | Not generated |\n| --- | --- | --- |\n"
    return head + "".join(f"| {r.label} | {r.generated} | {r.not_generated} |\n" for r in policy_rows())


def render() -> dict[Path, str]:
    limits = LIMITS.read_text(encoding="utf-8")
    if len(_TABLE.findall(limits)) != 1:
        raise SystemExit("docs/limits.md: expected exactly one platform table; the document's shape changed")
    limits = _TABLE.sub(lambda _: _table(), limits, count=1)

    cases = USE_CASES.read_text(encoding="utf-8")
    if len(_COMPACTION.findall(cases)) != 1:
        raise SystemExit("docs/use-cases.md: expected exactly one compaction measurement; the shape changed")
    m = compaction()
    cases = _COMPACTION.sub(
        f"that is {m.findings} findings over {m.rules} rules, and the JSON goes from {thousands(m.flat_bytes)} to\n"
        f"{thousands(m.compact_bytes)} bytes",
        cases,
        count=1,
    )
    road = ROADMAP.read_text(encoding="utf-8")
    for pattern, what in ((_MEASURED, "measured sentence"), (_CEILING, "control sentence")):
        if len(pattern.findall(road)) != 1:
            raise SystemExit(f"docs/roadmap.md: expected exactly one {what}; the document's shape changed")
    n = measured()
    road = _MEASURED.sub(
        lambda m: (
            f"{m[1]}{_k(n.engine_lines)}{m[2]}{n.modules}{m[3]}{_k(n.test_lines)}{m[4]}"
            f"{n.rules}{m[5]}{n.mcp_tools}{m[6]}{n.commands}{m[7]}{n.chart_templates}{m[8]}"
        ),
        road,
        count=1,
    )
    road = _CEILING.sub(lambda m: f"{m[1]}{n.controls}{m[2]}{n.rules}{m[3]}", road, count=1)
    road = _CEILING_EVIDENCE.sub(lambda m: f"{m[1]}{n.controls}{m[2]}", road)
    return {LIMITS: limits, USE_CASES: cases, ROADMAP: road}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--check", action="store_true", help="exit 1 when a committed document is stale")
    a = ap.parse_args(argv)
    rendered = render()
    stale = [p for p, text in rendered.items() if p.read_text(encoding="utf-8") != text]
    if a.check:
        if stale:
            for p in stale:
                print(f"{p.relative_to(ROOT)} is stale: run python scripts/doc_numbers.py", file=sys.stderr)
            return 1
        print("docs/limits.md, docs/use-cases.md and docs/roadmap.md state the measured numbers")
        return 0
    for p, text in rendered.items():
        p.write_text(text, encoding="utf-8")
    print("wrote " + ", ".join(str(p.relative_to(ROOT)) for p in rendered))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
