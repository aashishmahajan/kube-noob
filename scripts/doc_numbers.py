#!/usr/bin/env python3
"""Generate the measured numbers the documents quote, from the code that produces them.

Four of these were wrong at once on 2026-11-05, all of them the same defect `docs/compliance.md` had before
`scripts/compliance_doc.py` (G206): a number somebody typed, beside code that moved. `docs/limits.md` published
"47 generated / 31 not generated" for Kubernetes and "54 / 24" for OpenShift -- both pairs summing to 78, the rule
count this project retired, because the generated column was updated and the other was not. `docs/use-cases.md`
sold the compact report as "105 findings over 19 rules ... 118 631 to 54 694 bytes" when it was 115 over 21 and
141 349 to 69 936.

Two regions are rewritten and nothing else:

- the platform table in `docs/limits.md`, from `kube_noob.generate.policies.generate` for each platform the table
  lists, with its own `policy generate` header as the authority a reader can reproduce;
- the compaction sentence in `docs/use-cases.md`, from an actual audit of `examples/` and an actual compaction of
  that report.

Both measurements are deterministic: fixed inputs, same bytes every run, which is what makes `--check` meaningful
rather than flaky.

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


@dataclass(frozen=True)
class Row:
    label: str
    platform: str
    version: str | None
    generated: int
    not_generated: int


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
    return {LIMITS: limits, USE_CASES: cases}


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
        print("docs/limits.md and docs/use-cases.md state the measured numbers")
        return 0
    for p, text in rendered.items():
        p.write_text(text, encoding="utf-8")
    print("wrote " + ", ".join(str(p.relative_to(ROOT)) for p in rendered))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
