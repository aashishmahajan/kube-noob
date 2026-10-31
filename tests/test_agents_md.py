"""AGENTS.md makes checkable claims, so they are checked.

An instruction file for an agent is read as authoritative and acted on without question, which makes a stale claim
in it worse than no claim: it sends the next agent at the wrong gate, or tells it an exit code means something it
does not. Every test name, script and exit code the file names has to exist.
"""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
AGENTS = (ROOT / "AGENTS.md").read_text(encoding="utf-8")


def test_claude_md_points_at_the_one_agent_file() -> None:
    """Two instruction files drift apart; one of them is a pointer."""
    claude = (ROOT / "CLAUDE.md").read_text(encoding="utf-8")
    assert "AGENTS.md" in claude
    assert len(claude.splitlines()) <= 4, "CLAUDE.md is a pointer, not a second copy of the instructions"


def test_every_test_it_names_exists() -> None:
    cited = set(re.findall(r"`(tests/[a-z0-9_]+\.py)::([a-zA-Z0-9_]+)`", AGENTS))
    assert cited, "AGENTS.md cites no tests; the gate table is the point of the file"
    missing = [f"{f}::{n}" for f, n in sorted(cited) if f"def {n}(" not in (ROOT / f).read_text(encoding="utf-8")]
    assert missing == [], f"AGENTS.md names tests that do not exist: {missing}"


def test_every_script_it_names_exists() -> None:
    scripts = set(re.findall(r"(scripts/[a-z0-9_]+\.(?:py|sh))", AGENTS))
    assert scripts
    assert [s for s in sorted(scripts) if not (ROOT / s).is_file()] == []


def test_the_exit_codes_it_documents_are_the_ones_the_cli_uses() -> None:
    """The table is a public contract. If the CLI gains a code, the table says what it means."""
    documented = {int(m) for m in re.findall(r"^\| (\d+) \| ", AGENTS, re.M)}
    assert documented == {0, 1, 2, 3, 4, 5, 141}, documented
    cli = (ROOT / "src" / "kube_noob" / "cli.py").read_text(encoding="utf-8")
    for code in (2, 3, 4, 5, 141):
        assert f"return {code}" in cli or f"= {code}" in cli, f"exit {code} is documented but the CLI never leaves it"


def test_it_does_not_tell_an_agent_to_edit_the_generated_copy() -> None:
    """The plugin server is generated. An agent that edits it loses the change at the next sync, and the sync
    check fails without saying why."""
    assert "never edit it" in AGENTS
    assert "generated copy" in AGENTS
