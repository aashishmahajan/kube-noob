"""Completion scripts are generated from the parser, so they cannot name a command that does not exist.

A hand-written completion goes stale the first time a subcommand is added or removed, and a stale completion
teaches the wrong command. These are walked off `build_parser()` at the moment the user runs the generator.
"""

from __future__ import annotations

import shutil
import subprocess

import pytest

from kube_noob.cli import build_parser
from kube_noob.completion import SHELLS, script, tree


def test_the_tree_is_the_parser() -> None:
    t = tree(build_parser())
    assert "policy" in t["commands"] and "audit" in t["commands"] and "gate" in t["commands"]
    assert set(t["commands"]["policy"]["commands"]) >= {"reach", "explain", "generate"}
    assert "--format" in t["options"]


@pytest.mark.parametrize("shell", SHELLS)
def test_every_top_level_command_appears(shell: str) -> None:
    out = script(shell, build_parser())
    for name in tree(build_parser())["commands"]:
        assert name in out, f"{shell} completion does not offer {name}"


@pytest.mark.parametrize("shell", SHELLS)
def test_the_script_is_not_empty_and_names_itself(shell: str) -> None:
    out = script(shell, build_parser())
    assert out.endswith("\n") and len(out.splitlines()) > 10
    assert "kube-noob" in out


def test_an_unknown_shell_is_refused() -> None:
    with pytest.raises(ValueError, match="Unknown shell"):
        script("powershell", build_parser())


@pytest.mark.parametrize("shell", ["bash", "zsh"])
def test_the_script_parses_in_its_own_shell(shell: str, tmp_path) -> None:  # type: ignore[no-untyped-def]
    exe = shutil.which(shell)
    if exe is None:
        pytest.skip(f"{shell} is not installed")
    f = tmp_path / f"c.{shell}"
    f.write_text(script(shell, build_parser()), encoding="utf-8")
    done = subprocess.run([exe, "-n", str(f)], capture_output=True, text=True, check=False)
    assert done.returncode == 0, done.stderr


def test_bash_completion_offers_the_policy_subcommands(tmp_path) -> None:  # type: ignore[no-untyped-def]
    """Not just present in the file: actually produced by the completion function."""
    bash = shutil.which("bash")
    if bash is None:
        pytest.skip("bash is not installed")
    f = tmp_path / "c.bash"
    f.write_text(script("bash", build_parser()), encoding="utf-8")
    prog = (
        f"source {f}; COMP_WORDS=(kube-noob policy ''); COMP_CWORD=2; "
        '_kube_noob_complete; printf "%s\\n" "${COMPREPLY[@]}"'
    )
    done = subprocess.run([bash, "-c", prog], capture_output=True, text=True, check=False)
    offered = set(done.stdout.split())
    assert {"reach", "explain", "generate"} <= offered, done.stdout or done.stderr
