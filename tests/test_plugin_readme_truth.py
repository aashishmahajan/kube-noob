"""The plugin README must describe the lock file it ships beside, not a smaller one.

The README told reviewers "There is no HTTP client and no web server among them -- so the installed tree cannot
reach the network even if something asked it to", and listed eight dependencies "and no others". The `uv.lock`
beside it names 32 packages, among them `httpx2`, `httpcore2`, `h11`, `uvicorn` and `sse-starlette`: `mcp` declares
its HTTP transports as dependencies whether or not a plugin uses them. That claim was published on kube-noob.com and
sent to a plugin directory whose reviewer can open the lock file and check.

A prose claim about a machine-readable file drifts the moment the file changes, so the test reads both.
"""

from __future__ import annotations

import re
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PLUGIN = ROOT / "plugin" / "kube-noob"
README = PLUGIN / "README.md"
LOCK = PLUGIN / "uv.lock"

# Packages that can open a socket or serve one. If any of these is in the lock, the README may not claim the tree
# cannot reach the network.
_NETWORK_CAPABLE = {
    "aiohttp",
    "h11",
    "httpcore",
    "httpcore2",
    "httpx",
    "httpx2",
    "requests",
    "sse-starlette",
    "urllib3",
    "uvicorn",
}


def _locked_packages() -> set[str]:
    data = tomllib.loads(LOCK.read_text(encoding="utf-8"))
    return {str(p["name"]) for p in data.get("package", []) if p.get("name") != "kube-noob-plugin"}


def test_the_readme_states_the_real_number_of_locked_packages() -> None:
    names = _locked_packages()
    text = README.read_text(encoding="utf-8")
    counts = {int(m) for m in re.findall(r"`uv\.lock`[^.]{0,40}?names (\d+) packages", text)}
    assert counts, "the README does not state how many packages uv.lock names"
    # The lock lists the plugin itself as a package; the README counts the dependencies it installs.
    assert counts == {len(names)} or counts == {len(names) + 1}, (
        f"the README says {counts} packages and uv.lock names {len(names)} dependencies"
    )


def test_the_readme_does_not_deny_a_dependency_the_lock_file_contains() -> None:
    """The specific false claim, and anything shaped like it."""
    names = _locked_packages()
    text = README.read_text(encoding="utf-8").lower()
    present = sorted(names & _NETWORK_CAPABLE)
    if not present:
        return
    for denial in (
        "no http client",
        "no web server",
        "cannot reach the network",
        "cannot reach the\nnetwork",
    ):
        assert denial not in re.sub(r"\s+", " ", text), (
            f"the README denies what uv.lock ships ({', '.join(present)}): {denial!r}. "
            "Say what the bundled code does instead, which is checkable."
        )


def test_every_package_the_readme_names_is_in_the_lock() -> None:
    """The other direction: a package named in prose that the lock dropped is just as wrong."""
    names = _locked_packages()
    text = README.read_text(encoding="utf-8")
    # Backticked identifiers in the dependency paragraph only.
    para = text.split("`uv.lock` beside this file names", 1)
    assert len(para) == 2, "the dependency paragraph moved; update this test with it"
    claimed = {c.lower() for c in re.findall(r"`([a-zA-Z][a-zA-Z0-9_.-]{1,30})`", para[1][:1200])}
    unknown = sorted(c for c in claimed if c.replace("_", "-") not in names and "." not in c and c != "frozen")
    assert unknown == [], f"the README names packages that uv.lock does not ship: {unknown}"
