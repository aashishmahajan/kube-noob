"""The Claude plugin runs the bundled, readable server with hash-locked dependencies and fits the directory's limits."""

from __future__ import annotations

import importlib.util
import json
import re
import sys
import tomllib
from pathlib import Path

from kube_noob import __version__

ROOT = Path(__file__).resolve().parents[1]
PLUGIN = ROOT / "plugin" / "kube-noob"


def _sync():  # type: ignore[no-untyped-def]
    spec = importlib.util.spec_from_file_location("sync_plugin_server", ROOT / "scripts" / "sync_plugin_server.py")
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules["sync_plugin_server"] = mod
    spec.loader.exec_module(mod)
    return mod


def test_bundled_server_matches_the_source() -> None:
    sync = _sync()
    assert sync.check(ROOT) == [], "run: python scripts/sync_plugin_server.py"
    bundled = (PLUGIN / "server" / "kube_noob" / "__init__.py").read_text()
    assert f'__version__ = "{__version__}"' in bundled
    assert (PLUGIN / "server" / "kube_noob" / "data" / "examples" / "insecure-deployment.yaml").is_file()


def test_mcp_config_runs_the_bundled_source_from_the_lock() -> None:
    spec = json.loads((PLUGIN / ".mcp.json").read_text())["mcpServers"]["kube-noob"]
    assert spec["command"] == "uv"
    args = spec["args"]
    assert args[0] == "run" and "--frozen" in args and "--exact" in args
    # --isolated: a throwaway environment in uv's cache, so nothing is written into the plugin root
    assert "--isolated" in args
    assert args[args.index("--project") + 1] == "${CLAUDE_PLUGIN_ROOT}"
    # -I: no current directory, PYTHONPATH or user site on sys.path; -B: no .pyc files written into the plugin root
    assert args[-4:] == ["python", "-I", "-B", "${CLAUDE_PLUGIN_ROOT}/server/kube_noob_plugin.py"]
    assert not any("kube-noob==" in a or a in {"--from", "--with"} for a in args), "never installs from an index"
    env = spec["env"]
    # The directory blocks any registry or index redirect in the server env; set nothing for uv, pip or npm.
    assert set(env) == {"KUBE_NOOB_WEB_ENABLED", "KUBE_NOOB_CLUSTER_ENABLED", "KUBE_NOOB_LLM_PROVIDER"}
    assert env["KUBE_NOOB_WEB_ENABLED"] == "false" and env["KUBE_NOOB_CLUSTER_ENABLED"] == "false"
    assert env["KUBE_NOOB_LLM_PROVIDER"] == "none"
    entry = (PLUGIN / "server" / "kube_noob_plugin.py").read_text()
    assert "from kube_noob.server.stdio import main as serve" in entry and "expected the bundled server" in entry


def test_lock_pins_every_dependency_with_registry_and_hashes() -> None:
    lock = tomllib.loads((PLUGIN / "uv.lock").read_text())
    project = tomllib.loads((PLUGIN / "pyproject.toml").read_text())["project"]
    assert project["version"] == __version__
    packages = {p["name"]: p for p in lock["package"]}
    me = packages.pop("kube-noob-plugin")
    assert me["version"] == __version__ and me["source"] == {"virtual": "."}
    declared = {re.match(r"[A-Za-z0-9._-]+", d).group(0).lower() for d in project["dependencies"]}  # type: ignore[union-attr]
    assert {d["name"].lower() for d in me["dependencies"]} == declared
    assert packages, "the lock is empty"
    for name, pkg in packages.items():
        assert pkg["source"] == {"registry": "https://pypi.org/simple"}, name
        assert re.fullmatch(r"\d+(\.\d+)*([a-z]+\d+)?(\.post\d+)?", pkg["version"]), name
        files = [pkg["sdist"]] if "sdist" in pkg else []
        files += pkg.get("wheels", [])
        assert files and all(f["hash"].startswith("sha256:") for f in files), name


def test_plugin_installs_no_llm_sdk() -> None:
    lock = tomllib.loads((PLUGIN / "uv.lock").read_text())
    names = {p["name"] for p in lock["package"]}
    assert not names & {"anthropic", "openai", "litellm", "google-genai", "cohere"}
    project = tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]
    assert not any(d.startswith("anthropic") for d in project["dependencies"]), "no LLM SDK in the core install"
    assert any(d.startswith("anthropic") for d in project["optional-dependencies"]["ask"])


def test_plugin_fits_the_directory_limits() -> None:
    files = [p for p in PLUGIN.rglob("*") if p.is_file() and "__pycache__" not in p.parts and ".venv" not in p.parts]
    assert len(files) < 512
    too_big = [str(p.relative_to(PLUGIN)) for p in files if p.stat().st_size >= 256 * 1024]
    assert too_big == []
    binary = []
    for p in files:
        try:
            p.read_bytes().decode("utf-8")
        except UnicodeDecodeError:
            binary.append(str(p.relative_to(PLUGIN)))
    assert binary == [".claude-plugin/icon.png"], "everything but the listing icon is readable text"
    assert not (PLUGIN / "bin").exists(), "claude.ai and Cowork do not install a plugin with a top-level bin/"
    assert (PLUGIN / "LICENSE").read_text() == (ROOT / "LICENSE").read_text()


_SHELL_PATTERNS = [
    rb"curl",
    rb"wget",
    rb"\|\s*\w{0,4}sh\b",
    rb"bash",
    rb"\biex\b",
    rb"\$\(",
    rb"powershell",
    rb"base64",
    rb"https?:",
    rb"chmod",
]


def test_icon_is_small_and_carries_no_shell_like_text() -> None:
    icon = PLUGIN / ".claude-plugin" / "icon.png"
    data = icon.read_bytes()
    assert data[:8] == b"\x89PNG\r\n\x1a\n" and len(data) < 64 * 1024
    printable = bytes(c for c in data if 32 <= c < 127)
    for pat in _SHELL_PATTERNS:
        assert not re.search(pat, data, re.IGNORECASE), pat
        assert not re.search(pat, printable, re.IGNORECASE), pat


def test_manifest_uses_only_fields_the_plugin_reference_defines() -> None:
    manifest = json.loads((PLUGIN / ".claude-plugin" / "plugin.json").read_text())
    known = {"name", "version", "description", "author", "homepage", "repository", "license", "keywords", "icon"}
    assert set(manifest) <= known, set(manifest) - known
    assert (PLUGIN / manifest["icon"]).is_file()
    assert manifest["homepage"].startswith("https://github.com/aashishmahajan/kube-noob")
    assert (ROOT / "PRIVACY.md").is_file()
    assert "No AI inside" in manifest["description"]


def _bundled_text() -> dict[str, str]:
    bundle = PLUGIN / "server"
    return {
        str(p.relative_to(PLUGIN)): p.read_text(encoding="utf-8")
        for p in bundle.rglob("*")
        if p.is_file() and "__pycache__" not in p.parts
    }


def test_bundle_reads_no_credentials_from_the_machine() -> None:
    """No env token or API key, kubeconfig, ServiceAccount token or Jira credential is read by bundled code."""
    reads = re.compile(
        r"environ(?:\.get)?\(\s*[\"'][A-Z0-9_]*(?:TOKEN|API_KEY|SECRET|PASSWORD)[\"']"
        r"|environ\.get\(\s*(?:srv|llm|settings)\.\w*(?:token|key)\w*"
        r"|/var/run/secrets/kubernetes\.io/serviceaccount|environ(?:\.get)?\(\s*[\"']KUBECONFIG|JIRA_API_TOKEN"
    )
    found = {path: m.group(0) for path, text in _bundled_text().items() if (m := reads.search(text))}
    assert found == {}


def test_bundle_has_no_download_and_execute_pattern() -> None:
    pattern = re.compile(
        r"(?i)\b(curl|wget|iwr|irm|invoke-webrequest|invoke-restmethod)\b.{0,200}?\|.{0,40}?\b(sudo\s+)?(ba|z|da|k)?sh\b"
        r"|\b(curl|wget)\b.{0,40}\|"
    )
    found = {path: m.group(0)[:80] for path, text in _bundled_text().items() if (m := pattern.search(text))}
    assert found == {}


def test_bundle_names_no_credential_variables() -> None:
    """The directory holds a plugin whose code names credential variables (GITHUB_TOKEN-style) for a reviewer."""
    names = re.compile(r"\b[A-Z][A-Z0-9_]*_(?:TOKEN|API_KEY|SECRET_ACCESS_KEY|ACCESS_KEY_ID)\b")
    allowed = {"PATH_TOKEN"}  # a path-segment constant in the grader, not a credential
    found: dict[str, list[str]] = {}
    for path, text in _bundled_text().items():
        hits = sorted(set(names.findall(text)) - allowed)
        if hits:
            found[path] = hits
    assert found == {}
