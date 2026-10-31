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
    # The directory blocks any registry or index redirect in the server env; set nothing for uv, pip or npm. An exact
    # allowlist, not a KUBE_NOOB_ prefix check: the prefix would also admit KUBE_NOOB_SERVER_HOST=0.0.0.0, a redirect
    # in KUBE_NOOB_LLM_BASE_URL, or KUBE_NOOB_ANYTHING=${GITHUB_TOKEN}, which would forward a secret off the user's
    # machine -- the very thing the userConfig option exists to avoid.
    assert set(env) == {"KUBE_NOOB_WEB_ENABLED", "KUBE_NOOB_CLUSTER_ENABLED", "KUBE_NOOB_LLM_PROVIDER"}
    assert env["KUBE_NOOB_WEB_ENABLED"] == "false" and env["KUBE_NOOB_CLUSTER_ENABLED"] == "false"
    assert env["KUBE_NOOB_LLM_PROVIDER"] == "none"
    # every value is either a literal or this plugin's own userConfig option: never another variable of the machine's
    for key, value in env.items():
        for ref in re.findall(r"\$\{([^}]*)\}", value):
            assert ref.startswith("user_config."), f"{key} forwards ${{{ref}}} from the user's environment"
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
    known = {
        "name",
        "version",
        "description",
        "author",
        "homepage",
        "repository",
        "license",
        "keywords",
        "icon",
        "userConfig",
    }
    # The directory's listing fields (plugin manifest reference, "Directory listing fields"): https URLs, plugin.json
    # only; Claude Code ignores them at load time.
    listing = {"documentationUrl", "supportUrl", "privacyPolicyUrl", "termsOfServiceUrl"}
    assert set(manifest) <= known | listing, set(manifest) - known - listing
    assert all(manifest[k].startswith("https://") for k in listing & set(manifest))
    assert manifest["privacyPolicyUrl"].endswith("/PRIVACY.md")
    assert (PLUGIN / manifest["icon"]).is_file()
    assert manifest["homepage"].startswith("https://github.com/aashishmahajan/kube-noob")
    assert (ROOT / "PRIVACY.md").is_file()
    assert "No AI inside" in manifest["description"]
    # userConfig: the plugin manifest reference's own option keys, and nothing kube-noob would have to be trusted
    # with. `sensitive` is deliberately absent everywhere (test_distribution holds that too): the plugin asks for a
    # folder, never a credential.
    option_keys = {
        "type",
        "title",
        "description",
        "required",
        "default",
        "options",
        "multiple",
        "sensitive",
        "min",
        "max",
    }
    for name, option in manifest.get("userConfig", {}).items():
        assert re.fullmatch(r"[a-z0-9_]+", name), name
        assert set(option) <= option_keys, set(option) - option_keys
        assert option["type"] in {"string", "number", "boolean", "directory", "file"}
        assert option["title"] and option["description"]


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


def test_bundle_reads_no_host_system_files() -> None:
    """The plugin directory's scan flags reads outside the plugin's own folders (it held 0.5.0 for /proc/sys/crypto)."""
    paths = re.compile(r"[\"'](?:/proc/sys|/proc/self|/sys/(?:kernel|class|devices|fs)|~/\.kube|/var/run/secrets)")
    found = {
        path: m.group(0) for path, text in _bundled_text().items() if path.endswith(".py") and (m := paths.search(text))
    }
    assert found == {}
    from kube_noob.posture import crypto_posture

    assert crypto_posture()["fipsMode"] in {"on", "off", "unknown"}


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


def test_the_plugin_ships_no_rhacs_central_reader() -> None:
    """The RHACS comparison ships; the Central reader (the only code that reads its API token) does not."""
    mods = _sync().plugin_modules(ROOT)
    assert "kube_noob.rhacs" in mods and "kube_noob.rhacs_central" not in mods
    assert not (PLUGIN / "server" / "kube_noob" / "rhacs_central.py").exists()


def test_the_plugin_ships_build_log_diagnosis_but_not_the_image_audit() -> None:
    mods = _sync().plugin_modules(ROOT)
    assert "kube_noob.build.logs" in mods
    assert not {"kube_noob.build.containerfile", "kube_noob.build.image", "kube_noob.build.oci"} & mods


# Offered only when the user turns on cluster access or team memory; the plugin skills may name them for that case.
_CONDITIONAL_TOOLS = {"cluster_check_traffic", "cluster_debug_workload", "memory_propose", "memory_match"}
_PLUGIN_TOOLS = r"""
import json, sys
sys.path.insert(0, sys.argv[1])
from kube_noob import toolkit
from kube_noob.config import load_settings
print(json.dumps(sorted(s.name for s in toolkit.Toolkit(load_settings()).specs())))
"""


def test_plugin_skills_name_only_tools_the_plugin_offers() -> None:
    """The E2E review found the openshift-platform skill sending Claude to two tools the plugin leaves out."""
    import re
    import subprocess
    import sys

    res = subprocess.run(
        [sys.executable, "-I", "-c", _PLUGIN_TOOLS, str(PLUGIN / "server")],
        check=False,
        capture_output=True,
        text=True,
        timeout=300,
    )
    assert res.returncode == 0, res.stderr[-2000:]
    offered = set(json.loads(res.stdout.strip().splitlines()[-1])) | _CONDITIONAL_TOOLS
    for skill in sorted((PLUGIN / "skills").glob("*/SKILL.md")):
        named = set(re.findall(r"kubenoob_([a-z][a-z_]*[a-z])", skill.read_text(encoding="utf-8")))
        assert named <= offered, (skill.parent.name, sorted(named - offered))


def test_the_plugin_bundle_can_neither_connect_nor_start_a_program() -> None:
    """No bundled module imports an HTTP client, sockets or subprocess: the plugin makes no network calls of its own
    and starts no program (the directory review reads the bundle; Helm rendering and web_fetch stay in the CLI)."""
    import ast

    banned = {"subprocess", "socket", "httpx", "httpcore", "requests", "urllib.request", "http.client", "aiohttp"}
    found: list[str] = []
    for path in sorted((PLUGIN / "server").rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            names: list[str] = []
            if isinstance(node, ast.Import):
                names = [a.name for a in node.names]
            elif isinstance(node, ast.ImportFrom) and node.module:
                names = [node.module] + [f"{node.module}.{a.name}" for a in node.names]
            found += [f"{path.relative_to(PLUGIN)}: {n}" for n in names if n in banned or n.split(".")[0] in banned]
    assert found == []
