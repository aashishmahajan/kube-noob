"""kube-noob.com is generated from the checkout: it builds, links resolve, it loads nothing from other hosts, and the
in-browser tools are exactly the read-only, offline subset of the MCP surface."""

from __future__ import annotations

import importlib.util
import json
import re
import sys
from pathlib import Path
from types import ModuleType

import pytest

ROOT = Path(__file__).resolve().parents[1]


def _module(name: str, path: Path) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture(scope="module")
def site(tmp_path_factory: pytest.TempPathFactory) -> Path:
    pytest.importorskip("markdown", reason="the site build needs the dev extra")
    builder = _module("build_site", ROOT / "scripts" / "build_site.py")
    out = tmp_path_factory.mktemp("site")
    assert builder.main(["--out", str(out)]) == 0  # main() also fails on any broken internal link
    return out


def test_site_builds_every_page(site: Path) -> None:
    for page in (
        "index.html",
        "journey/index.html",
        "playground/index.html",
        "ask/index.html",
        "insights/index.html",
        "videos/index.html",
        "docs/overview/index.html",
        "docs/privacy/index.html",
        "reference/mcp/index.html",
        "reference/cli/index.html",
        "reference/rules/index.html",
        "reference/helm-values/index.html",
        "404.html",
    ):
        assert (site / page).is_file(), page
    assert (site / "CNAME").read_text().strip() == "kube-noob.com"
    index = json.loads((site / "search-index.json").read_text())
    assert len(index) > 30 and all({"u", "t", "h", "b"} <= set(d) for d in index)


def test_site_loads_nothing_from_other_hosts(site: Path) -> None:
    for page in site.rglob("*.html"):
        text = page.read_text()
        assert "Content-Security-Policy" in text, page
        csp = re.search(r'http-equiv="Content-Security-Policy" content="([^"]+)"', text)
        assert csp and "script-src 'self' 'wasm-unsafe-eval';" in csp.group(1), page
        assert "unsafe-eval'" not in csp.group(1).replace("wasm-unsafe-eval'", ""), page
        assert not re.search(
            r'<(script|img|video|link|iframe)[^>]+(src|href)="(https?:)?//',
            text.replace('rel="canonical" href="https://kube-noob.com', ""),
        ), page


def test_reference_pages_match_the_code(site: Path) -> None:
    from kube_noob.audit.engine import list_rules
    from kube_noob.config import load_settings
    from kube_noob.server.mcp_app import TOOL_PREFIX
    from kube_noob.toolkit import Toolkit

    mcp = (site / "reference" / "mcp" / "index.html").read_text()
    for spec in Toolkit(load_settings(overrides={"offline": True})).specs():
        assert f'id="{TOOL_PREFIX}{spec.name}"' in mcp, spec.name
    rules = (site / "reference" / "rules" / "index.html").read_text()
    for rule in list_rules():
        assert f'id="{rule["ruleId"]}"' in rules
    journey = (site / "journey" / "index.html").read_text()
    assert journey.count('class="chapter"') >= 7 and "kube-noob demo audit" in journey


def test_browser_tools_are_the_read_only_offline_subset() -> None:
    sys.path.insert(0, str(ROOT / "site" / "static"))
    try:
        bridge = _module("kn_bridge_test", ROOT / "site" / "static" / "bridge.py")
    finally:
        sys.path.pop(0)
    info = json.loads(bridge.info())
    assert set(info["tools"]) == set(bridge.BROWSER_TOOLS)  # every listed tool exists, read-only and offline
    tools = json.loads(bridge.tools())
    assert all(t["name"].startswith("kube_noob_") and t["input_schema"]["type"] == "object" for t in tools)
    assert bridge._settings.offline and not bridge._settings.web_enabled and not bridge._settings.cluster.enabled
    res = json.loads(bridge.call("kube_noob_known_issues", json.dumps({"text": "x" * 10})))
    assert res["ok"] and "knowledgeAsOf" in res["result"]
    assert json.loads(bridge.call("kube_noob_web_fetch", "{}"))["ok"] is False
    assert json.loads(bridge.call("kube_noob_diagnose", "{not json"))["ok"] is False


def test_browser_code_pins_its_dependencies_and_never_uses_a_cdn() -> None:
    pkg = json.loads((ROOT / "site" / "package.json").read_text())
    assert all(re.fullmatch(r"\d+\.\d+\.\d+", v) for v in pkg["devDependencies"].values()), "pin exact versions"
    assert (ROOT / "site" / "package-lock.json").is_file()
    worker = (ROOT / "site" / "static" / "kn-worker.js").read_text()
    assert 'from "../pyodide/pyodide.mjs"' in worker and "://" not in worker
    agent = (ROOT / "site" / "src" / "agent.js").read_text()
    assert "localStorage." not in agent  # the key is in memory, or sessionStorage only with consent
    assert "dangerouslyAllowBrowser: true" in agent and 'fallbacks: "default"' in agent
    assert '<option value="claude-opus-5-5" selected>' in (ROOT / "scripts" / "build_site.py").read_text()


def test_helm_values_table_documents_every_top_level_key() -> None:
    import yaml

    builder = _module("build_site_values", ROOT / "scripts" / "build_site.py")
    keys = {k for k, _, _ in builder.helm_values()}
    values = yaml.safe_load((ROOT / "deploy" / "helm" / "kube-noob" / "values.yaml").read_text())
    assert set(values) <= {k.split(".")[0] for k in keys}
    assert "config.offline" in keys and "auth.existingSecret" in keys
