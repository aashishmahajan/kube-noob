"""Release metadata must agree across PyPI, the MCP Registry, the Claude plugin, the image and the chart."""

from __future__ import annotations

import json
import re
from pathlib import Path

import yaml

from kube_noob import __version__

ROOT = Path(__file__).resolve().parents[1]
SERVER_NAME = "io.github.aashishmahajan/kube-noob"


def test_mcp_registry_metadata() -> None:
    server = json.loads((ROOT / "server.json").read_text())
    assert server["name"] == SERVER_NAME and server["version"] == __version__
    assert server["packages"][0]["identifier"] == "kube-noob" and server["packages"][0]["version"] == __version__
    assert len(server["description"]) <= 100
    readme = (ROOT / "README.md").read_text()
    assert re.search(rf"mcp-name: {re.escape(SERVER_NAME)}(\s|-->)", readme), "PyPI ownership marker missing"
    assert f'io.modelcontextprotocol.server.name="{SERVER_NAME}"' in (ROOT / "Containerfile").read_text()


def test_plugin_pins_the_release() -> None:
    import tomllib

    plugin = json.loads((ROOT / "plugin/kube-noob/.claude-plugin/plugin.json").read_text())
    market = json.loads((ROOT / ".claude-plugin/marketplace.json").read_text())
    assert plugin["version"] == __version__ == market["plugins"][0]["version"]
    assert tomllib.loads((ROOT / "plugin/kube-noob/pyproject.toml").read_text())["project"]["version"] == __version__
    lock = tomllib.loads((ROOT / "plugin/kube-noob/uv.lock").read_text())
    assert next(p for p in lock["package"] if p["name"] == "kube-noob-plugin")["version"] == __version__
    assert (ROOT / "plugin/kube-noob/LICENSE").read_text() == (ROOT / "LICENSE").read_text()
    assert len((ROOT / "plugin/kube-noob/README.md").read_text().split()) >= 40
    pins = re.findall(r"kube-noob==(\d+\.\d+\.\d+)", (ROOT / "README.md").read_text())
    assert pins and set(pins) == {__version__}, "README.md uvx pin for other MCP clients"


def test_chart_and_image_versions() -> None:
    chart = yaml.safe_load((ROOT / "deploy/helm/kube-noob/Chart.yaml").read_text())
    assert chart["appVersion"] == __version__ and chart["annotations"]["charts.openshift.io/name"] == "kube-noob"
    containerfile = (ROOT / "Containerfile").read_text()
    for label in ("name=", "vendor=", "version=", "release=", "summary=", "description=", "maintainer="):
        assert re.search(rf"^(LABEL)?\s+{label}", containerfile, re.MULTILINE), label
    assert "COPY LICENSE NOTICE THIRD_PARTY_NOTICES.md /licenses/" in containerfile


def test_image_build_context_has_every_wheel_input() -> None:
    """The Containerfile builds the wheel itself, so it must copy every path the wheel force-includes."""
    import tomllib

    cfg = tomllib.loads((ROOT / "pyproject.toml").read_text())
    wheel = cfg["tool"]["hatch"]["build"]["targets"]["wheel"]
    containerfile = (ROOT / "Containerfile").read_text()
    ignored = (ROOT / ".dockerignore").read_text().split()
    for src in list(wheel.get("force-include", {})) + [p.split("/")[0] for p in wheel["packages"]]:
        assert re.search(rf"^COPY .*\b{re.escape(src)}\b", containerfile, re.MULTILINE), src
        assert src not in ignored, src


def test_scheduled_cadences_and_rox_corpus_scope() -> None:
    """Weekly risk review, weekly corpus refresh, and a ROX Jira pull of 1000+ issues from 4.10 onward."""
    import yaml

    wf = ROOT / ".github" / "workflows"
    risk = yaml.safe_load((wf / "risk-review.yml").read_text())
    corpus_text = (wf / "corpus-refresh.yml").read_text()
    corpus = yaml.safe_load(corpus_text)
    triggers = risk.get("on") or risk.get(True)
    assert re.fullmatch(r"\d+ \d+ \* \* \d", triggers["schedule"][0]["cron"])
    ctriggers = corpus.get("on") or corpus.get(True)
    assert re.fullmatch(r"\d+ \d+ \* \* \d", ctriggers["schedule"][0]["cron"])
    assert "--project ROX" in corpus_text and "'4.10'" in corpus_text
    assert int(re.search(r"jira_target \|\| '(\d+)'", corpus_text).group(1)) >= 1000


def test_ships_as_mcp_plugin_cli_and_openshift_service() -> None:
    import tomllib

    cfg = tomllib.loads((ROOT / "pyproject.toml").read_text())
    assert cfg["project"]["scripts"]["kube-noob"] == "kube_noob.cli:main"
    assert (ROOT / "plugin/kube-noob/.mcp.json").is_file() and (ROOT / ".claude-plugin/marketplace.json").is_file()
    assert (ROOT / "deploy/helm/kube-noob/Chart.yaml").is_file()
    assert "kube-noob" in (ROOT / "deploy/sidecar/app-with-kube-noob-sidecar.yaml").read_text()
