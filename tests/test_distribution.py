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
    mcp = json.loads((ROOT / "plugin/kube-noob/.mcp.json").read_text())
    args = mcp["mcpServers"]["kube-noob"]["args"]
    assert args[:2] == ["--from", f"kube-noob=={__version__}"]
    plugin = json.loads((ROOT / "plugin/kube-noob/.claude-plugin/plugin.json").read_text())
    market = json.loads((ROOT / ".claude-plugin/marketplace.json").read_text())
    assert plugin["version"] == __version__ == market["plugins"][0]["version"]
    assert (ROOT / "plugin/kube-noob/LICENSE").read_text() == (ROOT / "LICENSE").read_text()
    assert len((ROOT / "plugin/kube-noob/README.md").read_text().split()) >= 40
    for readme in ("README.md", "plugin/kube-noob/README.md"):
        pins = re.findall(r"kube-noob==(\d+\.\d+\.\d+)", (ROOT / readme).read_text())
        assert pins and set(pins) == {__version__}, readme


def test_chart_and_image_versions() -> None:
    chart = yaml.safe_load((ROOT / "deploy/helm/kube-noob/Chart.yaml").read_text())
    assert chart["appVersion"] == __version__ and chart["annotations"]["charts.openshift.io/name"] == "kube-noob"
    containerfile = (ROOT / "Containerfile").read_text()
    for label in ("name=", "vendor=", "version=", "release=", "summary=", "description=", "maintainer="):
        assert re.search(rf"^(LABEL)?\s+{label}", containerfile, re.MULTILINE), label
    assert "COPY LICENSE NOTICE THIRD_PARTY_NOTICES.md /licenses/" in containerfile
