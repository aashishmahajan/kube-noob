"""scripts/bump_version.py must move every shipped version reference together (PyPI, MCP Registry, plugin, chart,
image, sidecar example) so tests/test_distribution.py keeps passing after a release bump."""

from __future__ import annotations

import importlib.util
import json
import shutil
import sys
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
FILES = [
    "src/kube_noob/__init__.py",
    "server.json",
    ".claude-plugin/marketplace.json",
    "plugin/kube-noob/.claude-plugin/plugin.json",
    "plugin/kube-noob/.mcp.json",
    "plugin/kube-noob/README.md",
    "deploy/helm/kube-noob/Chart.yaml",
    "deploy/sidecar/app-with-kube-noob-sidecar.yaml",
    "Containerfile",
    "CHANGELOG.md",
]


def _load():  # type: ignore[no-untyped-def]
    spec = importlib.util.spec_from_file_location("bump_version", ROOT / "scripts" / "bump_version.py")
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules["bump_version"] = mod
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    for f in FILES:
        (tmp_path / f).parent.mkdir(parents=True, exist_ok=True)
        shutil.copy(ROOT / f, tmp_path / f)
    return tmp_path


def test_bump_updates_every_reference(repo: Path) -> None:
    bv = _load()
    old = bv.current_version(repo)
    changed = bv.bump(repo, "0.1.1", "Security: rebuild on patched UBI base image.")
    assert old == "0.1.0" and set(changed) == set(FILES)
    assert '__version__ = "0.1.1"' in (repo / "src/kube_noob/__init__.py").read_text()
    server = json.loads((repo / "server.json").read_text())
    assert server["version"] == server["packages"][0]["version"] == "0.1.1"
    assert json.loads((repo / "plugin/kube-noob/.mcp.json").read_text())["mcpServers"]["kube-noob"]["args"][1] == (
        "kube-noob==0.1.1"
    )
    chart = yaml.safe_load((repo / "deploy/helm/kube-noob/Chart.yaml").read_text())
    assert chart["version"] == "0.1.1" and chart["appVersion"] == "0.1.1"
    assert "kube-noob:0.1.1" in (repo / "deploy/sidecar/app-with-kube-noob-sidecar.yaml").read_text()
    changelog = (repo / "CHANGELOG.md").read_text()
    assert changelog.index("## 0.1.1") < changelog.index("## 0.1.0") and "patched UBI" in changelog
    for f in FILES:
        assert "0.1.0" not in (repo / f).read_text() or f == "CHANGELOG.md", f


def test_bump_rejects_bad_or_non_increasing_versions(repo: Path) -> None:
    bv = _load()
    with pytest.raises(ValueError):
        bv.bump(repo, "0.1", "x")
    with pytest.raises(ValueError):
        bv.bump(repo, "0.0.9", "x")
    with pytest.raises(ValueError):
        bv.bump(repo, "0.1.1", "")
