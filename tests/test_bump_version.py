"""scripts/bump_version.py must move every shipped version reference together (PyPI, MCP Registry, plugin, chart,
image, sidecar example) so tests/test_distribution.py keeps passing after a release bump."""

from __future__ import annotations

import importlib.util
import json
import shutil
import sys
import tomllib
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
FILES = [
    "src/kube_noob/__init__.py",
    "server.json",
    ".claude-plugin/marketplace.json",
    "plugin/kube-noob/.claude-plugin/plugin.json",
    "plugin/kube-noob/pyproject.toml",
    "plugin/kube-noob/uv.lock",
    "plugin/kube-noob/server/kube_noob/__init__.py",
    "README.md",
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


def _next_patch(version: str) -> str:
    major, minor, patch = (int(x) for x in version.split("."))
    return f"{major}.{minor}.{patch + 1}"


def test_bump_updates_every_reference(repo: Path) -> None:
    bv = _load()
    old = bv.current_version(repo)
    new = _next_patch(old)
    changed = bv.bump(repo, new, "Security: rebuild on patched UBI base image.")
    assert set(changed) == set(FILES)
    assert f'__version__ = "{new}"' in (repo / "src/kube_noob/__init__.py").read_text()
    server = json.loads((repo / "server.json").read_text())
    assert server["version"] == server["packages"][0]["version"] == new
    lock = tomllib.loads((repo / "plugin/kube-noob/uv.lock").read_text())
    assert next(p for p in lock["package"] if p["name"] == "kube-noob-plugin")["version"] == new
    assert tomllib.loads((repo / "plugin/kube-noob/pyproject.toml").read_text())["project"]["version"] == new
    assert f'__version__ = "{new}"' in (repo / "plugin/kube-noob/server/kube_noob/__init__.py").read_text()
    chart = yaml.safe_load((repo / "deploy/helm/kube-noob/Chart.yaml").read_text())
    assert chart["version"] == new and chart["appVersion"] == new
    assert f"kube-noob:{new}" in (repo / "deploy/sidecar/app-with-kube-noob-sidecar.yaml").read_text()
    changelog = (repo / "CHANGELOG.md").read_text()
    assert changelog.index(f"## {new}") < changelog.index(f"## {old}")
    if "## Unreleased" in (ROOT / "CHANGELOG.md").read_text():
        assert "## Unreleased" not in changelog, "the Unreleased notes become the new version's entry"
    else:
        assert "patched UBI" in changelog
    for f in FILES:
        # CHANGELOG keeps history; uv.lock may hold dependency versions that contain the old string (checked above).
        assert old not in (repo / f).read_text() or f in {"CHANGELOG.md", "plugin/kube-noob/uv.lock"}, f


def test_bump_rejects_bad_or_non_increasing_versions(repo: Path) -> None:
    bv = _load()
    with pytest.raises(ValueError):
        bv.bump(repo, "0.1", "x")
    with pytest.raises(ValueError):
        bv.bump(repo, "0.0.9", "x")
    with pytest.raises(ValueError):
        bv.bump(repo, bv.current_version(repo), "x")
    with pytest.raises(ValueError):
        bv.bump(repo, _next_patch(bv.current_version(repo)), "")
