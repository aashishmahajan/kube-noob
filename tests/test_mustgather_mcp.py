"""G5: the analyze_must_gather MCP tool. Offered by the local stdio server; by a shared (HTTP) server only with
mustGather.allowedDir, and then only for paths that resolve inside it; never in the Claude plugin."""

from __future__ import annotations

from pathlib import Path

import pytest

from kube_noob import toolkit as tk
from kube_noob.config import ConfigError, load_settings
from kube_noob.mustgather import sample


def _kit(tmp_path: Path, *, shared: bool, allowed: Path | None = None) -> tk.Toolkit:
    overrides: dict[str, object] = {"dataDir": str(tmp_path / "data")}
    if allowed is not None:
        overrides["mustGather"] = {"allowedDir": str(allowed)}
    return tk.Toolkit(load_settings(overrides=overrides), shared=shared)


def _names(kit: tk.Toolkit) -> set[str]:
    return {s.name for s in kit.specs()}


def test_offered_locally_and_on_a_shared_server_only_with_an_allowed_dir(tmp_path: Path) -> None:
    assert "analyze_must_gather" in _names(_kit(tmp_path, shared=False))
    assert "analyze_must_gather" not in _names(_kit(tmp_path, shared=True))
    assert "analyze_must_gather" in _names(_kit(tmp_path, shared=True, allowed=tmp_path))
    with pytest.raises(ValueError, match="this server reads no must-gather"):
        _kit(tmp_path, shared=True)._must_gather_path(str(tmp_path / "x.tgz"))


def test_local_reads_any_absolute_path(tmp_path: Path) -> None:
    tgz = sample.write(tmp_path / "case")
    out = _kit(tmp_path, shared=False).analyze_must_gather(tk.MustGatherIn(path=str(tgz), top=3, case_draft=True))
    assert out["cluster"]["version"] == "4.20.3" and len(out["findings"]) == 3 and out["findingsTotal"] == 24
    assert out["caseDraft"].startswith("# Support case draft") and "source" in out and out["source"] == tgz.name
    assert str(tmp_path) not in str(out["source"])
    with pytest.raises(ValueError, match="absolute path"):
        _kit(tmp_path, shared=False).analyze_must_gather(tk.MustGatherIn(path="case/must-gather.tar.gz"))


def test_confined_to_the_allowed_dir(tmp_path: Path) -> None:
    allowed = tmp_path / "gathers"
    inside = sample.write(allowed / "case-1")
    outside = sample.write(tmp_path / "elsewhere")
    (allowed / "escape.tgz").symlink_to(outside)
    (allowed / "dir-link").symlink_to(tmp_path / "elsewhere")
    kit = _kit(tmp_path, shared=True, allowed=allowed)
    assert kit.analyze_must_gather(tk.MustGatherIn(path=str(inside)))["counts"]["critical"] == 2
    for bad in (
        outside,
        allowed / "escape.tgz",
        allowed / "dir-link" / "must-gather.tar.gz",
        allowed / ".." / "elsewhere" / "must-gather.tar.gz",
        Path("/etc/passwd"),
    ):
        with pytest.raises(ValueError, match=r"outside mustGather\.allowedDir"):
            kit.analyze_must_gather(tk.MustGatherIn(path=str(bad)))
    with pytest.raises(ValueError, match="no such file"):
        kit.analyze_must_gather(tk.MustGatherIn(path=str(allowed / "missing.tgz")))
    with pytest.raises(ValueError):
        tk.MustGatherIn(path="/a\x00b")


def test_settings_and_environment(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(ConfigError):
        load_settings(overrides={"mustGather": {"allowedDir": "relative/dir"}})
    monkeypatch.setenv("KUBE_NOOB_MUST_GATHER_DIR", str(tmp_path))
    assert load_settings(overrides={}).must_gather.allowed_dir == tmp_path


def test_mcp_server_and_plugin(tmp_path: Path) -> None:
    import importlib.util
    import sys

    from kube_noob.server.mcp_app import TOOL_PREFIX, build_server

    def tools(shared: bool, allowed: Path | None) -> set[str]:
        overrides: dict[str, object] = {"dataDir": str(tmp_path / "d")}
        if allowed:
            overrides["mustGather"] = {"allowedDir": str(allowed)}
        server = build_server(load_settings(overrides=overrides), shared=shared)
        return {t.name for t in server._tool_manager.list_tools()}

    name = TOOL_PREFIX + "analyze_must_gather"
    assert name in tools(False, None) and name not in tools(True, None) and name in tools(True, tmp_path)
    root = Path(__file__).resolve().parents[1]
    spec = importlib.util.spec_from_file_location("sync_plugin", root / "scripts" / "sync_plugin_server.py")
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules["sync_plugin"] = mod
    spec.loader.exec_module(mod)
    assert not any(m.startswith("kube_noob.mustgather") for m in mod.plugin_modules())
