from __future__ import annotations

from pathlib import Path

import pytest

from kube_noob.config import Settings, load_settings, set_settings

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture(autouse=True)
def _isolated_env(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    for var in (
        "KUBE_NOOB_CONFIG",
        "KUBE_NOOB_WEB_ENABLED",
        "KUBE_NOOB_CLUSTER_ENABLED",
        "KUBE_NOOB_HTTP_TOKEN",
        "KUBE_NOOB_LLM_PROVIDER",
        "KUBE_NOOB_LLM_MODEL",
        "KUBE_NOOB_DEFAULT_PLATFORM",
    ):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("KUBE_NOOB_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "cfg"))
    monkeypatch.chdir(tmp_path)


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    s = load_settings()
    set_settings(s)
    return s


def fixture_text(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")
