"""Upgrade-safe learning file: confirmed notes, profile, aggregate counters; never credentials, logs or manifests."""

from __future__ import annotations

import json
import os
import stat
from pathlib import Path

import pytest

from kube_noob import toolkit as tk
from kube_noob.cli import main
from kube_noob.config import load_settings
from kube_noob.evals.export import knowledge_records
from kube_noob.knowledge.store import get_store
from kube_noob.learn.memory import SCHEMA_VERSION, LearningStore

NOTE = {
    "symptom": "Pods on the payments namespace fail with 'unable to validate against any security context constraint'",
    "cause": "The Deployment pinned runAsUser 1000 outside the namespace UID range",
    "fix": "Drop runAsUser and let restricted-v2 assign a UID from openshift.io/sa.scc.uid-range",
}


def test_confirmed_note_persists_and_is_searchable(tmp_path: Path) -> None:
    data = tmp_path / "data"
    note = LearningStore(data).add_note(**NOTE, platform="openshift", tags=["scc"])
    path = data / "learning.json"
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    raw = json.loads(path.read_text())
    assert raw["schemaVersion"] == SCHEMA_VERSION and raw["notes"][0]["id"] == note["id"]
    assert LearningStore(data).summary()["notes"] == 1
    hits = get_store(data).search("security context constraint runAsUser payments", limit=3)
    local = [h for h in hits if h.chunk.origin == "local"]
    assert local and local[0].chunk.chunk_id == f"kn:{note['id']}#0"
    assert local[0].chunk.redistributable is False


@pytest.mark.parametrize(
    "field,value",
    [
        ("fix", "export TOKEN=ghp_abcdefghijklmnopqrstuvwxyz0123456789 then retry"),
        ("cause", "password: hunter2 was wrong"),
        ("fix", "use AKIAABCDEFGHIJKLMNOP"),
        ("symptom", "apiVersion: v1\nkind: Secret\nmetadata:\n  name: db\ndata:\n  pw: aGk="),
        ("symptom", "\n".join(f"2026-10-27T10:00:{i:02d}Z ERROR boom {i}" for i in range(20))),
    ],
)
def test_rejects_credentials_manifests_and_raw_logs(tmp_path: Path, field: str, value: str) -> None:
    store = LearningStore(tmp_path)
    with pytest.raises(ValueError):
        store.add_note(**{**NOTE, field: value})
    assert not (tmp_path / "learning.json").exists()


def test_older_file_loads_after_upgrade_and_keeps_unknown_keys(tmp_path: Path) -> None:
    (tmp_path / "learning.json").write_text(
        json.dumps({"notes": [{"symptom": "s1 symptom text", "cause": "c1", "fix": "f1"}], "keptByNewerTool": {"a": 1}})
    )
    store = LearningStore(tmp_path)
    assert store.summary()["notes"] == 1
    store.set_profile(platform="rosa-hcp", versions={"openshift": "4.22"})
    raw = json.loads((tmp_path / "learning.json").read_text())
    assert raw["schemaVersion"] == SCHEMA_VERSION and raw["keptByNewerTool"] == {"a": 1}
    assert raw["notes"][0]["id"].startswith("local-") and raw["profile"]["platform"] == "rosa-hcp"


def test_newer_or_corrupt_files_are_never_clobbered(tmp_path: Path) -> None:
    f = tmp_path / "learning.json"
    f.write_text(json.dumps({"schemaVersion": SCHEMA_VERSION + 1, "notes": []}))
    with pytest.raises(ValueError, match="newer"):
        LearningStore(tmp_path).add_note(**NOTE)
    f.write_text("{not json")
    store = LearningStore(tmp_path)
    assert store.summary()["notes"] == 0
    store.add_note(**NOTE)
    assert list(tmp_path.glob("learning.json.corrupt-*"))


def test_tools_count_patterns_not_content(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    s = load_settings()
    kit = tk.Toolkit(s)
    kit.diagnose(tk.DiagnoseIn(text="Warning BackOff pod/api-1 Back-off restarting failed container"))
    counters = LearningStore(s.data_dir).summary()["counters"]
    assert counters and all(":" in k and " " not in k for k in counters)
    assert "Back-off" not in (s.data_dir / "learning.json").read_text()
    monkeypatch.setenv("KUBE_NOOB_LEARNING_ENABLED", "false")
    off = load_settings()
    (off.data_dir / "learning.json").unlink()
    tk.Toolkit(off).diagnose(tk.DiagnoseIn(text="Warning BackOff pod/api-1 Back-off restarting failed container"))
    assert not (off.data_dir / "learning.json").exists()


def test_mcp_note_requires_user_confirmation_and_never_exports(tmp_path: Path) -> None:
    s = load_settings()
    kit = tk.Toolkit(s)
    names = {spec.name: spec for spec in kit.specs()}
    assert {"learning_summary", "learning_note_add", "learning_profile_set"} <= set(names)
    assert names["learning_note_add"].read_only is False
    with pytest.raises(ValueError, match="confirm"):
        kit.learning_note_add(tk.LearningNoteIn(**NOTE, confirmed_by_user=False))
    kit.learning_note_add(tk.LearningNoteIn(**NOTE, confirmed_by_user=True))
    recs = list(knowledge_records(get_store(s.data_dir), include_restricted=True))
    assert not any(r["metadata"]["id"].startswith("kn:local-") for r in recs)


def test_cli_learning_round_trip(capsys: pytest.CaptureFixture[str]) -> None:
    rc = main(["learning", "note", "--symptom", NOTE["symptom"], "--cause", NOTE["cause"], "--fix", NOTE["fix"]])
    assert rc == 0
    capsys.readouterr()
    assert main(["learning", "profile", "--platform", "openshift", "--openshift", "4.22"]) == 0
    capsys.readouterr()
    assert main(["learning", "show", "--format", "json"]) == 0
    shown = json.loads(capsys.readouterr().out)
    assert shown["notes"] == 1 and shown["profile"]["platform"] == "openshift"
    note_id = shown["recentNotes"][0]["id"]
    assert main(["learning", "forget", note_id]) == 0
    assert LearningStore(Path(os.environ["KUBE_NOOB_DATA_DIR"])).summary()["notes"] == 0


def test_agent_prompt_carries_profile_and_lock(monkeypatch: pytest.MonkeyPatch) -> None:
    from kube_noob.agent.loop import system_prompt

    s = load_settings()
    LearningStore(s.data_dir).set_profile(platform="rosa-hcp", versions={"openshift": "4.22"})
    prompt = system_prompt(s)
    assert "platform rosa-hcp" in prompt and "openshift 4.22" in prompt
    monkeypatch.setenv("KUBE_NOOB_OFFLINE", "1")
    locked = system_prompt(load_settings())
    assert "locked kube-noob offline" in locked and "suggest enabling webEnabled" not in locked
