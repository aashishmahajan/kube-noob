"""The Jira main copy: change tracking for reconciliation, the snapshot other installs import and keep syncing from,
the seed a new server imports on start, and the CLI and tool that read the changes."""

from __future__ import annotations

import io
import json
import stat
import tarfile
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import httpx
import pytest

from kube_noob import ticket_changes, tickets
from kube_noob.cli import main
from kube_noob.sources.corpus import import_corpus, read_manifest
from kube_noob.sources.jira import MAX_CHANGES, append_changes, change_event, changes_path, load_state, sync_projects
from kube_noob.sources.jira_snapshot import FORMAT, export_snapshot, seed_on_start
from tests.test_tickets import BASE, MIRROR, NOW, OVN, ROUTER, ROUTER_DUP, SENSOR, FakeJira, _client, _issue

LATER = NOW + timedelta(hours=26)


def _synced(tmp_path: Path) -> tuple[FakeJira, Path]:
    fake = FakeJira({"OCPBUGS": [ROUTER, MIRROR, OVN, ROUTER_DUP], "ROX": [SENSOR]})
    data = tmp_path / "main"
    sync_projects(_client(fake, []), ["OCPBUGS", "ROX"], data, BASE, NOW)
    return fake, data


def _changed(fake: FakeJira) -> None:
    """A day later: OVN fixed, the router bug reopened, the mirror bug given a fix version, one new ticket."""
    fake.updated = {
        "OCPBUGS-103": _issue(
            "OCPBUGS-103", OVN["fields"]["summary"], "merged", status="Closed", resolution="Done-Errata", fix=["4.22.1"]
        ),
        "OCPBUGS-101": _issue("OCPBUGS-101", ROUTER["fields"]["summary"], "seen again on 4.22", status="ASSIGNED"),
        "OCPBUGS-102": {
            **MIRROR,
            "fields": {**MIRROR["fields"], "fixVersions": [{"name": "4.21.9"}]},
        },
        "OCPBUGS-110": {
            **_issue("OCPBUGS-110", "Console route flaps after the plinkmirror change", "new", status="New"),
        },
    }
    fake.updated["OCPBUGS-110"]["fields"]["created"] = (NOW + timedelta(hours=20)).isoformat()


# ------------------------------------------------------------------------------------------------ change tracking


def test_a_new_copy_records_no_changes_then_each_sync_records_what_moved(tmp_path: Path) -> None:
    fake, data = _synced(tmp_path)
    assert not changes_path(data).exists()  # a first copy has nothing to compare with
    _changed(fake)
    out = sync_projects(_client(fake, []), ["OCPBUGS"], data, BASE, LATER)
    assert out["changes"] == {"fix-version": 1, "fixed": 1, "opened": 1, "reopened": 1}
    events = {e["key"]: e for e in map(json.loads, changes_path(data).read_text().splitlines())}
    assert events["OCPBUGS-103"]["from"]["verdict"] == "fix-proposed"
    assert events["OCPBUGS-103"]["to"]["fixVersions"] == ["4.22.1"]
    assert events["OCPBUGS-101"]["from"]["statusCategory"] == "done" and events["OCPBUGS-101"]["kind"] == "reopened"
    assert events["OCPBUGS-110"]["kind"] == "opened" and "from" not in events["OCPBUGS-110"]
    assert stat.S_IMODE(changes_path(data).stat().st_mode) == 0o600
    again = sync_projects(_client(fake, []), ["OCPBUGS"], data, BASE, LATER + timedelta(minutes=30))
    assert again["changes"] == {}  # the same tickets served again are not changes
    assert len(changes_path(data).read_text().splitlines()) == 4


def test_change_event_kinds() -> None:
    rec = {"id": "jira-X-1", "sourceId": "jira:X", "issueType": "Bug", "retrievedAt": "t", "created": "2026-01-01"}
    open_ = {**rec, "status": "New", "statusCategory": "new", "resolution": None, "fixVersions": []}
    done = {**rec, "status": "Closed", "statusCategory": "done", "resolution": "Won't Do", "fixVersions": []}
    assert change_event(open_, done, "forward", None)["kind"] == "wont-fix"
    assert change_event(done, open_, "forward", None)["kind"] == "reopened"
    assert change_event(open_, {**open_, "status": "MODIFIED"}, "forward", None)["kind"] == "fix-in-progress"
    assert change_event(open_, {**open_, "status": "ASSIGNED"}, "forward", None)["kind"] == "status"
    assert change_event(open_, {**open_, "priority": "Blocker"}, "forward", None) is None  # untracked field
    since = datetime(2026, 6, 1, tzinfo=UTC)
    assert change_event(None, open_, "forward", since) is None  # created before the last sync: history
    assert change_event(None, {**open_, "created": "2026-07-01T00:00:00+00:00"}, "backfill", since) is None
    assert change_event(None, {**open_, "created": "2026-07-01T00:00:00+00:00"}, "forward", since)["kind"] == "opened"


def test_the_change_log_is_capped(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from kube_noob.sources import jira

    monkeypatch.setattr(jira, "MAX_CHANGES", 5)
    append_changes(tmp_path, [{"key": f"X-{i}", "kind": "fixed", "at": f"t{i}"} for i in range(4)])
    append_changes(tmp_path, [{"key": f"X-{i}", "kind": "fixed", "at": f"t{i}"} for i in range(4, 8)])
    keys = [json.loads(line)["key"] for line in changes_path(tmp_path).read_text().splitlines()]
    assert keys == ["X-3", "X-4", "X-5", "X-6", "X-7"] and MAX_CHANGES == 200_000


def test_a_fresh_copy_fetches_open_tickets_first(tmp_path: Path) -> None:
    fake = FakeJira({"OCPBUGS": [ROUTER, MIRROR, OVN, ROUTER_DUP]}, page=1)
    sync_projects(_client(fake, [], budget=1), ["OCPBUGS"], tmp_path, BASE, NOW)
    assert tickets.ticket("OCPBUGS-103", tmp_path)["verdict"] == "fix-proposed"  # the only open ticket, first
    assert tickets.ticket("OCPBUGS-104", tmp_path)["found"] is False  # the newest closed one waits for the next run


# ------------------------------------------------------------------------------------------------ reconciliation


def test_changes_since_a_date_with_titles_links_and_filters(tmp_path: Path) -> None:
    fake, data = _synced(tmp_path)
    _changed(fake)
    sync_projects(_client(fake, []), ["OCPBUGS"], data, BASE, LATER)
    res = ticket_changes.changes(data, NOW, limit=10)
    assert res["tickets"] == 4 and res["counts"] == {"fix-version": 1, "fixed": 1, "opened": 1, "reopened": 1}
    row = next(r for r in res["changes"] if r["key"] == "OCPBUGS-103")
    assert row["title"].startswith("ovnkube-node restarts") and row["url"] == f"{BASE}/browse/OCPBUGS-103"
    assert row["from"]["verdict"] == "fix-proposed" and row["to"]["verdict"] == "fixed"
    only = ticket_changes.changes(data, NOW, kinds=["fixed", "reopened"])
    assert sorted(r["key"] for r in only["changes"]) == ["OCPBUGS-101", "OCPBUGS-103"]
    assert ticket_changes.changes(data, NOW, project="ROX")["tickets"] == 0
    assert ticket_changes.changes(data, LATER + timedelta(days=1))["tickets"] == 0
    capped = ticket_changes.changes(data, NOW, limit=1)
    assert len(capped["changes"]) == 1 and capped["truncated"] == 3


def test_open_tickets_by_project_and_verdict(tmp_path: Path) -> None:
    fake, data = _synced(tmp_path)
    before = ticket_changes.open_summary(data)
    assert before["available"] and before["open"] == 1 and before["byProject"] == {"OCPBUGS": {"fix-proposed": 1}}
    assert before["topComponents"] == [["Networking / router", 1]] or before["topComponents"] == [
        ("Networking / router", 1)
    ]
    _changed(fake)
    sync_projects(_client(fake, []), ["OCPBUGS"], data, BASE, LATER)
    after = ticket_changes.open_summary(data, "ocpbugs")
    assert after["byProject"] == {"OCPBUGS": {"open": 2}} and after["open"] == 2  # 101 reopened, 110 new
    assert ticket_changes.open_summary(tmp_path / "empty")["available"] is False


@pytest.mark.parametrize(
    ("text", "hours"),
    [("2d", 48), ("36h", 36), ("90m", 1.5), (" 1d ", 24)],
)
def test_parse_since(text: str, hours: float) -> None:
    assert ticket_changes.parse_since(text, NOW) == NOW - timedelta(hours=hours)


def test_parse_since_dates_and_errors() -> None:
    assert ticket_changes.parse_since("2026-10-25") == datetime(2026, 10, 25, tzinfo=UTC)
    for bad in ("yesterday", "2 weeks", "-1d", "99999d", ""):
        with pytest.raises(ValueError, match="--since"):
            ticket_changes.parse_since(bad)


def test_no_changes_yet_says_how_they_appear(tmp_path: Path) -> None:
    _, data = _synced(tmp_path)
    res = ticket_changes.changes(data, NOW - timedelta(days=30))
    assert res["tickets"] == 0 and "second sync" in res["note"]


def test_hostile_change_log_lines_are_skipped(tmp_path: Path) -> None:
    fake, data = _synced(tmp_path)
    _changed(fake)
    sync_projects(_client(fake, []), ["OCPBUGS"], data, BASE, LATER)
    with changes_path(data).open("a", encoding="utf-8") as fh:
        fh.write('not json\n[1, 2]\n{"key": 5, "kind": "fixed"}\n{"key": "X-1", "kind": "fixed", "at": "nope"}\n')
        fh.write('{"key": "X-2", "kind": "fixed", "at": "2026-10-29T00:00:00+00:00", "to": "\\u0000"}\n')
    res = ticket_changes.changes(data, NOW)
    assert res["tickets"] == 5 and {r["key"] for r in res["changes"]} >= {"X-2", "OCPBUGS-103"}


# ------------------------------------------------------------------------------------------------ the main copy


def test_snapshot_round_trip_resumes_with_only_the_forward_pass(tmp_path: Path) -> None:
    fake, data = _synced(tmp_path)
    _changed(fake)
    sync_projects(_client(fake, []), ["OCPBUGS", "ROX"], data, BASE, LATER)
    snap = tmp_path / "out" / "jira-snapshot.tgz"
    info = export_snapshot(data, snap)
    assert info["projects"] == ["OCPBUGS", "ROX"] and info["tickets"] == 6 and info["changes"] == 4
    assert stat.S_IMODE(snap.stat().st_mode) == 0o600
    with tarfile.open(snap) as tf:
        names = sorted(m.name for m in tf.getmembers())
        manifest = json.loads(tf.extractfile("jira-snapshot/MANIFEST.json").read())  # type: ignore[union-attr]
        assert all(m.mode == 0o600 and m.uid == 0 and not m.uname for m in tf.getmembers())
    assert "jira-snapshot/jira-state.json" in names and "jira-snapshot/jira-changes.jsonl" in names
    assert manifest["format"] == FORMAT and set(manifest["shards"]) >= {"jira-ocpbugs", "jira-rox"}
    assert all(not e["redistributable"] for n, e in manifest["shards"].items() if n != "jira-insights")

    other = tmp_path / "other"
    out = import_corpus(snap, other)
    assert out["jira"] == {"stateProjects": ["OCPBUGS", "ROX"], "changes": 4}
    assert load_state(other)["projects"] == load_state(data)["projects"]
    assert tickets.ticket("OCPBUGS-103", other)["verdict"] == "fixed"
    assert ticket_changes.changes(other, NOW)["tickets"] == 4

    fake.jql.clear()
    fake.updated = {}
    sync_projects(_client(fake, []), ["OCPBUGS", "ROX"], other, BASE, LATER + timedelta(hours=24))
    assert fake.jql and all("updated >=" in q for q in fake.jql)  # no open pass, no backfill: it resumed

    assert import_corpus(snap, other)["jira"]["changes"] == 4  # importing twice keeps each change once


def test_a_snapshot_from_another_jira_or_tampered_is_refused_before_anything_is_copied(tmp_path: Path) -> None:
    _, data = _synced(tmp_path)
    snap = export_snapshot(data, tmp_path / "s.tgz")["snapshot"]
    other = tmp_path / "other"
    (other / "jira").mkdir(parents=True)
    (other / "jira" / "state.json").write_text(json.dumps({"baseUrl": "https://issues.example.org", "projects": {}}))
    with pytest.raises(ValueError, match="comes from"):
        import_corpus(Path(snap), other)
    assert not read_manifest(other).get("shards")  # nothing copied

    tampered = tmp_path / "t.tgz"
    with tarfile.open(snap) as src, tarfile.open(tampered, "w:gz") as dst:
        for m in src.getmembers():
            data_bytes = src.extractfile(m).read()  # type: ignore[union-attr]
            if m.name.endswith("jira-state.json"):
                data_bytes = data_bytes.replace(b"OCPBUGS-101", b"OCPBUGS-999")
            m.size = len(data_bytes)
            dst.addfile(m, io.BytesIO(data_bytes))
    fresh = tmp_path / "fresh"
    with pytest.raises(ValueError, match="checksum mismatch"):
        import_corpus(tampered, fresh)
    assert not read_manifest(fresh).get("shards")


@pytest.mark.parametrize(
    "jira_block",
    [
        "nope",
        {"state": "../state.json", "stateSha256": "x"},
        {"state": "missing.json", "stateSha256": "x"},
    ],
)
def test_hostile_snapshot_manifests_are_refused(tmp_path: Path, jira_block: Any) -> None:
    root = tmp_path / "snap"
    root.mkdir()
    (root / "MANIFEST.json").write_text(json.dumps({"format": FORMAT, "shards": {}, "jira": jira_block}))
    with pytest.raises(ValueError):
        import_corpus(root, tmp_path / "data")


def test_there_is_nothing_to_snapshot_without_a_copy(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="no Jira copy"):
        export_snapshot(tmp_path, tmp_path / "s.tgz")


def test_a_new_server_starts_from_the_seed_once(tmp_path: Path) -> None:
    _, data = _synced(tmp_path)
    pod = tmp_path / "pod"
    (pod / "seed").mkdir(parents=True)
    assert seed_on_start(pod) is None  # an empty seed folder: nothing to import
    export_snapshot(data, pod / "seed" / "jira-snapshot.tgz")
    seeded = seed_on_start(pod)
    assert seeded and seeded["seed"].endswith("jira-snapshot.tgz") and "jira-ocpbugs" in seeded["imported"]
    assert tickets.ticket("OCPBUGS-101", pod)["verdict"] == "fixed"
    assert seed_on_start(pod) is None  # the copy exists: the seed is not imported again
    assert seed_on_start(tmp_path / "no-seed") is None


# ------------------------------------------------------------------------------------------------ CLI and tool


def test_cli_snapshot_and_changes(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    fake, data = _synced(tmp_path)
    monkeypatch.setenv("KUBE_NOOB_DATA_DIR", str(data))
    _changed(fake)
    sync_projects(_client(fake, []), ["OCPBUGS"], data, BASE, LATER)
    since = NOW.date().isoformat()
    assert main(["corpus", "jira-changes", "--since", since]) == 0
    text = capsys.readouterr().out
    assert "1 fixed" in text and "OCPBUGS-103" in text and "fix-proposed -> fixed (fix 4.22.1)" in text
    assert "open tickets: 2 (OCPBUGS 2 open)" in text and "reopened" in text
    assert main(["corpus", "jira-changes", "--since", since, "--kind", "opened", "--format", "json"]) == 0
    out = json.loads(capsys.readouterr().out)
    assert [r["key"] for r in out["changes"]] == ["OCPBUGS-110"] and out["openTickets"]["open"] == 2
    snap = tmp_path / "snap.tgz"
    assert main(["corpus", "jira-snapshot", "-o", str(snap)]) == 0
    assert "keep this file within your organisation" in capsys.readouterr().out and snap.is_file()
    assert main(["corpus", "jira-changes", "--since", "last week"]) == 2


def test_cli_changes_work_under_the_offline_lock(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    _, data = _synced(tmp_path)
    monkeypatch.setenv("KUBE_NOOB_DATA_DIR", str(data))
    monkeypatch.setenv("KUBE_NOOB_OFFLINE", "1")
    assert main(["corpus", "jira-changes"]) == 0
    assert "open tickets: 1" in capsys.readouterr().out


def test_ticket_changes_tool(tmp_path: Path) -> None:
    from pydantic import ValidationError

    from kube_noob.config import load_settings
    from kube_noob.toolkit import TicketChangesIn, Toolkit

    fake, data = _synced(tmp_path)
    _changed(fake)
    sync_projects(_client(fake, []), ["OCPBUGS"], data, BASE, LATER)
    kit = Toolkit(load_settings(overrides={"dataDir": str(data)}))
    assert "ticket_changes" in {t.name for t in kit.specs()}
    res = kit.ticket_changes(TicketChangesIn(since=NOW.date().isoformat(), kinds=["fixed"]))
    assert [r["key"] for r in res["changes"]] == ["OCPBUGS-103"] and res["openTickets"]["open"] == 2
    for bad in ({"since": "1; DROP"}, {"project": "OCP) OR 1=1"}, {"limit": 501}, {"kinds": ["everything"]}):
        with pytest.raises(ValidationError):
            TicketChangesIn.model_validate(bad)


def test_a_server_with_no_network_uses_its_seed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """serve imports the seed before the background sync starts; the sync itself is not needed for answers."""
    from kube_noob import cli

    _, data = _synced(tmp_path)
    pod = tmp_path / "pod"
    export_snapshot(data, pod / "seed" / "jira-snapshot.tgz")
    ran: list[str] = []
    monkeypatch.setenv("KUBE_NOOB_DATA_DIR", str(pod))
    monkeypatch.setattr("uvicorn.run", lambda *a, **k: ran.append("uvicorn"))
    cli.main(["serve", "--allow-unauthenticated"])
    assert ran == ["uvicorn"] and tickets.ticket("OCPBUGS-103", pod) is not None


def test_http_is_never_used_by_reconciliation(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _, data = _synced(tmp_path)

    def boom(*a: Any, **k: Any) -> None:
        raise AssertionError("network used")

    monkeypatch.setattr(httpx.Client, "send", boom)
    ticket_changes.changes(data, NOW)
    ticket_changes.open_summary(data)
    export_snapshot(data, tmp_path / "s.tgz")


def test_the_plugin_gets_reconciliation_without_the_jira_client() -> None:
    """The bundled stdio server can answer ticket_changes, but the sync client and snapshot code stay out of it."""
    import importlib.util

    root = Path(__file__).resolve().parents[1]
    spec = importlib.util.spec_from_file_location("sync_plugin_server", root / "scripts" / "sync_plugin_server.py")
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    shipped = mod.plugin_modules(root)
    assert "kube_noob.ticket_changes" in shipped and "kube_noob.tickets" in shipped
    assert not any(m.startswith("kube_noob.sources") for m in shipped), sorted(shipped)
