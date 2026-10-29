"""Offline ticket importers (T1): resolved ServiceNow and Jira tickets become proposed memory entries; people,
contact details and credentials never reach an entry; tickets without a fix are skipped with the reason."""

from __future__ import annotations

import json
import re
from collections import Counter
from pathlib import Path

import pytest

from kube_noob.cli import main
from kube_noob.learn.memory import contains_credential
from kube_noob.memory import load_entry, repo, verify
from kube_noob.memory.importers import FORMATS, TicketImportError, clean, import_tickets, parse

TICKETS = Path(__file__).parent / "fixtures" / "tickets"
FILES = {
    "servicenow-json": "servicenow.json",
    "servicenow-csv": "servicenow.csv",
    "jira-json": "jira.json",
    "jira-csv": "jira.csv",
}
PEOPLE = re.compile(
    r"Jane|Doe|Raj|Patel|Ana Lima|jdoe|rpatel|alima|example\.(com|org|net)|555|7946|557058|S3cretValue|AKIA",
    re.IGNORECASE,
)


def _export(fmt: str) -> str:
    return (TICKETS / FILES[fmt]).read_text(encoding="utf-8")


@pytest.fixture
def root(tmp_path: Path) -> Path:
    r = tmp_path / "team"
    repo.init_repo(r)
    return r


def test_fixtures_have_at_least_fifty_tickets_per_format() -> None:
    assert set(FILES) == set(FORMATS)
    for fmt in FORMATS:
        assert len(parse(fmt, _export(fmt))) >= 50, fmt


@pytest.mark.parametrize("fmt", FORMATS)
def test_import_writes_proposed_entries_and_lists_every_skip(root: Path, fmt: str) -> None:
    out = import_tickets(root, fmt, _export(fmt), "openshift", "platform-team", cluster="prod-east")
    created, skipped = out["created"], out["skipped"]
    assert len(created) + len(skipped) == 55
    reasons = Counter(s["reason"].split(" (")[0] for s in skipped)
    assert reasons["no resolution"] == 5  # open tickets
    assert "closed without a fix" in reasons
    if fmt.startswith("servicenow"):
        assert reasons["canceled"] == 3 and reasons["no resolution notes"] == 3
    assert Counter(c["outcome"] for c in created)["partial"] == 6
    entries = [load_entry(root / "entries" / f"{c['entry']}.yaml") for c in created]
    assert all(e.status == "proposed" and e.owners == ["platform-team"] for e in entries)
    assert all(e.outcomes[0].cluster == "prod-east" and e.outcomes[0].ticket for e in entries)
    oom = next(e for e in entries if "OOMKilled" in e.symptom)
    assert ("pod_reason", "OOMKilled") in {(s.kind, s.name) for s in oom.signals}
    assert oom.cause.startswith("the import loaded the whole catalogue")
    etcd = next(e for e in entries if "etcd leader" in e.symptom)
    assert ("alert", "etcdHighNumberOfLeaderChanges") in {(s.kind, s.name) for s in etcd.signals}
    rep = verify.validate_repo(root)
    assert rep["ok"], rep["errors"][:3]


@pytest.mark.parametrize("fmt", FORMATS)
def test_no_person_contact_detail_or_credential_survives(root: Path, fmt: str) -> None:
    import_tickets(root, fmt, _export(fmt), "openshift", "platform-team")
    for path in (root / "entries").glob("MEM-*.yaml"):
        text = path.read_text(encoding="utf-8")
        assert not PEOPLE.search(text), (path.name, PEOPLE.search(text))
        assert not contains_credential(text), path.name


def test_rerunning_an_import_skips_what_is_already_there(root: Path) -> None:
    first = import_tickets(root, "jira-json", _export("jira-json"), "openshift", "platform-team")
    again = import_tickets(root, "jira-json", _export("jira-json"), "openshift", "platform-team")
    assert again["created"] == []
    already = [s for s in again["skipped"] if s["reason"].startswith("already imported as MEM-")]
    assert len(already) == len(first["created"])


def test_dry_run_writes_nothing(root: Path) -> None:
    out = import_tickets(root, "servicenow-json", _export("servicenow-json"), "openshift", "x", dry_run=True)
    assert out["created"] and not list((root / "entries").glob("MEM-*.yaml"))
    assert [c["entry"] for c in out["created"]][:2] == ["MEM-1", "MEM-2"]


def test_cleaning_removes_people_and_keeps_the_fix() -> None:
    text = (
        "Caller: Jane Doe\nAssigned to: Raj Patel\nRaised the memory limit. Reported by Jane Doe <jane@example.com>. "
        "Checked with @jdoe, call +1 555 123 4567. Password is hunter2hunter2.\n"
        "2026-10-01T09:12:41Z kubelet started\napiVersion: v1\nkind: Secret"
    )
    out = clean(text)
    assert out == "Raised the memory limit. Reported by someone <<email>>. Checked with someone, call <phone>."


@pytest.mark.parametrize(
    ("fmt", "text", "message"),
    [
        ("servicenow-json", "{not json", "JSON cannot be read"),
        ("servicenow-json", '{"records": []}', "result"),
        ("jira-json", "[" * 100_000 + "]" * 100_000, "JSON cannot be read"),
        ("jira-json", '{"issues": 3}', "issues"),
        ("jira-csv", "", "empty"),
        ("jira-csv", "Key,Title\nX-1,y\n", "Issue key and Summary"),
        ("servicenow-csv", "Number,Other\nINC1,x\n", "short_description"),
        ("servicenow-csv", "x" * 50_000_001, "larger than"),
        ("zip", "x", "unknown format"),
    ],
)
def test_bad_exports_are_refused_with_a_reason(fmt: str, text: str, message: str) -> None:
    with pytest.raises(TicketImportError, match=message):
        parse(fmt, text)


def test_hostile_rows_are_bounded() -> None:
    huge = "Issue key,Summary,Resolution,Comment\n" + "".join(
        f'K-{n},"{"word " * 3000}",Done,"01/Oct/26 9:00 AM;x;{"y" * 60_000}"\n' for n in range(30)
    )
    tickets = parse("jira-csv", huge)
    assert len(tickets) == 30 and all(len(t.resolution) <= 50_000 for t in tickets)
    many = json.dumps({"result": [{"number": f"INC{n}", "short_description": "x"} for n in range(25_000)]})
    assert len(parse("servicenow-json", many)) == 20_000


def test_cli_import(root: Path, capsys: pytest.CaptureFixture[str]) -> None:
    f = TICKETS / "servicenow.csv"
    assert main(["memory", "import", str(root), "--from", "servicenow-csv", "-f", str(f), "--dry-run"]) == 0
    text = capsys.readouterr().out
    assert "would write 40 proposed entries; skipped 15 tickets" in text and "INC0010036 skipped: no resolution" in text
    assert (
        main(["memory", "import", str(root), "--from", "servicenow-csv", "-f", str(f), "--cluster", "prod-east"]) == 0
    )
    assert "wrote 40 proposed entries" in capsys.readouterr().out
    assert main(["memory", "import", str(root), "--from", "jira-csv", "-f", str(root / "nope.csv")]) == 2
