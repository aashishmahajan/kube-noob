"""The replay harness (T2): a synthetic 50-ticket seed and a 20-ticket replay set with a known hit rate (14 of 20),
labels that put useful matches at 50% (gate 30%), no hindsight with --as-of-ticket-date, and no ticket matching the
entry it became."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from kube_noob.cli import main
from kube_noob.memory import repo
from kube_noob.memory.importers import import_tickets
from kube_noob.memory.replay import load_labels, markdown, replay

KNOWN = [
    (
        "orders pods OOMKilled",
        "Last State: Terminated Reason: OOMKilled Exit Code: 137 during the batch import.",
        "Raised the memory limit to 1Gi and streamed the import in pages.",
    ),
    (
        "payments ImagePullBackOff",
        "Pods stuck in ImagePullBackOff: unauthorized: authentication required.",
        "Linked the new pull secret to the default ServiceAccount.",
    ),
    (
        "etcd leader elections",
        "etcdHighNumberOfLeaderChanges is firing on all masters after the update.",
        "Updated to 4.21.1, which fixes catalog sync I/O on the control plane.",
    ),
    (
        "api CrashLoopBackOff",
        "The api container is in CrashLoopBackOff; logs show a missing DATABASE_URL.",
        "Restored the DATABASE_URL entry in the ConfigMap the Deployment reads.",
    ),
    (
        "checkout pods Pending",
        "Warning FailedScheduling 0/3 nodes are available: 3 Insufficient memory.",
        "Lowered the memory request to the measured peak and added a node to the pool.",
    ),
    (
        "reporting volume mount fails",
        "Warning FailedMount MountVolume.SetUp failed for volume report-data.",
        "Fixed the NFS export permissions for the reporting volume.",
    ),
    (
        "batch pods Evicted",
        "Pods Evicted: The node was low on resource: ephemeral-storage.",
        "Moved scratch files to an emptyDir with a sizeLimit and cleaned the node image cache.",
    ),
    (
        "router maxconn restarts",
        "HAProxy router pods restarted by the liveness probe when maxconn is reached.",
        "Raised maxConnections in the IngressController tuningOptions.",
    ),
    (
        "internal route certificate",
        "x509 certificate has expired for the internal-api route, clients fail TLS.",
        "Renewed the certificate in cert-manager and set the route to reencrypt.",
    ),
    (
        "analytics DNS timeouts",
        "lookup db.analytics.svc i/o timeout from analytics pods after the NetworkPolicy change.",
        "Allowed egress DNS to openshift-dns on port 5353 in the NetworkPolicy.",
    ),
]
REPLAY_KNOWN = [
    ("search indexer OOMKilled again", "Container restarted, Reason: OOMKilled, exit code 137."),
    ("ImagePullBackOff on the new release", "ImagePullBackOff after moving to the new registry."),
    ("leader changes alert", "etcdHighNumberOfLeaderChanges fired twice this morning."),
    ("worker CrashLoopBackOff", "worker pod CrashLoopBackOff after the config change."),
    ("FailedScheduling for the cache", "Warning FailedScheduling: 0/5 nodes are available, Insufficient memory."),
    ("FailedMount on the archive volume", "Warning FailedMount for volume archive, MountVolume.SetUp failed."),
    ("Evicted pods on worker-7", "Several pods Evicted for ephemeral-storage pressure."),
    ("OOMKilled nightly export", "Reason: OOMKilled for the export job."),
    ("ImagePullBackOff for tools", "tools pods ImagePullBackOff, pull access denied."),
    ("etcdHighNumberOfLeaderChanges in staging", "The etcdHighNumberOfLeaderChanges alert is firing in staging."),
    ("CrashLoopBackOff for billing", "billing CrashLoopBackOff since the deploy."),
    ("FailedScheduling, cluster full", "Warning FailedScheduling Insufficient memory on every node."),
    ("FailedMount in shop", "Warning FailedMount for the shop uploads volume."),
    ("Evicted after the load test", "Pods Evicted during the load test, low on resource."),
]
REPLAY_NOVEL = [
    ("Laptop battery drains quickly", "The finance laptop battery lasts one hour."),
    ("Printer on floor three jams", "Paper jams in the third floor printer every morning."),
    ("Spreadsheet macro error", "The quarterly spreadsheet macro shows a type mismatch."),
    ("Meeting room screen flickers", "The large screen in room 4B flickers during calls."),
    ("Expense form rejects receipts", "Receipts larger than two megabytes are rejected by the expense form."),
    ("Badge reader at the garage", "The garage badge reader beeps red for valid badges."),
]


def _issue(key: str, title: str, desc: str, fix: str | None, created: str, resolved: str | None) -> dict[str, Any]:
    return {
        "key": key,
        "fields": {
            "summary": title,
            "description": desc,
            "created": f"{created}T08:00:00.000+0000",
            "status": {"name": "Done" if fix else "Open", "statusCategory": {"key": "done" if fix else "new"}},
            "resolution": {"name": "Done"} if fix else None,
            "resolutiondate": f"{resolved}T10:00:00.000+0000" if resolved else None,
            "comment": {"comments": [{"body": fix}] if fix else []},
        },
    }


def _seed() -> str:
    issues = []
    for n in range(50):
        title, desc, fix = KNOWN[n % 10]
        day = f"2026-09-{1 + n % 28:02d}"
        issues.append(_issue(f"SEED-{n + 1}", f"{title} (seed {n})", desc, fix, day, day))
    return json.dumps({"issues": issues})


def _replay_set(month: str) -> str:
    issues = []
    for n, (title, desc) in enumerate(REPLAY_KNOWN + REPLAY_NOVEL):
        issues.append(_issue(f"NEW-{n + 1}", title, desc, None, f"2026-{month}-{1 + n:02d}", None))
    return json.dumps({"issues": issues})


@pytest.fixture
def memory(tmp_path: Path) -> Path:
    root = tmp_path / "team"
    repo.init_repo(root)
    out = import_tickets(root, "jira-json", _seed(), "openshift", "platform-team")
    assert len(out["created"]) == 50
    return root


def test_the_known_hit_rate_and_the_gate(memory: Path) -> None:
    labels = {f"NEW-{n}": n <= 10 for n in range(1, 21)}  # 10 useful of 14 hits; misses are never useful
    rep = replay(memory, "jira-json", _replay_set("10"), load_labels(json.dumps(labels)))
    assert rep["tickets"] == 20 and rep["hits"] == 14 and rep["hitRate"] == 0.7
    assert {m["ticket"] for m in rep["misses"]} == {f"NEW-{n}" for n in range(15, 21)}
    assert rep["gate"] == {"threshold": 0.3, "labelled": 20, "useful": 10, "usefulRate": 0.5, "passed": True}
    assert rep["hitsBySignalKind"]["pod_reason"] >= 8 and rep["hitsBySignalKind"]["alert"] == 2
    md = markdown(rep)
    assert "| Hits | 14 of 20 (70%) |" in md and "**PASSED**" in md and "| NEW-15 |" in md


def test_no_hindsight_with_as_of_ticket_date(memory: Path) -> None:
    before = replay(memory, "jira-json", _replay_set("08"), as_of_ticket_date=True)
    assert before["hits"] == 0 and before["gate"]["passed"] is None
    after = replay(memory, "jira-json", _replay_set("10"), as_of_ticket_date=True)
    assert after["hits"] == 14


def test_a_ticket_never_matches_the_entry_it_became(memory: Path) -> None:
    from kube_noob.memory import load_entry

    rep = replay(memory, "jira-json", _seed())
    became = {
        o.ticket: e.id for p in (memory / "entries").glob("MEM-*.yaml") for e in [load_entry(p)] for o in e.outcomes
    }
    assert rep["hits"] == 50
    assert all(row["entry"] != became[row["ticket"]] for row in rep["matched"])


def test_approved_only_ignores_proposed_entries(memory: Path) -> None:
    rep = replay(memory, "jira-json", _replay_set("10"), include_proposed=False)
    assert rep["hits"] == 0


@pytest.mark.parametrize("bad", ["- a list", "NEW-1: maybe", "x: [1]"])
def test_bad_labels_are_refused(bad: str) -> None:
    with pytest.raises(ValueError):
        load_labels(bad)


def test_cli_replay_writes_both_reports(memory: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    tickets = tmp_path / "new.json"
    tickets.write_text(_replay_set("10"), encoding="utf-8")
    labels = tmp_path / "labels.yaml"
    labels.write_text("\n".join(f"NEW-{n}: {'yes' if n <= 3 else 'no'}" for n in range(1, 21)), encoding="utf-8")
    out = tmp_path / "report"
    args = ["memory", "replay", "--memory", str(memory), "--tickets", str(tickets), "--from", "jira-json"]
    assert main([*args, "--labels", str(labels), "--out", str(out)]) == 0
    text = capsys.readouterr().out
    assert "Gate (useful matches >= 30%): **FAILED**." in text
    assert json.loads((out / "report.json").read_text())["gate"]["usefulRate"] == 0.15
    assert (out / "report.md").read_text() == text
    assert main([*args, "--format", "json"]) == 0
    assert json.loads(capsys.readouterr().out)["hits"] == 14
    assert main(["memory", "replay", "--memory", str(memory), "--tickets", "nope.json", "--from", "jira-json"]) == 2
