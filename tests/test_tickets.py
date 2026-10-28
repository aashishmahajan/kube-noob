"""The local Red Hat Jira copy: full-project sync (paced, budgeted, resumable) and ticket matching with verdicts."""

from __future__ import annotations

import json
import random
import stat
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import httpx
import pytest

from kube_noob import known_issues, tickets
from kube_noob.sources.corpus import write_shard
from kube_noob.sources.jira import (
    CRAWL_DELAY,
    DEFAULT_PROJECTS,
    JiraClient,
    JiraError,
    issue_to_record,
    load_state,
    select_projects,
    shard_name,
    state_from_records,
    sync_projects,
)

NOW = datetime(2026, 10, 28, 12, 0, tzinfo=UTC)
BASE = "https://redhat.atlassian.net"


def _adf(*paragraphs: str) -> dict[str, Any]:
    return {
        "type": "doc",
        "content": [{"type": "paragraph", "content": [{"type": "text", "text": p}]} for p in paragraphs],
    }


def _issue(
    key: str,
    summary: str,
    description: str,
    *,
    itype: str = "Bug",
    status: str = "New",
    resolution: str | None = None,
    fix: list[str] | None = None,
    comments: list[tuple[str, str]] | None = None,
    links: list[dict[str, Any]] | None = None,
    updated: str = "2026-10-01T10:00:00.000-0400",
) -> dict[str, Any]:
    return {
        "key": key,
        "fields": {
            "summary": summary,
            "description": _adf(description),
            "issuetype": {"name": itype},
            "status": {"name": status, "statusCategory": {"key": "done" if resolution else "new"}},
            "priority": {"name": "Major"},
            "resolution": {"name": resolution} if resolution else None,
            "resolutiondate": "2026-09-15T08:00:00.000+0000" if resolution else None,
            "labels": [],
            "components": [{"name": "Networking / router"}],
            "fixVersions": [{"name": v} for v in fix or []],
            "versions": [],
            "created": "2026-01-10T10:00:00.000+0000",
            "updated": updated,
            "issuelinks": links or [],
            "comment": {
                "comments": [
                    {"created": d, "author": {"displayName": "Real Name"}, "body": _adf(t)} for d, t in comments or []
                ]
            },
        },
    }


ROUTER = _issue(
    "OCPBUGS-101",
    "Router pods crash after rotating the default ingress certificate",
    "After rotating the certificate the haproxy reload fails: unable to load default certificate file "
    "/etc/pki/tls/private/tls.crt. The frobnicator sidecar keeps the quuxd socket open and zebrafish logs show it.",
    status="Closed",
    resolution="Done-Errata",
    fix=["4.21.3", "4.22.0"],
    comments=[
        ("2026-08-02", "Reproduced on 4.21.1."),
        ("2026-08-03", "Workaround: delete the router-certs-default secret so the ingress operator recreates it."),
    ],
)
MIRROR = _issue(
    "OCPBUGS-102",
    "Image pulls from the plinkmirror registry fail with an unknown authority",
    "Pulling through plinkmirror fails: x509: certificate signed by unknown authority on the wobblecache endpoint "
    "behind the grommetproxy.",
    status="Closed",
    resolution="Not a Bug",
    comments=[
        (
            "2026-07-01",
            "This is expected behavior: the mirror CA must be added to additionalTrustedCA, it is a configuration "
            "issue rather than a defect.",
        )
    ],
)
OVN = _issue(
    "OCPBUGS-103",
    "ovnkube-node restarts when the snorkelnet annotation is missing",
    "ovnkube-node fails: failed to get node annotation for snorkelnet subnets on the blimpzone nodes with "
    "kelpforest routing.",
    status="POST",
)
ROUTER_DUP = _issue(
    "OCPBUGS-104",
    "haproxy reload fails after certificate change",
    "Seen again: unable to load default certificate file after rotation, frobnicator and quuxd involved.",
    status="Closed",
    resolution="Duplicate",
    links=[
        {
            "type": {"name": "Duplicate", "inward": "is duplicated by", "outward": "duplicates"},
            "outwardIssue": {"key": "OCPBUGS-101"},
        }
    ],
)
SENSOR = _issue(
    "ROX-201",
    "Sensor cannot reach Central through the gizmoproxy",
    "Sensor logs: rpc error: code = Unavailable desc = connection error via gizmoproxy to the doodadgate "
    "with the whatsit handshake.",
    status="Closed",
    resolution="Done",
    fix=["4.10.1"],
)


def _filler(n: int) -> list[dict[str, Any]]:
    """Ordinary tickets that make the generic words common, as in the real copy."""
    out = []
    for i in range(n):
        out.append(
            _issue(
                f"OCPBUGS-{1000 + i}",
                f"Pod restarts in namespace team{i}",
                "Warning BackOff: Back-off restarting failed container app in pod web; the deployment shows "
                f"CrashLoopBackOff and the error repeats. Router certificate unknown authority note {i}.",
                status="Closed",
                resolution="Done",
                fix=["4.20.0"],
            )
        )
    return out


def _seed(data_dir: Path, issues: list[dict[str, Any]]) -> None:
    by_project: dict[str, list[dict[str, Any]]] = {}
    for issue in issues:
        project = issue["key"].split("-")[0]
        by_project.setdefault(project, []).append(
            issue_to_record(issue, BASE, project, [], "sync", "2026-10-28T12:00:00Z", max_text=12_000)
        )
    for project, records in by_project.items():
        write_shard(data_dir, shard_name(project), records)


@pytest.fixture
def copy(tmp_path: Path) -> Path:
    _seed(tmp_path, [ROUTER, MIRROR, OVN, ROUTER_DUP, SENSOR, *_filler(220)])
    return tmp_path


# ---------------------------------------------------------------------------------------------------------- verdicts


def test_verdicts_cover_every_outcome() -> None:
    v = tickets.verdict
    assert v("Bug", "Closed", "Done-Errata") == "fixed"
    assert v("Story", "Closed", "Done") == "done"
    assert v("Bug", "Closed", "Not a Bug") == "not-a-bug"
    assert v("Bug", "Closed", "Won't Do") == "wont-fix"
    assert v("Bug", "Closed", "Cannot Reproduce") == "cannot-reproduce"
    assert v("Bug", "Closed", "Duplicate") == "duplicate"
    assert v("Bug", "Closed", "Obsolete") == "obsolete"
    assert v("Bug", "ON_QA", None) == "fix-in-progress"
    assert v("Bug", "POST", None) == "fix-proposed"
    assert v("Bug", "ASSIGNED", None) == "open"


def test_fix_assessment_against_the_running_version() -> None:
    fa = tickets.fix_assessment
    assert fa(["4.21.3", "4.22.0"], "4.21.1")[:2] == ("4.21.3", True)
    assert fa(["4.21.3", "4.22.0"], "4.21.5")[:2] == ("4.21.3", False)
    assert fa(["4.22.0"], "4.21.1")[:2] == ("4.22.0", True)
    assert fa(["4.19.4"], "4.21.1")[:2] == ("4.19.4", False)
    name, applies, note = fa(["4.21.z"], "4.21.1")
    assert name == "4.21.z" and applies is None and "exact release" in note


def test_error_phrases_skip_numbers_and_hashes() -> None:
    text = "router-default-7d9f6c8b5-x2k9p: unable to load default certificate file /etc/pki/tls/private/tls.crt"
    assert tickets.error_phrases(text) == ["unable to load default certificate file"]
    long = "Error: failed to sync the quota controller because the informer cache never became ready in time"
    assert tickets.error_phrases(long) == ["failed to sync the quota controller because the informer cache"]
    assert tickets.error_phrases("all good here, nothing to see") == []


# ---------------------------------------------------------------------------------------------------------- matching


def test_a_fixed_bug_with_the_fix_and_workaround(copy: Path) -> None:
    text = "haproxy reload failed: unable to load default certificate file; frobnicator quuxd zebrafish"
    out = tickets.match(text, "openshift", "4.21.1", 3, copy)
    top = out["matches"][0]
    assert top["id"] == "OCPBUGS-101" and top["verdict"] == "fixed" and top["exactError"] is True
    assert "updating to 4.21.3 or later fixes it" in top["status"]
    assert top["workaround"] and "router-certs-default" in top["workaround"]
    assert top["url"] == f"{BASE}/browse/OCPBUGS-101"
    assert {"frobnicator", "quuxd"} <= set(top["sharedTerms"])
    dup = next(m for m in out["matches"] if m["id"] == "OCPBUGS-104")
    assert dup["verdict"] == "duplicate" and dup["duplicateOf"] == "OCPBUGS-101" and "4.21.3" in dup["status"]


def test_a_cluster_that_already_has_the_fix_is_not_told_about_it(copy: Path) -> None:
    text = "haproxy reload failed: unable to load default certificate file; frobnicator quuxd zebrafish"
    out = tickets.match(text, "openshift", "4.21.5", 3, copy)
    assert all(m["id"] not in {"OCPBUGS-101", "OCPBUGS-104"} for m in out["matches"])


def test_not_a_bug_says_so_with_the_reason(copy: Path) -> None:
    text = "pull through plinkmirror: x509: certificate signed by unknown authority wobblecache grommetproxy"
    top = tickets.match(text, "openshift", None, 3, copy)["matches"][0]
    assert top["id"] == "OCPBUGS-102" and top["verdict"] == "not-a-bug"
    assert "Not a Bug" in top["status"] and "configuration" in top["status"]
    assert any(r["kind"] == "expected" and "additionalTrustedCA" in r["text"] for r in top["remarks"])


def test_an_open_bug_with_a_proposed_fix(copy: Path) -> None:
    top = tickets.match("ovnkube-node: snorkelnet blimpzone kelpforest", "openshift", None, 3, copy)["matches"][0]
    assert top["id"] == "OCPBUGS-103" and top["verdict"] == "fix-proposed" and "not merged" in top["status"]


def test_generic_errors_match_nothing(copy: Path) -> None:
    text = "Warning BackOff: Back-off restarting failed container app in pod web; CrashLoopBackOff"
    out = tickets.match(text, "openshift", None, 3, copy)
    assert out["matches"] == [] and "No ticket" in out["note"]


def test_openshift_tickets_stay_out_of_plain_kubernetes(copy: Path) -> None:
    router = "unable to load default certificate file frobnicator quuxd zebrafish"
    assert tickets.match(router, "kubernetes", None, 3, copy)["matches"] == []
    rox = "rpc error: code = Unavailable gizmoproxy doodadgate whatsit"
    top = tickets.match(rox, "kubernetes", None, 3, copy)["matches"][0]
    assert top["id"] == "ROX-201" and top["verdict"] == "fixed"
    assert "You run" not in top["status"]  # RHACS versions are not OpenShift versions


def test_known_issues_merges_tickets_and_reports_the_copy(copy: Path) -> None:
    text = "haproxy reload failed: unable to load default certificate file; frobnicator quuxd zebrafish"
    out = known_issues.match(text, "openshift", "4.21.1", 3, copy)
    assert out["knowledge"]["jiraTickets"]["tickets"] == 225
    assert any(m["id"] == "OCPBUGS-101" and m["kind"] == "ticket" for m in out["matches"])
    assert "note" not in out


def test_index_is_private_and_rebuilt_when_the_copy_changes(copy: Path) -> None:
    db = tickets.ensure_index(copy)
    assert db is not None and stat.S_IMODE(db.stat().st_mode) == 0o600
    assert tickets.stats(copy)["byVerdict"]["fixed"] >= 200  # type: ignore[index]
    first = db.stat().st_mtime_ns
    assert tickets.ensure_index(copy) == db and db.stat().st_mtime_ns == first
    _seed(copy, [_issue("ROX-202", "New ticket", "nothing special here at all", status="New")])
    tickets.ensure_index(copy)
    assert tickets.stats(copy)["tickets"] == 2 + 223  # type: ignore[index]  # ROX shard replaced by one ticket


def test_ticket_lookup(copy: Path) -> None:
    t = tickets.ticket("ocpbugs-101", copy, "4.21.1")
    assert t["found"] and t["verdict"] == "fixed" and t["appliesToVersion"] is True and t["comments"] == 2
    assert "Real Name" not in json.dumps(t)
    missing = tickets.ticket("OCPBUGS-9", copy)
    assert missing["found"] is False and missing["url"].endswith("/browse/OCPBUGS-9")
    with pytest.raises(tickets.TicketIndexError):
        tickets.ticket("OCPBUGS-1 OR 1=1", copy)


def test_no_copy_means_no_ticket_answers(tmp_path: Path) -> None:
    assert tickets.match("anything", "openshift", None, 3, tmp_path) == {"available": False, "matches": []}
    assert "jiraTickets" not in known_issues.match("anything", "openshift", None, 3, tmp_path)["knowledge"]


# ---------------------------------------------------------------------------------------------------------- sync


class FakeJira:
    """Serves /project/search and /search/jql the way Jira Cloud does, and records every JQL it is asked."""

    def __init__(self, issues: dict[str, list[dict[str, Any]]], page: int = 2) -> None:
        self.issues = issues
        self.page = page
        self.jql: list[str] = []
        self.updated: dict[str, dict[str, Any]] = {}

    def handler(self, req: httpx.Request) -> httpx.Response:
        if req.url.path == "/rest/api/3/project/search":
            start = int(req.url.params["startAt"])
            keys = [{"key": k, "name": f"{k} project"} for k in self.issues]
            return httpx.Response(
                200,
                json={"values": keys[start : start + 1], "total": len(keys), "isLast": start + 1 >= len(keys)},
            )
        assert req.url.path == "/rest/api/3/search/jql"
        jql = req.url.params["jql"]
        token = int(req.url.params.get("nextPageToken") or 0)
        if not token:
            self.jql.append(jql)
        project = jql.split("project = ", 1)[1].split()[0]
        pool = sorted(self.issues[project], key=lambda i: -int(i["key"].split("-")[1]))
        if "updated >=" in jql:
            pool = list(self.updated.values())
        if " key < " in jql:
            below = int(jql.split(" key < ", 1)[1].split()[0].split("-")[1])
            pool = [i for i in pool if int(i["key"].split("-")[1]) < below]
        chunk = pool[token : token + self.page]
        body: dict[str, Any] = {"issues": chunk, "isLast": token + self.page >= len(pool)}
        if not body["isLast"]:
            body["nextPageToken"] = str(token + self.page)
        return httpx.Response(200, json=body)


def _client(fake: FakeJira, sleeps: list[float], budget: int | None = None) -> JiraClient:
    return JiraClient(
        httpx.Client(transport=httpx.MockTransport(fake.handler)),
        BASE,
        sleep=sleeps.append,
        rng=random.Random(7),
        max_requests=budget,
        min_delay=0.0,  # raised to the crawl delay regardless
    )


def test_project_selection() -> None:
    available = [{"key": k, "name": k} for k in ("OCPBUGS", "ROX", "RHEL")]
    assert select_projects("default", available) == ["OCPBUGS", "ROX"]
    assert select_projects("all", available) == ["OCPBUGS", "ROX", "RHEL"]
    assert select_projects("rhel, ocpbugs", available) == ["RHEL", "OCPBUGS"]
    assert select_projects("default") == list(DEFAULT_PROJECTS)
    with pytest.raises(JiraError, match="not visible"):
        select_projects("NOPE", available)
    with pytest.raises(JiraError, match="not Jira project keys"):
        select_projects("OCPBUGS) OR project = (X", available)


def test_projects_are_listed_page_by_page() -> None:
    fake = FakeJira({"OCPBUGS": [], "ROX": [], "RHEL": []})
    sleeps: list[float] = []
    assert [p["key"] for p in _client(fake, sleeps).projects(page_size=1)] == ["OCPBUGS", "ROX", "RHEL"]
    assert len(sleeps) == 2 and all(s >= CRAWL_DELAY for s in sleeps)


def test_sync_copies_every_status_then_only_changes(tmp_path: Path) -> None:
    fake = FakeJira({"OCPBUGS": [ROUTER, MIRROR, OVN, ROUTER_DUP], "ROX": [SENSOR]})
    sleeps: list[float] = []
    out = sync_projects(_client(fake, sleeps), ["OCPBUGS", "ROX"], tmp_path, BASE, NOW)
    assert [p["fetched"] for p in out["projects"]] == [4, 1] and all(p["complete"] for p in out["projects"])
    assert fake.jql == ["project = OCPBUGS ORDER BY key DESC", "project = ROX ORDER BY key DESC"]
    assert all(s >= CRAWL_DELAY for s in sleeps) and len(sleeps) == out["requests"] - 1
    state = load_state(tmp_path)
    assert state["projects"]["OCPBUGS"]["lowestKey"] == "OCPBUGS-101"
    assert stat.S_IMODE((tmp_path / "jira" / "state.json").stat().st_mode) == 0o600
    shard = (tmp_path / "corpus" / "jira-ocpbugs.jsonl").read_text()
    assert "Real Name" not in shard and "Not a Bug" in shard and '"redistributable": false' in shard

    fake.jql.clear()
    fake.updated = {"OCPBUGS-103": _issue("OCPBUGS-103", OVN["fields"]["summary"], "now merged", status="MODIFIED")}
    later = NOW + timedelta(hours=2)
    out = sync_projects(_client(fake, sleeps), ["OCPBUGS"], tmp_path, BASE, later)
    assert fake.jql == ["project = OCPBUGS AND updated >= -130m ORDER BY updated ASC"]
    assert out["projects"][0]["fetched"] == 1 and out["projects"][0]["total"] == 4
    assert tickets.ticket("OCPBUGS-103", tmp_path)["verdict"] == "fix-in-progress"


def test_a_budget_stops_cleanly_and_the_next_run_resumes(tmp_path: Path) -> None:
    fake = FakeJira({"OCPBUGS": [ROUTER, MIRROR, OVN, ROUTER_DUP], "ROX": [SENSOR]}, page=1)
    out = sync_projects(_client(fake, [], budget=2), ["OCPBUGS", "ROX"], tmp_path, BASE, NOW)
    assert out["stoppedBy"] == "budget" and out["skipped"] == ["ROX"]
    assert out["projects"][0]["fetched"] == 2 and not out["projects"][0]["complete"]
    assert load_state(tmp_path)["projects"]["OCPBUGS"]["lowestKey"] == "OCPBUGS-103"
    fake.jql.clear()
    out = sync_projects(_client(fake, []), ["OCPBUGS", "ROX"], tmp_path, BASE, NOW + timedelta(minutes=5))
    assert "project = OCPBUGS AND key < OCPBUGS-103 ORDER BY key DESC" in fake.jql
    assert out["projects"][0]["total"] == 4 and out["projects"][0]["complete"] and out["projects"][1]["fetched"] == 1


def test_an_imported_copy_resumes_without_a_state_file(tmp_path: Path) -> None:
    records = {
        r["id"]: r
        for r in (
            issue_to_record(i, BASE, "OCPBUGS", [], "sync", "2026-10-20T00:00:00+00:00") for i in (ROUTER_DUP, OVN)
        )
    }
    st = state_from_records(records)
    assert st == {"complete": False, "lowestKey": "OCPBUGS-103", "lastSyncAt": "2026-10-20T00:00:00Z"}


def test_records_keep_links_and_the_latest_comments() -> None:
    long_comments = [(f"2026-0{1 + i % 9}-01", f"comment {i} " + "words " * 400) for i in range(12)]
    issue = _issue("OCPBUGS-7", "s", "d", comments=[*long_comments, ("2026-10-01", "Workaround: restart sensor.")])
    rec = issue_to_record(issue, BASE, "OCPBUGS", [], "sync", "t", max_text=6000)
    assert len(rec["text"]) <= 6000 and "Workaround: restart sensor." in rec["text"]
    rec = issue_to_record(ROUTER_DUP, BASE, "OCPBUGS", [], "sync", "t")
    assert rec["links"] == [{"type": "Duplicate", "relation": "duplicates", "key": "OCPBUGS-101"}]


# ---------------------------------------------------------------------------------------------------------- wiring


def test_run_sync_end_to_end_writes_insights_and_index(tmp_path: Path) -> None:
    from kube_noob.config import load_settings
    from kube_noob.sources.jira import run_sync

    fake = FakeJira({"OCPBUGS": [ROUTER, MIRROR, OVN, ROUTER_DUP], "ROX": [SENSOR], "RHEL": []})
    s = load_settings(overrides={"dataDir": str(tmp_path)})
    http = httpx.Client(transport=httpx.MockTransport(fake.handler))
    out = run_sync(s, "default", 50, None, NOW, http)
    assert out["selected"] == ["OCPBUGS", "ROX"] and out["visibleProjects"] == 3
    assert out["index"]["tickets"] == 5 and out["index"]["byVerdict"]["duplicate"] == 1
    manifest = json.loads((tmp_path / "corpus" / "MANIFEST.json").read_text())
    assert manifest["shards"]["jira-ocpbugs"]["redistributable"] is False
    assert manifest["shards"]["jira-insights"]["redistributable"] is True
    from kube_noob.knowledge_status import line, status

    assert status(tmp_path)["jiraTickets"]["tickets"] == 5 and "Red Hat Jira copy: 5 tickets" in line(tmp_path)


def test_ticket_shards_stay_out_of_the_general_index(copy: Path) -> None:
    from kube_noob.knowledge.store import get_store

    sources = {c.source_id for c in get_store(copy).chunks}
    assert not any(s.startswith("jira:") for s in sources)


def test_the_sync_client_only_reads_from_the_jira_host(tmp_path: Path) -> None:
    from kube_noob.config import load_settings
    from kube_noob.errors import DomainNotAllowedError
    from kube_noob.sources.jira import jira_http

    s = load_settings(overrides={"dataDir": str(tmp_path)})
    with pytest.raises(DomainNotAllowedError):
        jira_http(s, "https://jira.example.com")
    with jira_http(s, BASE) as http:
        with pytest.raises(DomainNotAllowedError):
            http.get("https://example.com/rest/api/3/project/search")
        with pytest.raises(DomainNotAllowedError):
            http.post(f"{BASE}/rest/api/3/issue", json={})
    locked = load_settings(overrides={"dataDir": str(tmp_path), "offline": True})
    from kube_noob.errors import WebDisabledError

    with pytest.raises(WebDisabledError):
        jira_http(locked, BASE)


def test_cli_ticket_and_known_issues_show_the_verdict(
    copy: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    from kube_noob.cli import main

    monkeypatch.setenv("KUBE_NOOB_DATA_DIR", str(copy))
    assert main(["ticket", "OCPBUGS-102"]) == 0
    out = capsys.readouterr().out
    assert "Not a Bug" in out and "why closed" in out and "additionalTrustedCA" in out
    assert main(["ticket", "OCPBUGS-999999"]) == 1
    text = "haproxy reload failed: unable to load default certificate file; frobnicator quuxd zebrafish"
    assert main(["known-issues", text, "--version", "4.21.1"]) == 0
    out = capsys.readouterr().out
    assert "OCPBUGS-101  Known bug, fixed" in out and "workaround: Workaround: delete" in out
    assert "Red Hat Jira tickets (OCPBUGS, ROX) retrieved" in out
    assert main(["corpus", "jira-projects"]) == 2  # network: needs --online


def test_incident_headline_names_the_ticket() -> None:
    from kube_noob.incidents import _headline

    inc = {
        "signal": "CrashLoopBackOff",
        "workload": "deployment/router-default",
        "namespace": "openshift-ingress",
        "analysis": {"knownIssues": [{"id": "OCPBUGS-101", "verdict": "fixed", "fixedIn": "4.21.3"}]},
    }
    assert "reported as OCPBUGS-101 (fixed, fixed in 4.21.3)" in _headline(inc)


def test_only_one_sync_runs_per_data_folder(tmp_path: Path) -> None:
    from kube_noob.sources.jira import _sync_lock

    fake = FakeJira({"OCPBUGS": [ROUTER]})
    with _sync_lock(tmp_path), pytest.raises(JiraError, match="another Jira sync"):
        sync_projects(_client(fake, []), ["OCPBUGS"], tmp_path, BASE, NOW)
    assert sync_projects(_client(fake, []), ["OCPBUGS"], tmp_path, BASE, NOW)["projects"][0]["fetched"] == 1
