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
        if 'statusCategory in ("To Do", "In Progress")' in jql:
            pool = [i for i in pool if i["fields"]["status"]["statusCategory"]["key"] != "done"]
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
    # open tickets first (OCPBUGS-103 is open), then everything by key: the open one is fetched twice
    assert [p["fetched"] for p in out["projects"]] == [5, 1] and all(p["complete"] for p in out["projects"])
    assert fake.jql == [
        'project = OCPBUGS AND statusCategory in ("To Do", "In Progress") ORDER BY key DESC',
        "project = OCPBUGS ORDER BY key DESC",
        'project = ROX AND statusCategory in ("To Do", "In Progress") ORDER BY key DESC',
        "project = ROX ORDER BY key DESC",
    ]
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
    assert out["projects"][0]["fetched"] == 2 and not out["projects"][0]["complete"]  # the open ticket, then one more
    assert load_state(tmp_path)["projects"]["OCPBUGS"]["lowestKey"] == "OCPBUGS-104"
    assert load_state(tmp_path)["projects"]["OCPBUGS"]["openDone"] is True
    fake.jql.clear()
    out = sync_projects(_client(fake, []), ["OCPBUGS", "ROX"], tmp_path, BASE, NOW + timedelta(minutes=5))
    assert "project = OCPBUGS AND key < OCPBUGS-104 ORDER BY key DESC" in fake.jql
    assert not any("statusCategory" in q for q in fake.jql if "OCPBUGS" in q)  # the open pass is done
    assert out["projects"][0]["total"] == 4 and out["projects"][0]["complete"] and out["projects"][1]["fetched"] == 1


def test_an_imported_copy_resumes_without_a_state_file(tmp_path: Path) -> None:
    records = {
        r["id"]: r
        for r in (
            issue_to_record(i, BASE, "OCPBUGS", [], "sync", "2026-10-20T00:00:00+00:00") for i in (ROUTER_DUP, OVN)
        )
    }
    st = state_from_records(records, "OCPBUGS")
    assert st == {"complete": False, "lowestKey": "OCPBUGS-103", "lastSyncAt": "2026-10-20T00:00:00Z"}
    foreign = {**records, "jira-ROX-1": {**records["jira-OCPBUGS-103"], "id": "jira-ROX-1"}}
    assert state_from_records(foreign, "OCPBUGS")["lowestKey"] == "OCPBUGS-103"
    filtered = {k: {**r, "versionBasis": "explicit-version"} for k, r in records.items()}
    assert state_from_records(filtered, "OCPBUGS") == {}  # 0.4's version-filtered pull is not contiguous by key


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
    from kube_noob.sources.jira import sync_lock

    fake = FakeJira({"OCPBUGS": [ROUTER]})
    with sync_lock(tmp_path), pytest.raises(JiraError, match="another Jira sync"):
        sync_projects(_client(fake, []), ["OCPBUGS"], tmp_path, BASE, NOW)
    assert sync_projects(_client(fake, []), ["OCPBUGS"], tmp_path, BASE, NOW)["projects"][0]["fetched"] == 1


# ---------------------------------------------------------------------------------------------------- review fixes


def test_each_project_measures_its_window_from_its_own_start(tmp_path: Path) -> None:
    """A project synced late in a long run must still reach back to its own last sync."""
    from kube_noob.sources.jira import sync_project

    fake = FakeJira({"ROX": [SENSOR]})
    last = datetime.now(UTC) - timedelta(minutes=30)
    state = {"lastSyncAt": last.isoformat(), "complete": True}
    sync_project(_client(fake, []), "ROX", {}, state, BASE)  # no fixed `now`: the clock is read here
    minutes = int(fake.jql[0].split("updated >= -", 1)[1].split("m", 1)[0])
    assert 40 <= minutes <= 42  # 30 minutes since the last sync, rounded up, plus the 10-minute overlap


def test_an_interrupted_forward_pass_does_not_move_the_mark(tmp_path: Path) -> None:
    from kube_noob.sources.jira import sync_project

    fake = FakeJira({"OCPBUGS": [ROUTER, MIRROR, OVN]}, page=1)
    fake.updated = {i["key"]: i for i in (ROUTER, MIRROR, OVN)}
    state = {"lastSyncAt": "2026-10-28T10:00:00Z", "complete": True}
    res = sync_project(_client(fake, [], budget=2), "OCPBUGS", {}, state, BASE, NOW)
    assert res.stopped == "budget" and state["lastSyncAt"] == "2026-10-28T10:00:00Z"


def test_a_replaced_or_old_style_shard_restarts_the_backfill(tmp_path: Path) -> None:
    old = [issue_to_record(i, BASE, "ROX", ["4.10.1"], "explicit-version", "t") for i in (SENSOR,)]
    write_shard(tmp_path, "jira-rox", old)  # what `corpus jira` wrote before the full sync existed
    fake = FakeJira({"ROX": [SENSOR, _issue("ROX-150", "older", "older ticket", status="New")]})
    out = sync_projects(_client(fake, []), ["ROX"], tmp_path, BASE, NOW)
    assert fake.jql[-1] == "project = ROX ORDER BY key DESC" and out["projects"][0]["complete"]
    assert out["projects"][0]["total"] == 2
    _seed(tmp_path, [SENSOR])  # `corpus import` replaces the shard: the stored state no longer describes it
    fake.jql.clear()
    sync_projects(_client(fake, []), ["ROX"], tmp_path, BASE, NOW + timedelta(hours=1))
    assert fake.jql[-1] == "project = ROX AND key < ROX-201 ORDER BY key DESC"


def test_a_foreign_lowest_key_cannot_stall_the_backfill(tmp_path: Path) -> None:
    from kube_noob.sources.jira import sync_project

    fake = FakeJira({"ROX": [SENSOR]})
    state = {"lowestKey": "OCPBUGS-1", "complete": False}
    res = sync_project(_client(fake, []), "ROX", {}, state, BASE, NOW)
    assert res.complete and state["lowestKey"] == "ROX-201" and fake.jql[-1] == "project = ROX ORDER BY key DESC"


def test_backfill_steps_past_a_key_the_server_rejects(tmp_path: Path) -> None:
    from kube_noob.sources.jira import sync_project

    fake = FakeJira({"OCPBUGS": [ROUTER, MIRROR]})
    handler = fake.handler

    def rejecting(req: httpx.Request) -> httpx.Response:
        if "key < OCPBUGS-99" in req.url.params.get("jql", ""):
            return httpx.Response(400, json={"errorMessages": ["An issue with key 'OCPBUGS-99' does not exist"]})
        return handler(req)

    client = JiraClient(httpx.Client(transport=httpx.MockTransport(rejecting)), BASE, sleep=lambda _: None)
    held = {f"jira-{i['key']}": issue_to_record(i, BASE, "OCPBUGS", [], "sync", "t") for i in (OVN, ROUTER_DUP)}
    state = {"lowestKey": "OCPBUGS-99", "complete": False, "lastSyncAt": NOW.isoformat()}
    res = sync_project(client, "OCPBUGS", held, state, BASE, NOW)
    assert res.error is None and res.complete and state["lowestKey"] == "OCPBUGS-101"


def test_retries_wait_at_least_the_crawl_delay() -> None:
    calls = {"n": 0}

    def flaky(req: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        return httpx.Response(503) if calls["n"] == 1 else httpx.Response(200, json={"values": [], "isLast": True})

    sleeps: list[float] = []
    client = JiraClient(
        httpx.Client(transport=httpx.MockTransport(flaky)), BASE, sleep=sleeps.append, rng=random.Random(0)
    )
    client.projects()
    assert sleeps and all(x >= CRAWL_DELAY for x in sleeps)


def test_a_second_sync_sends_nothing(tmp_path: Path) -> None:
    from kube_noob.config import load_settings
    from kube_noob.sources.jira import run_sync, sync_lock

    sent: list[str] = []
    fake = FakeJira({"OCPBUGS": [ROUTER]})

    def counting(req: httpx.Request) -> httpx.Response:
        sent.append(str(req.url))
        return fake.handler(req)

    s = load_settings(overrides={"dataDir": str(tmp_path)})
    with sync_lock(tmp_path), pytest.raises(JiraError):
        run_sync(s, "OCPBUGS", 10, None, NOW, httpx.Client(transport=httpx.MockTransport(counting)))
    assert sent == []


def test_operator_versions_are_not_compared_with_openshift_versions(tmp_path: Path) -> None:
    assert tickets.fix_assessment(["OADP 1.4.2"], "4.16.5") == (None, None, "")
    oadp = _issue(
        "OADP-7",
        "Velero restore hangs on the quibblefish plugin",
        "restore stuck: quibblefish plugin timeout in the wumbleset with gronkle snapshots",
        status="Closed",
        resolution="Done",
        fix=["OADP 1.4.2"],
    )
    _seed(tmp_path, [oadp, *_filler(120)])
    top = tickets.match("quibblefish wumbleset gronkle", "openshift", "4.16.5", 3, tmp_path)["matches"][0]
    assert top["id"] == "OADP-7" and top["fixedIn"] == "OADP 1.4.2" and "You run" not in top["status"]


def test_generic_errors_stay_unmatched_even_when_some_tickets_paste_describe_output(tmp_path: Path) -> None:
    describe = (
        "Warning BackOff kubelet Back-off restarting failed container app in pod web. Last State: Terminated "
        "Reason: OOMKilled Exit Code: 137. Warning Failed: ErrImagePull rpc error: code = NotFound failed to pull "
        "and unpack image. CrashLoopBackOff"
    )
    pasted = [_issue(f"OCPBUGS-{500 + i}", f"Odd thing {i}", f"{describe} zorblax{i}") for i in range(3)]
    quiet = [_issue(f"OCPBUGS-{900 + i}", f"Quiet ticket {i}", f"Nothing to see in area{i}.") for i in range(120)]
    _seed(tmp_path, [*pasted, *quiet])
    for text in (
        "Back-off restarting failed container",
        "Last State: Terminated Reason: OOMKilled Exit Code: 137",
        "Failed to pull image: rpc error: code = NotFound failed to pull and unpack image",
        "CrashLoopBackOff",
    ):
        assert tickets.match(text, "openshift", None, 3, tmp_path)["matches"] == [], text


def test_hostile_records_and_odd_paths_never_break_answers(tmp_path: Path) -> None:
    data = tmp_path / "odd #dir?%"
    good = issue_to_record(ROUTER, BASE, "OCPBUGS", [], "sync", "t")
    bad = [
        {**good, "id": "jira-OCPBUGS-7", "links": 1, "fixVersions": "4.21.3", "text": 5, "title": None},
        {**good, "id": "jira-OCPBUGS-8", "url": "https://evil.example/browse/OCPBUGS-8"},
        {**good, "id": "not-a-key"},
    ]
    entry = write_shard(data, "jira-ocpbugs", [good])
    shard = data / "corpus" / entry["file"]  # what a hand-made or damaged import could hold: write_shard refuses it
    shard.write_text("".join(json.dumps(r) + "\n" for r in [good, *bad]) + "not json\n", encoding="utf-8")
    import hashlib

    manifest = data / "corpus" / "MANIFEST.json"
    doc = json.loads(manifest.read_text())
    doc["shards"]["jira-ocpbugs"]["sha256"] = hashlib.sha256(shard.read_bytes()).hexdigest()
    manifest.write_text(json.dumps(doc))
    t = tickets.ticket("OCPBUGS-8", data)
    assert t["found"] and t["url"] == f"{BASE}/browse/OCPBUGS-8"  # an imported record cannot relabel another site
    assert tickets.ticket("OCPBUGS-7", data)["found"]
    assert tickets.stats(data)["tickets"] == 3  # type: ignore[index]
    out = tickets.match("unable to load default certificate file frobnicator", "openshift", None, 3, data)
    assert out["available"]


def test_scrub_removes_server_mentions_and_profile_links() -> None:
    from kube_noob.sources.jira import scrub

    text = "thanks [~jsmith], see https://redhat.atlassian.net/jira/people/712020:abc-def and [~accountid:5b10]"
    cleaned = scrub(text)
    assert "jsmith" not in cleaned and "712020" not in cleaned and "5b10" not in cleaned
