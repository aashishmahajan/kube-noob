"""J1: the Jira copy keeps each ticket's full text with every comment, and keeps no people.

Comment authors become per-ticket pseudonyms (Commenter A, B, ... in order of first comment); their display names and
the first name where it addresses them ("Hi Jane", "cc Jane", "@Jane") become the same label; mentions of a commenter
become their label and any other mention ``@user``; emails, account ids, profile links and phone numbers are removed.
A search returns a ticket's latest comments only, so the rest come from the issue's paged comment endpoint inside the
request budget; a ticket is kept only once all its comments are in. A copy made before refetches its tickets once.
"""

from __future__ import annotations

import json
import random
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx

from kube_noob import tickets
from kube_noob.sources.jira import (
    SYNC_MAX_TEXT,
    TEXT_VERSION,
    issue_to_record,
    load_state,
    save_state,
    sync_projects,
)
from tests.test_tickets import BASE, NOW, FakeJira, _adf, _client, _issue

PEOPLE = [
    ("acc-1111111111", "Jane Smith", "jane.smith@example.com"),
    ("acc-2222222222", "Ravi Kumar", "ravi@example.org"),
    ("acc-3333333333", "Li Wei", "li.wei@example.net"),
]


def _comment(i: int, who: int, text: str) -> dict[str, Any]:
    acc, name, email = PEOPLE[who]
    return {
        "id": str(1000 + i),
        "created": f"2026-01-{1 + i // 24:02d}T{i % 24:02d}:00:00.000+0000",
        "author": {"accountId": acc, "displayName": name, "emailAddress": email},
        "body": _adf(text),
    }


def _long_ticket(n: int = 60) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    comments = [_comment(i, i % 3, f"note {i}: still seeing the router reload failure on worker-{i}") for i in range(n)]
    comments[1]["body"] = {
        "type": "doc",
        "content": [
            {
                "type": "paragraph",
                "content": [
                    {"type": "text", "text": "Hi Jane, thanks. "},
                    {"type": "mention", "attrs": {"id": "acc-3333333333", "text": "@Li Wei"}},
                    {"type": "text", "text": " and "},
                    {"type": "mention", "attrs": {"id": "acc-9999999999", "text": "@Someone Else"}},
                    {
                        "type": "text",
                        "text": " please look. Jane Smith said call +1 415 555 0134 or jane.smith@example.com",
                    },
                ],
            }
        ],
    }
    comments[-1]["body"] = _adf("Workaround: delete the router-certs-default secret. cc Ravi")
    issue = _issue("OCPBUGS-500", "Router reload fails", "The reload fails after rotation.", status="ASSIGNED")
    issue["fields"]["comment"] = {"comments": comments[-20:], "total": n, "maxResults": 20, "startAt": n - 20}
    return issue, comments


class CommentJira(FakeJira):
    """FakeJira plus the issue comment endpoint, paged by startAt."""

    def __init__(self, issues: dict[str, list[dict[str, Any]]], comments: dict[str, list[dict[str, Any]]]) -> None:
        super().__init__(issues)
        self.comments = comments
        self.comment_calls: list[tuple[str, int]] = []

    def handler(self, req: httpx.Request) -> httpx.Response:
        path = req.url.path
        if path.startswith("/rest/api/3/issue/") and path.endswith("/comment"):
            key = path.split("/")[5]
            start, size = int(req.url.params["startAt"]), int(req.url.params["maxResults"])
            assert req.url.params["orderBy"] == "created" and req.method == "GET"
            self.comment_calls.append((key, start))
            all_ = self.comments[key]
            return httpx.Response(
                200, json={"comments": all_[start : start + size], "total": len(all_), "startAt": start}
            )
        return super().handler(req)


def test_every_comment_is_kept_and_no_person_is(tmp_path: Path) -> None:
    issue, comments = _long_ticket()
    fake = CommentJira({"OCPBUGS": [issue]}, {"OCPBUGS-500": comments})
    sync_projects(_client(fake, []), ["OCPBUGS"], tmp_path, BASE, NOW)
    assert fake.comment_calls == [("OCPBUGS-500", 0)]  # 60 comments: one page of 100
    shard = (tmp_path / "corpus" / "jira-ocpbugs.jsonl").read_text()
    rec = json.loads(shard.splitlines()[0])
    assert rec["comments"] == 60 and rec["commentsTotal"] == 60 and "textCut" not in rec
    text = rec["text"]
    assert all(f"note {i}:" in text for i in range(2, 59)) and "note 0:" in text  # 1 and 59 carry other text
    assert "Comment (2026-01-01) by Commenter A: note 0" in text
    assert (
        "Hi Commenter A, thanks. @Commenter C and @user please look. Commenter A said call <phone> or <email>" in text
    )
    assert text.rstrip().endswith("cc Commenter B")
    for acc, name, email in PEOPLE:
        assert acc not in shard and name not in shard and email not in shard
    for first in ("Jane", "Ravi"):
        assert first not in shard
    assert "Someone Else" not in shard
    desc, parsed = tickets.split_body(text)
    assert desc.startswith("The reload fails") and len(parsed) == 60 and parsed[0][0] == "2026-01-01"
    found = tickets.ticket("OCPBUGS-500", tmp_path)
    assert found["found"] is not False and "delete the router-certs-default secret" in json.dumps(found)


def test_a_budget_spent_during_comments_keeps_the_ticket_for_the_next_run(tmp_path: Path) -> None:
    issue, comments = _long_ticket()
    fake = CommentJira({"OCPBUGS": [issue]}, {"OCPBUGS-500": comments})
    out = sync_projects(_client(fake, [], budget=1), ["OCPBUGS"], tmp_path, BASE, NOW)
    assert out["stoppedBy"] == "budget"
    assert tickets.ticket("OCPBUGS-500", tmp_path) is None or not tickets.ticket("OCPBUGS-500", tmp_path)["found"]
    sync_projects(_client(fake, []), ["OCPBUGS"], tmp_path, BASE, NOW)
    rec = json.loads((tmp_path / "corpus" / "jira-ocpbugs.jsonl").read_text().splitlines()[0])
    assert rec["comments"] == 60


def test_a_ticket_longer_than_the_cap_keeps_its_latest_comments_and_says_so() -> None:
    big = [_comment(i, i % 3, f"log {i} " + "x" * 6_000) for i in range(200)]
    issue = _issue("OCPBUGS-7", "huge", "short description")
    issue["fields"]["comment"] = {"comments": big, "total": 200}
    rec = issue_to_record(issue, BASE, "OCPBUGS", [], "sync", "t", max_text=SYNC_MAX_TEXT)
    assert rec["textCut"] is True and len(rec["text"]) <= SYNC_MAX_TEXT
    assert "log 199 " in rec["text"] and "short description" in rec["text"] and "log 0 " not in rec["text"]


def test_a_copy_made_before_refetches_its_tickets_once(tmp_path: Path) -> None:
    issue, comments = _long_ticket()
    fake = CommentJira({"OCPBUGS": [issue]}, {"OCPBUGS-500": comments})
    sync_projects(_client(fake, []), ["OCPBUGS"], tmp_path, BASE, NOW)
    state = load_state(tmp_path)
    assert state["projects"]["OCPBUGS"]["textVersion"] == TEXT_VERSION and state["projects"]["OCPBUGS"]["complete"]
    del state["projects"]["OCPBUGS"]["textVersion"]  # what 0.5.0 wrote
    save_state(tmp_path, state)
    fake.jql.clear()
    later = datetime(2026, 10, 29, tzinfo=UTC)
    sync_projects(_client(fake, []), ["OCPBUGS"], tmp_path, BASE, later)
    assert "project = OCPBUGS ORDER BY key DESC" in fake.jql  # the backfill starts again from the newest key
    assert load_state(tmp_path)["projects"]["OCPBUGS"]["textVersion"] == TEXT_VERSION
    fake.jql.clear()
    sync_projects(_client(fake, []), ["OCPBUGS"], tmp_path, BASE, later.replace(hour=2))
    assert all("updated >=" in q for q in fake.jql)  # once only


def test_hostile_people_never_reach_the_copy() -> None:
    rng = random.Random(11)
    first = ["Aisha", "Bjorn", "Chen", "Dmitri", "Elena", "Fatima", "Gustavo", "Hiroshi", "Ingrid", "Jamal"]
    last = ["Okafor", "Lindqvist", "Nakamura", "Petrov", "Rossi", "Haddad", "Silva", "Tanaka", "Berg", "Mensah"]
    leaked: list[str] = []
    for t in range(500):
        people = [
            (f"acc-{t:04d}{i:06d}", f"{rng.choice(first)} {rng.choice(last)}", f"u{t}{i}@corp.example.com")
            for i in range(3)
        ]
        comments = []
        for i in range(6):
            acc, name, email = people[i % 3]
            other = people[(i + 1) % 3]
            text = rng.choice(
                [
                    f"Hi {other[1].split()[0]}, can you check? {name}",
                    f"cc {other[1].split()[0]} - mail me at {email} or call (415) 555-01{i:02d}",
                    f"{other[1]} confirmed the fix in 4.21.3 on 10.0.12.5",
                    f"@{other[1].split()[0]} see https://redhat.atlassian.net/jira/people/{other[0]}",
                ]
            )
            comments.append(
                {"id": str(i), "created": "2026-10-01", "author": {"accountId": acc, "displayName": name}, "body": text}
            )
        issue = _issue(f"OCPBUGS-{t + 1}", "t", "d")
        issue["fields"]["comment"] = {"comments": comments, "total": len(comments)}
        rec = issue_to_record(issue, BASE, "OCPBUGS", [], "sync", "t", max_text=SYNC_MAX_TEXT)
        blob = json.dumps(rec)
        for acc, name, email in people:
            if acc in blob or name in blob or email in blob or name.split()[0] in blob or "555-01" in blob:
                leaked.append(f"OCPBUGS-{t + 1}: {name}")
        if any("confirmed the fix" in str(c["body"]) for c in comments):  # versions and addresses are not people
            assert "4.21.3" in rec["text"] and "10.0.12.5" in rec["text"]
    assert leaked == []
