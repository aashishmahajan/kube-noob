"""Every enrichment fetch is jittered: the background Jira sync waits a random 30 s to 10 min before its first run and
repeats every interval +/- 10%; clones from the same host are spaced by a random pause; the scheduled corpus refresh
starts at a random offset; and the Jira client already spaces requests by the crawl delay plus random jitter."""

from __future__ import annotations

import random
import statistics
from pathlib import Path
from typing import Any

import pytest
import yaml

from kube_noob.config import load_settings
from kube_noob.sources import pacing

ROOT = Path(__file__).resolve().parents[1]


def test_start_delay_and_interval_spread() -> None:
    rng = random.Random(3)
    delays = [pacing.start_delay(rng) for _ in range(500)]
    assert all(30.0 <= d <= 600.0 for d in delays) and statistics.pstdev(delays) > 100
    day = 24 * 3600
    spread = [pacing.jittered_interval(day, rng) for _ in range(500)]
    assert all(0.9 * day <= s <= 1.1 * day for s in spread) and len({round(s) for s in spread}) > 400
    assert pacing.jittered_interval(1, rng) == 60.0  # never below a minute


def test_pause_sleeps_a_random_time_within_bounds() -> None:
    slept: list[float] = []
    for _ in range(50):
        pacing.pause((1.0, 4.0), random.Random(), slept.append)
    assert all(1.0 <= s <= 4.0 for s in slept) and len(set(slept)) == 50


def test_background_jira_sync_waits_before_its_first_run(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from kube_noob.sources import jira

    runs: list[str] = []
    monkeypatch.setattr(jira, "run_sync", lambda s: runs.append("run") or {"projects": [], "requests": 0})
    s = load_settings(overrides={"dataDir": str(tmp_path)})
    stop = jira.start_background(s, random.Random(1))
    assert 30.0 <= stop.first_delay <= 600.0
    stop.set()
    assert runs == []  # stopped before the jittered first run


def test_clones_are_spaced_by_a_random_pause(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    from kube_noob.cli import main
    from kube_noob.sources import git_ingest
    from kube_noob.sources.registry import GIT_SOURCES

    pauses: list[float] = []
    monkeypatch.setattr(pacing, "pause", lambda *a, **k: pauses.append(1.0) or 1.0)
    monkeypatch.setattr(git_ingest, "ingest", lambda src, limit=None: iter(()))
    monkeypatch.setenv("KUBE_NOOB_DATA_DIR", str(tmp_path))
    ids = ",".join(s.source_id for s in GIT_SOURCES[:3])
    main(["corpus", "build", "--online", "--sources", ids])
    assert len(pauses) == 2  # between the three clones, not before the first


def test_release_notes_clones_are_spaced(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    from kube_noob.sources import git_ingest, release_notes

    pauses: list[int] = []
    monkeypatch.setattr(pacing, "pause", lambda *a, **k: pauses.append(1) or 1.0)

    def fake_git(args: list[str], cwd: Any = None, timeout: int = 600) -> str:
        if args[0] == "clone":
            Path(args[-1]).mkdir(parents=True)
        return "0" * 40

    monkeypatch.setattr(git_ingest, "_git", fake_git)
    monkeypatch.setattr(release_notes, "parse_release", lambda rel: [])
    release_notes.fetch(["4.20", "4.21", "4.22"], tmp_path)
    assert len(pauses) == 2


def test_the_scheduled_refresh_starts_at_a_random_offset() -> None:
    wf = yaml.safe_load((ROOT / ".github" / "workflows" / "corpus-refresh.yml").read_text())
    due = next(s for s in wf["jobs"]["corpus"]["steps"] if s.get("name") == "Decide whether this run is due")
    assert "/dev/urandom" in due["run"] and "% 900" in due["run"] and 'sleep "$wait"' in due["run"]
    assert 'if [ "$EVENT" = "schedule" ]; then' in due["run"]  # a dispatched run starts at once


def test_the_jira_client_jitters_every_request() -> None:
    import httpx

    from kube_noob.sources.jira import CRAWL_DELAY, JiraClient

    sleeps: list[float] = []
    client = JiraClient(
        httpx.Client(transport=httpx.MockTransport(lambda r: httpx.Response(200, json={"values": [], "isLast": True}))),
        "https://redhat.atlassian.net",
        sleep=sleeps.append,
        rng=random.Random(5),
    )
    for _ in range(20):
        client.get("/rest/api/3/project/search", {"startAt": 0})
    assert all(s >= CRAWL_DELAY for s in sleeps) and len(set(sleeps)) == len(sleeps) == 19
