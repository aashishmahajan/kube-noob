"""R4.4: flaky tests, step times and their trend, failure classes over time; the GitHub Actions history reader."""

from __future__ import annotations

import importlib.util
import json
import random
import sys
from pathlib import Path
from typing import Any

import httpx
import pytest

from kube_noob.build import analytics, github_history
from kube_noob.cli import main
from kube_noob.config import load_settings
from kube_noob.errors import ConfigError, DomainNotAllowedError, WebDisabledError
from kube_noob.net import Purpose, http_client

ROOT = Path(__file__).resolve().parents[1]
GEN = ROOT / "tests" / "fixtures" / "ci_history" / "generate.py"
TOKEN = "gho_" + "t3" * 18


def _generate(out: Path) -> dict[str, Any]:
    spec = importlib.util.spec_from_file_location("ci_history_generate", GEN)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules["ci_history_generate"] = mod
    spec.loader.exec_module(mod)
    mod.main(out)
    return dict(json.loads((out / "expected.json").read_text()))


def test_a_200_run_history_gives_the_exact_flaky_set_and_step_times(tmp_path: Path) -> None:
    expected = _generate(tmp_path)
    got = analytics.analyse(analytics.load_history(tmp_path))
    assert got["runs"] == expected["runs"] == 200
    assert got["conclusions"] == expected["conclusions"]
    assert [f["test"] for f in got["flakyTests"]] == expected["flakyTests"]
    assert len(expected["flakyTests"]) == 4, "three flaky across reruns of a commit, one rerun within a run"
    assert [f["test"] for f in got["failingTests"]] == expected["failingTests"], "a real regression is not flaky"
    assert [r["commit"] for r in got["flakyRuns"]] == expected["flakyRuns"]
    assert {r["commit"]: r["failedSteps"] for r in got["flakyRuns"]} == expected["flakyRunSteps"]
    steps = {r["step"]: r for r in got["steps"]}
    assert set(steps) == set(expected["steps"])
    for name, want in expected["steps"].items():
        assert {k: steps[name][k] for k in want} == want, name
    assert steps["Run mvn -B verify"]["trendPercent"] > 20, "the planted slowdown (120 s to 180 s) shows"
    assert got["slowerSteps"][0]["step"] == "Run mvn -B verify"
    assert got["failureClasses"] == expected["failureClasses"]


def test_junit_variants_and_hostile_xml() -> None:
    surefire = (
        b'<testsuite name="s"><testcase classname="A" name="ok" time="1.5"/>'
        b'<testcase classname="A" name="flaky" time="2"><flakyFailure message="x"/></testcase>'
        b'<testcase classname="A" name="bad" time="0.1"><failure message="boom"/></testcase>'
        b'<testcase classname="A" name="err"><error/></testcase>'
        b'<testcase classname="A" name="skip"><skipped/></testcase>'
        b'<testcase name="go_style" time="NaN"/></testsuite>'
    )
    cases = {c.test: c for c in analytics.parse_junit(surefire)}
    assert cases["A::ok"].outcome == "passed" and cases["A::ok"].seconds == 1.5
    assert cases["A::flaky"].outcome == "flaky" and cases["A::bad"].outcome == "failed"
    assert cases["A::err"].outcome == "failed" and cases["A::skip"].outcome == "skipped"
    assert cases["go_style"].seconds == 0.0
    laughs = b'<?xml version="1.0"?><!DOCTYPE l [<!ENTITY a "aaaa"><!ENTITY b "&a;&a;">]><testsuite>&b;</testsuite>'
    with pytest.raises(analytics.HistoryError, match="DOCTYPE or ENTITY"):
        analytics.parse_junit(laughs)
    with pytest.raises(analytics.HistoryError, match="not XML"):
        analytics.parse_junit(b"<testsuite><testcase")
    with pytest.raises(analytics.HistoryError, match="larger than"):
        analytics.parse_junit(b" " * (analytics.MAX_XML_BYTES + 1))


def test_run_folders_in_gh_cli_shape_and_bad_ones(tmp_path: Path) -> None:
    run = tmp_path / "r1"
    run.mkdir()
    (run / "run.json").write_text(
        json.dumps(
            {
                "databaseId": 1,
                "headSha": "a" * 40,
                "attempt": 1,
                "conclusion": "success",
                "createdAt": "2026-07-01T00:00:00Z",
                "jobs": [
                    {
                        "name": "build",
                        "steps": [
                            {
                                "name": "Run make",
                                "conclusion": "success",
                                "startedAt": "2026-07-01T00:00:00Z",
                                "completedAt": "2026-07-01T00:01:30Z",
                            }
                        ],
                    }
                ],
            }
        )
    )
    got = analytics.analyse(analytics.load_history(tmp_path))
    assert got["steps"][0]["meanSeconds"] == 90.0 and got["steps"][0]["trendPercent"] is None
    (run / "run.json").write_text(json.dumps({"id": 1, "head_sha": "not-a-sha", "created_at": "2026-07-01T00:00:00Z"}))
    with pytest.raises(analytics.HistoryError, match="needs an id, a commit"):
        analytics.load_history(tmp_path)
    (run / "run.json").write_text("[1, 2]")
    with pytest.raises(analytics.HistoryError, match="not a JSON object"):
        analytics.load_history(tmp_path)
    with pytest.raises(analytics.HistoryError, match="no run folders"):
        analytics.load_history(tmp_path / "r1")


def test_cli_analytics(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    _generate(tmp_path / "h")
    assert main(["build", "analytics", "--history", str(tmp_path / "h"), "--format", "text", "--top", "3"]) == 0
    text = capsys.readouterr().out
    assert "200 runs of" in text and "flaky tests (4):" in text and "Run mvn -B verify" in text
    assert main(["build", "analytics", "--history", str(tmp_path / "missing")]) == 2


# -- GitHub Actions API reader ---------------------------------------------------------------------------------------


def _settings(**ci: Any) -> Any:
    return load_settings(overrides={"ci": {"githubEnabled": True, **ci}})


class _GitHub:
    """Two runs: 101 (attempt 2 succeeded after attempt 1 failed) and 102 (one attempt)."""

    def __init__(self) -> None:
        self.seen: list[httpx.Request] = []

    def __call__(self, req: httpx.Request) -> httpx.Response:
        self.seen.append(req)
        path = req.url.path
        if path.endswith("/workflows/ci.yml/runs"):
            page = int(req.url.params.get("page", "1"))
            runs = [{"id": 101, "run_attempt": 2}, {"id": 102, "run_attempt": 1}] if page == 1 else []
            return httpx.Response(200, json={"total_count": 2, "workflow_runs": runs})
        if "/attempts/" in path and path.endswith("/jobs"):
            rid, att = path.split("/runs/")[1].split("/attempts/")
            failed = rid == "101" and att.startswith("1")
            step = {
                "name": "Run tests",
                "conclusion": "failure" if failed else "success",
                "started_at": "2026-07-01T00:00:00Z",
                "completed_at": "2026-07-01T00:02:00Z",
            }
            return httpx.Response(200, json={"total_count": 1, "jobs": [{"name": "test", "steps": [step]}]})
        if "/attempts/" in path:
            rid, att = path.split("/runs/")[1].split("/attempts/")
            failed = rid == "101" and att == "1"
            return httpx.Response(
                200,
                json={
                    "id": int(rid),
                    "head_sha": "b" * 40 if rid == "101" else "c" * 40,
                    "run_attempt": int(att),
                    "conclusion": "failure" if failed else "success",
                    "run_started_at": f"2026-07-0{att}T00:00:00Z",
                },
            )
        return httpx.Response(404)


def test_history_from_the_github_api(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GITHUB_TOKEN", TOKEN)
    gh = _GitHub()
    pauses: list[float] = []
    done = github_history.fetch(
        _settings(),
        "acme/shop",
        tmp_path / "h",
        workflow="ci.yml",
        transport=httpx.MockTransport(gh),
        sleep=pauses.append,
    )
    assert done["runs"] == 2 and done["attempts"] == 3
    assert {r.method for r in gh.seen} == {"GET"} and {r.url.host for r in gh.seen} == {"api.github.com"}
    assert all(r.headers["authorization"] == f"Bearer {TOKEN}" for r in gh.seen)
    assert pauses and all(0.2 <= p <= 0.6 for p in pauses) and len(set(pauses)) > 1, "jittered"
    got = analytics.analyse(analytics.load_history(tmp_path / "h"))
    assert got["flakyRuns"] == [{"commit": "b" * 40, "failedSteps": ["test / Run tests"]}]
    assert TOKEN not in "".join(p.read_text() for p in (tmp_path / "h").rglob("run.json"))


def test_history_refusals(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(WebDisabledError, match="githubEnabled"):
        github_history.fetch(load_settings(), "acme/shop", tmp_path)
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    with pytest.raises(ConfigError, match="Set GITHUB_TOKEN"):
        github_history.fetch(_settings(), "acme/shop", tmp_path)
    monkeypatch.setenv("GITHUB_TOKEN", TOKEN)
    for repo in ("acme", "acme/shop/../x", "acme/shop?x=1", "../.."):
        with pytest.raises(ConfigError):
            github_history.fetch(_settings(), repo, tmp_path)
    with pytest.raises(ConfigError):
        github_history.fetch(_settings(), "acme/shop", tmp_path, branch="../../etc")
    denied = httpx.MockTransport(lambda r: httpx.Response(403))
    with pytest.raises(github_history.HistoryFetchError, match="actions: read"):
        github_history.fetch(_settings(), "acme/shop", tmp_path, transport=denied, sleep=lambda _: None)
    client = http_client(_settings(), Purpose.CI, transport=httpx.MockTransport(lambda r: httpx.Response(200)))
    with pytest.raises(DomainNotAllowedError):
        client.get("https://evil.example.com/repos")
    with pytest.raises(WebDisabledError, match="read-only"):
        client.post("https://api.github.com/repos/acme/shop/actions/runs/1/rerun")
    assert client.follow_redirects is False
    offline = load_settings(overrides={"offline": True, "ci": {"githubEnabled": True}})
    with pytest.raises(WebDisabledError, match="offline lock"):
        http_client(offline, Purpose.CI)
    for bad in (
        {"githubApiUrl": "http://api.github.com"},
        {"githubApiUrl": "https://ghe.acme.com/v4"},
        {"githubTokenEnv": "AWS_SECRET_ACCESS_KEY"},
        {"maxRuns": 0},
    ):
        with pytest.raises(ConfigError):
            load_settings(overrides={"ci": bad})
    assert load_settings(overrides={"ci": {"githubApiUrl": "https://ghe.acme.com/api/v3"}}).ci.github_api_url


def test_jitter_rng_is_its_own() -> None:
    reader = github_history.Reader(object(), "https://api.github.com", rng=random.Random(3))
    assert 0.2 <= reader.rng.uniform(0.2, 0.6) <= 0.6
