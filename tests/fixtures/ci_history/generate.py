"""A CI history of 200 runs for the R4.4 gate, and what its analysis must say, computed here from the raw values.

``python tests/fixtures/ci_history/generate.py <dir>`` writes one folder per run (``run.json`` in the shape of the
GitHub Actions API with jobs and steps, a JUnit XML report, a build log for runs that failed before the tests) and
``expected.json``. The expectations are computed from the values this script chose (the flaky tests it planted, the
seconds it gave each step) with the statistics module, not by kube-noob's analysis.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import math
import random
import statistics
import sys
from pathlib import Path
from xml.sax.saxutils import quoteattr

RUNS = 200
START = dt.datetime(2026, 7, 1, tzinfo=dt.UTC)
TESTS = [
    "com.acme.orders.OrderServiceTest::cancelsExpiredOrders",
    "com.acme.orders.OrderServiceTest::refundsPartially",
    "com.acme.orders.OrderServiceTest::createsOrder",
    "com.acme.cart.CartTest::appliesDiscountOnce",
    "com.acme.cart.CartTest::totalsRoundHalfEven",
    "com.acme.pay.PayTest::timesOutGracefully",
    "com.acme.pay.PayTest::retriesDeclined",
    "tests.test_api::test_retry_backoff",
    "tests.test_api::test_login",
    "tests.test_api::test_logout",
    "web.src.cart::totals_rounds_once",
    "web.src.cart::empty_cart",
]
FLAKY_SAME_COMMIT = {
    "com.acme.cart.CartTest::appliesDiscountOnce",
    "tests.test_api::test_retry_backoff",
    "web.src.cart::totals_rounds_once",
}
FLAKY_IN_RUN = "com.acme.pay.PayTest::timesOutGracefully"  # Surefire reran it within the run and it passed
REGRESSION = "com.acme.orders.OrderServiceTest::refundsPartially"  # broken on commits 30-32, then fixed
COMPILE_BROKEN = {40, 41}  # these commits do not compile
FETCH_BROKEN = {50}  # a dependency was missing on this commit
LOGS = Path(__file__).resolve().parents[1] / "build_logs"
COMPILE_LOG = "03-github-actions-compile.log"
FETCH_LOG = "01-github-actions-dependency-fetch.log"


def sha(i: int) -> str:
    return hashlib.sha1(f"commit-{i}".encode(), usedforsecurity=False).hexdigest()


def plan() -> list[dict]:  # type: ignore[type-arg]
    rng = random.Random(4242)
    runs = []
    commit = 0
    n = 0
    while n < RUNS:
        attempts = 2 if commit % 7 == 3 else 1  # every seventh commit is rerun: the flaky ones fail on attempt 1
        for attempt in range(1, attempts + 1):
            if n >= RUNS:
                break
            runs.append({"n": n, "commit": commit, "attempt": attempt, "rng": rng.random()})
            n += 1
        commit += 1
    return runs


def outcome(test: str, run: dict) -> str:  # type: ignore[type-arg]
    c, attempt = run["commit"], run["attempt"]
    if test == REGRESSION and 30 <= c <= 32:
        return "failed"
    if (
        test in FLAKY_SAME_COMMIT
        and c % 7 == 3
        and attempt == 1
        and (c // 7) % 3 == sorted(FLAKY_SAME_COMMIT).index(test)
    ):
        return "failed"
    if test == FLAKY_IN_RUN and run["n"] % 23 == 5:
        return "flaky"
    return "passed"


def step_seconds(run: dict) -> dict[str, int]:  # type: ignore[type-arg]
    n = run["n"]
    return {
        "Set up job": 3 + n % 2,
        "Run actions/checkout@v4": 4 + (n % 5 == 0),
        "Run mvn -B verify": 120 + (60 * n) // (RUNS - 1),  # 120 s at the start, 180 s at the end
        "Run docker build": 45 + (n * 37) % 7 - 3,
        "Complete job": 1,
    }


def main(out: Path) -> None:
    out.mkdir(parents=True, exist_ok=True)
    seconds: dict[str, list[float]] = {}
    observed: dict[tuple[str, str], set[str]] = {}
    in_run: set[str] = set()
    fails: dict[str, int] = {}
    classes: dict[str, dict[str, int]] = {}
    conclusions: dict[str, int] = {}
    commit_outcomes: dict[str, set[str]] = {}
    commit_failed_steps: dict[str, set[str]] = {}
    for run in plan():
        n, c = run["n"], run["commit"]
        created = START + dt.timedelta(hours=3 * n)
        folder = out / f"run-{n:03d}"
        folder.mkdir(exist_ok=True)
        broken = c in COMPILE_BROKEN or c in FETCH_BROKEN
        cases = [] if broken else [(t, outcome(t, run)) for t in TESTS]
        failed = broken or any(o == "failed" for _, o in cases)
        conclusion = "failure" if failed else "success"
        conclusions[conclusion] = conclusions.get(conclusion, 0) + 1
        commit_outcomes.setdefault(sha(c), set()).add(conclusion)
        secs = step_seconds(run)
        steps, t = [], created
        failed_step = "Run mvn -B verify" if failed else None
        for name, s in secs.items():
            stop = broken and name == "Run docker build"  # the build stopped before this step
            steps.append(
                {
                    "name": name,
                    "status": "completed",
                    "conclusion": "skipped" if stop else ("failure" if name == failed_step else "success"),
                    "started_at": None if stop else t.isoformat().replace("+00:00", "Z"),
                    "completed_at": None if stop else (t + dt.timedelta(seconds=s)).isoformat().replace("+00:00", "Z"),
                }
            )
            if not stop:
                seconds.setdefault(name, []).append(float(s))
                t += dt.timedelta(seconds=s)
        if failed_step:
            commit_failed_steps.setdefault(sha(c), set()).add(f"build / {failed_step}")
        doc = {
            "id": 9_000_000 + n,
            "head_sha": sha(c),
            "run_attempt": run["attempt"],
            "conclusion": conclusion,
            "created_at": created.isoformat().replace("+00:00", "Z"),
            "jobs": [{"name": "build", "conclusion": conclusion, "steps": steps}],
        }
        (folder / "run.json").write_text(json.dumps(doc, indent=1) + "\n", encoding="utf-8")
        if cases:
            xml = ['<?xml version="1.0" encoding="UTF-8"?>', '<testsuites name="all">']
            for test, o in cases:
                cls, name = test.split("::")
                body = {
                    "failed": '<failure message="assertion failed" type="AssertionError">expected 2 got 3</failure>',
                    "flaky": '<flakyFailure message="timeout" type="java.net.SocketTimeoutException"/>',
                }.get(o, "")
                xml.append(
                    f'  <testcase classname={quoteattr(cls)} name={quoteattr(name)} time="0.25">{body}</testcase>'
                )
                if o in {"passed", "failed"}:
                    observed.setdefault((test, sha(c)), set()).add(o)
                if o == "flaky":
                    in_run.add(test)
                if o == "failed":
                    fails[test] = fails.get(test, 0) + 1
            xml.append("</testsuites>")
            (folder / "junit.xml").write_text("\n".join(xml) + "\n", encoding="utf-8")
        if failed:
            week = created.strftime("%G-W%V")
            if broken:
                (folder / "build.log").write_bytes(
                    (LOGS / (COMPILE_LOG if c in COMPILE_BROKEN else FETCH_LOG)).read_bytes()
                )
                cls = "compile" if c in COMPILE_BROKEN else "dependency-fetch"
            else:
                cls = "test"
            classes.setdefault(week, {})
            classes[week][cls] = classes[week].get(cls, 0) + 1

    flaky_commit = {t for (t, _), o in observed.items() if o == {"passed", "failed"}}

    def p(values: list[float], q: float) -> float:
        ordered = sorted(values)
        return ordered[max(1, math.ceil(q * len(ordered))) - 1]

    def trend(values: list[float]) -> float | None:
        half = len(values) // 2
        if half < 2:
            return None
        old = statistics.fmean(values[:half])
        return round((statistics.fmean(values[-half:]) - old) / old * 100, 1)

    expected = {
        "runs": RUNS,
        "conclusions": conclusions,
        "flakyTests": sorted(flaky_commit | in_run),
        "failingTests": sorted(t for t in fails if t not in flaky_commit | in_run),
        "flakyRuns": sorted(c for c, o in commit_outcomes.items() if o == {"success", "failure"}),
        "flakyRunSteps": {
            c: sorted(commit_failed_steps.get(c, set()))
            for c, o in commit_outcomes.items()
            if o == {"success", "failure"}
        },
        "steps": {
            name: {
                "runs": len(v),
                "meanSeconds": round(statistics.fmean(v), 2),
                "medianSeconds": round(statistics.median_low(v), 2),
                "p90Seconds": round(p(v, 0.9), 2),
                "maxSeconds": round(max(v), 2),
                "trendPercent": trend(v),
            }
            for name, v in seconds.items()
        },
        "failureClasses": {w: dict(sorted(c.items())) for w, c in sorted(classes.items())},
    }
    (out / "expected.json").write_text(json.dumps(expected, indent=1, sort_keys=True) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main(Path(sys.argv[1]))
