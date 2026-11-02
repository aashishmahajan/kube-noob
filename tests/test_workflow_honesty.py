"""A job that cannot do its work must not report success.

Three times in one release cycle a green check meant nothing: the chart's Route passed both probes while every MCP
call answered 421; `kube-noob doctor` printed `posture: OK` with no SDK and no key; and the `site` job of a release
printed SUCCESS while doing nothing at all, because `SITE_DISPATCH_TOKEN` was unset -- it warned and `exit 0`. The
site then served the previous release's media under the new release's banner for a day, and nobody saw a red check.

A missing secret is a real failure of the thing the job exists to do. It belongs in the part of the run a person
looks at, which is the conclusion, not a warning annotation nobody opens.
"""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = ROOT / ".github" / "workflows"

# A step that bails out because a secret or a variable is absent. The two shapes used in this repository.
_MISSING_SECRET = re.compile(r'if \[ -z "\$\{(?P<var>[A-Z_]*(?:TOKEN|PASSPHRASE|KEY))\}" \]; then')


def test_no_job_exits_zero_because_a_secret_it_needs_is_missing() -> None:
    """`exit 0` there is the lie. Either the job does its work, or the run is red and says what to add."""
    offenders: list[str] = []
    for path in sorted(WORKFLOWS.glob("*.yml")):
        lines = path.read_text(encoding="utf-8").splitlines()
        for n, line in enumerate(lines):
            m = _MISSING_SECRET.search(line)
            if not m:
                continue
            # Look at the branch body: the first `exit` after the guard decides whether this job can lie.
            for follow in lines[n + 1 : n + 8]:
                if "exit 1" in follow:
                    break
                # A guard may exit 0 when the run still does the work another way, and it has to say which way:
                # `# honest-skip: <what happens instead>` in the branch. Stating it is the point.
                if "honest-skip:" in follow:
                    break
                if "exit 0" in follow:
                    offenders.append(f"{path.name}:{n + 1}: no {m['var']} -> exit 0")
                    break
    assert offenders == [], (
        "these jobs report success while skipping the work they exist to do, so nobody learns the secret is "
        f"missing: {offenders}"
    )


def test_the_drift_check_does_not_call_a_site_that_is_ahead_a_failure() -> None:
    """Equality alone called a site serving a NEWER ref than the latest release a failed deploy, which is how
    `site-sync` went red on 2026-11-01 while nothing was wrong, and how a site deliberately built from a branch
    would be reported as broken.
    """
    text = (WORKFLOWS / "site-sync.yml").read_text(encoding="utf-8")
    assert "sort -V" in text, "the drift check compares versions by string equality, so 'ahead' reads as 'behind'"
    assert "non-release ref" in text, "a site built from a branch must be a notice, not a failure"
