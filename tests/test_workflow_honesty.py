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
# The first version of this only matched `if [ -z "${X_TOKEN}" ]; then` exactly, which let 13 of 14 shapes past --
# including `"$X_TOKEN"` without braces, a form already in jira-db-image.yml. Match the shapes a person writes.
_MISSING_SECRET = re.compile(
    r"""(?:if|elif)\s+\[\[?\s+-z\s+"?\$\{?(?P<var>[A-Z][A-Z0-9_]*(?:TOKEN|PASSPHRASE|KEY|SECRET|PASSWORD|PAT))"""
    r"""(?::-[^}]*)?\}?"?\s+\]\]?|test\s+-z\s+"?\$\{?(?P<var2>[A-Z][A-Z0-9_]*(?:TOKEN|PASSPHRASE|KEY|SECRET|PASSWORD|PAT))(?::-[^}]*)?\}?"?"""
)


def test_no_job_exits_zero_because_a_secret_it_needs_is_missing() -> None:
    """`exit 0` there is the lie. Either the job does its work, or the run is red and says what to add."""
    offenders: list[str] = []
    for path in sorted(WORKFLOWS.glob("*.yml")):
        lines = path.read_text(encoding="utf-8").splitlines()
        for n, line in enumerate(lines):
            m = _MISSING_SECRET.search(line)
            if not m:
                continue
            var = m["var"] or m["var2"]
            # Read the guard's own line too (a one-liner puts the exit there) and stop at its `fi`, so the window
            # cannot bleed into the next step. Any non-zero exit, or `false`, means the job does not lie.
            body = [line[m.end() :]]
            for follow in lines[n + 1 :]:
                if re.match(r"\s*fi\b", follow):
                    break
                body.append(follow)
            verdict = None
            for follow in body:
                if re.search(r"\bexit\s+[1-9]|^\s*false\b|\bthen\s+false\b", follow):
                    verdict = "fails"
                    break
                # A guard may exit 0 when the run still does the work another way, and it has to say which way:
                # `# honest-skip: <what happens instead>` in the branch. Stating it is the point.
                if re.search(r"#\s*honest-skip:", follow):
                    verdict = "declared"
                    break
                if re.search(r"\bexit\s+0\b", follow):
                    verdict = "lies"
                    break
            if verdict == "lies":
                offenders.append(f"{path.name}:{n + 1}: no {var} -> exit 0")
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


def test_the_drift_check_still_alarms_while_the_site_is_built_from_a_branch() -> None:
    """The first rewrite traded a false alarm for no alarm. Treating any non-release ref as a notice meant that
    while kube-noob.com served `main` -- which it does, and which is the only way to publish a correction before
    the next tag -- a release whose deploy never ran would never be reported. That is the one thing the job is
    for. The branch case now compares the version the build recorded, and falls through to the age check when it
    is behind.
    """
    text = (WORKFLOWS / "site-sync.yml").read_text(encoding="utf-8")
    branch_case = text.split("*)", 1)[1].split("esac", 1)[0]
    assert "jq -r '.product" in branch_case, (
        "the non-release branch ignores build.json's product version, so it cannot tell a deliberate branch build "
        "from a deploy that never ran"
    )
    assert "sort -V" in branch_case, "the branch case does not compare versions"
    # It must not short-circuit unconditionally: an exit 0 has to sit inside the at-or-past test.
    stripped = "\n".join(ln for ln in branch_case.splitlines() if not ln.strip().startswith("#"))
    tail = stripped.rsplit("fi", 1)[-1]
    assert "exit 0" not in tail, (
        "the branch case exits 0 after its version test, so a site behind the latest release is still passed"
    )


def test_the_secret_that_gates_an_hour_of_work_is_checked_before_the_hour() -> None:
    """corpus-refresh failed on a missing CORPUS_PASSPHRASE only at its last step, after a paced Jira fetch of up
    to 3000 requests a second apart. A check whose answer is known at the start belongs at the start.
    """
    import yaml

    doc = yaml.safe_load((WORKFLOWS / "corpus-refresh.yml").read_text(encoding="utf-8"))
    steps = [s for job in doc["jobs"].values() for s in job.get("steps", [])]
    names = [str(s.get("name", "")) for s in steps]
    guards = [
        i
        for i, s in enumerate(steps)
        if "CORPUS_PASSPHRASE" in str(s.get("run", "")) and "exit 1" in str(s.get("run", ""))
    ]
    assert guards, "no step fails on a missing CORPUS_PASSPHRASE"
    fetch = next((i for i, n in enumerate(names) if "paced" in n.lower()), None)
    assert fetch is not None, "could not find the paced fetch step; update this test with it"
    assert min(guards) < fetch, (
        f"the first passphrase check is step {min(guards)} ({names[min(guards)]!r}) and the paced fetch is step "
        f"{fetch}; the run spends the hour before finding out it cannot keep the result"
    )
