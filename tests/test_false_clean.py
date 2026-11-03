"""Four places that reported a clean result without having checked anything.

Each is the same shape as the known coverage-record bug -- silence read as satisfaction -- and each was found by
asking what the output asserts rather than what the code does.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from kube_noob import gate
from kube_noob.evals import checks
from kube_noob.sources import jira


def test_the_gate_says_the_manifest_audit_did_not_run_when_it_had_nothing_to_audit() -> None:
    """`notRun` listed only the two absent-report cases, so a pipeline whose manifest glob stopped matching -- a
    renamed `deploy/` directory -- kept passing its scanner and SARIF reports, exited 0, printed "gate passed",
    and rendered an **empty** "Not run" section, which positively asserts that nothing was left out."""
    report = gate.run([], scanner_reports=[("t", '{"SchemaVersion": 2, "Results": []}')])
    assert report["notRun"], "nothing was audited, so something must be listed as not run"
    assert any("manifest" in entry.lower() for entry in report["notRun"]), report["notRun"]
    text = gate.markdown(report)
    assert "### Not run" in text
    # the section must not be present and empty
    body = text.split("### Not run", 1)[1]
    assert body.strip(), "an empty 'Not run' section claims full coverage"


def test_the_gate_still_lists_nothing_when_everything_ran() -> None:
    """The entry must be absent when manifests were in fact audited, or it is noise that trains people to skip it."""
    manifest = "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: c\n  namespace: n\ndata:\n  a: b\n"
    report = gate.run(
        [gate.Source(uri="c.yaml", text=manifest)],
        scanner_reports=[("t", '{"SchemaVersion": 2, "Results": []}')],
        sarif_reports=[("s", '{"version": "2.1.0", "runs": []}')],
    )
    assert not any("manifest" in e.lower() for e in report["notRun"]), report["notRun"]


def test_an_assertion_with_no_recognised_operator_is_refused_not_passed() -> None:
    """`_check_value` returns None when no operator is recognised, and `_assert` turned that into a pass. A typo
    -- `equal` for `equals` -- therefore converted a gating, weight-2.0 assertion into a free pass, and because
    nothing was failing it also disengaged the GATE_CAP clamp, so a wrong answer scored high instead of 0.4."""
    with pytest.raises(checks.CheckSpecError, match="operator"):
        checks.validate_assertion({"kind": "ConfigMap", "path": "metadata.name", "equal": "x"})


def test_an_assertion_that_only_checks_presence_is_still_allowed() -> None:
    """`exists` is a real operator and a bare presence check is a legitimate assertion; the guard is for a key
    nothing recognises, not for an assertion with no comparison."""
    checks.validate_assertion({"kind": "Service", "path": "metadata.annotations", "exists": True})
    checks.validate_assertion({"kind": "ConfigMap", "path": "metadata.name", "equals": "x"})


def test_the_shipped_benchmark_assertions_all_carry_a_recognised_operator() -> None:
    """The guard is worth nothing if the bundled tasks do not satisfy it."""
    import pathlib

    import yaml

    root = pathlib.Path(checks.__file__).resolve().parent.parent
    spec = yaml.safe_load((root / "data" / "evals" / "tasks.yaml").read_text())
    seen = 0
    for task in spec.get("tasks", []):
        for a in (task.get("checks") or {}).get("assertions", []) or []:
            checks.validate_assertion(a)
            seen += 1
    assert seen > 0, "the fixture must contain assertions for this to mean anything"


def test_the_jira_scrubber_is_at_least_as_strong_as_the_detector_that_gates_it() -> None:
    """The scrubber matched an account id only with a prefix (`[~...]`, `accountId:`, a profile URL); the audit
    that gates the weekly refresh matches bare ids. So a reporter id pasted bare into a description survived the
    scrub and then failed the gate -- which does not leak, because no workflow commits Jira data and the gate
    exits 1, but it deadlocks the refresh every week and discards an hour of paced fetching each time."""
    from kube_noob import jira_audit

    bare = [
        "see 5b10a2844c20165700ede21f for details",
        "557058:ab12cd34-1234-5678-9abc-def012345678",
        "712020:0a1b2c3d-4e5f-6071-8293a4b5c6d7",
    ]
    for text in bare:
        assert jira_audit._ACCOUNT_ID.search(text), f"the detector must flag this for the test to mean anything: {text}"
        scrubbed = jira.scrub(text)
        assert not jira_audit._ACCOUNT_ID.search(scrubbed), f"survived the scrub: {text!r} -> {scrubbed!r}"


def test_the_scrubber_leaves_ordinary_text_alone() -> None:
    """Over-redaction is its own failure: these must not be mistaken for account ids."""
    for text in ("the fix landed in 4.20.3", "see commit abc123 for details", "error code 500600"):
        assert jira.scrub(text) == text, text


def test_the_bundle_checks_its_own_size_caps_instead_of_leaving_them_to_the_reader() -> None:
    """`MAX_MEMBER` and `MAX_MEMBERS` were referenced only inside `_extract`, so `build()` could pack an archive
    that nothing can `import`, and reported success doing it. `check()` on a *directory* enforced neither, so
    `corpus db-check <dir>` reported clean on a tree whose tarball `import` would refuse.

    `db-image.yml` runs `db-bundle` then `db-check` back to back, so an over-cap bundle fails CI rather than
    shipping -- but only after a full `corpus build --online`, and a local `db-bundle` still claimed success.
    """
    import inspect

    from kube_noob.sources import db_bundle

    # One call site, not two that can drift: `check` applies the predicate and `build` runs `check` over its
    # staging tree before packing, so the writer, the directory check and the reader all agree.
    assert "_member_problems" in inspect.getsource(db_bundle.check)
    assert "check(stage)" in inspect.getsource(db_bundle.build)
    # and it actually fires
    import tempfile

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "big.jsonl").write_bytes(b"x" * 16)
        monkey = db_bundle.MAX_MEMBER
        try:
            db_bundle.MAX_MEMBER = 8
            problems = db_bundle._member_problems(root)
        finally:
            db_bundle.MAX_MEMBER = monkey
    assert any("larger than" in p for p in problems), problems
