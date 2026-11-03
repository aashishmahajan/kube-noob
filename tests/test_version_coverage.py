"""`REMOVED_APIS` was read from the upstream deprecation guide at Kubernetes 1.37 and nothing said so in the data.

The guide lists no removals after v1.32, so for every target the table's answer is a list that happens to be
complete -- until the target is a minor nobody has checked. Then `removedInTarget: []` and a validate with no
removed-API findings are a verdict earned by absence (G163), and the caller cannot tell the difference between
"nothing is removed in 1.38" and "nobody has looked at 1.38".

That stops being hypothetical on 16 December 2026, when Kubernetes 1.38 is released, and on the OpenShift minor
that maps to it. The fix is not more data -- it is saying where the data stops.
"""

from __future__ import annotations

from pathlib import Path

from kube_noob.catalog import CHECKED_THROUGH, REMOVED_APIS, beyond_checked, parse_minor

EXAMPLE = Path(__file__).resolve().parent.parent / "examples" / "netpol-shop.yaml"


def test_the_table_knows_where_it_stops() -> None:
    assert parse_minor(CHECKED_THROUGH) >= max(parse_minor(r.removed_in) for r in REMOVED_APIS), (
        "the table cannot have been checked through a version older than a removal it already lists"
    )


def test_beyond_checked_is_true_only_past_the_ceiling() -> None:
    assert not beyond_checked(CHECKED_THROUGH), "the ceiling itself was checked"
    major, minor = parse_minor(CHECKED_THROUGH)
    assert not beyond_checked(f"{major}.{minor - 1}")
    assert beyond_checked(f"{major}.{minor + 1}"), "one minor past the ceiling is not covered"
    assert beyond_checked(f"{major}.{minor + 9}")


def test_api_history_says_how_far_it_was_checked() -> None:
    from kube_noob.config import Settings
    from kube_noob.toolkit import ApiHistoryIn, Toolkit

    kit = Toolkit(Settings())
    major, minor = parse_minor(CHECKED_THROUGH)

    covered = kit.api_history(ApiHistoryIn(platform="kubernetes", version=CHECKED_THROUGH))
    assert covered["checkedThrough"] == CHECKED_THROUGH
    assert covered["beyondCheckedVersions"] is False

    future = kit.api_history(ApiHistoryIn(platform="kubernetes", version=f"{major}.{minor + 1}"))
    assert future["beyondCheckedVersions"] is True, "a target past the ceiling has to say so"
    assert CHECKED_THROUGH in future["note"], "and the note has to name the ceiling, not just a boolean"


def test_a_report_targeting_an_unchecked_version_says_what_it_did_not_check() -> None:
    """A gate reads the report. An empty removed-API result for a version the table has never seen must not
    read like a clean one."""
    from kube_noob.audit.engine import analyze

    major, minor = parse_minor(CHECKED_THROUGH)
    covered = analyze("", "kubernetes", CHECKED_THROUGH).as_dict()
    assert "notCheckedBeyond" not in covered, "a covered target must be byte-identical to what it always was"

    future = analyze("", "kubernetes", f"{major}.{minor + 1}").as_dict()
    note = future.get("notCheckedBeyond")
    assert note, "a target past the ceiling has to carry the limit into the report"
    assert note["removalData"] == CHECKED_THROUGH
    assert note["target"] == f"{major}.{minor + 1}"
    assert CHECKED_THROUGH in note["why"]


def test_the_openshift_minor_that_maps_past_the_ceiling_is_flagged_too() -> None:
    """The ceiling is a Kubernetes minor, but most callers pass an OpenShift one. 4.x tracks 1.(x+13), so the
    flag has to survive the mapping rather than only firing when someone types a Kubernetes version."""
    from kube_noob.audit.engine import analyze
    from kube_noob.catalog import k8s_version_for

    major, minor = parse_minor(CHECKED_THROUGH)
    ocp = f"4.{minor + 1 - 13}"
    assert k8s_version_for("openshift", ocp) == f"{major}.{minor + 1}"
    assert "notCheckedBeyond" in analyze("", "openshift", ocp).as_dict()


def test_the_terminal_report_shows_the_limit_before_the_findings(capsys) -> None:
    """A gate's reader sees text, not JSON. The limit has to appear above an empty finding list, not below it."""
    from kube_noob.cli import main

    major, minor = parse_minor(CHECKED_THROUGH)
    assert main(["validate", "-f", str(EXAMPLE), "--platform", "kubernetes", "--version", f"{major}.{minor + 1}"]) in (
        0,
        1,
    )
    out = capsys.readouterr().out
    assert "not checked:" in out
    assert CHECKED_THROUGH in out
    head = out.partition("not checked:")[0]
    assert "[" not in head, "the limit must come before the first finding line"
