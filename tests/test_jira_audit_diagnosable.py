"""The privacy gate refuses the corpus and does not say enough to fix it.

`corpus-refresh` has failed every run since 2026-10-31 with `123 person-shaped findings:
['CNV-95960: spelled-out email', 'CNV-87557: spelled-out email', 'CNV-85843: account id', ...]`. That names the
ticket and the kind and nothing else, so telling a real leak from a false positive needs the encrypted corpus and
the passphrase. The gate is right to fail closed; it just cannot be acted on.

Printing the matched text would be strictly worse -- that writes the personal data into a public CI log. So the
report carries a *shape*: which field it came from, and the match's character classes with no literal characters
kept. Enough to recognise "this is a digest, not an account id", not enough to identify anyone.

The second defect here is a false positive the gate manufactures itself: it scanned `text + " " + title`, so a
pattern could match across the join between two separately scrubbed fields and flag a leak that exists in
neither.
"""

from __future__ import annotations

from kube_noob.jira_audit import redacted_shape


def test_the_shape_keeps_no_literal_characters() -> None:
    """The whole point: a reviewer learns the form, never the content.

    The shape deliberately keeps the structural words `at` and `dot`, because they are what makes a spelled-out
    email recognisable as one. So the property is not "no letter of the input appears" -- `at` shares letters
    with almost anything -- but that every alphanumeric run has been replaced: the only letters left are `A` and
    those two words, and the only digit is `9`.
    """
    import re

    for raw in ("alice at example.com", "5b10a2844c20165700ede21g", "+1 415 555 0100", "@someone"):
        shape = redacted_shape(raw)
        leftover = re.sub(r"\b(?:at|dot)\b", "", shape)
        assert not re.search(r"[B-Zb-z]", leftover), f"content survived from {raw!r} into {shape!r}"
        assert not re.search(r"[0-8]", leftover), f"a digit survived from {raw!r} into {shape!r}"


def test_the_shape_distinguishes_the_two_kinds_that_are_failing() -> None:
    """A 24-hex digest fragment and a real Atlassian account id both match `BARE_ACCOUNT_ID`. The shapes have to
    read differently enough for a human to tell which one they are looking at."""
    assert redacted_shape("alice at example.com") != redacted_shape("5b10a2844c20165700ede21g")
    assert "at" in redacted_shape("alice at example.com"), "the separator is structure, not content"


def test_the_shape_is_short_enough_to_print_in_a_ci_log() -> None:
    assert len(redacted_shape("a" * 400 + " at " + "b" * 400 + ".com")) <= 80


def _audit(tmp_path, *records) -> dict:
    """Run the real audit over a one-shard copy written to disk, the way corpus-refresh does."""
    import json

    from kube_noob.jira_audit import audit

    data = tmp_path / "corpus"
    data.mkdir(parents=True, exist_ok=True)
    shard = data / "jira-cnv.jsonl"
    shard.write_text("".join(json.dumps({"sourceId": "jira:CNV", **r}) + "\n" for r in records), encoding="utf-8")
    return audit(tmp_path)


def test_a_finding_says_which_field_it_came_from(tmp_path) -> None:
    """`text` and `title` are scrubbed separately and a reviewer needs to know which one to look at."""
    rep = _audit(
        tmp_path,
        {
            "id": "jira-CNV-1",
            "title": "CNV-1: crash on upgrade",
            "text": "ping alice at example.com for the must-gather",
            "comments": 1,
            "commentsTotal": 1,
        },
    )
    leaks = rep["selfCheck"]["examples"]
    assert leaks, "a spelled-out email in the text has to be reported"
    assert any("text" in leak for leak in leaks), f"the field must be named: {leaks}"
    assert any("spelled-out email" in leak for leak in leaks)
    assert all("alice" not in leak and "example" not in leak for leak in leaks), f"content leaked: {leaks}"


def test_a_pattern_cannot_match_across_the_join_between_two_fields(tmp_path) -> None:
    """`body = text + " " + title` let a match straddle the seam, so the gate could refuse a corpus over text
    that exists in neither field. Each field is scanned on its own."""
    # Neither field holds a spelled-out email; concatenated with a space they read as one.
    rep = _audit(
        tmp_path,
        {
            "id": "jira-CNV-2",
            "title": "example.com upgrade notes",
            "text": "escalated to Commenter A at",
            "comments": 1,
            "commentsTotal": 1,
        },
    )
    assert rep["selfCheck"]["personShapedFindings"] == 0, (
        f"a match straddling the text/title join is not a leak: {rep['selfCheck']['examples']}"
    )
