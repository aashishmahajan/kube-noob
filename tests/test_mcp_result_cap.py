"""A result a caller cannot hold is not an answer.

kube-noob is an MCP server, so a result is spent out of the caller's context window. `policy_generate` was the
one tool whose result could exceed any caller's budget: on the bundled rule set for OpenShift, every rule on
every engine renders 380,670 bytes -- about 95,000 tokens, 96% of it one YAML string. The CLI gained `-o FILE`
to write it instead, but `PolicyGenerateIn` has no `output` field and an MCP caller has no filesystem to write
to, so the fix reached the audience that was not the problem.

The cap refuses rather than truncates. Half a policy set is not a policy set: a caller that applied it would
enforce some rules and silently drop the rest, which is the kind of quiet partial answer this project treats as
a wrong one. The refusal still carries the counts and `skipped`, so the caller learns what it asked for and how
to ask for less, and `allow_large` is there for a caller that knows its own budget.
"""

from __future__ import annotations

import json

from kube_noob.config import Settings
from kube_noob.toolkit import MAX_INLINE_POLICY_YAML, PolicyGenerateIn, Toolkit

SMALL = {"rules": ["KN-S001", "KN-S003", "KN-S008", "KN-S009", "KN-S011"], "engines": ["vap"]}


def _gen(**kw) -> dict:
    return Toolkit(Settings()).policy_generate(PolicyGenerateIn(platform="openshift", **kw))


def _bytes(result: dict) -> int:
    return len(json.dumps(result, separators=(",", ":")))


def test_the_whole_rule_set_is_refused_rather_than_returned() -> None:
    out = _gen()
    assert out["yamlOmitted"] is True
    assert "yaml" not in out, "the point is not to send it"
    assert out["yamlBytes"] > MAX_INLINE_POLICY_YAML
    assert out["limit"] == MAX_INLINE_POLICY_YAML


def test_the_refusal_is_far_smaller_than_what_it_replaced() -> None:
    big, refused = _bytes(_gen(allow_large=True)), _bytes(_gen())
    assert refused < big * 0.1, f"expected the refusal to be a fraction of the payload, got {big} -> {refused}"


def test_the_refusal_still_says_what_was_generated_and_how_to_ask_for_less() -> None:
    """A refusal that leaves the caller with nothing to do is just a failure."""
    out = _gen()
    assert out["generated"], "the counts a caller reasons over must survive the refusal"
    assert "rules" in out["why"] and "engines" in out["why"]
    assert "allow_large" in out["why"]
    assert "-o" in out["why"], "the CLI route has to be named, because an MCP caller cannot write a file"
    assert "truncated" in out["why"], "say plainly that nothing was cut, or it reads as data loss"


def test_nothing_is_truncated_only_omitted() -> None:
    """Truncation is the failure mode this avoids: a half policy set applies some rules and drops the rest."""
    out = _gen()
    full = _gen(allow_large=True)
    assert out["yamlBytes"] == len(full["yaml"].encode("utf-8"))
    assert out["generated"] == full["generated"], "the same set was rendered either way"


def test_a_request_a_caller_can_hold_is_unchanged() -> None:
    out = _gen(**SMALL)
    assert out.get("yaml")
    assert "yamlOmitted" not in out and "limit" not in out
    assert _bytes(out) < MAX_INLINE_POLICY_YAML


def test_allow_large_returns_the_whole_set() -> None:
    out = _gen(allow_large=True)
    assert "yaml" in out and "yamlOmitted" not in out
    assert len(out["yaml"].encode("utf-8")) > MAX_INLINE_POLICY_YAML


def test_narrowing_as_the_refusal_advises_actually_works() -> None:
    """The advice has to be true: following it must produce a result under the limit."""
    assert _gen()["yamlOmitted"] is True
    narrowed = _gen(**SMALL)
    assert "yaml" in narrowed, "the refusal told the caller to narrow with rules and engines; that must work"
