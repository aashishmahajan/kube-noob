"""What answers the question (G235).

`insight` recognises what was pasted. Asked a question in words about a job this product does, it used to run
the generic evidence-gathering steps -- `get pods`, `describe pod`, `get events` -- and return nothing. Those
answer "something is broken, what is it", which is a different question: eight of eighteen realistic questions
came back with no findings and no next step, in a product whose whole adoption story is "paste anything".

These tests hold three properties: the question reaches the command that answers it, the command named exists,
and a pasted error that is not a question gets no advice about any of them.
"""

from __future__ import annotations

import argparse
import sys

import pytest

from kube_noob.cli import build_parser
from kube_noob.insight import CAPABILITY_ROUTES, MAX_ROUTES, capability_routes


def _commands() -> set[tuple[str, ...]]:
    """Every command path the CLI serves, as a tuple: ("posture", "scan") and so on."""
    out: set[tuple[str, ...]] = set()

    def walk(parser: argparse.ArgumentParser, prefix: tuple[str, ...]) -> None:
        for action in parser._actions:
            if isinstance(action, argparse._SubParsersAction):
                for name, sub in action.choices.items():
                    out.add((*prefix, name))
                    walk(sub, (*prefix, name))

    walk(build_parser(), ())
    return out


def test_every_routed_command_exists() -> None:
    """A suggestion that cannot be run is worse than none: it reads as a product that does not know itself."""
    served = _commands()
    for _pattern, command, _why in CAPABILITY_ROUTES:
        for invocation in command.split("&&"):
            words = invocation.split()
            assert words and words[0] == "kube-noob", command
            path = tuple(w for w in words[1:] if not w.startswith("-") and not w.startswith("<"))
            # the longest prefix of the words that is a real command
            assert any(path[:n] in served for n in range(len(path), 0, -1)), f"{command}: no such command"


def test_every_route_says_why() -> None:
    for _pattern, command, why in CAPABILITY_ROUTES:
        # Lower case unless it starts with a proper noun, and no full stop: these are printed as a continuation
        # of the command above them, not as sentences of their own.
        assert why and not why.endswith("."), command
        assert why[0].islower() or why.split()[0].strip(",") in {"Kyverno", "Gatekeeper", "FedRAMP", "Red"}, command
        assert len(why) < 200, command


@pytest.mark.parametrize(
    ("question", "expected"),
    [
        ("which of our exposed services could reach a node?", "posture scan"),
        ("can a pod in shop reach a pod in payments?", "policy reach"),
        ("what could break if I upgrade OpenShift from 4.16 to 4.18?", "upgrade-risks"),
        ("we are going from 4.14 to 4.16, what should we watch out for", "upgrade-risks"),
        ("Kyverno 1.20 is dropping old policy types, are our policies affected?", "policy migrate-check"),
        ("which FedRAMP indicators does this speak to?", "ksi"),
        ("how do I suppress KN-S010 for one namespace until next quarter?", "exceptions check"),
        ("what is KN-S010 and why does it matter", "explain"),
        ("what does RHACS check that you do not?", "rhacs compare"),
        ("which of these CVEs actually matter in our cluster?", "vuln rank"),
        ("how do I fail a pull request when the audit finds something critical?", "gate"),
        ("what changed in our cluster since yesterday?", "posture diff"),
        ("why did my helm upgrade fail with a rendered manifest error?", "helm-audit"),
        ("my image build failed, what do I do", "build"),
        ("teach me about NetworkPolicy", "learn"),
        ("is this deployment safe to ship?", "audit"),
        ("what could go wrong with this application?", "vuln threat"),
        ("generate a Kyverno policy for this", "generate policies"),
        ("can you fix this manifest for me", "fix"),
        ("open this must-gather", "must-gather"),
    ],
)
def test_a_question_reaches_the_command_that_answers_it(question: str, expected: str) -> None:
    routes = [r["command"] for r in capability_routes(question)]
    assert routes, f"no route for {question!r}"
    assert expected in routes[0], f"{question!r} -> {routes}"


@pytest.mark.parametrize(
    "pasted",
    [
        "0/3 nodes are available: 3 Insufficient cpu.",
        'Error from server (Forbidden): pods is forbidden: User "x" cannot list resource "pods"',
        "Back-off restarting failed container",
        "CrashLoopBackOff",
        "ImagePullBackOff: rpc error: code = Unknown desc = failed to pull and unpack image",
        'MountVolume.SetUp failed for volume "data" : timed out waiting for the condition',
        "The node was low on resource: ephemeral-storage.",
        'admission webhook "validation.gatekeeper.sh" denied the request',
        "readiness probe failed: HTTP probe failed with statuscode: 503",
        'no matches for kind "Route" in version "apps.openshift.io/v1"',
        "kubectl get pods",
        "my cluster is slow",
        "hello",
        "what is a pod",
    ],
)
def test_a_pasted_error_is_not_answered_with_a_command_for_something_else(pasted: str) -> None:
    """An ImagePullBackOff is a runtime pull failure, not a build failure, and the build route matched it on
    "image" plus "failed" until that word came out of the pattern. A wrong suggestion reads as a product that
    does not know what it does."""
    assert capability_routes(pasted) == [], pasted


def test_a_pasted_manifest_or_log_is_never_routed() -> None:
    """Multi-line input is something pasted, not a question, and advice about `upgrade-risks` does not belong
    under somebody's stack trace."""
    manifest = "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: upgrade-me\nspec:\n  replicas: 1\n"
    assert capability_routes(manifest) == []
    assert capability_routes("why did the helm upgrade fail\n" + "x" * 50) == []
    assert capability_routes("is this deployment safe to ship? " + "y" * 700) == []


def test_at_most_two_suggestions() -> None:
    """A question that touches several jobs gets the two best, not a menu."""
    busy = (
        "which exposed services reach a node, can pods reach each other, what breaks on upgrade to 4.18, "
        "are our Kyverno policies affected, which FedRAMP indicators, and how do I fail the pull request"
    )
    assert len(capability_routes(busy)) == MAX_ROUTES


def test_the_insight_response_carries_the_routes_and_says_so() -> None:
    from kube_noob.config import load_settings
    from kube_noob.insight import insight
    from kube_noob.toolkit import Toolkit

    kit = Toolkit(load_settings())
    out = insight(kit, "which of our exposed services could reach a node?", platform="openshift")
    assert [r["command"] for r in out["answeredBy"]] == ["kube-noob posture scan -f <dir>"]
    assert "answeredBy" in out["approach"], "the reader has to be told where to look"


def test_the_terminal_prints_them(capsys: pytest.CaptureFixture[str]) -> None:
    from kube_noob import cli

    rc = cli.main(["insight", "which of our exposed services could reach a node?"])
    printed = capsys.readouterr().out
    assert rc == 0
    assert "kube-noob answers this directly:" in printed
    assert "posture scan" in printed


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(pytest.main([__file__, "-q", *sys.argv[1:]]))
