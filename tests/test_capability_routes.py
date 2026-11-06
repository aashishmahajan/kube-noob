"""What answers the question (G235).

`insight` recognises what was pasted. Asked a question in words about a job this product does, it used to run
the generic evidence-gathering steps -- `get pods`, `describe pod`, `get events` -- and return nothing. Those
answer "something is broken, what is it", which is a different question: eight of eighteen realistic questions
came back with no findings and no next step, in a product whose whole adoption story is "paste anything".

These tests hold three properties: the question reaches the command that answers it, the command named exists,
and a pasted error that is not a question gets no advice about any of them.
"""

from __future__ import annotations

import contextlib
import io
import sys

import pytest

from kube_noob.cli import build_parser
from kube_noob.insight import CAPABILITY_ROUTES, MAX_ROUTES, capability_routes


def test_every_routed_command_actually_parses() -> None:
    """A suggestion that cannot be run is worse than none: it reads as a product that does not know itself.

    The first version of this test checked that the longest REAL PREFIX of the words was a command, which is a
    one-directional guard of the kind G206 is about: `kube-noob vuln rank` passed because `vuln` exists, and
    eight of the twenty printed invocations could not be run -- a missing `--port`, a required positional, a
    subcommand that does not exist, `-f` that means `--values`. It parses them now, which is the claim.
    """
    for _pattern, command, _why in CAPABILITY_ROUTES:
        for invocation in command.split("&&"):
            words = [("X" if w.startswith("<") else w) for w in invocation.split()]
            assert words and words[0] == "kube-noob", command
            err = io.StringIO()
            try:
                with contextlib.redirect_stderr(err), contextlib.redirect_stdout(io.StringIO()):
                    build_parser().parse_args(words[1:])
            except SystemExit:  # pragma: no cover - only on a regression
                last = (err.getvalue().strip().splitlines() or ["?"])[-1]
                pytest.fail(f"{invocation.strip()!r} does not parse: {last}")


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
        ("which of these CVEs actually matter in our cluster?", "vuln report"),
        ("how do I fail a pull request when the audit finds something critical?", "gate"),
        ("what changed in our cluster since yesterday?", "posture diff"),
        ("why did my helm upgrade fail with a rendered manifest error?", "helm-audit"),
        ("my image build failed, what do I do", "build"),
        ("teach me about NetworkPolicy", "learn"),
        ("is this deployment safe to ship?", "audit"),
        ("what could go wrong with this application?", "vuln threat"),
        ("generate a Kyverno policy for this", "policy generate"),
        ("can you fix this manifest for me", "fix"),
        ("open this must-gather", "must-gather analyze"),
        # Added after a red team listed questions with a precise answer and no route at all (G237).
        ("is this a known bug in OpenShift 4.20?", "known-issues"),
        ("why was my pod denied by the SCC?", "policy explain"),
        ("which of these Semgrep findings are in shipped code?", "code report"),
        ("red team these manifests, what would an attacker do?", "redteam"),
        ("scaffold a Helm chart for orders-api", "helm-chart"),
        ("which APIs are removed when we go to Kubernetes 1.32?", "audit"),
        # A third pass (G247): one question was answered with the wrong command and three had no answer at all.
        # "exposed in the public repo" is about Git -- the attack-path scan reads a cluster.
        ("which secrets are exposed in the public repo?", "audit"),
        ("did we commit a secret to git?", "audit"),
        ("we pushed an API key to github by mistake", "audit"),
        # And the plainest form of the question `posture scan` exists for matched nothing, because `internet`
        # and `public` sat in the first lookahead group where the second group could never also hold them.
        ("is anything in my cluster exposed to the internet?", "posture scan"),
        ("is my ingress internet-facing?", "posture scan"),
        ("are any of our services publicly reachable?", "posture scan"),
        ("can anything be reached from outside?", "posture scan"),
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


def test_a_pasted_denial_is_left_to_the_explainer_that_already_ran() -> None:
    """`policy explain` IS the right answer to "why was this denied", so the route is correct in substance -- but
    a pasted denial has already been through the denial explainer by the time the response is assembled, and
    repeating the command under its own output is noise. The kinds gate in `insight` is what distinguishes them,
    which is why that gate lives there and not in `capability_routes` (G237)."""
    from kube_noob.config import load_settings
    from kube_noob.insight import insight
    from kube_noob.toolkit import Toolkit

    denial = 'admission webhook "validation.gatekeeper.sh" denied the request: privileged containers are refused'
    assert capability_routes(denial), "the text alone does match the route"
    out = insight(Toolkit(load_settings()), denial, platform="openshift")
    assert out["answeredBy"] == [], "but the explainer already answered it"


# --- the second pass: what a red team found in the first (G237) --------------------------------------------------


@pytest.mark.parametrize(
    "text",
    [
        # A route word inside a resource NAME. `\b` treats `-`, `/`, `:` and `.` as boundaries, so these leaked.
        "pod ci-runner-gate-5 is in CrashLoopBackOff",
        "deployment gate in ci is failing readiness",
        "the build deployment keeps restarting, why",
        "my pod called upgrade-checker is OOMKilled, version 1.2",
        "the release pod in namespace migrate is pending",
        "deployment named control in namespace evidence is stuck",
        'Failed to pull image "quay.io/acme/build:latest": unauthorized',
        "OutOfSync: Deployment ci/gate is OutOfSync and Progressing",
        "service ingress-nginx in namespace public crashes on the new node",
        "why can't the app called threats connect to the lesson service",
        # A single word pretending to be two, because it was in both lookahead groups of its route.
        "gate",
        "Gate",
        "takeover",
        "blast radius",
        "threats",
        "evidence",
        "new cluster",
        "ok this",
        "check this",
        "wrong pod",
        "is this cluster ok?",
        # Questions `upgrade-risks` cannot answer: its snapshot holds OpenShift 4.18 and later only.
        "Error: UPGRADE FAILED: release upgrade failed: timed out waiting for the condition",
        "should we move from Calico to Cilium, what breaks?",
        "we are moving the cluster to a new VPC, what breaks?",
        "what version of cert-manager should I upgrade to?",
        "how do I update the node pool to a new instance type with no risk?",
        # Out of scope, or a malfunction rather than a question.
        "what is the blast radius of losing one node?",
        "how do I accept the risk of the node going down temporarily?",
        "I have an exception in my Java stack trace, which rule applies?",
        # G247: the words the exposure route gained must not fire on text that is not asking about exposure.
        "dial tcp: lookup api.example.com: no route to host",
        "the public internet gateway",
        "git commit",
        "publicly",
    ],
)
def test_nothing_is_routed_for_text_that_only_shares_words(text: str) -> None:
    """Every string here routed somewhere before the second pass, and each was wrong for one of three reasons:
    a route word sat inside a Kubernetes name, a word was in both lookahead groups of its route so one word
    satisfied both, or the sentence reports a malfunction and the answer is the diagnosis that already ran."""
    assert capability_routes(text) == [], f"{text!r} -> {capability_routes(text)}"


def test_no_word_is_in_two_lookahead_groups_of_a_route() -> None:
    """The structural guard. Every over-matching defect in this table has been this one: `fail` in both halves of
    the CI route, then `gate`, then `takeover` and `blast radius`, then `evidence`. A word in two groups makes a
    route fire on ONE word, which is exactly what requiring two groups was meant to prevent. `_route` refuses it
    at import, so this test is really asserting that the guard is still wired in."""
    from kube_noob import insight

    with pytest.raises(ValueError, match="two lookahead groups"):
        insight._route(r"(?i)(?=.*\bfail\b)(?=.*\b(?:fail|block)\b)")


def test_every_route_is_anchored_so_the_cost_stays_linear() -> None:
    """Unanchored, `search` retried each pattern's lookaheads from every one of up to 600 start positions: 75-92
    ms per call on a 600-character line that matches nothing, paid on every one-line paste, on every surface."""
    for pattern, command, _why in CAPABILITY_ROUTES:
        assert pattern.pattern.startswith("(?i)\\A"), command


def test_a_long_non_matching_line_is_cheap() -> None:
    import time

    worst = ("zzz " * 150)[:600]
    started = time.perf_counter()
    for _ in range(20):
        capability_routes(worst)
    each_ms = (time.perf_counter() - started) / 20 * 1000
    assert each_ms < 15, f"{each_ms:.1f} ms per call on a 600-char non-matching line"


@pytest.mark.parametrize(
    ("text", "first"),
    [
        ("why did the build fail in the CI pipeline?", "build diagnose"),
        ("which CVEs matter before we upgrade to 4.18?", "vuln report"),
        ("what is the risk of the Kyverno 1.14 upgrade for our policies?", "policy migrate-check"),
        ("scaffold a Helm chart for orders-api on ROSA HCP", "helm-chart"),
        ("how do I suppress KN-S010 for one namespace until next quarter?", "exceptions check"),
    ],
)
def test_the_better_answer_comes_first(text: str, first: str) -> None:
    """The cap is two and table order decides which of them leads, so the order is part of the answer."""
    routes = [r["command"] for r in capability_routes(text)]
    assert routes and first in routes[0], f"{text!r} -> {routes}"


def test_carriage_returns_count_as_a_line_break() -> None:
    """A manifest with old Mac line endings has no `\n` at all and was read as one long question."""
    assert capability_routes("apiVersion: apps/v1\rkind: Deployment\rmetadata:\r  name: upgrade\r") == []


@pytest.mark.parametrize(
    "pasted",
    [
        '{"apiVersion":"v1","kind":"Event","metadata":{"name":"x"},"message":"pods \\"gate-7d9f\\" is forbidden"}',
        '{"apiVersion":"apps/v1","kind":"Deployment","metadata":{"name":"upgrade","labels":{"version":"1.2"}}}',
        "NAME                 READY   STATUS             RESTARTS   AGE\ngate-7d9f-abc        0/1     "
        "CrashLoopBackOff   5          3m",
    ],
)
def test_a_recognised_artifact_is_not_routed_even_on_one_line(pasted: str) -> None:
    """`capability_routes` sees text, not kinds, so on its own it sent a pasted Event whose pod was called
    `gate-7d9f` to the CI gate and a Deployment named `upgrade` to `upgrade-risks`. `insight` gates on what was
    recognised, which is where that decision belongs (G237)."""
    from kube_noob.config import load_settings
    from kube_noob.insight import insight
    from kube_noob.toolkit import Toolkit

    out = insight(Toolkit(load_settings()), pasted, platform="openshift")
    assert out["answeredBy"] == [], f"{out['kinds']} -> {out['answeredBy']}"


def test_a_question_with_a_direct_answer_is_not_also_given_pod_triage_steps() -> None:
    """The steps G235 condemned were still printed underneath the right answer."""
    from kube_noob.config import load_settings
    from kube_noob.insight import insight
    from kube_noob.toolkit import Toolkit

    out = insight(Toolkit(load_settings()), "which of our exposed services could reach a node?", platform="openshift")
    assert out["answeredBy"]
    assert not out["findings"]
    assert out["readOnlyNextSteps"] == [], out["readOnlyNextSteps"]
    assert "gather" not in out["ran"]


def test_a_question_about_a_repository_is_not_answered_with_a_cluster_scan() -> None:
    """S6 from the second red team: "which secrets are exposed in the public repo?" got `posture scan`.

    It is a question about files in Git, and that command walks Routes, ServiceAccounts and RBAC in a cluster.
    The negative lookahead is the fix, and it is asserted here as well as by the route order, because the two
    routes would otherwise both match and the cap of two would simply hide the wrong one behind the right one.
    """
    for question in (
        "which secrets are exposed in the public repo?",
        "are there credentials committed in this repository?",
        "is any token exposed in our gitlab repos?",
    ):
        routes = [r["command"] for r in capability_routes(question)]
        assert routes and "audit" in routes[0], f"{question!r} -> {routes}"
        assert not any("posture scan" in r for r in routes), f"{question!r} -> {routes}"


def test_a_negative_lookahead_may_lead_a_route_and_is_still_anchored() -> None:
    """The structural guard had to learn one more shape, so the invariant it protects is asserted directly."""
    from kube_noob import insight

    pattern = insight._route(r"(?i)(?!.*\bgit\b)(?=.*\bexposed\b)(?=.*\bnode\b)")
    assert pattern.pattern.startswith("(?i)\\A")
    assert pattern.search("is the node exposed")
    assert not pattern.search("is the node exposed in git")
    with pytest.raises(ValueError, match="must start with"):
        insight._route(r"(?i)\bexposed\b")
