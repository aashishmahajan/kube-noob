"""A cluster-scoped policy kube-noob cannot read must not be answered with a verdict.

`ClusterNetworkPolicy` (policy.networking.k8s.io/v1alpha2) sits above NetworkPolicy and is decided before it, and
this evaluator does not read it. The kind was already named under `notEvaluated` and already attached a caveat to
every proposed manifest -- but the verdict still said "allowed" and `kube-noob policy reach` still exited 0. A
note in a JSON list does not stop a CI gate, so a pipeline merged on an answer a `Deny` in that policy reverses.

This is not a future-API edge case. Calico 3.32 (13 May 2026) removed AdminNetworkPolicy and
BaselineAdminNetworkPolicy enforcement outright -- "You must migrate to ClusterNetworkPolicy before upgrading to
v3.32, as Calico will no longer enforce the old resources" -- so on a current Calico cluster the policy that
actually decides the traffic is the one kind this evaluator cannot read.

Deliberately NOT "denied": nothing here knows what the unread policy says. Unknown is the honest third answer,
the same one a same-priority AdminNetworkPolicy tie already gets.
"""

from __future__ import annotations

from kube_noob.debug.netpol import Inventory, check_reachability

WORKLOADS = """
apiVersion: v1
kind: Namespace
metadata: {name: web, labels: {kubernetes.io/metadata.name: web}}
---
apiVersion: apps/v1
kind: Deployment
metadata: {name: frontend, namespace: web}
spec:
  selector: {matchLabels: {app: frontend}}
  template:
    metadata: {labels: {app: frontend}}
    spec: {containers: [{name: app, image: nginx, ports: [{containerPort: 8080}]}]}
---
apiVersion: apps/v1
kind: Deployment
metadata: {name: api, namespace: web}
spec:
  selector: {matchLabels: {app: api}}
  template:
    metadata: {labels: {app: api}}
    spec: {containers: [{name: app, image: nginx, ports: [{containerPort: 8080}]}]}
"""

CNP = """
---
apiVersion: policy.networking.k8s.io/v1alpha2
kind: ClusterNetworkPolicy
metadata: {name: deny-all-cross-namespace}
spec:
  tier: Admin
  priority: 10
  subject: {namespaces: {}}
  ingress:
  - name: deny-everything
    action: Deny
    from: [{namespaces: {}}]
"""

SRC, DST = "web/deployment/frontend", "web/deployment/api"


def _reach(manifests: str) -> dict:
    return check_reachability(Inventory.from_yaml(manifests), SRC, DST, 8080, "TCP")


def test_an_unreadable_cluster_scoped_policy_makes_the_verdict_undetermined() -> None:
    out = _reach(WORKLOADS + CNP)
    assert out["verdict"] == "undetermined", (
        "no NetworkPolicy selects either pod, so the NetworkPolicy tier allows this -- but a "
        "ClusterNetworkPolicy Deny is decided first and would reverse it"
    )
    assert out["undeterminedBy"] == ["ClusterNetworkPolicy/deny-all-cross-namespace"]


def test_the_summary_says_unknown_and_names_the_policy_that_made_it_unknown() -> None:
    summary = _reach(WORKLOADS + CNP)["summary"]
    assert summary.startswith("Undetermined:")
    assert "ClusterNetworkPolicy/deny-all-cross-namespace" in summary
    assert "does not evaluate it yet" in summary
    # It must not be reported as a denial either: nothing here knows what the policy says.
    assert not summary.startswith("Denied")


def test_the_unread_policy_is_still_named_under_not_evaluated() -> None:
    """The verdict change is additive: the existing disclosure has to survive it."""
    out = _reach(WORKLOADS + CNP)
    assert any("ClusterNetworkPolicy/deny-all-cross-namespace" in n for n in out["notEvaluated"])


def test_without_the_cluster_scoped_policy_the_verdict_is_unchanged() -> None:
    out = _reach(WORKLOADS)
    assert out["verdict"] == "allowed"
    assert "undeterminedBy" not in out
    assert out["summary"].startswith("Allowed:")


def test_the_cli_exit_code_stops_a_gate_instead_of_passing_it() -> None:
    """`policy reach` returns 0 only for "allowed". Before this change the gate read 0 on an unknown answer,
    which is the whole reason the verdict and not just the note had to move."""
    from kube_noob.cli import main

    with_cnp = main(
        [
            "--format",
            "json",
            "policy",
            "reach",
            "--from",
            SRC,
            "--to",
            DST,
            "--port",
            "8080",
            "-f",
            _tmp(WORKLOADS + CNP),
        ]
    )
    without = main(
        ["--format", "json", "policy", "reach", "--from", SRC, "--to", DST, "--port", "8080", "-f", _tmp(WORKLOADS)]
    )
    assert with_cnp == 1, "an unknown verdict must fail a gate"
    assert without == 0, "and a genuinely allowed one must still pass it"


def _tmp(text: str) -> str:
    import tempfile
    from pathlib import Path

    p = Path(tempfile.mkdtemp()) / "m.yaml"
    p.write_text(text, encoding="utf-8")
    return str(p)


# --- the surface a human reads ---------------------------------------------------------------------------------
# G172 moved the verdict and the exit code, and put the reason in `undeterminedBy` and `summary`. Both are JSON
# keys. `_print_reach` printed neither, so the terminal showed "UNDETERMINED" over two lines reading "allowed"
# with nothing saying why -- the information was present and the surface a person reads ignored it, which is the
# defect this very commit was fixing one layer down.

CNP_PORT_8080 = """apiVersion: policy.networking.k8s.io/v1alpha2
kind: ClusterNetworkPolicy
metadata:
  name: deny-8080
spec:
  priority: 10
  subject:
    namespaces: {}
  ingress:
  - action: Deny
    from:
    - namespaces: {}
    protocols:
    - tcp:
        destinationPort: 8080
"""


def _reach_text(tmp_path, capsys) -> str:
    from pathlib import Path

    from kube_noob.cli import main

    example = Path(__file__).resolve().parent.parent / "examples" / "netpol-shop.yaml"
    manifests = tmp_path / "with-cnp.yaml"
    manifests.write_text(example.read_text(encoding="utf-8") + "\n" + CNP_PORT_8080, encoding="utf-8")
    code = main(
        [
            "policy",
            "reach",
            "-f",
            str(manifests),
            "--from",
            "web/frontend",
            "--to",
            "shop/orders-api",
            "--port",
            "8080",
        ]
    )
    assert code == 1, "an undetermined verdict is not a pass"
    return capsys.readouterr().out


def test_the_terminal_says_why_the_verdict_is_undetermined(tmp_path, capsys) -> None:
    out = _reach_text(tmp_path, capsys)
    assert "UNDETERMINED" in out
    head = out.partition("check (read-only)")[0]
    assert "ClusterNetworkPolicy/deny-8080" in head, (
        "the policy that made the answer unknown must be named above the check list, not left to the trailing "
        "'not evaluated' line among boilerplate"
    )
    assert "reverse" in head.lower(), "the reader has to be told it can go either way"


def test_the_check_list_tells_the_operator_to_look_at_the_policy_that_decides(tmp_path, capsys) -> None:
    """The read-only steps named adminnetworkpolicy and baselineadminnetworkpolicy but not the kind that
    actually made the verdict unknown, so following the printed advice could not resolve it."""
    out = _reach_text(tmp_path, capsys)
    # Only the commands. Partitioning on the heading also swallows the trailing "not evaluated:" line, which
    # does name the policy -- so a looser assertion here passes while the printed advice still cannot resolve
    # the verdict. That is the same mistake as G174: a test that matches the wrong text proves nothing.
    section = out.partition("check (read-only)")[2].partition("not evaluated")[0]
    commands = [ln.strip() for ln in section.splitlines() if ln.strip().startswith("kubectl")]
    assert commands, "no read-only commands were printed"
    assert any("clusternetworkpolicy" in c.lower() for c in commands), (
        "the printed checks name adminnetworkpolicy and baselineadminnetworkpolicy but not the kind that made "
        f"the verdict unknown, so following them cannot resolve it: {commands}"
    )
