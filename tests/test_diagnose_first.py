"""Diagnose before change: read-only evidence first, anything that executes or mutates is labelled and gated."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from kube_noob.debug.diagnose import diagnose
from kube_noob.debug.playbooks import PLAYBOOKS
from kube_noob.debug.steps import classify_step, split_comment


@pytest.mark.parametrize(
    ("cmd", "kind"),
    [
        ("oc get pods -n shop", "read"),
        ("kubectl describe pod api-1 -n shop", "read"),
        ("oc logs api-1 -n shop --previous", "read"),
        ("oc auth can-i list pods --as=system:serviceaccount:a:b", "read"),
        ("oc adm top pod api-1 -n shop --containers", "read"),
        ("oc adm policy scc-subject-review -f pod.yaml", "read"),
        ("helm history orders -n shop", "read"),
        ("rosa describe cluster -c demo", "read"),
        ("skopeo inspect docker://quay.io/a/b:1", "read"),
        ("kube-noob audit -f k8s/", "read"),
        ("Read the policy names in the denial message.", "read"),
        ("oc rsh -n shop api-1 id", "exec"),
        ("kubectl exec -it api-1 -- sh", "exec"),
        ("oc debug node/ip-10-0-1-1", "exec"),
        ("openssl s_client -connect a.example.com:443", "exec"),
        ("oc delete pod api-1 -n shop", "change"),
        ("kubectl apply -f fix.yaml", "change"),
        ("oc patch deployment api -p '{}'", "change"),
        ("oc rollout restart deployment/api", "change"),
        ("oc adm drain node-1", "change"),
        ("helm rollback orders 3", "change"),
        ("rosa edit machinepool -c demo pool --replicas 3", "change"),
        ("oc scale deployment api --replicas=0", "change"),
    ],
)
def test_classify_step(cmd: str, kind: str) -> None:
    assert classify_step(cmd) == kind


def test_playbook_checks_never_mutate() -> None:
    offenders = [(p.pid, c) for p in PLAYBOOKS for c in p.checks if classify_step(c) == "change"]
    assert offenders == []
    assert all(any(classify_step(c) == "read" for c in p.checks) for p in PLAYBOOKS)


def test_diagnosis_orders_read_only_steps_first_and_gates_the_rest() -> None:
    text = "Warning BackOff pod/api-1 Back-off restarting failed container\nNamespace: shop\n"
    d = diagnose(text).as_dict()["diagnoses"][0]
    keys = list(d)
    assert keys.index("readOnlyNextSteps") < keys.index("diagnosticCommands") < keys.index("proposedChanges")
    steps = d["readOnlyNextSteps"]
    assert steps and all(classify_step(s.get("command") or s["instruction"]) == "read" for s in steps)
    assert all(c["requiresApproval"] for c in d["diagnosticCommands"] + d["proposedChanges"])
    probe = diagnose("Readiness probe failed: HTTP probe failed with statuscode: 503 pod/api-1").as_dict()
    rsh = [c for dg in probe["diagnoses"] for c in dg["diagnosticCommands"] if "rsh" in c["command"]]
    assert rsh and all(c["requiresApproval"] for c in rsh)


def test_bundle_writes_redacted_read_only_evidence(tmp_path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    import json
    import os

    from kube_noob.cli import main
    from tests.test_debug import _fake_kubectl

    log = _fake_kubectl(tmp_path)
    monkeypatch.setenv("PATH", f"{tmp_path / 'bin'}{os.pathsep}{os.environ['PATH']}")
    out = tmp_path / "bundle"
    rc = main(["bundle", "deployment/api", "-n", "orders", "--cluster-enabled", "-o", str(out)])
    assert rc == 0
    data = json.loads((out / "bundle.json").read_text())
    md = (out / "bundle.md").read_text()
    assert data["target"] == "deployment/orders/api" and data["diagnoses"]
    assert "hunter2" not in md and "hunter2" not in json.dumps(data)
    assert md.index("Read-only next steps") < md.index("Proposed changes (require approval)")
    argvs = [json.loads(line) for line in log.read_text().splitlines()]
    assert all(a[0] in {"get", "logs", "version"} for a in argvs), "only read-only commands"


@pytest.mark.parametrize(
    ("raw", "cmd", "why"),
    [
        (
            "oc logs p -n a --previous            # output of the crashed attempt",
            "oc logs p -n a --previous",
            "output of the crashed attempt",
        ),
        (
            "oc get ns a -o jsonpath='{.metadata.annotations.x#y}'",
            "oc get ns a -o jsonpath='{.metadata.annotations.x#y}'",
            None,
        ),
        ('oc get pods -l "app=a # b"  # quoted hash stays', 'oc get pods -l "app=a # b"', "quoted hash stays"),
        ("oc get pods", "oc get pods", None),
    ],
)
def test_split_comment(raw: str, cmd: str, why: str | None) -> None:
    assert split_comment(raw) == (cmd, why)


def test_no_copyable_command_carries_a_shell_comment() -> None:
    """zsh treats `#` as an argument unless interactivecomments is set, so pasted commands must be comment-free."""
    texts = [
        "Warning BackOff pod/api-1 Back-off restarting failed container\nNamespace: shop\n",
        'pods "a-" is forbidden: unable to validate against any security context constraint',
        "x509: certificate signed by unknown authority",
        "Readiness probe failed: HTTP probe failed with statuscode: 503 pod/api-1",
    ]
    for text in texts:
        for d in diagnose(text).as_dict()["diagnoses"]:
            cmds = [s["command"] for s in d["readOnlyNextSteps"] if "command" in s]
            cmds += [c["command"] for c in d["diagnosticCommands"]]
            assert cmds and not [c for c in cmds if split_comment(c)[1] is not None], d["id"]


def test_specific_cause_outranks_generic_crashloop() -> None:
    text = (
        "Reason: CrashLoopBackOff\nLast State: Terminated\n  Reason: OOMKilled\n  Exit Code: 137\n"
        "Warning BackOff kubelet Back-off restarting failed container api in pod api-1_shop"
    )
    assert [d["id"] for d in diagnose(text).as_dict()["diagnoses"]][:2] == ["DBG-OOM", "DBG-CRASHLOOP"]


def test_diagnose_cli_takes_pasted_text_a_file_or_stdin(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    import io

    from kube_noob.cli import main

    pasted = (
        'Warning FailedCreate replicaset/api-7d9f Error creating: pods "api-7d9f-" is forbidden: unable to validate '
        'against any security context constraint: [provider "restricted-v2": .containers[0].runAsUser: Invalid value: '
        "1000: must be in the ranges: [1000680000, 1000689999]]\nNormal ScalingReplicaSet deployment/api Scaled up"
    )

    def top(argv: list[str]) -> str:
        assert main([*argv, "--format", "json"]) == 0
        return str(json.loads(capsys.readouterr().out)["diagnoses"][0]["id"])

    assert top(["diagnose", "-f", pasted]) == "DBG-SCC"
    assert top(["diagnose", pasted]) == "DBG-SCC"
    assert top(["diagnose", "Reason: OOMKilled", "Exit Code: 137"]) == "DBG-OOM"
    events = tmp_path / "events.txt"
    events.write_text(pasted)
    assert top(["diagnose", "-f", str(events)]) == "DBG-SCC"
    monkeypatch.setattr("sys.stdin", io.StringIO("Failed to pull image: manifest unknown\nImagePullBackOff\n"))
    assert top(["diagnose"]) == "DBG-IMAGEPULL"
    assert top(["diagnose", "-f", "x" * 5000 + " CrashLoopBackOff"])
    assert main(["diagnose", "-f", str(tmp_path / "evnts.txt")]) == 2
    assert "no such file" in capsys.readouterr().err
    assert main(["diagnose", "text", "-f", str(events)]) == 2


def test_x509_rbac_and_platform_specific_steps() -> None:
    """Client-side x509 needs local checks, RBAC errors name the real subject, Kubernetes gets kubectl."""
    x509 = diagnose("Unable to connect to the server: x509: certificate signed by unknown authority").as_dict()
    top = x509["diagnoses"][0]
    assert top["id"] == "DBG-X509-CLIENT"
    assert all(not s["command"].startswith("oc get") for s in top["readOnlyNextSteps"])
    rbac = diagnose(
        'Error from server (Forbidden): pods is forbidden: User "dev" cannot list resource "pods" in API group "" '
        'in the namespace "shop"'
    ).as_dict()["diagnoses"][0]
    assert rbac["readOnlyNextSteps"][0]["command"] == "oc auth can-i list pods -n shop --as=dev"
    nginx = diagnose('[emerg] mkdir() "/var/cache/nginx/client_temp" failed (13: Permission denied)').as_dict()
    assert nginx["diagnoses"][0]["id"] == "DBG-ARBITRARY-UID"
    k8s = diagnose("Reason: OOMKilled\nExit Code: 137", platform="kubernetes").as_dict()["diagnoses"][0]
    commands = [s["command"] for s in k8s["readOnlyNextSteps"]]
    assert commands and all(c.startswith(("kubectl", "openssl")) for c in commands)
