"""ImagePullBackOff when the pull secret sits in a different namespace from the pod (asked on the launch post).

kubelet looks up each imagePullSecrets name in the pod's own namespace (getPullSecretsForPod in
pkg/kubelet/kubelet_pods.go) and, when the pull then fails, emits Warning FailedToRetrieveImagePullSecret "Unable to
retrieve some image pull secrets (<names>); attempting to pull the image may not succeed." (pkg/kubelet/kubelet.go).
Every surface must name that cause, the secret and the namespace, and give read-only checks first: the CLI, the MCP
server, the live (sidecar) debug and the audit of a bundle before it is deployed.
"""

from __future__ import annotations

import json
import os
import stat
from pathlib import Path
from typing import Any

import anyio
import pytest
from mcp import Client

from kube_noob.audit.engine import analyze
from kube_noob.cli import main
from kube_noob.config import load_settings
from kube_noob.debug.backends import KubectlBackend
from kube_noob.debug.diagnose import debug_workload, diagnose, extract_context
from kube_noob.server.mcp_app import build_server
from kube_noob.signals import for_text, playbooks_for

EVENTS = """\
Events:
  Type     Reason                           Age                From               Message
  ----     ------                           ----               ----               -------
  Normal   Scheduled                        2m                 default-scheduler  Successfully assigned shop/web-7d9c6b9f5-x2k8p to worker-1
  Normal   Pulling                          60s (x3 over 2m)   kubelet            Pulling image "quay.io/acme/private-web:1.4.2"
  Warning  Failed                           60s (x3 over 2m)   kubelet            Failed to pull image "quay.io/acme/private-web:1.4.2": reading manifest 1.4.2 in quay.io/acme/private-web: unauthorized: access to the requested resource is not authorized
  Warning  Failed                           60s (x3 over 2m)   kubelet            Error: ErrImagePull
  Warning  FailedToRetrieveImagePullSecret  60s (x3 over 2m)   kubelet            Unable to retrieve some image pull secrets (regcred); attempting to pull the image may not succeed.
  Normal   BackOff                          30s (x4 over 2m)   kubelet            Back-off pulling image "quay.io/acme/private-web:1.4.2"
  Warning  Failed                           30s (x4 over 2m)   kubelet            Error: ImagePullBackOff
"""  # noqa: E501 - the shape `oc describe pod` prints
QUESTION = "ImagePullBackOff when the pull secret sits in a different namespace from the pod"
BUNDLE = """\
apiVersion: v1
kind: Secret
metadata: {name: regcred, namespace: build}
type: kubernetes.io/dockerconfigjson
data: {.dockerconfigjson: e30=}
---
apiVersion: v1
kind: ServiceAccount
metadata: {name: web, namespace: shop}
imagePullSecrets: [{name: regcred}]
---
apiVersion: apps/v1
kind: Deployment
metadata: {name: web, namespace: shop}
spec:
  selector: {matchLabels: {app: web}}
  template:
    metadata: {labels: {app: web}}
    spec:
      serviceAccountName: web
      imagePullSecrets: [{name: regcred}]
      containers: [{name: web, image: "quay.io/acme/private-web:1.4.2"}]
"""


def test_events_name_the_cause_the_secret_and_the_namespace() -> None:
    out = diagnose(EVENTS, platform="openshift").as_dict()
    assert out["context"]["ns"] == "shop" and out["context"]["secret"] == "regcred"
    top = out["diagnoses"][0]
    assert top["id"] == "DBG-PULLSECRET" and out["diagnoses"][1]["id"] == "DBG-IMAGEPULL"
    assert "kubelet looks up regcred in shop" in top["rootCauses"][0]
    steps = [s["command"] for s in top["readOnlyNextSteps"]]
    assert "oc get secrets -A --field-selector metadata.name=regcred" in " ".join(steps)
    assert all(not s.startswith(("oc create", "oc patch", "oc set", "oc policy")) for s in steps)
    fixes = " ".join(c["change"] for c in top["proposedChanges"])
    assert "oc secrets link default regcred --for=pull -n shop" in fixes
    assert "system:image-puller system:serviceaccount:shop:default" in fixes and "openshift-config" in fixes
    assert all(c["requiresApproval"] for c in top["proposedChanges"]) and "{" not in fixes.replace("{.", "")


def test_plain_kubernetes_gets_kubectl_and_no_openshift_fixes() -> None:
    top = diagnose(EVENTS, platform="kubernetes").as_dict()["diagnoses"][0]
    fixes = " ".join(c["change"] for c in top["proposedChanges"])
    assert top["id"] == "DBG-PULLSECRET"
    assert "kubectl patch serviceaccount default -n shop" in fixes and '"name": "regcred"' in fixes
    assert "openshift-config" not in fixes and "image-puller" not in fixes
    assert not any(c.startswith("[OCP]") for c in top["rootCauses"])


def test_the_question_as_asked() -> None:
    out = diagnose(QUESTION, platform="openshift").as_dict()
    assert out["diagnoses"][0]["id"] == "DBG-PULLSECRET"
    assert "ns" not in out["context"]  # "a different namespace from the pod" names no namespace


@pytest.mark.parametrize(
    ("text", "ns"),
    [
        ("the secret is in another namespace from the pod", None),
        ("pods in namespace shop fail", "shop"),
        ("oc get pods -n shop", "shop"),
        ('pods is forbidden ... in the namespace "orders"', "orders"),
        ("namespace default has no pull secret", "default"),
        ("Successfully assigned payments/api-1 to worker-2", "payments"),
    ],
)
def test_namespace_context_skips_english_words(text: str, ns: str | None) -> None:
    assert extract_context(text).get("ns") == ns


def test_signal_is_catalogued_and_points_at_the_playbook() -> None:
    signals = for_text(EVENTS)
    assert any(s.kind == "event_reason" and s.name == "FailedToRetrieveImagePullSecret" for s in signals)
    assert "DBG-PULLSECRET" in playbooks_for(signals)


def _c013(bundle: str) -> list[dict[str, Any]]:
    return [f.as_dict() for f in analyze(bundle, "openshift", "4.21").findings if f.rule_id == "KN-C013"]


def test_audit_finds_the_secret_in_the_wrong_namespace_before_deploy() -> None:
    findings = _c013(BUNDLE)
    assert {f["resource"] for f in findings} == {"Deployment/shop/web", "ServiceAccount/shop/web"}
    assert all("defined in namespace build, not in shop" in f["message"] for f in findings)
    assert all(f["severity"] == "high" for f in findings)
    same_ns = BUNDLE.replace("namespace: build", "namespace: shop")
    assert not _c013(same_ns)
    no_secret = BUNDLE.split("---\n", 1)[1]
    assert not _c013(no_secret)


def test_cli_and_mcp_give_the_same_answer(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    assert main(["diagnose", EVENTS, "--platform", "openshift", "--format", "json"]) == 0
    cli = json.loads(capsys.readouterr().out)
    server = build_server(load_settings(overrides={"dataDir": str(tmp_path)}))

    async def run() -> Any:
        async with Client(server) as c:
            res = await c.call_tool("kubenoob_diagnose", {"text": EVENTS, "platform": "openshift"})
            return res.structured_content

    mcp = anyio.run(run)
    assert cli["diagnoses"][0]["id"] == mcp["diagnoses"][0]["id"] == "DBG-PULLSECRET"
    assert mcp["diagnoses"][0]["rootCauses"] == cli["diagnoses"][0]["rootCauses"]


def _fake_cluster(tmp_path: Path) -> Path:
    log = tmp_path / "argv.log"
    script = tmp_path / "bin" / "kubectl"
    script.parent.mkdir()
    pod = {
        "metadata": {"name": "web-7d9c6b9f5-x2k8p", "namespace": "shop"},
        "spec": {"nodeName": "worker-1", "serviceAccountName": "web", "imagePullSecrets": [{"name": "regcred"}]},
        "status": {
            "phase": "Pending",
            "containerStatuses": [
                {
                    "name": "web",
                    "ready": False,
                    "restartCount": 0,
                    "state": {"waiting": {"reason": "ImagePullBackOff", "message": "Back-off pulling image"}},
                }
            ],
        },
    }
    deploy = {"metadata": {"name": "web"}, "spec": {"selector": {"matchLabels": {"app": "web"}}}, "status": {}}
    events = {
        "items": [
            {
                "type": "Warning",
                "reason": "FailedToRetrieveImagePullSecret",
                "message": "Unable to retrieve some image pull secrets (regcred); attempting to pull the image may "
                "not succeed.",
                "involvedObject": {"kind": "Pod", "name": "web-7d9c6b9f5-x2k8p"},
                "lastTimestamp": "2026-10-28T10:00:00Z",
            },
            {
                "type": "Warning",
                "reason": "Failed",
                "message": "Error: ImagePullBackOff",
                "involvedObject": {"kind": "Pod", "name": "web-7d9c6b9f5-x2k8p"},
                "lastTimestamp": "2026-10-28T10:00:01Z",
            },
        ]
    }
    sa = {"metadata": {"name": "web"}, "imagePullSecrets": [{"name": "regcred"}]}
    script.write_text(f"""#!/usr/bin/env python3
import json, sys
open({str(log)!r}, "a").write(json.dumps(sys.argv[1:]) + "\\n")
args = sys.argv[1:]
if args[0] == "logs":
    print("")
elif args[0] == "version":
    print(json.dumps({{"serverVersion": {{"gitVersion": "v1.35.1"}}}}))
elif args[1] == "deployments.apps":
    print({json.dumps(deploy)!r})
elif args[1] == "events":
    print({json.dumps(events)!r})
elif args[1] == "serviceaccounts":
    print({json.dumps(sa)!r})
elif args[1] == "secrets":
    raise SystemExit("secrets must never be read")
else:
    print({json.dumps({"items": [pod]})!r})
""")
    script.chmod(script.stat().st_mode | stat.S_IEXEC)
    return log


def test_live_debug_in_the_sidecar_reads_names_never_secrets(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    log = _fake_cluster(tmp_path)
    monkeypatch.setenv("PATH", f"{tmp_path / 'bin'}{os.pathsep}{os.environ['PATH']}")
    out = debug_workload(KubectlBackend("kubectl", context=None, timeout=10), "shop", "deployment", "web")
    assert out["diagnoses"][0]["id"] == "DBG-PULLSECRET"
    assert "spec serviceAccountName=web imagePullSecrets=['regcred']" in "\n".join(out["evidence"])
    assert "serviceaccount/web imagePullSecrets=['regcred']" in out["evidence"]
    fixes = " ".join(c["change"] for c in out["diagnoses"][0]["proposedChanges"])
    assert "oc secrets link web regcred --for=pull -n shop" in fixes
    argvs = [json.loads(line) for line in log.read_text().splitlines()]
    assert all(a[0] in {"get", "logs", "version"} for a in argvs)
    assert not any(len(a) > 1 and a[1].startswith("secrets") for a in argvs)
