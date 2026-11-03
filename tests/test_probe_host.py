"""A `host` on a probe or lifecycle handler, and the Pod Security denial it causes.

KEP-4940 (sig-auth, psa-block-host-field-in-probes) adds a `probeHost` check to the Pod Security baseline: a
`host` on an httpGet or tcpSocket handler makes the kubelet -- a trusted node component -- open a connection to
that address on the pod's behalf. Anyone who can create a pod can therefore have the kubelet reach somewhere the
pod itself may not be allowed to, including node-local endpoints no NetworkPolicy sees.

Two gaps, one on each side of the deploy. `kube-noob audit` did not check the field at all, so nothing caught it
before admission. And `policy explain` had no entry for the check, so a real denial -- the message is
`probeHost (container "liveness" uses probeHost 135.45.63.4)` -- fell through to the generic branch, which
echoes the denial back as its own "fix" and attributes no rule, while `readOnlyNextSteps` still offered
`kube-noob fix`, which could do nothing for it.

The check name matters and was verified against the KEP rather than guessed: it is `probeHost`, one word. An
invented name would have produced a regex that matches nothing real, and a test written against the same
invention would have passed.
"""

from __future__ import annotations

from kube_noob.audit.engine import analyze
from kube_noob.debug.policy import explain

# Every path KEP-4940 names that this manifest can exercise: an initContainer probe, a container probe, and a
# lifecycle handler. The second container is clean and must stay clean.
MANIFEST = """
apiVersion: apps/v1
kind: Deployment
metadata: {name: web, namespace: app}
spec:
  selector: {matchLabels: {app: web}}
  template:
    metadata: {labels: {app: web}}
    spec:
      initContainers:
      - name: wait
        image: busybox
        readinessProbe: {tcpSocket: {host: 10.0.0.5, port: 5432}}
      containers:
      - name: liveness
        image: nginx
        livenessProbe: {httpGet: {host: 135.45.63.4, path: /healthz, port: 8080}}
        lifecycle: {preStop: {httpGet: {host: metadata.internal, path: /drain, port: 80}}}
      - name: clean
        image: nginx
        livenessProbe: {httpGet: {path: /healthz, port: 8080}}
"""

DENIAL = (
    'pods "web" is forbidden: violates PodSecurity "restricted:latest": '
    'probeHost (container "liveness" uses probeHost 135.45.63.4)'
)


def _findings() -> list[dict]:
    report = analyze(MANIFEST).as_dict()
    return [f for f in report["findings"] if f["ruleId"] == "KN-S029"]


def test_every_handler_with_a_host_is_found_including_init_containers_and_lifecycle() -> None:
    msgs = [f["message"] for f in _findings()]
    assert len(msgs) == 3, msgs
    assert any("'wait' sets readinessProbe.tcpSocket.host" in m for m in msgs), "initContainers count too"
    assert any("'liveness' sets livenessProbe.httpGet.host" in m for m in msgs)
    assert any("'liveness' sets lifecycle.preStop.httpGet.host" in m for m in msgs), "lifecycle handlers too"


def test_a_handler_without_a_host_is_not_a_finding() -> None:
    assert not any("'clean'" in f["message"] for f in _findings())


def test_the_finding_says_what_the_host_actually_causes() -> None:
    """ "has a host" is not a reason; "the kubelet connects there instead of the pod" is."""
    f = _findings()[0]
    assert "the kubelet connects to that address instead of the pod" in f["message"]
    assert f["controls"] == ["SC-7", "CM-7"]
    assert f["path"], "the finding has to point at the field, so `fix` and a reviewer can find it"


def test_the_pod_security_denial_is_attributed_and_gets_a_real_fix() -> None:
    d = explain(DENIAL, platform="kubernetes")["denials"][0]
    assert d["engine"] == "pod-security"
    assert d["relatedRules"] == ["KN-S029"], "the denial must point back at the rule that catches it pre-deploy"
    fixes = [c["change"] for c in d["proposedChanges"]]
    # The generic branch's shape was "Satisfy the <check> check: <the denial, repeated>".
    assert not any(c.startswith("Satisfy the probeHost check") for c in fixes), "that is the denial echoed back"
    fix = next(c for c in fixes if "host field" in c)
    assert "container liveness" in fix, "name the container the denial named"
    assert "tcpSocket" in fix and "lifecycle" in fix, "the KEP covers more paths than the one that tripped"


def test_the_check_name_is_the_one_the_kep_defines() -> None:
    """Guards the regex against drifting back to a plausible-looking invention."""
    assert explain(DENIAL, platform="kubernetes")["denials"][0]["details"]["violations"] == [
        {"check": "probeHost", "detail": 'container "liveness" uses probeHost 135.45.63.4'}
    ]
