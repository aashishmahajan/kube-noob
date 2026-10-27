"""Regression tests for the independent red-team review (fixer, generator and rule correctness)."""

from __future__ import annotations

import pydantic
import pytest

from kube_noob.audit.engine import analyze
from kube_noob.audit.fixer import fix_manifests
from kube_noob.audit.podspec import pdb_allows_no_disruption
from kube_noob.generate.blueprint import Blueprint
from kube_noob.generate.manifests import generate
from kube_noob.yamlio import load_documents


def _rules(yaml_text: str, platform: str = "kubernetes", version: str | None = None) -> list[tuple[str, str]]:
    rep = analyze(load_documents(yaml_text), platform=platform, version=version)
    return [(f.rule_id, f.severity.name) for f in rep.findings]


def _deploy(container: str, pod_sc: str = "") -> str:
    return (
        "apiVersion: apps/v1\nkind: Deployment\nmetadata: {name: a, namespace: n}\nspec:\n"
        "  selector: {matchLabels: {app: a}}\n  template:\n    metadata: {labels: {app: a}}\n    spec:\n"
        f"{pod_sc}      containers:\n{container}"
    )


def test_fixer_leaves_privileged_containers_valid() -> None:
    res = fix_manifests(_deploy("      - name: cni\n        image: x:1\n        securityContext: {privileged: true}\n"))
    sc = res.documents[0]["spec"]["template"]["spec"]["containers"][0]["securityContext"]
    # API validation rejects allowPrivilegeEscalation: false together with privileged: true
    assert sc == {"privileged": True}
    assert any("privileged" in m for m in res.manual)
    cap = fix_manifests(
        _deploy(
            "      - name: a\n        image: x:1\n        securityContext: {capabilities: {add: [CAP_SYS_ADMIN]}}\n"
        )
    )
    assert (
        "allowPrivilegeEscalation"
        not in cap.documents[0]["spec"]["template"]["spec"]["containers"][0]["securityContext"]
    )


def test_fixer_does_not_add_pod_run_as_non_root_over_root_containers() -> None:
    two = (
        "      - name: legacy\n        image: x:1\n        securityContext: {runAsUser: 0}\n"
        "      - name: app\n        image: y:1\n"
    )
    res = fix_manifests(_deploy(two))
    pod = res.documents[0]["spec"]["template"]["spec"]
    assert "runAsNonRoot" not in pod["securityContext"]
    legacy, app = pod["containers"]
    assert "runAsNonRoot" not in legacy["securityContext"] and app["securityContext"]["runAsNonRoot"] is True


def test_fixer_handles_null_security_contexts_and_duplicate_firewalls() -> None:
    res = fix_manifests(
        _deploy("      - name: a\n        image: x:1\n        securityContext:\n", pod_sc="      securityContext:\n")
    )
    c = res.documents[0]["spec"]["template"]["spec"]["containers"][0]
    assert c["securityContext"]["allowPrivilegeEscalation"] is False
    caps = fix_manifests(
        _deploy("      - name: a\n        image: x:1\n        securityContext: {capabilities: null}\n")
    ).documents[0]["spec"]["template"]["spec"]["containers"][0]["securityContext"]
    assert caps["capabilities"] == {"drop": ["ALL"]}
    fw = (
        "apiVersion: k8s.ovn.org/v1\nkind: EgressFirewall\nmetadata: {name: a, namespace: etl}\n"
        "spec: {egress: [{type: Deny, to: {cidrSelector: 0.0.0.0/0}}]}\n---\n"
        "apiVersion: k8s.ovn.org/v1\nkind: EgressFirewall\nmetadata: {name: b, namespace: etl}\n"
        "spec: {egress: [{type: Allow, to: {dnsName: x.example.com}}]}\n"
    )
    out = fix_manifests(fw, platform="openshift")
    assert [d["metadata"]["name"] for d in out.documents] == ["default", "b"]
    assert any("merge these rules" in m for m in out.manual)


def test_run_as_group_is_not_an_scc_violation() -> None:
    y = _deploy(
        "      - name: a\n        image: x:1\n        securityContext: {runAsGroup: 3000}\n",
        pod_sc="      securityContext: {runAsGroup: 3000, fsGroup: 2000}\n",
    )
    s004 = [r for r in _rules(y, "openshift") if r[0] == "KN-S004"]
    assert s004 == [("KN-S004", "HIGH")]  # fsGroup only
    fixed = fix_manifests(y, platform="openshift").documents[0]["spec"]["template"]["spec"]
    assert fixed["securityContext"]["runAsGroup"] == 3000 and "fsGroup" not in fixed["securityContext"]
    assert fixed["containers"][0]["securityContext"]["runAsGroup"] == 3000


def test_internal_load_balancer_annotations() -> None:
    svc = (
        "apiVersion: v1\nkind: Service\nmetadata:\n  name: s\n  namespace: n\n  annotations:\n    {ann}\n"
        "spec: {{type: LoadBalancer, selector: {{app: a}}, ports: [{{port: 80}}]{extra}}}\n"
    )
    aws = svc.format(ann="service.beta.kubernetes.io/aws-load-balancer-scheme: internal", extra="")
    assert not [r for r in _rules(aws) if r[0] == "KN-N004"]
    gke = svc.format(ann="networking.gke.io/load-balancer-type: Internal", extra="")
    assert not [r for r in _rules(gke) if r[0] == "KN-N004"]
    public = svc.format(ann="foo: bar", extra=", loadBalancerSourceRanges: [0.0.0.0/0]")
    assert [r for r in _rules(public) if r[0] == "KN-N004"]


def test_networkpolicy_allow_all_peers() -> None:
    np = (
        "apiVersion: networking.k8s.io/v1\nkind: NetworkPolicy\nmetadata: {name: p, namespace: n}\n"
        "spec:\n  podSelector: {}\n  ingress:\n  - from: [{ipBlock: {cidr: 0.0.0.0/0}}]\n"
        "  - from: [{namespaceSelector: {}}]\n  - from: [{namespaceSelector: {}, podSelector: {matchLabels: {a: b}}}]\n"
    )
    rep = analyze(load_documents(np), platform="kubernetes")
    paths = sorted(f.path for f in rep.findings if f.rule_id == "KN-N007")
    assert paths == ["spec.ingress[0].from[0].ipBlock", "spec.ingress[1].from[0].namespaceSelector"]


def test_names_and_pdb_percentages() -> None:
    ns = "apiVersion: v1\nkind: Namespace\nmetadata: {name: team.a}\n"
    assert ("KN-V009", "HIGH") in _rules(ns)
    svc = "apiVersion: v1\nkind: Service\nmetadata: {name: 1st, namespace: n}\nspec: {ports: [{port: 80}]}\n"
    assert ("KN-V009", "HIGH") in _rules(svc)
    assert pdb_allows_no_disruption({"minAvailable": "90%"}, 2)
    assert not pdb_allows_no_disruption({"minAvailable": "50%"}, 2)
    assert not pdb_allows_no_disruption({"maxUnavailable": "10%"}, 3)  # rounds up to 1
    assert pdb_allows_no_disruption({"maxUnavailable": "0%"}, 3)


def test_gateway_api_is_built_in_on_openshift_419_plus() -> None:
    hr = (
        "apiVersion: gateway.networking.k8s.io/v1\nkind: HTTPRoute\nmetadata: {name: r, namespace: n}\n"
        "spec: {parentRefs: [{name: gw}], rules: [{backendRefs: [{name: s, port: 80}]}]}\n"
    )
    assert not [r for r in _rules(hr, "openshift", "4.22") if r[0] == "KN-V004"]
    assert [r for r in _rules(hr, "openshift", "4.18") if r[0] == "KN-V004"]
    assert [r for r in _rules(hr, "kubernetes") if r[0] == "KN-V004"]


def test_generator_passthrough_probes_and_input_validation() -> None:
    bp = Blueprint.model_validate(
        {
            "name": "tls",
            "namespace": "web",
            "image": "quay.io/a/tls:1.0.0",
            "platform": "openshift",
            "exposure": {"type": "route", "tls": "passthrough", "host": "tls.apps.example.com"},
        }
    )
    gen = generate(bp)
    dep = next(o for o in gen.objects if o["kind"] == "Deployment")
    probe = dep["spec"]["template"]["spec"]["containers"][0]["readinessProbe"]["httpGet"]
    assert probe["scheme"] == "HTTPS" and any("passthrough" in p for p in gen.prerequisites)
    base = {"name": "x", "namespace": "y", "image": "nginx:1.27"}
    for bad in (
        {"portName": "a-very-long-port-name"},
        {"portName": "a--b"},
        {"egressCidrs": ["10.0.0.0/33"]},
        {"platform": "openshift", "exposure": {"type": "route", "host": "*.apps.example.com"}},
    ):
        with pytest.raises(pydantic.ValidationError):
            Blueprint.model_validate({**base, **bad})
    assert Blueprint.model_validate({**base, "egressCidrs": ["10.0.0.1/8"]}).egress_cidrs == ["10.0.0.0/8"]


def test_literal_credentials_in_args() -> None:
    y = _deploy(
        "      - name: a\n        image: x:1\n"
        '        args: ["--db-password=hunter2", "--api-key=$(API_KEY)", "--password-file=/etc/p"]\n'
        '        env: [{name: DATABASE_URL, value: "postgres://app:hunter2@db/app"}]\n'
    )
    rep = analyze(load_documents(y), platform="kubernetes")
    paths = sorted(f.path for f in rep.findings if f.rule_id == "KN-S013")
    assert paths == ["spec.template.spec.containers[0].args[0]", "spec.template.spec.containers[0].env[0].value"]
