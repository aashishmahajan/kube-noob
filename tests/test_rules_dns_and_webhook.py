"""Two defects a manifest can prove and kube-noob did not report.

KN-N013: a default-deny egress policy with no allowance for cluster DNS. Every workload it selects stops
resolving names, which looks like an application outage rather than a policy change. It is the most-cited
NetworkPolicy footgun there is, and it is decidable from the YAML.

KN-S030: a validating or mutating admission webhook with `failurePolicy: Ignore`. The cluster believes it
has the control; whenever the webhook service is unreachable the control is silently not applied. The
default is `Fail`, so only an explicit Ignore is a decision someone made.

Both rules have to survive the obvious false positive. NetworkPolicies are ADDITIVE: a deny-all-egress
policy beside a policy that allows 53 leaves DNS working, so the rule reasons over the union of every
egress policy selecting the pod, not over one policy at a time.
"""

from __future__ import annotations

import re
from pathlib import Path

from kube_noob.audit.engine import analyze

ROOT = Path(__file__).resolve().parents[1]

_APP = """
apiVersion: apps/v1
kind: Deployment
metadata: {name: app, namespace: prod}
spec:
  selector: {matchLabels: {app: app}}
  template:
    metadata: {labels: {app: app}}
    spec:
      containers: [{name: c, image: acme/app@sha256:%s}]
""" % ("a" * 64)

_DENY_EGRESS = """
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: {name: deny-egress, namespace: prod}
spec:
  podSelector: {}
  policyTypes: [Egress]
"""

_DNS_ALLOWED = """
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: {name: allow-dns, namespace: prod}
spec:
  podSelector: {}
  policyTypes: [Egress]
  egress:
    - ports: [{protocol: UDP, port: 53}, {protocol: TCP, port: 53}]
"""

_DENY_INGRESS_ONLY = """
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: {name: deny-ingress, namespace: prod}
spec:
  podSelector: {}
  policyTypes: [Ingress]
"""


def _ids(*parts: str) -> set[str]:
    return {f.rule_id for f in analyze("\n---\n".join(parts), "kubernetes", None).findings}


def test_deny_all_egress_without_dns_is_reported() -> None:
    assert "KN-N013" in _ids(_APP, _DENY_EGRESS)


def test_a_second_policy_allowing_dns_clears_it() -> None:
    """NetworkPolicies are additive. This is the false positive the rule must not have."""
    assert "KN-N013" not in _ids(_APP, _DENY_EGRESS, _DNS_ALLOWED)


def test_one_policy_that_allows_dns_is_fine() -> None:
    assert "KN-N013" not in _ids(_APP, _DNS_ALLOWED)


def test_an_ingress_only_policy_does_not_touch_dns() -> None:
    assert "KN-N013" not in _ids(_APP, _DENY_INGRESS_ONLY)


def test_no_egress_policy_at_all_is_not_a_dns_finding() -> None:
    """Without an egress policy, egress is unrestricted; there is nothing to report."""
    assert "KN-N013" not in _ids(_APP)


def test_an_allow_all_egress_rule_clears_it() -> None:
    allow_all = _DENY_EGRESS.replace("policyTypes: [Egress]", "policyTypes: [Egress]\n  egress: [{}]")
    assert "KN-N013" not in _ids(_APP, allow_all)


_WEBHOOK = """
apiVersion: admissionregistration.k8s.io/v1
kind: %s
metadata: {name: gate}
webhooks:
  - name: gate.example.com
    failurePolicy: %s
    sideEffects: None
    admissionReviewVersions: [v1]
    clientConfig: {service: {name: gate, namespace: sec, path: /validate}}
    rules: [{operations: [CREATE], apiGroups: [""], apiVersions: [v1], resources: [pods]}]
"""


def test_a_webhook_that_fails_open_is_reported() -> None:
    for kind in ("ValidatingWebhookConfiguration", "MutatingWebhookConfiguration"):
        assert "KN-S030" in _ids(_WEBHOOK % (kind, "Ignore")), kind


def test_failing_closed_is_fine() -> None:
    assert "KN-S030" not in _ids(_WEBHOOK % ("ValidatingWebhookConfiguration", "Fail"))


def test_the_default_is_fail_so_an_absent_field_is_fine() -> None:
    """Only an explicit Ignore is a decision someone made; the API default is Fail."""
    text = _WEBHOOK % ("ValidatingWebhookConfiguration", "Fail")
    assert "KN-S030" not in _ids(text.replace("    failurePolicy: Fail\n", ""))


def test_the_finding_names_the_webhook() -> None:
    rep = analyze(_WEBHOOK % ("ValidatingWebhookConfiguration", "Ignore"), "kubernetes", None)
    hit = [f for f in rep.findings if f.rule_id == "KN-S030"]
    assert hit, "the rule did not fire"
    assert re.findall(r"Webhook '([^']+)'", hit[0].message) == ["gate.example.com"], hit[0].message


_OPENSHIFT_DNS = """
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: {name: allow-dns-openshift, namespace: prod}
spec:
  podSelector: {}
  policyTypes: [Egress]
  egress:
    - to: [{namespaceSelector: {matchLabels: {kubernetes.io/metadata.name: openshift-dns}}}]
      ports: [{protocol: UDP, port: 5353}, {protocol: TCP, port: 5353}]
"""


def test_openshift_dns_port_5353_counts() -> None:
    """A NetworkPolicy matches the POD port after Service translation, and OpenShift's CoreDNS pods
    listen on 5353 while the dns-default Service publishes 53. Insisting on 53 would report every
    correctly configured OpenShift cluster -- the repo's own gate fixture is one."""
    assert "KN-N013" not in _ids(_APP, _OPENSHIFT_DNS)


# -- red team: every case below was a wrong answer before the reach engine's helpers were reused ----------


def _np(body: str, name: str = "p") -> str:
    head = "apiVersion: networking.k8s.io/v1\nkind: NetworkPolicy\n"
    return f"{head}metadata: {{name: {name}, namespace: prod}}\nspec:\n{body}"


def test_tcp_only_53_does_not_clear_dns() -> None:
    """protocol defaults to TCP, and resolvers query UDP first: glibc falls back to TCP only on a
    truncated answer and musl does not fall back at all. TCP-only 53 leaves lookups timing out."""
    tcp_only = _np("  podSelector: {}\n  policyTypes: [Egress]\n  egress:\n    - ports: [{port: 53}]\n")
    assert "KN-N013" in _ids(_APP, tcp_only)


def test_udp_53_clears_dns() -> None:
    udp = _np("  podSelector: {}\n  policyTypes: [Egress]\n  egress:\n    - ports: [{protocol: UDP, port: 53}]\n")
    assert "KN-N013" not in _ids(_APP, udp)


def test_sctp_on_53_does_not_clear_dns() -> None:
    sctp = _np("  podSelector: {}\n  policyTypes: [Egress]\n  egress:\n    - ports: [{protocol: SCTP, port: 53}]\n")
    assert "KN-N013" in _ids(_APP, sctp)


def test_policy_types_defaults_are_honoured() -> None:
    """The API adds Egress whenever egress rules are present, so an omitted policyTypes still restricts."""
    restricting = _np("  podSelector: {}\n  egress:\n    - ports: [{protocol: TCP, port: 443}]\n", "api-egress")
    assert "KN-N013" in _ids(_APP, restricting), "an omitted policyTypes hid a real stranding"
    allowing = _np("  podSelector: {}\n  egress:\n    - ports: [{protocol: UDP, port: 53}]\n", "allow-dns")
    assert "KN-N013" not in _ids(_APP, _DENY_EGRESS, allowing), "an omitted policyTypes hid a working allowance"


def test_a_port_range_covering_53_clears_dns() -> None:
    """`{port: 1, endPort: 65535}` is the common 'all ports to this peer' idiom."""
    ranged = _np(
        "  podSelector: {}\n  policyTypes: [Egress]\n"
        "  egress:\n    - ports: [{protocol: UDP, port: 1, endPort: 1024}]\n"
    )
    assert "KN-N013" not in _ids(_APP, ranged)
    high = _np(
        "  podSelector: {}\n  policyTypes: [Egress]\n"
        "  egress:\n    - ports: [{protocol: UDP, port: 8000, endPort: 9000}]\n"
    )
    assert "KN-N013" in _ids(_APP, high), "a range that excludes 53 must still report"


def test_a_named_port_clears_dns() -> None:
    """CoreDNS names its ports `dns`/`dns-tcp`. The DNS pod is never in the bundle, so the manifest
    cannot prove stranding, and a rule that reported it would flag a policy that works."""
    named = _np("  podSelector: {}\n  policyTypes: [Egress]\n  egress:\n    - ports: [{protocol: UDP, port: dns}]\n")
    assert "KN-N013" not in _ids(_APP, named)


def test_a_host_network_pod_is_not_governed_by_networkpolicy() -> None:
    host = _APP.replace("    spec:\n", "    spec:\n      hostNetwork: true\n", 1)
    assert "KN-N013" not in _ids(host, _DENY_EGRESS)


def test_an_invalid_failure_policy_is_not_the_safe_default() -> None:
    """The API server refuses the object, so the check it describes is not running at all (G185)."""
    for bad in ("ignore", "Fial"):
        found = _ids(_WEBHOOK % ("ValidatingWebhookConfiguration", bad))
        assert "KN-S030" in found, bad


def _rendered_webhook_name() -> str:
    """Build the webhook's object name from the CHART and the WORKFLOW, never from memory.

    The first version of this test hardcoded the name in both the exception file and the assertion, so it
    compared one guess against itself and passed while CI failed: the real object is
    `<fullname>-admission.<namespace>.kube-noob.io`, and `kube-noob.admissionName` names the Service. Deriving
    it here means a change to the template's name expression, to the release name, or to the namespace CI
    renders into fails in this suite instead of in a workflow.
    """
    chart = ROOT / "deploy" / "helm" / "kube-noob" / "templates"
    tpl = chart / "admission.yaml"
    body = tpl.read_text(encoding="utf-8")
    # The ValidatingWebhookConfiguration's own metadata.name, not the Service's.
    block = body[body.index("kind: ValidatingWebhookConfiguration") :]
    expr = re.search(r"^  name: (.+)$", block, re.M)
    assert expr, f"{tpl.name} no longer declares the webhook configuration's name where this test looks"
    pattern = expr.group(1).strip()
    assert pattern == "{{ $name }}.{{ $ns }}.kube-noob.io", f"the name expression changed: {pattern}"

    helpers = (chart / "_helpers.tpl").read_text(encoding="utf-8")
    assert '{{- printf "%s-admission" (include "kube-noob.fullname" .) ' in helpers, "admissionName changed"

    # The release name and the namespace the admission step renders with.
    workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    render = re.search(r"at\(\) \{ helm template (\S+) deploy/helm/kube-noob -n (\S+) ", workflow)
    assert render, "the admission step no longer renders with a fixed release name and namespace"
    release, namespace = render.group(1), render.group(2)
    fullname = release if "kube-noob" in release else f"{release}-kube-noob"
    return f"{fullname}-admission.{namespace}.kube-noob.io"


def test_our_own_exceptions_file_still_covers_our_own_webhook() -> None:
    """KN-S030 reports kube-noob's own chart, and the acceptance is on the record rather than the rule weakened.

    The chart sets `failurePolicy: Ignore` deliberately: the webhook turns findings into kubectl warnings and
    denies only the rules listed in `admission.enforce`, so an audit webhook that is down must not stop a
    cluster admitting objects. This test exists so the acceptance cannot rot -- if the rendered webhook is
    renamed, or the entry expires, or someone deletes it to make CI green, this fails here rather than in a
    workflow (G205).
    """
    import yaml

    from kube_noob.audit import exceptions as exc

    path = ROOT / ".github" / "kube-noob-exceptions.yaml"
    review = exc.review(path.read_text(encoding="utf-8"))
    assert review.summary()["gate"], [e.as_dict() for e in review.gate_failures]
    name = _rendered_webhook_name()
    hit = exc.match(review, "KN-S030", f"ValidatingWebhookConfiguration/{name}")
    assert hit is not None, f"the exception does not cover the webhook the chart renders: {name}"
    assert hit.owner and hit.expires, "an accepted risk names who answers for it and when it is reviewed again"
    entry = yaml.safe_load(path.read_text(encoding="utf-8"))["exceptions"][0]
    assert "warnings" in entry["reason"] and "SECURITY.md" in entry["reason"], entry["reason"]
