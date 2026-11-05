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

from kube_noob.audit.engine import analyze

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
    assert hit and "gate.example.com" in hit[0].message, hit


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
