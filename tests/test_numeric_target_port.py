"""A numeric targetPort nothing declares: advisory, and only where the author declares ports at all (roadmap N7).

KN-V012 reports a NAMED targetPort no selected container declares, and it is HIGH because the name must resolve or
the Service gets no endpoints. The numeric case is different and the difference is the whole design: Kubernetes
does not require a containerPort declaration, so a Service pointing at 8080 works whenever something listens on
8080, declared or not. Reporting every undeclared numeric port would fire on correct repositories -- the
absence-read-as-defect failure. So the rule fires only where the selected containers DO declare ports and the
target is outside that set, which is the case that is a typo rather than a style, and it is LOW and says plainly
that it is not proof.
"""

from __future__ import annotations

from kube_noob.audit.engine import analyze, explain_rule
from kube_noob.audit.model import Finding, Severity

RULE = "KN-V023"

SVC = """
apiVersion: v1
kind: Service
metadata:
  name: orders
  namespace: shop
spec:
  selector:
    app: orders
  ports:
    - name: http
      port: 80
      targetPort: {target}
"""

DEPLOY = """
apiVersion: apps/v1
kind: Deployment
metadata:
  name: orders
  namespace: shop
spec:
  template:
    metadata:
      labels:
        app: orders
    spec:
      containers:
        - name: c
          image: orders:1
{ports}
"""

DECLARES_8081 = """          ports:
            - containerPort: 8081
"""
DECLARES_BOTH = """          ports:
            - containerPort: 8081
            - containerPort: 8080
"""
NO_PORTS = ""


def _of(text: str) -> list[Finding]:
    return [f for f in analyze(text, platform="kubernetes").findings if f.rule_id == RULE]


def _hits(target: str = "8080", ports: str = DECLARES_8081, extra: str = "") -> list[Finding]:
    parts = [SVC.format(target=target), DEPLOY.format(ports=ports)]
    if extra:
        parts.append(extra)
    return _of("\n---\n".join(parts))


def test_a_numeric_target_outside_the_declared_ports_is_reported() -> None:
    hit = _hits()
    assert len(hit) == 1
    assert hit[0].severity is Severity.LOW
    assert hit[0].path == "spec.ports[0].targetPort"
    assert "8080" in hit[0].message and "8081" in hit[0].message


def test_the_message_says_it_is_not_proof() -> None:
    """A LOW finding that reads like a broken Service sends someone to fix working YAML."""
    message = _hits()[0].message.lower()
    assert "does not require" in message or "not proof" in message or "may still" in message


def test_a_target_the_containers_declare_is_silent() -> None:
    assert _hits(target="8080", ports=DECLARES_BOTH) == []


def test_a_workload_that_declares_no_ports_at_all_is_silent() -> None:
    """containerPort is optional and widely omitted. Firing here would report every correct repository."""
    assert _hits(target="8080", ports=NO_PORTS) == []


def test_a_named_target_is_left_to_the_rule_that_owns_it() -> None:
    """KN-V012 reports the named case as HIGH. Two findings for one mistake is one too many."""
    assert _hits(target="http") == []


def test_an_omitted_target_port_defaults_to_the_service_port_and_is_checked() -> None:
    """An absent targetPort is not an absent target: it is the `port` value, so the same mismatch is there."""
    text = (
        """
apiVersion: v1
kind: Service
metadata:
  name: orders
  namespace: shop
spec:
  selector:
    app: orders
  ports:
    - name: http
      port: 80
"""
        + "\n---\n"
        + DEPLOY.format(ports=DECLARES_8081)
    )
    hit = _of(text)
    assert len(hit) == 1
    assert hit[0].path == "spec.ports[0].port"
    assert "80" in hit[0].message and "no targetPort" in hit[0].message


def test_a_service_whose_workload_is_not_in_the_bundle_is_silent() -> None:
    """The claim needs the pod spec. Without it there is nothing to compare, and guessing would be a false finding."""
    assert _of(SVC.format(target="8080")) == []


def test_a_workload_in_another_namespace_does_not_satisfy_the_target() -> None:
    """A Service only reaches pods in its own namespace, so 8080 declared next door clears nothing."""
    other = DEPLOY.format(ports=DECLARES_BOTH).replace("namespace: shop", "namespace: other")
    hit = _hits(target="8080", ports=DECLARES_8081, extra=other)
    assert len(hit) == 1
    assert "declared: 8081)" in hit[0].message  # the other namespace's 8080 is not in the set


def test_a_headless_or_selectorless_service_is_silent() -> None:
    """With no selector the endpoints come from an EndpointSlice this bundle may not carry."""
    text = SVC.format(target="8080").replace("  selector:\n    app: orders\n", "")
    assert _of(text) == []


def test_an_init_container_port_does_not_satisfy_a_service_target() -> None:
    """A Service never reaches an init container: it has exited before the pod is ready."""
    init = """          ports:
            - containerPort: 8081
      initContainers:
        - name: init
          image: busybox:1
          ports:
            - containerPort: 8080
"""
    assert len(_hits(target="8080", ports=init)) == 1


def test_the_rule_is_explainable_and_carries_its_controls() -> None:
    meta = explain_rule(RULE)
    assert meta["defaultSeverity"] == "low" and meta["controls"]
