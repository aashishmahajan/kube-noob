"""KN-N008 carried CVE-2020-8554 and recommended hardening. It did not say the field is being removed.

The two call for different work. "Anyone who can create a Service can intercept your traffic" is answered by
enabling `DenyServiceExternalIPs`; "the field is deprecated in 1.36 and the gate goes off by default a few
releases later" is answered by moving the Service to a LoadBalancer, an Ingress controller or the Gateway API.
A reader told only the first will harden a field that is going away.

Nothing asserted the second, so the citation and the sentence could be dropped by any later edit of this rule
and every test would stay green. This file is that assertion.
"""

from __future__ import annotations

from kube_noob.audit.rules import RULES
from kube_noob.catalog import SOURCES

RULE = "KN-N008"


def test_the_rule_cites_the_kep_that_removes_the_field() -> None:
    rule = RULES[RULE]
    assert "k8s-kep-5707" in rule.citations, "the deprecation has to be cited, not only described"
    assert "k8s-cve-2020-8554" in rule.citations, "and the original flaw stays cited"
    for cid in rule.citations:
        assert cid in SOURCES, f"{cid} resolves to no source"


def test_the_description_says_the_field_is_going_away_and_not_only_that_it_is_risky() -> None:
    text = RULES[RULE].description
    assert "KEP-5707" in text
    assert "1.36" in text, "the release that deprecates it is the fact a reader plans around"
    assert "deprecat" in text.lower()


def test_the_fix_names_somewhere_to_go() -> None:
    """A deprecation with no replacement named is a dead end. KEP-5707 offers no in-API successor, so the
    remediation has to point outside the Service API."""
    fix = RULES[RULE].remediation
    assert any(w in fix for w in ("LoadBalancer", "Ingress", "Route", "Gateway")), fix


def test_a_service_with_external_ips_is_still_reported(tmp_path) -> None:
    """The claim changed; the check must not have. A rule whose text improved while its detection broke is a
    worse outcome than leaving the text alone."""
    from kube_noob.audit.engine import analyze
    from kube_noob.yamlio import load_documents

    manifest = """apiVersion: v1
kind: Service
metadata:
  name: web
  namespace: shop
spec:
  selector: {app: web}
  ports:
  - {port: 80, targetPort: 8080}
  externalIPs: [192.0.2.10]
"""
    ids = {f.rule_id for f in analyze(load_documents(manifest), "kubernetes").findings}
    assert RULE in ids

    clean = manifest.replace("  externalIPs: [192.0.2.10]\n", "")
    assert RULE not in {f.rule_id for f in analyze(load_documents(clean), "kubernetes").findings}
