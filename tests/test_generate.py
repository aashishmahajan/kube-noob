from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from kube_noob.audit.engine import analyze
from kube_noob.audit.model import Severity
from kube_noob.errors import ClarificationNeeded
from kube_noob.generate.blueprint import Blueprint
from kube_noob.generate.helm import generate_chart, lint_chart_metadata
from kube_noob.generate.manifests import generate

DIGEST = "quay.io/acme/app@sha256:" + "b" * 64

CASES = [
    {"platform": "kubernetes", "exposure": {"type": "ingress", "host": "a.example.com"}, "egress": "dns-only"},
    {"platform": "kubernetes", "exposure": {"type": "gateway", "gatewayName": "gw", "gatewayNamespace": "infra"}},
    {"platform": "kubernetes", "exposure": {"type": "loadbalancer"}, "hpaMaxReplicas": 8},
    {"platform": "openshift", "exposure": {"type": "route", "tls": "reencrypt"}},
    {"platform": "openshift", "workload": "statefulset", "storage": {"size": "5Gi"}, "probe": "tcp"},
    {
        "platform": "rosa-hcp",
        "exposure": {"type": "route", "host": "x.apps.example.com"},
        "storage": {"size": "5Gi", "accessMode": "ReadWriteMany"},
        "egressDnsNames": ["api.example.com"],
    },
    {"platform": "rosa-classic", "exposure": {"type": "route", "tls": "passthrough"}, "replicas": 1},
]


@pytest.mark.parametrize("extra", CASES)
def test_generated_bundles_are_clean(extra: dict) -> None:  # type: ignore[type-arg]
    bp = Blueprint.model_validate({"name": "app", "namespace": "team", "image": DIGEST, **extra})
    g = generate(bp)
    r = analyze(g.yaml(), bp.platform)
    bad = [f"{f.rule_id} {f.message}" for f in r.findings if f.severity >= Severity.MEDIUM]
    if bp.replicas == 1:
        bad = [b for b in bad if not b.startswith("KN-C007")]
    if bp.exposure.type == "gateway":  # Gateway API CRDs are a documented prerequisite on vanilla Kubernetes
        bad = [b for b in bad if not b.startswith("KN-V004")]
        assert any("Gateway API CRDs" in p for p in g.prerequisites)
    assert not bad, bad
    assert not [n for n in r.assumptions if "No bundled schema" in n and "HTTPRoute" not in n]


def test_clarification_gate() -> None:
    bp = Blueprint.model_validate(
        {
            "name": "a",
            "namespace": "b",
            "image": "x:1",
            "platform": "kubernetes",
            "exposure": {"type": "route"},
            "storage": {"size": "1Gi"},
        }
    )
    with pytest.raises(ClarificationNeeded) as exc:
        generate(bp)
    assert len(exc.value.questions) == 2


def test_blueprint_validation_rejects_secrets_and_fixed_uid() -> None:
    with pytest.raises(ValueError, match="secretEnv"):
        Blueprint.model_validate({"name": "a", "namespace": "b", "image": "x:1", "env": {"DB_PASSWORD": "x"}})
    with pytest.raises(ValueError, match="runAsUser"):
        Blueprint.model_validate(
            {"name": "a", "namespace": "b", "image": "x:1", "platform": "openshift", "runAsUser": 1000}
        )


def test_helm_chart_structure(tmp_path: Path) -> None:
    bp = Blueprint.model_validate(
        {
            "name": "web",
            "namespace": "n",
            "image": "ghcr.io/a/web:1.2.3",
            "platform": "openshift",
            "exposure": {"type": "route", "host": "w.example.com"},
            "hpaMaxReplicas": 5,
        }
    )
    info = generate_chart(bp, tmp_path)
    root = Path(info["chartDir"])
    chart = yaml.safe_load((root / "Chart.yaml").read_text())
    assert chart["apiVersion"] == "v2" and chart["appVersion"] == "1.2.3"
    values = yaml.safe_load((root / "values.yaml").read_text())
    assert values["image"] == {"repository": "ghcr.io/a/web", "tag": "1.2.3", "pullPolicy": "IfNotPresent"}
    dep = (root / "templates" / "deployment.yaml").read_text()
    assert "{{ .Values.replicaCount }}" in dep and "toYaml .Values.resources | nindent" in dep
    assert "namespace:" not in dep
    assert (
        (root / "templates" / "horizontalpodautoscaler.yaml")
        .read_text()
        .startswith("{{- if .Values.autoscaling.enabled }}")
    )
    assert not lint_chart_metadata(root)
    with pytest.raises(Exception, match="not empty"):
        generate_chart(bp, tmp_path)
