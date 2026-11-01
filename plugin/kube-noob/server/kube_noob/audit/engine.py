"""Entry points: validate / audit / red-team a manifest bundle."""

from __future__ import annotations

from kube_noob.audit.model import Report, Severity, Stage
from kube_noob.audit.redteam import red_team
from kube_noob.audit.rules import RULES, AuditContext, run_rules
from kube_noob.catalog import OPENSHIFT_FAMILY, PLATFORMS, k8s_version_for
from kube_noob.errors import ConfigError
from kube_noob.schemas.validate import validate_documents
from kube_noob.yamlio import Document, load_documents

ALL_STAGES = frozenset(Stage)


def build_context(docs: list[Document], platform: str, version: str | None) -> AuditContext:
    if platform not in PLATFORMS:
        raise ValueError(f"Unknown platform {platform!r}; use one of {', '.join(PLATFORMS)}")
    k8s = k8s_version_for(platform, version)
    platform_version = version if platform in OPENSHIFT_FAMILY else None
    return AuditContext(docs=docs, platform=platform, k8s_version=k8s, platform_version=platform_version)


def analyze(
    manifests: str | list[Document],
    platform: str = "kubernetes",
    version: str | None = None,
    stages: frozenset[Stage] | set[Stage] = ALL_STAGES,
    min_severity: Severity = Severity.INFO,
    schema: bool = True,
) -> Report:
    docs = load_documents(manifests) if isinstance(manifests, str) else manifests
    ctx = build_context(docs, platform, version)
    report = Report(
        platform=platform,
        kubernetes_version=ctx.k8s_version,
        platform_version=ctx.platform_version,
        resources=[d.ref() for d in docs],
    )
    if platform in OPENSHIFT_FAMILY and version is None:
        report.assumptions.append(f"No OpenShift version given; assumed Kubernetes {ctx.k8s_version} semantics.")
    if platform == "kubernetes" and version is None:
        report.assumptions.append(f"No Kubernetes version given; assumed {ctx.k8s_version}.")
    if not docs:
        report.assumptions.append("Input contained no YAML documents.")
        return report
    rule_stages: set[Stage] = {s for s in stages if s is not Stage.RED_TEAM}
    findings = run_rules(ctx, rule_stages) if rule_stages else []
    if schema and Stage.VALIDATE in stages:
        schema_findings, notes = validate_documents(docs)
        findings.extend(schema_findings)
        report.assumptions.extend(notes)
    if Stage.RED_TEAM in stages:
        # Red team always reasons over the complete finding set, even if the caller filters the output.
        all_findings = findings if rule_stages >= {Stage.AUDIT, Stage.CALIBRATE} else run_rules(ctx, None)
        report.scenarios = red_team(ctx, all_findings)
    report.findings = [f for f in findings if f.severity >= min_severity]
    return report


def explain_rule(rule_id: str) -> dict[str, object]:
    r = RULES.get(rule_id.upper())
    if r is None:
        build_checks: list[str] = []
        try:
            from kube_noob.build import containerfile
        except ImportError:  # the Claude plugin build ships without the Containerfile checks
            pass
        else:
            built = containerfile.explain(rule_id)
            if built is not None:
                return built
            build_checks = sorted(containerfile.CHECKS)
        known = ", ".join([*sorted(RULES), *build_checks])
        raise KeyError(f"Unknown rule {rule_id!r}. Known rules: {known}")
    from kube_noob.audit.controls import CATALOG, describe
    from kube_noob.catalog import SOURCES

    out = r.as_dict()
    out["citations"] = [SOURCES[c].as_dict() for c in r.citations if c in SOURCES]
    out["controls"] = describe(r.rule_id)
    out["controlCatalog"] = CATALOG
    return out


def list_rules() -> list[dict[str, object]]:
    return [r.as_dict() for r in sorted(RULES.values(), key=lambda x: x.rule_id)]


# The scaffold keys `helm create` writes and every chart keeps. Two of them, with no Kubernetes object anywhere in
# the file, is a confident read: this is a values file, not a manifest.
_VALUES_KEYS = frozenset(
    {
        "replicaCount",
        "image",
        "imagePullSecrets",
        "nameOverride",
        "fullnameOverride",
        "serviceAccount",
        "podAnnotations",
        "podSecurityContext",
        "securityContext",
        "resources",
        "nodeSelector",
        "tolerations",
        "affinity",
        "autoscaling",
        "ingress",
    }
)


def refuse_if_not_manifests(manifests: str | list[Document]) -> None:
    """Raise when nothing in the input is a Kubernetes object.

    The audit reads Kubernetes objects. Given something else it used to read the whole file as one unnamed object,
    report that it was missing `apiVersion`, and return a score -- 90 out of 100 for a Helm values file whose
    images were `:latest` and whose `securityContext` and `resources` were empty. A score says the rules were
    applied, so a score on a file the rules never saw is a wrong answer, not a thin one. One Kubernetes document is
    enough to proceed: a values block pasted above a manifest must not refuse the manifest.
    """
    docs = manifests if isinstance(manifests, list) else load_documents(manifests)
    objects = [d.data for d in docs if isinstance(d.data, dict)]
    if any("apiVersion" in o and "kind" in o for o in objects):
        return
    keys: set[str] = set()
    for o in objects:
        keys |= {k for k in o if isinstance(k, str)}
    looks_like_values = len(keys & _VALUES_KEYS) >= 2
    what = "a Helm values file" if looks_like_values else "not a Kubernetes manifest"
    how = (
        "Render the chart first and audit the output: helm template <release> <chart> -f <this file> | "
        "kube-noob audit -f -"
        if looks_like_values
        else "Pass Kubernetes objects: every document needs apiVersion and kind."
    )
    raise ConfigError(
        f"nothing here is a Kubernetes manifest ({'this looks like ' + what if looks_like_values else what}): "
        f"no document has both apiVersion and kind, so none of the audit rules apply. {how}"
    )
