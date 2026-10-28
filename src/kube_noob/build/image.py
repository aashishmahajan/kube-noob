"""One report for a Containerfile, the image built from it (an OCI layout) and the manifests that run it."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from kube_noob.build import containerfile as cf
from kube_noob.build import oci


def manifests_have_probes(text: str) -> bool:
    """Whether a workload in the manifests defines a readiness, liveness or startup probe on an app container."""
    from kube_noob.audit.podspec import containers, pod_template
    from kube_noob.yamlio import load_documents

    for doc in load_documents(text):
        pod = pod_template(doc)
        if pod is None:
            continue
        for ref in containers(pod, include_init=False, ephemeral=False):
            if any(isinstance(ref.container.get(k), dict) for k in ("readinessProbe", "livenessProbe", "startupProbe")):
                return True
    return False


def audit(
    containerfile: str | None,
    *,
    context: Path | None = None,
    manifests: str | None = None,
    layout: Path | None = None,
    platform: str | None = None,
) -> dict[str, Any]:
    if containerfile is None and layout is None:
        raise cf.ContainerfileError("pass a Containerfile, an OCI image layout, or both")
    probes = manifests_have_probes(manifests) if manifests is not None else None
    image = oci.scan(layout, platform) if layout is not None else None
    if containerfile is not None:
        report = cf.audit(containerfile, context=context, probes=probes, image_user=image.user if image else None)
    else:
        report = {"stages": [], "findings": [], "counts": {}, "checks": sorted(cf.CHECKS), "notChecked": [], "notes": []}
        if image is not None and (not image.user.strip() or image.user.strip() in cf.ROOT_USERS):
            report["findings"].append(
                cf.Finding("KN-B002", None, f"the image's config runs as {image.user.strip() or 'root (empty User)'}")
                .as_dict()
            )
    if image is not None:
        extra: list[dict[str, Any]] = []
        for hit in image.hits:
            msg = f"a {hit['kind']} at {hit['where']} in layer {hit['layer']} ({hit.get('preview', '****')})"
            if hit.get("deletedInLayer"):
                msg += f"; deleted in layer {hit['deletedInLayer']} but still in layer {hit['layer']}"
            extra.append({**cf.Finding("KN-B009", None, msg).as_dict(), "layer": hit["layer"]})
        for hit in image.config_hits:
            extra.append(cf.Finding("KN-B010", None, f"a {hit['kind']} in {hit['where']} ({hit['preview']})").as_dict())
        report["findings"] = extra + report["findings"]
        report["image"] = image.as_dict()
        order = {s: i for i, s in enumerate(cf.SEVERITIES)}
        report["findings"].sort(key=lambda r: (-order[r["severity"]], r.get("line") or 0, r["ruleId"]))
    report["counts"] = {s: sum(1 for r in report["findings"] if r["severity"] == s) for s in reversed(cf.SEVERITIES)}
    if manifests is not None:
        report["probesInManifests"] = probes
    return report
