"""Helm chart generation and Helm chart linting/auditing.

``generate_chart`` turns a Blueprint into a Helm v3-compatible chart (apiVersion: v2): the generator's audited
manifests become templates whose tunables (image, replicas, resources, host) come from values.yaml, with a
values.schema.json so `helm install` rejects bad values before rendering.

``audit_chart`` renders a chart with the `helm` binary (if available) and runs the full audit on the output.
"""

from __future__ import annotations

import copy
import json
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any

import yaml

from kube_noob.audit.engine import analyze
from kube_noob.audit.model import Report
from kube_noob.errors import KubeNoobError
from kube_noob.generate.blueprint import Blueprint
from kube_noob.generate.manifests import generate
from kube_noob.yamlio import dump_documents

_SEMVER = re.compile(r"^\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$")
_SCALAR = "__KN_S__"
_INT = "__KN_I__"
_BLOCK = "__KN_B__"


def _split_image(image: str) -> tuple[str, str]:
    if "@" in image:
        repo, digest = image.split("@", 1)
        return repo, "@" + digest
    last = image.rsplit("/", 1)[-1]
    if ":" in last:
        repo, tag = image.rsplit(":", 1)
        return repo, tag
    return image, ""


def _templatize(obj: dict[str, Any], name: str) -> dict[str, Any]:
    o = copy.deepcopy(obj)
    o.get("metadata", {}).pop("namespace", None)
    kind = o["kind"]
    if kind in {"Deployment", "StatefulSet"}:
        o["spec"]["replicas"] = f"{_INT}replicaCount"
        c = o["spec"]["template"]["spec"]["containers"][0]
        c["image"] = f"{_SCALAR}image"
        c["imagePullPolicy"] = f"{_SCALAR}pullPolicy"
        c["resources"] = f"{_BLOCK}resources"
        o["spec"]["template"].setdefault("metadata", {}).setdefault("annotations", {})
    if kind == "Route" and "host" in o["spec"]:
        o["spec"]["host"] = f"{_SCALAR}host"
    if kind == "Ingress":
        o["spec"]["rules"][0]["host"] = f"{_SCALAR}host"
        o["spec"]["tls"][0]["hosts"] = [f"{_SCALAR}host"]
    if kind == "PodDisruptionBudget":
        return {"__kn_if__": "podDisruptionBudget.enabled", "obj": o}
    if kind == "HorizontalPodAutoscaler":
        o["spec"]["maxReplicas"] = f"{_INT}autoscaling.maxReplicas"
        return {"__kn_if__": "autoscaling.enabled", "obj": o}
    if kind == "NetworkPolicy":
        return {"__kn_if__": "networkPolicy.enabled", "obj": o}
    return o


_REPLACEMENTS = {
    f"{_SCALAR}image": '"{{ .Values.image.repository }}{{ if hasPrefix "@" .Values.image.tag }}{{ .Values.image.tag }}'
    '{{ else }}:{{ .Values.image.tag | default .Chart.AppVersion }}{{ end }}"',
    f"{_SCALAR}pullPolicy": "{{ .Values.image.pullPolicy }}",
    f"{_SCALAR}host": "{{ .Values.host | quote }}",
    f"{_INT}replicaCount": "{{ .Values.replicaCount }}",
    f"{_INT}autoscaling.maxReplicas": "{{ .Values.autoscaling.maxReplicas }}",
}


def _render_template(entry: dict[str, Any]) -> str:
    cond = None
    obj = entry
    if "__kn_if__" in entry:
        cond, obj = entry["__kn_if__"], entry["obj"]
    text = yaml.safe_dump(obj, sort_keys=False, default_flow_style=False, width=1000)
    for k, v in _REPLACEMENTS.items():
        text = text.replace(f"'{k}'", v).replace(k, v)
    out_lines = []
    for line in text.splitlines():
        m = re.match(rf"^(\s*)(\w+): {_BLOCK}(\w+)$", line)
        if m:
            indent, key, val = m.groups()
            out_lines.append(f"{indent}{key}:")
            out_lines.append(f"{indent}  {{{{- toYaml .Values.{val} | nindent {len(indent) + 2} }}}}")
        else:
            out_lines.append(line)
    body = "\n".join(out_lines) + "\n"
    if cond:
        body = f"{{{{- if .Values.{cond} }}}}\n{body}{{{{- end }}}}\n"
    return body


def generate_chart(bp: Blueprint, out_dir: str | Path, chart_version: str = "0.1.0") -> dict[str, Any]:
    if not _SEMVER.match(chart_version):
        raise KubeNoobError(f"chart version {chart_version!r} must be SemVer 2 (e.g. 0.1.0)")
    gen = generate(bp)
    repo, tag = _split_image(bp.image)
    if not tag:
        tag = "latest"  # an untagged reference means :latest; keep that explicit (and audited) instead of 0.0.0
    app_version = tag.lstrip(":") if not tag.startswith("@") else "0.0.0"
    out = Path(out_dir) / bp.name
    if out.exists() and any(out.iterdir()):
        raise KubeNoobError(f"{out} already exists and is not empty; choose another output directory")
    (out / "templates").mkdir(parents=True, exist_ok=True)

    chart = {
        "apiVersion": "v2",
        "name": bp.name,
        "description": f"{bp.name} - generated and audited by kube-noob for {bp.platform}",
        "type": "application",
        "version": chart_version,
        "appVersion": str(app_version),
        "kubeVersion": ">=1.25.0-0",
        "annotations": {"kube-noob.io/platform": bp.platform},
    }
    values = {
        "image": {
            "repository": repo,
            "tag": tag if tag.startswith("@") else tag.lstrip(":"),
            "pullPolicy": "IfNotPresent",
        },
        "replicaCount": bp.replicas,
        "resources": next(o for o in gen.objects if o["kind"] in {"Deployment", "StatefulSet"})["spec"]["template"][
            "spec"
        ]["containers"][0]["resources"],
        "host": bp.exposure.host or "",
        "podDisruptionBudget": {"enabled": bp.replicas >= 2},
        "autoscaling": {"enabled": bool(bp.hpa_max_replicas), "maxReplicas": bp.hpa_max_replicas or bp.replicas},
        "networkPolicy": {"enabled": True},
    }
    schema = {
        "$schema": "https://json-schema.org/draft-07/schema#",
        "type": "object",
        "required": ["image", "replicaCount", "resources"],
        "properties": {
            "image": {
                "type": "object",
                "required": ["repository"],
                "additionalProperties": False,
                "properties": {
                    "repository": {"type": "string", "minLength": 1},
                    "tag": {"type": "string"},
                    "pullPolicy": {"enum": ["IfNotPresent", "Always", "Never"]},
                },
            },
            "replicaCount": {"type": "integer", "minimum": 1},
            "resources": {"type": "object"},
            "host": {"type": "string"},
            "podDisruptionBudget": {"type": "object", "properties": {"enabled": {"type": "boolean"}}},
            "autoscaling": {
                "type": "object",
                "properties": {"enabled": {"type": "boolean"}, "maxReplicas": {"type": "integer", "minimum": 1}},
            },
            "networkPolicy": {"type": "object", "properties": {"enabled": {"type": "boolean"}}},
        },
        "additionalProperties": False,
    }
    files: dict[str, str] = {
        "Chart.yaml": yaml.safe_dump(chart, sort_keys=False),
        "values.yaml": "# Values for "
        + bp.name
        + " (generated by kube-noob; audited before export)\n"
        + yaml.safe_dump(values, sort_keys=False),
        "values.schema.json": json.dumps(schema, indent=2) + "\n",
        ".helmignore": ".git/\n*.swp\n*.bak\n*.tmp\n.DS_Store\n",
        "templates/NOTES.txt": (
            f"{bp.name} deployed to {{{{ .Release.Namespace }}}}.\n"
            "Verify: kubectl rollout status deploy/" + bp.name + " -n {{ .Release.Namespace }}\n"
        ),
    }
    counts: dict[str, int] = {}
    for o in gen.objects:
        if o["kind"] == "Namespace":
            continue
        kind = o["kind"].lower()
        counts[kind] = counts.get(kind, 0) + 1
        suffix = "" if counts[kind] == 1 else f"-{counts[kind]}"
        files[f"templates/{kind}{suffix}.yaml"] = _render_template(_templatize(o, bp.name))
    for rel, content in files.items():
        p = out / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")
    return {
        "chartDir": str(out),
        "files": sorted(files),
        "assumptions": gen.assumptions,
        "prerequisites": gen.prerequisites,
        "renderedManifests": dump_documents([o for o in gen.objects if o["kind"] != "Namespace"]),
    }


def helm_binary() -> str | None:
    return shutil.which("helm")


def render_chart(
    chart_dir: str | Path,
    values_files: list[str] | None = None,
    namespace: str = "default",
    release: str = "release",
    timeout: float = 60.0,
) -> str:
    helm = helm_binary()
    if helm is None:
        raise KubeNoobError(
            "The `helm` binary is not on PATH; install Helm 3.8+ to render charts "
            "(https://helm.sh/docs/intro/install/)."
        )
    chart = Path(chart_dir)
    if not (chart / "Chart.yaml").is_file():
        raise KubeNoobError(f"{chart} is not a chart directory (no Chart.yaml)")
    args = [helm, "template", release, str(chart), "--namespace", namespace]
    for vf in values_files or []:
        args += ["--values", vf]
    with tempfile.TemporaryDirectory() as home:
        env = {"HELM_CACHE_HOME": home, "HELM_CONFIG_HOME": home, "HELM_DATA_HOME": home, "PATH": "/usr/bin:/bin"}
        proc = subprocess.run(args, capture_output=True, text=True, timeout=timeout, env=env, check=False)
    if proc.returncode != 0:
        raise KubeNoobError(f"helm template failed: {proc.stderr.strip()[:2000]}")
    return proc.stdout


def lint_chart_metadata(chart_dir: str | Path) -> list[str]:
    """Static checks that need no helm binary."""
    issues: list[str] = []
    chart = Path(chart_dir)
    cy = chart / "Chart.yaml"
    if not cy.is_file():
        return [f"{chart}: missing Chart.yaml"]
    meta = yaml.safe_load(cy.read_text(encoding="utf-8")) or {}
    if meta.get("apiVersion") != "v2":
        issues.append("Chart.yaml apiVersion should be v2 (Helm 3+).")
    if not meta.get("name"):
        issues.append("Chart.yaml is missing name.")
    if not _SEMVER.match(str(meta.get("version", ""))):
        issues.append(f"Chart.yaml version {meta.get('version')!r} is not SemVer 2.")
    if "appVersion" in meta and not isinstance(meta["appVersion"], str):
        issues.append('Chart.yaml appVersion should be a quoted string (e.g. "1.10" not 1.1).')
    values = chart / "values.yaml"
    if values.is_file():
        v = yaml.safe_load(values.read_text(encoding="utf-8")) or {}
        tag = (v.get("image") or {}).get("tag") if isinstance(v, dict) else None
        if tag in ("latest",):
            issues.append("values.yaml image.tag is 'latest'; pin a version or digest.")
    if not (chart / "values.schema.json").is_file():
        issues.append("No values.schema.json; add one so invalid values fail at install time.")
    return issues


def audit_chart(
    chart_dir: str | Path,
    platform: str = "kubernetes",
    version: str | None = None,
    values_files: list[str] | None = None,
    namespace: str = "default",
) -> tuple[Report, list[str]]:
    rendered = render_chart(chart_dir, values_files, namespace)
    return analyze(rendered, platform=platform, version=version), lint_chart_metadata(chart_dir)
