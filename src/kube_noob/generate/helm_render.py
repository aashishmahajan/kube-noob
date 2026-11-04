"""Render a Helm chart with the `helm` binary and audit the output (``kube-noob helm-audit`` and the gate).

Kept apart from ``kube_noob.generate.helm`` so the Claude plugin, which offers chart generation and the metadata lint
but never renders with `helm`, ships no subprocess call (``scripts/sync_plugin_server.py`` leaves this module out).
"""

from __future__ import annotations

import shutil
import subprocess
import tempfile
from pathlib import Path

from kube_noob.audit.engine import analyze
from kube_noob.audit.model import Report
from kube_noob.errors import KubeNoobError
from kube_noob.generate.helm import lint_chart_metadata


def helm_binary() -> str | None:
    return shutil.which("helm")


def kube_version_arg(platform: str, version: str | None) -> str | None:
    """The Kubernetes version to pass to ``helm template --kube-version``, or None when the caller named none.

    An OpenShift version is mapped with the table the removed-API checks already use. No version means no flag:
    Helm's own default (v1.20 on Helm 4.0.0) must not be replaced with one kube-noob invented.
    """
    if not version:
        return None
    from kube_noob.catalog import k8s_version_for

    try:
        minor = k8s_version_for(platform, version)
    except ValueError:
        return None
    return minor if minor.count(".") >= 2 else f"{minor}.0"


def render_chart(
    chart_dir: str | Path,
    values_files: list[str] | None = None,
    namespace: str = "default",
    release: str = "release",
    timeout: float = 60.0,
    kube_version: str | None = None,
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
    if kube_version:
        args += ["--kube-version", kube_version]
    for vf in values_files or []:
        args += ["--values", vf]
    with tempfile.TemporaryDirectory() as home:
        env = {"HELM_CACHE_HOME": home, "HELM_CONFIG_HOME": home, "HELM_DATA_HOME": home, "PATH": "/usr/bin:/bin"}
        proc = subprocess.run(args, capture_output=True, text=True, timeout=timeout, env=env, check=False)
    if proc.returncode != 0:
        raise KubeNoobError(f"helm template failed: {proc.stderr.strip()[:2000]}")
    return proc.stdout


def audit_chart(
    chart_dir: str | Path,
    platform: str = "kubernetes",
    version: str | None = None,
    values_files: list[str] | None = None,
    namespace: str = "default",
) -> tuple[Report, list[str]]:
    rendered = render_chart(chart_dir, values_files, namespace, kube_version=kube_version_arg(platform, version))
    return analyze(rendered, platform=platform, version=version), lint_chart_metadata(chart_dir)
