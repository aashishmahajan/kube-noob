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


def audit_chart(
    chart_dir: str | Path,
    platform: str = "kubernetes",
    version: str | None = None,
    values_files: list[str] | None = None,
    namespace: str = "default",
) -> tuple[Report, list[str]]:
    rendered = render_chart(chart_dir, values_files, namespace)
    return analyze(rendered, platform=platform, version=version), lint_chart_metadata(chart_dir)
