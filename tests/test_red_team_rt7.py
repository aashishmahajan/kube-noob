"""RT7: what a client gets when the pasted YAML is not a Kubernetes manifest.

From a real session on the Ask page: a user pasted the default `values.yaml` of the actions-runner-controller Helm
chart. `audit` read it as one unnamed Kubernetes object, reported a single validation finding, and scored it
**90 out of 100**. Nothing in that file is a manifest, and a score on it is not a weak answer but a wrong one: a
file full of `:latest` images, empty `securityContext` and empty `resources` came back looking almost clean.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from kube_noob.cli import main

VALUES = """# Default values for a chart.
replicaCount: 1
image:
  repository: "summerwind/actions-runner-controller"
  actionsRunnerRepositoryAndTag: "summerwind/actions-runner:latest"
  pullPolicy: IfNotPresent
securityContext: {}
resources: {}
serviceAccount:
  create: true
  name: ""
"""

MANIFEST = """apiVersion: apps/v1
kind: Deployment
metadata:
  name: web
  namespace: shop
spec:
  selector:
    matchLabels: {app: web}
  template:
    metadata:
      labels: {app: web}
    spec:
      containers:
        - name: web
          image: nginx:latest
          securityContext:
            privileged: true
"""


def _run(tmp_path: Path, body: str, name: str = "values.yaml", *args: str) -> tuple[int, str, str]:
    p = tmp_path / name
    p.write_text(body, encoding="utf-8")
    return main(["audit", "-f", str(p), "--fail-on", "never", *args]), str(p), body


def test_a_file_that_is_not_a_manifest_is_not_scored(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """RT7-1. No document with apiVersion and kind means there is nothing to audit. Saying so is the answer; a
    score implies the file was checked against the rules, and it was not."""
    code, _, _ = _run(tmp_path, VALUES)
    out = capsys.readouterr()
    assert code == 2, f"expected a configuration error, got {code}: {out.err}"
    assert "nothing here is a Kubernetes manifest" in out.err
    assert "90" not in out.out, "a score was reported for a file that was never audited"


def test_it_names_what_the_file_looks_like(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """RT7-2. "Not a manifest" leaves the user stuck. A Helm values file is the commonest thing to paste by
    mistake and has an exact next step, so the refusal names it and gives the command."""
    code, _, _ = _run(tmp_path, VALUES)
    err = capsys.readouterr().err
    assert code == 2
    assert "helm template" in err, "a values file has a known next step; say it"


def test_a_real_manifest_is_unaffected(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """RT7 regression: the check must not cost a single real audit."""
    code, _, _ = _run(tmp_path, MANIFEST, "deploy.yaml", "--format", "json")
    out = capsys.readouterr()
    assert code == 0, out.err
    report = json.loads(out.out)
    assert report["findings"], "the manifest was still audited"
    assert report["summary"]["counts"]["critical"] >= 1


def test_a_manifest_beside_a_values_file_still_audits(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """One document with apiVersion and kind is enough: a chart's README fragment or a values block pasted above a
    manifest must not refuse the manifest below it."""
    code, _, _ = _run(tmp_path, VALUES + "\n---\n" + MANIFEST, "mixed.yaml", "--format", "json")
    out = capsys.readouterr()
    assert code == 0, out.err
    assert json.loads(out.out)["findings"]


def test_the_toolkit_says_the_same_thing_as_the_cli(tmp_path: Path) -> None:
    """The Ask page calls the tool, not the CLI, so the tool is where the answer has to be right."""
    from kube_noob import toolkit as tk
    from kube_noob.config import load_settings
    from kube_noob.errors import KubeNoobError

    kit = tk.Toolkit(load_settings(overrides={"dataDir": str(tmp_path / "data")}))
    with pytest.raises((ValueError, KubeNoobError), match="nothing here is a Kubernetes manifest"):
        kit.audit(tk.AuditIn(manifests=VALUES))
    assert kit.audit(tk.AuditIn(manifests=MANIFEST))["findings"]


def test_a_client_can_find_out_what_kube_noob_itself_can_do() -> None:
    """RT7-3. On the Ask page the client searches kube-noob's knowledge to answer. Nothing in that corpus was
    about kube-noob, so a question about its own CI story returned Kyverno and RHACS documents -- and the session
    that prompted this wrote `kube-noob audit -f rendered.yaml  # check the CLI's --help for the flag` and never
    mentioned `gate`, the command built for exactly that job. A tool that cannot answer questions about itself
    makes its user guess at it in public.
    """
    from kube_noob.knowledge.store import get_store

    store = get_store()
    for query, expected in (
        ("kube-noob gate CI SARIF exceptions", "gate"),
        ("kube-noob exception list expired", "ExceptionList"),
        ("kube-noob exit codes", "exit"),
    ):
        hits = store.search(query, limit=3)
        assert hits, query
        top = hits[0].chunk
        assert "kube-noob" in top.doc_id, f"{query!r} -> {top.doc_id}, not kube-noob's own document"
        body = f"{top.title} {top.heading or ''} {top.text}".lower()
        assert expected.lower() in body, f"{query!r} found {top.doc_id} without {expected}"


def test_the_document_tells_the_truth_about_the_exit_codes() -> None:
    """A knowledge document that drifts from the code teaches the wrong thing with a citation attached."""
    from pathlib import Path

    doc = (
        Path(__file__).resolve().parents[1] / "src" / "kube_noob" / "data" / "knowledge" / "kube-noob-cli.md"
    ).read_text(encoding="utf-8")
    cli = (Path(__file__).resolve().parents[1] / "src" / "kube_noob" / "cli.py").read_text(encoding="utf-8")
    for code in ("1", "2", "3", "4", "5"):
        assert f"| {code} |" in doc, f"exit {code} is not documented"
    for code in ("2", "3", "4", "5"):
        assert f"return {code}" in cli, f"the document claims exit {code}, which the CLI never leaves"
    assert "gate" in doc and "--sarif" in doc and "--fail-on" in doc


def test_the_exception_example_in_the_document_actually_loads() -> None:
    """The session copied an exception list out of a model's answer. Whatever kube-noob's own document shows has
    to be something the loader accepts, or it teaches a file that fails in CI."""
    import re
    from pathlib import Path

    from kube_noob.audit import exceptions as exc

    doc = (
        Path(__file__).resolve().parents[1] / "src" / "kube_noob" / "data" / "knowledge" / "kube-noob-cli.md"
    ).read_text(encoding="utf-8")
    block = re.search(r"```yaml\n(apiVersion: kube-noob\.io/v1.*?)```", doc, re.S)
    assert block, "the document no longer shows an exception list"
    review = exc.review(block.group(1))
    assert review.summary()["counts"]["active"] >= 1
