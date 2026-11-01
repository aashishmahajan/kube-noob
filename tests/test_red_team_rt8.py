"""RT8: health signals that report OK while the thing they describe does not work.

Two of them, found by red-teaming the six delivery surfaces:

* the chart's natural OpenShift exposure (`route.enabled=true` with no `route.host`) returns HTTP 421 on every MCP
  call, while the liveness probe, the readiness probe and `helm test` all stay green;
* `kube-noob doctor` prints `posture: OK` with a model provider configured, no SDK installed and no key set, while
  its own help promises "exit 1 on conflicts".

Both are the same defect in different places: the signal a person checks is not the thing they care about.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[1]
CHART = ROOT / "deploy" / "helm" / "kube-noob" / "templates"


def test_no_exposure_can_create_a_hostname_the_server_will_refuse() -> None:
    """The MCP SDK checks the Host header against `server.allowedHosts` and answers 421 to anything else. The chart
    builds that list from the Service names, loopback, and `route.host`/`ingress.host` *when they are set*.

    Ingress is safe: its template marks the host `required`, so there is no way to create one the chart did not
    see. Route is not: `host` is optional, and an empty one makes OpenShift generate
    `<name>-<namespace>.<apps-domain>` -- a hostname the chart cannot predict and therefore never allows. The
    result is a Route that passes every probe and refuses every real call.

    The invariant: for each way of exposing the server, the host is either required or lands in allowedHosts.
    """
    exposure = (CHART / "exposure.yaml").read_text(encoding="utf-8")
    configmap = (CHART / "configmap.yaml").read_text(encoding="utf-8")
    allowed = configmap.split("allowedHosts:", 1)[1]

    for kind in ("route", "ingress"):
        required = f'required "{kind}.host' in exposure
        guarded = re.search(rf"fail\s+\"[^\"]*{kind}\.host", exposure) is not None
        in_allowed = f".Values.{kind}.host" in allowed
        assert required or guarded, (
            f"{kind}.host is optional, so a user can expose the server on a hostname the chart never adds to "
            f"allowedHosts; every MCP call then gets 421 while the probes stay green "
            f"(required={required} guarded={guarded} in_allowed={in_allowed})"
        )


def test_the_route_guard_says_what_to_do() -> None:
    """A refusal at render time is only better than a 421 at run time if it names the fix."""
    exposure = (CHART / "exposure.yaml").read_text(encoding="utf-8")
    guard = re.search(r"fail\s+\"([^\"]*route\.host[^\"]*)\"", exposure)
    assert guard, "no guard message mentions route.host"
    message = guard.group(1)
    assert "route.host" in message
    assert "421" in message or "Host" in message, "the message must say what goes wrong, not only what to set"


def _doctor(tmp_path: Path, capsys: pytest.CaptureFixture[str], **env: str) -> tuple[int, dict[str, Any]]:
    import json
    import os

    from kube_noob.cli import main

    old = {k: os.environ.get(k) for k in env}
    os.environ.update(env)
    os.environ["KUBE_NOOB_DATA_DIR"] = str(tmp_path / "data")
    try:
        code = main(["doctor", "--format", "json"])
        return code, json.loads(capsys.readouterr().out)
    finally:
        for k, v in old.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v


def test_doctor_does_not_call_a_model_path_healthy_that_cannot_run(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    """`doctor` is what a user runs to find out whether the thing is set up. With a provider configured and no key
    it reported `posture: OK` and printed the endpoint as though it were reachable. Its help says "exit 1 on
    conflicts"; a provider that cannot possibly answer is a conflict."""
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    code, report = _doctor(tmp_path, capsys, KUBE_NOOB_LLM_PROVIDER="anthropic")
    conflicts = " ".join(report.get("conflicts") or [])
    assert "ANTHROPIC_API_KEY" in conflicts, f"doctor did not name the unset key: {report.get('conflicts')}"
    assert code == 1, "doctor exited 0 for a model path that cannot run"


def test_doctor_is_quiet_when_no_model_is_configured(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    """The default is `provider: none`, which is not a conflict: nothing is meant to run."""
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("KUBE_NOOB_LLM_PROVIDER", raising=False)
    code, report = _doctor(tmp_path, capsys)
    assert code == 0, f"doctor reported a conflict with no model configured: {report.get('conflicts')}"


def test_doctor_is_satisfied_once_the_key_is_there(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    """And it must stop complaining when the user has done what it asked, or the check is noise."""
    pytest.importorskip("anthropic", reason="the [ask] extra is not installed in this environment")
    code, report = _doctor(
        tmp_path, capsys, KUBE_NOOB_LLM_PROVIDER="anthropic", ANTHROPIC_API_KEY="sk-ant-not-a-real-key-0123456789"
    )
    assert code == 0, f"doctor still reports a conflict with the key set: {report.get('conflicts')}"


def test_our_own_workflows_do_not_render_the_configuration_the_chart_refuses() -> None:
    """The guard above landed and CI went red: `.github/workflows/ci.yml` had been rendering the chart with
    `route.enabled=true` and no `route.host` since the Route was added, so the project's own OpenShift audit had
    been auditing a Route that would answer 421 on every MCP call. The guard found it, which is the point, but
    nothing stops the next workflow from doing the same -- so a workflow that turns the Route on must set its host
    in the same step.
    """
    workflows = sorted((ROOT / ".github" / "workflows").glob("*.yml"))
    assert workflows, "no workflows found, so this test proves nothing"
    for path in workflows:
        text = path.read_text(encoding="utf-8")
        # Steps are separated by `- name:`/`- run:`; a `--set` continues across escaped newlines within one step.
        for step in re.split(r"\n      - (?=name:|run:|uses:)", text):
            if "route.enabled=true" not in step:
                continue
            assert "route.host=" in step, (
                f"{path.name} renders the chart with route.enabled=true and no route.host in the same step. "
                "The chart refuses that (templates/exposure.yaml) because the generated hostname cannot reach "
                "server.allowedHosts, so every MCP call would answer 421 while both probes stayed green."
            )
