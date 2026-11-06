"""`/metrics`, the PrometheusRule and the Alertmanager receiver (N11, G236).

A platform team will not run a pod it cannot alert on. Until this, the server had no `/metrics`, the chart had no
PrometheusRule and no ServiceMonitor, and there was no inbound endpoint for an Alertmanager receiver to post to --
so a stale corpus, a failing tool or the sidecar itself dying were all invisible.

These tests hold the three properties that make a metrics endpoint safe rather than merely present: no caller data
in any label, a label space a caller cannot grow, and the same authentication as everything else by default.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
import yaml

from kube_noob.config import Settings, load_settings
from kube_noob.server import metrics as m

ROOT = Path(__file__).resolve().parents[1]
CHART = ROOT / "deploy" / "helm" / "kube-noob"


def _fresh() -> m.Metrics:
    reg = m.Metrics(frozenset({"audit_manifests", "insight"}))
    return reg


def _parse(text: str) -> dict[str, list[tuple[str, str]]]:
    """Every sample as {metric name: [(labels, value)]}, with the comment lines checked as we go."""
    out: dict[str, list[tuple[str, str]]] = {}
    seen_help: set[str] = set()
    seen_type: set[str] = set()
    for line in text.splitlines():
        if line.startswith("# HELP "):
            seen_help.add(line.split()[2])
            continue
        if line.startswith("# TYPE "):
            name, kind = line.split()[2], line.split()[3]
            assert kind in {"counter", "gauge", "histogram"}, line
            seen_type.add(name)
            continue
        assert not line.startswith("#"), line
        name, _, rest = line.partition("{" if "{" in line else " ")
        labels, value = ("", rest) if "{" not in line else rest.rsplit("}", 1)
        base = name.removesuffix("_bucket").removesuffix("_sum").removesuffix("_count")
        assert base in seen_help and base in seen_type, f"{name} has no HELP/TYPE above it"
        float(value.strip())  # every value must be a number
        out.setdefault(name, []).append((labels, value.strip()))
    return out


def test_the_document_is_well_formed_and_every_value_is_a_number() -> None:
    reg = _fresh()
    reg.record("audit_manifests", "mcp", "ok", 0.031)
    reg.record("insight", "rest", "ok", 1.2)
    samples = _parse(m.render(load_settings(), reg))
    assert samples["kube_noob_build_info"]
    assert samples["kube_noob_uptime_seconds"]
    assert len(samples["kube_noob_tool_calls_total"]) == 2


def test_an_unknown_exception_type_collapses_to_error() -> None:
    """`run_tool` labels an anticipated failure with the exception's class name, and exception types are
    open-ended: a caller who can provoke a new one would otherwise add a Prometheus label value each time, which
    is a cardinality attack on the monitoring system rather than on this process."""
    reg = _fresh()
    reg.record("insight", "mcp", "ManifestError", 0.01)
    reg.record("insight", "mcp", "SomeBrandNewError", 0.01)
    text = m.render(load_settings(), reg)
    assert 'outcome="error"' in text
    assert "ManifestError" not in text and "SomeBrandNewError" not in text


def test_an_unknown_tool_or_surface_does_not_become_a_label() -> None:
    reg = _fresh()
    reg.record("a_tool_that_does_not_exist", "websocket", "ok", 0.01)
    text = m.render(load_settings(), reg)
    assert 'tool="other"' in text and 'via="other"' in text
    assert "a_tool_that_does_not_exist" not in text and "websocket" not in text


def test_the_known_tool_set_comes_from_the_toolkit() -> None:
    """So a real tool is never reported as `other`, which would hide it rather than bound it."""
    from kube_noob.toolkit import Toolkit

    names = frozenset(s.name for s in Toolkit(load_settings()).specs())
    reg = m.Metrics(names)
    reg.record("insight", "mcp", "ok", 0.01)
    assert 'tool="insight"' in m.render(load_settings(), reg)


def test_the_buckets_are_cumulative() -> None:
    """Prometheus requires `_bucket{le=X}` to be the count of observations at or below X; a non-cumulative
    histogram renders without error and gives wrong quantiles, which is worse than no histogram."""
    reg = _fresh()
    for seconds in (0.005, 0.2, 0.2, 7.0):
        reg.record("insight", "mcp", "ok", seconds)
    rows = _parse(m.render(load_settings(), reg))["kube_noob_tool_duration_seconds_bucket"]
    values = [int(v) for _labels, v in rows]
    assert values == sorted(values), values
    assert values[-1] == 4, "the +Inf bucket is every observation"
    counts = _parse(m.render(load_settings(), reg))["kube_noob_tool_duration_seconds_count"]
    assert counts[0][1] == "4"


def test_no_label_value_can_carry_caller_data() -> None:
    """The whole safety argument: a scrape is readable by anyone who can reach the port and is kept for months."""
    reg = _fresh()
    reg.record("audit_manifests", "mcp", "ok", 0.01)
    text = m.render(load_settings(), reg)
    for label in ("namespace=", "resource=", "name=", "path=", "remote=", "user=", "error="):
        assert label not in text, label
    assert set(_label_keys(text)) <= {"version", "platform", "tool", "via", "outcome", "le"}


def _label_keys(text: str) -> set[str]:
    keys: set[str] = set()
    for line in text.splitlines():
        if line.startswith("#") or "{" not in line:
            continue
        inner = line[line.index("{") + 1 : line.rindex("}")]
        keys |= {part.split("=")[0] for part in inner.split(",") if part}
    return keys


def test_a_label_value_is_escaped_even_though_none_needs_it_today() -> None:
    assert m._escape('a"b\\c\nd') == 'a\\"b\\\\c\\nd'


def test_knowledge_age_is_reported_and_the_corpus_date_only_when_there_is_one() -> None:
    """Two different facts: `asOf` is when the IMAGE's knowledge was reviewed and is always there; the corpus
    date exists only where a corpus has been imported. Conflating them would alert about a refresh job that does
    not exist on most installs."""
    text = m.render(load_settings(), _fresh())
    assert "kube_noob_knowledge_age_seconds" in text
    assert "kube_noob_knowledge_as_of_timestamp_seconds" in text
    # No corpus in a default data dir, so no corpus metric rather than a zero (a zero reads as 1970).
    assert "kube_noob_corpus_as_of_timestamp_seconds" not in text


def test_a_bad_knowledge_date_is_omitted_rather_than_rendered_as_zero() -> None:
    assert m._date_to_epoch(None) is None
    assert m._date_to_epoch("") is None
    assert m._date_to_epoch("not-a-date") is None
    assert m._date_to_epoch("2026-10-27") is not None


# --- the endpoint ------------------------------------------------------------------------------------------------


def _scrape(app: Any, path: str = "/metrics", token: str | None = None, method: str = "GET") -> tuple[int, bytes]:
    """Drive the ASGI app directly: no server, no socket, no event-loop surprises."""
    import anyio

    headers: list[tuple[bytes, bytes]] = [(b"host", b"127.0.0.1")]
    if token is not None:
        headers.append((b"authorization", b"Bearer " + token.encode()))
    scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": method,
        "path": path,
        "raw_path": path.encode(),
        "query_string": b"",
        "headers": headers,
        "client": ("127.0.0.1", 1234),
        "server": ("127.0.0.1", 8080),
        "scheme": "http",
        "root_path": "",
    }
    status: list[int] = []
    body = bytearray()

    async def receive() -> dict[str, Any]:
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message: dict[str, Any]) -> None:
        if message["type"] == "http.response.start":
            status.append(int(message["status"]))
        elif message["type"] == "http.response.body":
            body.extend(message.get("body") or b"")

    anyio.run(app, scope, receive, send)
    return status[0], bytes(body)


#: The tests below bind a non-loopback host on purpose: the token refusal and the `/metrics` guard only apply
#: off loopback, so testing them on 127.0.0.1 would test nothing. Nothing is ever listened on -- the ASGI app is
#: driven directly.
ANY_INTERFACE = "0.0.0.0"  # noqa: S104


def _settings(**server: Any) -> Settings:
    base = load_settings().model_dump()
    base["server"] = {**base.get("server", {}), **server}
    return Settings.model_validate(base)


def test_metrics_needs_the_token_by_default(monkeypatch: pytest.MonkeyPatch) -> None:
    """An unauthenticated scrape endpoint on a non-loopback bind publishes which tools a team runs and how often.
    The refusal in `http_app` exists for exactly that reason, and `/metrics` is inside it."""
    from kube_noob.server.http import http_app

    monkeypatch.setenv("KUBE_NOOB_HTTP_TOKEN", "s3cret")
    app = http_app(_settings(host=ANY_INTERFACE, allowed_hosts=["127.0.0.1", "127.0.0.1:*"]))
    assert _scrape(app)[0] == 401
    status, body = _scrape(app, token="s3cret")
    assert status == 200
    assert b"kube_noob_build_info" in body


def test_metrics_can_be_opened_deliberately(monkeypatch: pytest.MonkeyPatch) -> None:
    from kube_noob.server.http import http_app

    monkeypatch.setenv("KUBE_NOOB_HTTP_TOKEN", "s3cret")
    app = http_app(
        _settings(
            host=ANY_INTERFACE,
            allowed_hosts=["127.0.0.1", "127.0.0.1:*"],
            metrics={"allow_unauthenticated": True},
        )
    )
    status, body = _scrape(app)
    assert status == 200 and b"kube_noob_build_info" in body
    # Everything else still needs the token: opening the scrape must not open the tools.
    assert _scrape(app, path="/mcp", method="POST")[0] == 401


def test_metrics_refuses_a_post(monkeypatch: pytest.MonkeyPatch) -> None:
    """It is a read. A POST to it would be a caller writing to the monitoring surface."""
    from kube_noob.server.http import http_app

    monkeypatch.setenv("KUBE_NOOB_HTTP_TOKEN", "s3cret")
    app = http_app(_settings(host=ANY_INTERFACE, allowed_hosts=["127.0.0.1", "127.0.0.1:*"]))
    assert _scrape(app, token="s3cret", method="POST")[0] == 405


def test_the_health_paths_are_still_the_only_public_ones(monkeypatch: pytest.MonkeyPatch) -> None:
    from kube_noob.server.http import PUBLIC_PATHS

    assert frozenset({"/healthz", "/readyz"}) == PUBLIC_PATHS, "guarded by wrapper order, not by this"


# --- the chart ---------------------------------------------------------------------------------------------------


def test_the_monitoring_objects_are_off_by_default() -> None:
    """Both need the Prometheus Operator CRDs, and a chart that renders a CRD the cluster does not serve fails
    the install."""
    values = yaml.safe_load((CHART / "values.yaml").read_text(encoding="utf-8"))
    mon = values["monitoring"]
    assert mon["serviceMonitor"]["enabled"] is False
    assert mon["prometheusRule"]["enabled"] is False
    assert mon["allowUnauthenticatedMetrics"] is False


def test_the_chart_wires_the_metrics_setting_through() -> None:
    cm = (CHART / "templates" / "configmap.yaml").read_text(encoding="utf-8")
    assert "allowUnauthenticated: {{ .Values.monitoring.allowUnauthenticatedMetrics" in cm


def test_the_rule_refuses_without_a_service_monitor() -> None:
    """An alert on a metric nobody scrapes never fires, which looks exactly like a healthy cluster."""
    tpl = (CHART / "templates" / "monitoring.yaml").read_text(encoding="utf-8")
    assert "fail " in tpl and "serviceMonitor.enabled" in tpl


def test_the_error_ratio_alert_excludes_invalid_arguments() -> None:
    """A caller sending bad input is not this pod failing, and paging someone for somebody else's typo teaches
    them to mute the alert."""
    tpl = (CHART / "templates" / "monitoring.yaml").read_text(encoding="utf-8")
    assert 'outcome=~"crash|error"' in tpl
    assert "invalid-arguments" in tpl, "and the template says why it is excluded"


def test_the_scrape_carries_the_token_unless_metrics_were_opened() -> None:
    tpl = (CHART / "templates" / "monitoring.yaml").read_text(encoding="utf-8")
    assert "{{- if not .Values.monitoring.allowUnauthenticatedMetrics }}" in tpl
    assert "authorization:" in tpl and "type: Bearer" in tpl
    assert "credentials:" in tpl, "Prometheus reads the Secret itself; the token is never rendered"


def test_every_alert_names_a_metric_this_code_emits() -> None:
    """An alert on a metric that does not exist is silent for ever, and silence is indistinguishable from health."""
    tpl = (CHART / "templates" / "monitoring.yaml").read_text(encoding="utf-8")
    emitted = m.render(load_settings(), _fresh())
    names = {line.split()[2] for line in emitted.splitlines() if line.startswith("# TYPE ")} | {"up"}
    import re

    for metric_name in re.findall(r"\bkube_noob_[a-z_]+\b", tpl):
        assert metric_name in names, f"{metric_name} is alerted on but never emitted"


# --- the Alertmanager receiver -----------------------------------------------------------------------------------


def test_there_is_an_inbound_route_for_an_alertmanager_webhook() -> None:
    """R6.5's third part needs somewhere for a receiver to POST. The incident watch already PARSES Alertmanager
    payloads, so without an endpoint the capability existed and was unreachable."""
    from kube_noob.server.rest import ROUTES

    route = next(r for r in ROUTES if r.path == "/v1/alerts")
    assert route.tool == "extract_signals"
    assert route.body_as == "text", "Alertmanager posts its own shape, not a kube-noob argument map"


def test_the_receiver_accepts_alertmanagers_own_payload_shape() -> None:
    """The point of `body_as`: `{"receiver": ..., "alerts": [...]}` has no `text` field and would be refused by
    the tool's `extra=forbid` model, so the payload is passed as the one argument it is."""
    from kube_noob.toolkit import Toolkit

    payload = {
        "receiver": "kube-noob",
        "status": "firing",
        "alerts": [
            {
                "status": "firing",
                "labels": {"alertname": "KubeNodeNotReady", "severity": "warning", "node": "worker-0"},
                "annotations": {"description": "node worker-0 has been unready for more than 15m"},
            }
        ],
    }
    kit = Toolkit(load_settings())
    spec = next(s for s in kit.specs() if s.name == "extract_signals")
    out = spec.fn(spec.model(text=json.dumps(payload)))
    result = out if isinstance(out, dict) else out.model_dump()
    assert result, "the payload carried a signal and the tool found nothing"
