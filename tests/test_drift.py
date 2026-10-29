"""POL3 (R3.4): daily drift and policy report. Two snapshots of a fixture cluster give the exact expected diff."""

from __future__ import annotations

import datetime as dt
import json
import stat
from pathlib import Path
from typing import Any

import pytest
import yaml

from kube_noob import drift
from kube_noob import toolkit as tk
from kube_noob.audit import exceptions as exc
from kube_noob.cli import main
from kube_noob.config import load_settings
from kube_noob.debug.cluster import resolve_resource
from kube_noob.errors import ClusterAccessError, ConfigError

FIX = Path(__file__).parent / "fixtures" / "drift"
T1 = dt.datetime(2026, 10, 27, 3, 0, tzinfo=dt.UTC)
T2 = dt.datetime(2026, 10, 28, 3, 0, tzinfo=dt.UTC)

# Written by hand from the two fixture files, before the code was run on them (see the iteration log).
EXPECTED: dict[str, Any] = {
    "format": "kube-noob-drift/1",
    "from": "2026-10-27T03:00:00Z",
    "to": "2026-10-28T03:00:00Z",
    "objects": {
        "added": ["Ingress/shop/web", "Role/shop/secret-reader", "RoleBinding/shop/web-secrets"],
        "removed": ["ConfigMap/shop/web-config"],
        "changed": [
            {
                "object": "DaemonSet/ops/agent",
                "owner": "unowned",
                "fields": [
                    "spec.template.spec.containers[0].securityContext.allowPrivilegeEscalation",
                    "spec.template.spec.containers[0].securityContext.privileged",
                ],
            },
            {
                "object": "Deployment/shop/web",
                "owner": "web-team",
                "fields": [
                    "spec.template.spec.containers[0].image",
                    "spec.template.spec.containers[0].readinessProbe.httpGet.path",
                    "spec.template.spec.containers[0].readinessProbe.httpGet.port",
                ],
            },
        ],
        "unchanged": 8,
    },
    "findings": {
        "new": [
            {
                "ruleId": "KN-S001",
                "resource": "DaemonSet/ops/agent",
                "severity": "critical",
                "namespace": "ops",
                "owner": "unowned",
            },
            {
                "ruleId": "KN-S002",
                "resource": "DaemonSet/ops/agent",
                "severity": "medium",
                "namespace": "ops",
                "owner": "unowned",
            },
            {
                "ruleId": "KN-S017",
                "resource": "Role/shop/secret-reader",
                "severity": "low",
                "namespace": "shop",
                "owner": "team-shop",
            },
        ],
        "fixed": [
            {
                "ruleId": "KN-C001",
                "resource": "Deployment/shop/web",
                "severity": "medium",
                "namespace": "shop",
                "owner": "web-team",
            },
        ],
        "open": 3,
        "excepted": 0,
    },
    "violations": {
        "byNamespace": [
            {"namespace": "ops", "findings": 2, "critical": 1, "medium": 1},
            {"namespace": "shop", "findings": 1, "low": 1},
        ],
        "byOwner": [
            {"owner": "unowned", "findings": 2, "critical": 1, "medium": 1},
            {"owner": "team-shop", "findings": 1, "low": 1},
        ],
        "byRule": [
            {"ruleId": "KN-S001", "findings": 1, "critical": 1},
            {"ruleId": "KN-S002", "findings": 1, "medium": 1},
            {"ruleId": "KN-S017", "findings": 1, "low": 1},
        ],
    },
}


def _docs(name: str) -> list[dict[str, Any]]:
    return [d for d in yaml.safe_load_all((FIX / name).read_text(encoding="utf-8")) if d]


def _snap(name: str, when: dt.datetime, **kw: Any) -> dict[str, Any]:
    return drift.snapshot(_docs(name), source="manifests", taken_at=when, **kw)


def test_two_snapshots_give_the_exact_expected_report() -> None:
    assert drift.diff(_snap("day1.yaml", T1), _snap("day2.yaml", T2)) == EXPECTED


def test_a_snapshot_holds_hashes_and_names_never_values() -> None:
    snap = _snap("day1.yaml", T1)
    text = json.dumps(snap)
    assert '"info"' not in text, "a ConfigMap value never reaches a snapshot"
    assert "sha256:aaaa" not in text and "quay.io" not in text and 'LOG_LEVEL": "info' not in text
    cm = snap["objects"]["ConfigMap/shop/web-config"]
    assert "data.LOG_LEVEL" in cm["fields"] and len(cm["fields"]["data.LOG_LEVEL"]) == 12
    assert all(len(h) == 12 for o in snap["objects"].values() for h in o["fields"].values())


def test_scaling_status_server_metadata_and_owned_objects_are_not_drift() -> None:
    base = _docs("day1.yaml")
    web = next(d for d in base if d["kind"] == "Deployment" and d["metadata"]["name"] == "worker")
    noisy = json.loads(json.dumps(web))
    noisy["spec"]["replicas"] = 9
    noisy["status"] = {"readyReplicas": 9}
    noisy["metadata"].update(
        {
            "uid": "x",
            "resourceVersion": "1",
            "generation": 4,
            "creationTimestamp": "t",
            "managedFields": [{"manager": "kubectl"}],
            "annotations": {"deployment.kubernetes.io/revision": "5"},
        }
    )
    noisy["spec"]["template"]["metadata"]["annotations"] = {"kubectl.kubernetes.io/restartedAt": "now"}
    rs = {
        "apiVersion": "apps/v1",
        "kind": "ReplicaSet",
        "metadata": {
            "name": "worker-1",
            "namespace": "shop",
            "ownerReferences": [{"kind": "Deployment", "name": "worker", "controller": True}],
        },
    }
    a = drift.snapshot(base, source="manifests", taken_at=T1)
    b = drift.snapshot([d for d in base if d is not web] + [noisy, rs], source="manifests", taken_at=T2)
    rep = drift.diff(a, b)
    assert rep["objects"]["changed"] == [] and rep["objects"]["added"] == []
    real = json.loads(json.dumps(web))
    real["spec"]["template"]["metadata"]["annotations"] = {"owner-note": "a real template change"}
    c = drift.snapshot([d for d in base if d is not web] + [real], source="manifests", taken_at=T2)
    assert drift.diff(a, c)["objects"]["changed"][0]["fields"] == ["spec.template.metadata.annotations.owner-note"]


def test_excepted_findings_are_not_counted_open() -> None:
    rev = exc.review(
        yaml.safe_dump(
            {
                "apiVersion": "kube-noob.io/v1",
                "kind": "ExceptionList",
                "exceptions": [
                    {
                        "id": "EXC-agent",
                        "rule": "KN-S001",
                        "owner": "ops",
                        "reason": "the agent reads host devices",
                        "expires": (dt.datetime.now(dt.UTC).date() + dt.timedelta(days=60)).isoformat(),
                        "scope": {"namespace": "ops", "kind": "DaemonSet", "name": "agent"},
                    }
                ],
            }
        )
    )
    rep = drift.diff(_snap("day1.yaml", T1), _snap("day2.yaml", T2, exceptions=rev))
    assert [f["ruleId"] for f in rep["findings"]["new"]] == ["KN-S002", "KN-S017"]
    assert rep["findings"]["open"] == 2 and rep["findings"]["excepted"] == 1


def test_the_daily_report_folder_keeps_the_newest_and_is_owner_only(tmp_path: Path) -> None:
    state = tmp_path / "posture"
    first, paths = drift.write_report(state, _snap("day1.yaml", T1), keep=2)
    assert first["from"] is None and len(first["objects"]["added"]) == 11
    second, paths = drift.write_report(state, _snap("day2.yaml", T2), keep=2)
    assert {k: v for k, v in second.items() if k != "from"} == {k: v for k, v in EXPECTED.items() if k != "from"}
    for p in paths.values():
        assert stat.S_IMODE(p.stat().st_mode) == 0o600
    assert stat.S_IMODE(state.stat().st_mode) == 0o700
    md = paths["markdown"].read_text(encoding="utf-8")
    assert "| KN-S001 | DaemonSet/ops/agent | critical | unowned |" in md and "## Fixed findings" in md
    third, _ = drift.write_report(state, _snap("day2.yaml", T2 + dt.timedelta(days=1)), keep=2)
    assert third["objects"]["changed"] == [] and third["findings"]["new"] == []
    assert len(list(state.glob("snapshot-*.json"))) == 2 and len(list(state.glob("report-*.json"))) == 2
    assert drift.latest_report(state) == third
    with pytest.raises(drift.DriftError):
        drift.write_report(state, _snap("day2.yaml", T2), keep=0)


def test_bad_snapshots_are_refused(tmp_path: Path) -> None:
    f = tmp_path / "x.json"
    for text in ("{", json.dumps({"format": "other"}), json.dumps([1])):
        f.write_text(text, encoding="utf-8")
        with pytest.raises(drift.DriftError):
            drift.load(f)
    with pytest.raises(drift.DriftError):
        drift.diff({"format": "x"}, _snap("day1.yaml", T1))
    with pytest.MonkeyPatch.context() as m:
        m.setattr(drift, "MAX_OBJECTS", 3)
        with pytest.raises(drift.DriftError, match="more than 3"):
            drift.watched(_docs("day1.yaml"))


class FakeBackend:
    name = "fake"

    def __init__(self, docs: list[dict[str, Any]]) -> None:
        self.calls: list[tuple[str, str | None]] = []
        self.docs = docs

    def get(self, resource: str, name: str | None = None, namespace: str | None = None, **_: Any) -> dict[str, Any]:
        resolve_resource(resource)
        self.calls.append((resource, namespace))
        kind = {**drift.LIVE_RESOURCES, **drift.EXTRA_LIVE}[resource]
        if kind == "SecurityContextConstraints":
            raise ClusterAccessError("not served")
        items = [
            {k: v for k, v in d.items() if k != "kind"}
            for d in self.docs
            if d.get("kind") == kind and (namespace is None or d["metadata"].get("namespace") == namespace)
        ]
        return {"items": items}


def test_live_snapshots_read_the_allowlist_only(tmp_path: Path) -> None:
    backend = FakeBackend(_docs("day2.yaml"))
    objects, not_read = drift.collect_live(backend, [])
    assert not any("secret" in r for r, _ in backend.calls)
    assert {r for r, _ in backend.calls} == set(drift.LIVE_RESOURCES) | set(drift.EXTRA_LIVE)
    assert any(n.startswith("securitycontextconstraints") for n in not_read)
    live = drift.snapshot(objects, source="live", taken_at=T2)
    assert set(live["objects"]) == set(_snap("day2.yaml", T2)["objects"])
    scoped = FakeBackend(_docs("day2.yaml"))
    objs, _ = drift.collect_live(scoped, ["shop"])
    assert ("namespaces", None) in scoped.calls and ("deployments", "shop") in scoped.calls
    assert {o["metadata"]["name"] for o in objs if o["kind"] == "Namespace"} == {"shop"}


def test_cli_snapshot_diff_and_report(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    s1, s2 = tmp_path / "1.json", tmp_path / "2.json"
    assert main(["posture", "snapshot", "-f", str(FIX / "day1.yaml"), "-o", str(s1)]) == 0
    assert main(["posture", "snapshot", "-f", str(FIX / "day2.yaml"), "-o", str(s2)]) == 0
    assert "11 objects, 1 findings" in capsys.readouterr().out
    md = tmp_path / "r.md"
    assert main(["--format", "json", "posture", "diff", str(s1), str(s2), "--markdown", str(md)]) == 0
    rep = json.loads(capsys.readouterr().out)
    assert {k: v for k, v in rep.items() if k not in {"from", "to"}} == {
        k: v for k, v in EXPECTED.items() if k not in {"from", "to"}
    }
    assert md.read_text(encoding="utf-8").startswith("# Drift and policy report")
    state = tmp_path / "state"
    assert main(["posture", "report", "-f", str(FIX / "day1.yaml"), "--state-dir", str(state)]) == 0
    assert main(["posture", "report", "-f", str(FIX / "day2.yaml"), "--state-dir", str(state)]) == 0
    out = capsys.readouterr().out
    assert "3 new, 1 fixed, 3 open" in out
    for argv in (
        ["posture", "snapshot", "-o", str(s1)],
        ["posture", "report", "--live"],
        ["posture", "diff", str(s1), str(md)],
    ):
        assert main(argv) == 2
        capsys.readouterr()


def test_mcp_tool_and_serve_settings(tmp_path: Path) -> None:
    s = load_settings()
    kit = tk.Toolkit(s)
    assert kit.posture_report(tk.EmptyIn())["report"] is None
    drift.write_report(s.data_dir / "posture", _snap("day1.yaml", T1))
    drift.write_report(s.data_dir / "posture", _snap("day2.yaml", T2))
    got = kit.posture_report(tk.EmptyIn())["report"]
    assert got["findings"]["new"] == EXPECTED["findings"]["new"]
    with pytest.raises(ConfigError, match="namespace names"):
        load_settings(overrides={"posture": {"namespaces": ["Bad NS"]}})
    on = load_settings(overrides={"posture": {"reportEnabled": True, "keep": 7}})
    assert on.posture.report_enabled and on.posture.keep == 7
    from kube_noob.drift_schedule import start_background

    stop = start_background(on)
    try:
        assert 30 <= stop.first_delay <= 600
    finally:
        stop.set()
