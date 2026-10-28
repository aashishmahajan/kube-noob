"""Capability tiers: everything beyond reading is off by default, and every action needs a single-use approval."""

from __future__ import annotations

import inspect
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from kube_noob import tiers
from kube_noob import toolkit as tk
from kube_noob.config import load_settings
from kube_noob.debug import backends
from kube_noob.errors import ApprovalError, TierDisabledError
from kube_noob.posture import posture, render_text

NOW = datetime(2026, 10, 28, 12, 0, tzinfo=UTC)
ALL_ON = {
    "cluster": {"enabled": True},
    "probe": {"enabled": True},
    "dryRun": {"enabled": True},
    "itsm": {"writeEnabled": True},
    "notify": {"enabled": True},
    "gate": {"enabled": True},
    "admission": {"enforce": ["KN-S001"]},
}


class ProbeWriter(tiers.Writer):
    tier = "P"


class GateWriter(tiers.Writer):
    tier = "G"


def test_every_tier_is_off_by_default(tmp_path: Path) -> None:
    s = load_settings(overrides={"dataDir": str(tmp_path)})
    rows = tiers.describe(s)
    assert [r["tier"] for r in rows] == ["R", "P", "D", "W", "G", "A"]
    assert not any(r["enabled"] for r in rows)
    assert all(r["switch"] and r["allows"] and r["rbac"] for r in rows)
    assert tiers.conflicts(s) == []


def test_enabled_tiers_and_their_contradictions(tmp_path: Path) -> None:
    s = load_settings(overrides={"dataDir": str(tmp_path), **ALL_ON})
    assert all(r["enabled"] for r in tiers.describe(s))
    lonely = load_settings(overrides={"dataDir": str(tmp_path), "probe": {"enabled": True}})
    assert any("probe.enabled needs cluster.enabled" in c for c in tiers.conflicts(lonely))
    lookups = load_settings(overrides={"dataDir": str(tmp_path), "admission": {"lookups": True}})
    assert any("admission.lookups" in c and "cluster.enabled" in c for c in tiers.conflicts(lookups))
    with pytest.raises(ApprovalError, match="read-only and needs no approval"):
        tiers.Approval.create("A", "deny", "alice", "configured in admission.enforce", now=NOW)
    writes = {"itsm": {"writeEnabled": True}, "notify": {"enabled": True}}
    locked = load_settings(overrides={"dataDir": str(tmp_path), "offline": True, **writes})
    found = tiers.conflicts(locked)
    assert any("itsm.writeEnabled" in c for c in found) and any("notify.enabled" in c for c in found)
    p = posture(locked)
    assert p["status"] == "conflict" and [t["tier"] for t in p["tiers"]] == ["R", "P", "D", "W", "G", "A"]
    text = render_text(p)
    assert "tier W" in text and "tier P" in text


def test_the_offline_lock_is_unaffected_by_tiers(tmp_path: Path) -> None:
    s = load_settings(overrides={"dataDir": str(tmp_path), "offline": True, **ALL_ON})
    assert s.offline and not s.web_enabled
    assert posture(s)["network"]["web"] == "locked-off"


def test_a_writer_exists_only_when_its_tier_is_on(tmp_path: Path) -> None:
    with pytest.raises(TierDisabledError, match=r"tier P .*probe\.enabled"):
        ProbeWriter(load_settings(overrides={"dataDir": str(tmp_path)}))
    assert ProbeWriter(load_settings(overrides={"dataDir": str(tmp_path), **ALL_ON})).tier == "P"


def test_approvals_are_bound_to_one_action_unexpired_and_single_use(tmp_path: Path) -> None:
    w = ProbeWriter(load_settings(overrides={"dataDir": str(tmp_path), **ALL_ON}))
    action = "probe shop/web -> db.shop.svc:5432"
    ok = tiers.Approval.create("P", action, "alice", "INC-42 connectivity check", now=NOW)
    w.authorize(ok, action, now=NOW + timedelta(minutes=1))
    with pytest.raises(ApprovalError, match="already used"):
        w.authorize(ok, action, now=NOW + timedelta(minutes=2))
    other = tiers.Approval.create("P", action, "alice", "INC-42", now=NOW)
    with pytest.raises(ApprovalError, match="different action"):
        w.authorize(other, "probe shop/web -> 10.0.0.1:22", now=NOW)
    with pytest.raises(ApprovalError, match="expired"):
        w.authorize(other, action, now=NOW + timedelta(hours=1))
    gate = tiers.Approval.create("G", action, "alice", "INC-42", now=NOW)
    with pytest.raises(ApprovalError, match="tier G"):
        w.authorize(gate, action, now=NOW)
    with pytest.raises(ApprovalError):
        w.authorize("yes please", action, now=NOW)  # type: ignore[arg-type]


def test_approvals_need_a_person_and_a_reason() -> None:
    for approver, reason in (("", "x"), ("alice", ""), ("alice\x1b[2J", "x"), ("a" * 200, "x"), ("alice", "r" * 600)):
        with pytest.raises(ApprovalError):
            tiers.Approval.create("P", "probe", approver, reason, now=NOW)
    with pytest.raises(ApprovalError, match="24 hours"):
        tiers.Approval.create("P", "probe", "alice", "x", ttl=timedelta(days=2), now=NOW)
    with pytest.raises(ApprovalError, match="unknown tier"):
        tiers.Approval.create("Z", "probe", "alice", "x", now=NOW)
    with pytest.raises(ApprovalError, match="read-only"):
        tiers.Approval.create("R", "probe", "alice", "x", now=NOW)


def test_the_read_only_backends_cannot_write() -> None:
    allowed = {"get", "logs", "version"}
    for cls in (backends.KubectlBackend, backends.InClusterBackend):
        public = {n for n, _ in inspect.getmembers(cls, inspect.isfunction) if not n.startswith("_")}
        assert public <= allowed, (cls.__name__, public - allowed)
    source = inspect.getsource(backends)
    for verb in (".post(", ".put(", ".patch(", ".delete(", '"apply"', '"create"', '"delete"', '"exec"', '"edit"'):
        assert verb not in source, verb


def test_tool_list_is_unchanged_with_defaults_and_tier_tools_need_their_tier(tmp_path: Path) -> None:
    default = tk.Toolkit(load_settings(overrides={"dataDir": str(tmp_path)}))
    assert all(t.tier is None for t in default.specs())
    spec = tk.ToolSpec("probe_run", "Run a probe", "x", tk.EmptyIn, lambda _: None, read_only=False, tier="P")
    assert not tiers.offered(spec, default.settings)
    on = load_settings(overrides={"dataDir": str(tmp_path), **ALL_ON})
    assert tiers.offered(spec, on)
    assert [t.name for t in tk.Toolkit(on).specs()] == [
        t.name
        for t in tk.Toolkit(load_settings(overrides={"dataDir": str(tmp_path), "cluster": {"enabled": True}})).specs()
    ]


def test_every_tier_cites_its_source() -> None:
    for t in tiers.TIERS:
        assert all(src.startswith("https://") for src in t.sources), t.code


def test_kube_noobs_own_audit_flags_what_tier_roles_allow() -> None:
    """Workload creation and ephemeral containers are escalation paths (Kubernetes RBAC good practices)."""
    from kube_noob.audit.engine import analyze

    roles = """
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata: {name: probe, namespace: shop}
rules:
  - {apiGroups: [""], resources: [pods/ephemeralcontainers], verbs: [patch]}
  - {apiGroups: [batch], resources: [jobs], verbs: [create, delete]}
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata: {name: deployer}
rules:
  - {apiGroups: [apps], resources: [deployments], verbs: [patch]}
  - {apiGroups: [""], resources: [persistentvolumes], verbs: [create]}
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata: {name: reader, namespace: shop}
rules:
  - {apiGroups: [apps], resources: [deployments], verbs: [get, list, watch]}
"""
    found = [
        (f["resource"], f["severity"], f["message"])
        for f in analyze(roles).as_dict()["findings"]
        if f["ruleId"] == "KN-S017"
    ]
    assert (
        "Role/shop/probe",
        "medium",
        "Can add ephemeral containers to running pods: code runs in the pod, like exec.",
    ) in found
    assert any(r == "Role/shop/probe" and s == "medium" and "jobs" in m for r, s, m in found)
    assert any(r == "ClusterRole/deployer" and s == "high" and "deployments" in m for r, s, m in found)
    assert any(r == "ClusterRole/deployer" and s == "high" and "hostPath" in m for r, s, m in found)
    assert not any(r == "Role/shop/reader" for r, _, _ in found)
