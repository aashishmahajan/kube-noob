"""POL3 (R3.5): exceptions as code. Expired, out-of-scope and ownerless exceptions are refused with the reason."""

from __future__ import annotations

import datetime as dt
import json
from pathlib import Path

import pytest
import yaml

from kube_noob import toolkit as tk
from kube_noob.audit import exceptions as exc
from kube_noob.cli import main
from kube_noob.config import load_settings

FIX = Path(__file__).parent / "fixtures" / "exceptions"
EXAMPLE = Path(__file__).parent.parent / "examples" / "kube-noob-exceptions.yaml"
TODAY = dt.date(2026, 10, 28)
FUTURE = (dt.datetime.now(dt.UTC).date() + dt.timedelta(days=95)).isoformat()

BUNDLE = """
apiVersion: apps/v1
kind: DaemonSet
metadata: {name: node-exporter, namespace: monitoring}
spec:
  selector: {matchLabels: {app: ne}}
  template:
    metadata: {labels: {app: ne}}
    spec:
      hostNetwork: true
      containers: [{name: ne, image: quay.io/prometheus/node-exporter:v1.8.0, securityContext: {privileged: true}}]
---
apiVersion: apps/v1
kind: DaemonSet
metadata: {name: log-agent, namespace: monitoring}
spec:
  selector: {matchLabels: {app: la}}
  template:
    metadata: {labels: {app: la}}
    spec:
      hostNetwork: true
      containers: [{name: la, image: quay.io/acme/log-agent:2.0.0}]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata: {name: monitoring-reader}
rules: [{apiGroups: ["*"], resources: [pods], verbs: [get]}]
"""


def _relative(text: str) -> str:
    """The fixture with its dates moved relative to the real today, for code paths that check against the clock."""
    today = dt.datetime.now(dt.UTC).date()
    for fixed, days in (("2027-01-31", 95), ("2026-09-30", -28), ("2030-01-01", 1160)):
        text = text.replace(fixed, (today + dt.timedelta(days=days)).isoformat())
    return text


def _review(name: str = "mixed.yaml") -> exc.Review:
    return exc.review((FIX / name).read_text(encoding="utf-8"), TODAY)


def test_every_entry_gets_a_status_and_a_reason() -> None:
    by_id = {e.id: e for e in _review().entries}
    assert by_id["ok-hostnet"].status == "active"
    assert by_id["cluster-role"].status == "active"
    assert by_id["expired-priv"].status == "expired" and "2026-09-30" in by_id["expired-priv"].reason
    expect_refused = {
        "no-owner": "no owner",
        "too-broad": "scope too broad",
        "star-namespace": "too broad",
        "unknown-rule": "unknown rule",
        "forever": "more than 400 days",
        "no-reason": "no reason",
        "extra-field": "unknown field",
    }
    for eid, why in expect_refused.items():
        assert by_id[eid].status == "refused", eid
        assert why in by_id[eid].reason, (eid, by_id[eid].reason)
    s = _review().summary()
    assert s["counts"] == {"active": 3, "expired": 1, "refused": 7} and s["gate"] is False


def test_the_example_file_is_valid_and_checked_by_the_cli(capsys: pytest.CaptureFixture[str]) -> None:
    rev = exc.review(EXAMPLE.read_text(encoding="utf-8"), TODAY)
    assert [e.status for e in rev.entries] == ["active", "active"] and rev.summary()["gate"]
    assert main(["exceptions", "check", str(EXAMPLE), "--today", "2026-10-28"]) == 0
    assert "2 active, 0 expired, 0 refused" in capsys.readouterr().out
    assert main(["exceptions", "check", str(FIX / "mixed.yaml"), "--today", "2026-10-28"]) == 1
    out = capsys.readouterr().out
    assert "[EXPIRED] expired-priv" in out and "[REFUSED] no-owner" in out
    assert main(["exceptions", "check", str(EXAMPLE), "--today", "2027-07-01"]) == 1, "expiry passes with time"
    capsys.readouterr()


def test_scope_decides_what_an_exception_hides() -> None:
    rev = _review()
    hit = exc.match(rev, "KN-S009", "DaemonSet/monitoring/node-exporter")
    assert hit is not None and hit.id == "ok-hostnet"
    assert exc.match(rev, "KN-S009", "DaemonSet/monitoring/log-agent") is None, "same rule, other object"
    assert exc.match(rev, "KN-S001", "DaemonSet/monitoring/node-exporter") is None, "expired never hides"
    assert exc.match(rev, "KN-S015", "ClusterRole/monitoring-reader") is not None
    assert exc.match(rev, "KN-S015", "ClusterRole/other") is None
    prefix = exc.review(EXAMPLE.read_text(encoding="utf-8"), TODAY)
    assert exc.match(prefix, "KN-C007", "Deployment/team-a/web-canary") is not None
    assert exc.match(prefix, "KN-C007", "Deployment/team-a/web") is None
    assert exc.match(prefix, "KN-C007", "Deployment/shop/web-canary") is None


def test_audit_hides_covered_findings_and_fails_the_gate_on_bad_entries(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    kit = tk.Toolkit(load_settings())
    good = yaml.safe_dump(
        {
            "apiVersion": "kube-noob.io/v1",
            "kind": "ExceptionList",
            "exceptions": [
                {
                    "id": "EXC-1",
                    "rule": "KN-S009",
                    "owner": "obs",
                    "reason": "host metrics need it",
                    "expires": FUTURE,
                    "scope": {"namespace": "monitoring", "name": "node-exporter"},
                },
                {
                    "id": "EXC-2",
                    "rule": "KN-S020",
                    "owner": "obs",
                    "reason": "an exception nothing uses",
                    "expires": FUTURE,
                    "scope": {"namespace": "monitoring"},
                },
            ],
        }
    )
    out = kit.audit(tk.AuditIn(manifests=BUNDLE, exceptions=good))
    ids = {(f["ruleId"], f["resource"]) for f in out["findings"]}
    assert ("KN-S009", "DaemonSet/monitoring/node-exporter") not in ids
    assert ("KN-S009", "DaemonSet/monitoring/log-agent") in ids
    assert ("KN-S001", "DaemonSet/monitoring/node-exporter") in ids, "an exception covers one rule only"
    assert [(f["ruleId"], f["exception"]["id"]) for f in out["excepted"]] == [("KN-S009", "EXC-1")]
    assert out["exceptions"]["unused"] == ["EXC-2"] and out["exceptions"]["gate"] is True
    assert sum(out["summary"]["counts"].values()) == len(out["findings"]), "counts are of the findings kept"
    manifests, ex_file = tmp_path / "m.yaml", tmp_path / "e.yaml"
    manifests.write_text(BUNDLE, encoding="utf-8")
    ex_file.write_text(good, encoding="utf-8")
    rc = main(["audit", "-f", str(manifests), "--exceptions", str(ex_file), "--fail-on", "never"])
    text = capsys.readouterr().out
    assert rc == 0 and "excepted KN-S009 DaemonSet/monitoring/node-exporter by EXC-1" in text
    assert "unused EXC-2" in text
    bad = _relative((FIX / "mixed.yaml").read_text(encoding="utf-8"))
    ex_file.write_text(bad, encoding="utf-8")
    rc = main(["audit", "-f", str(manifests), "--exceptions", str(ex_file), "--fail-on", "never"])
    text = capsys.readouterr().out
    assert rc == 1, "expired and refused entries fail the gate even with --fail-on never"
    assert "gate: failed" in text and "[EXPIRED] expired-priv" in text
    rc = main(["--format", "json", "audit", "-f", str(manifests), "--exceptions", str(ex_file)])
    assert json.loads(capsys.readouterr().out)["exceptions"]["gate"] is False and rc == 1


def test_files_that_are_not_exception_lists_are_refused(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    for text, why in (
        ("[1, 2", "not YAML"),
        ("apiVersion: v1\nkind: ConfigMap\n", "ExceptionList"),
        ("apiVersion: kube-noob.io/v1\nkind: ExceptionList\nexceptions: {a: 1}\n", "must be a list"),
        ("apiVersion: kube-noob.io/v1\nkind: ExceptionList\nwaivers: []\n", "unknown top-level"),
    ):
        with pytest.raises(exc.ExceptionsError, match=why):
            exc.review(text, TODAY)
    many = {"apiVersion": "kube-noob.io/v1", "kind": "ExceptionList", "exceptions": [{}] * (exc.MAX_EXCEPTIONS + 1)}
    with pytest.raises(exc.ExceptionsError, match="more than"):
        exc.review(yaml.safe_dump(many), TODAY)
    odd = exc.review("apiVersion: kube-noob.io/v1\nkind: ExceptionList\nexceptions: [7, {rule: KN-S001}]\n", TODAY)
    assert [e.status for e in odd.entries] == ["refused", "refused"]
    f = tmp_path / "x.yaml"
    f.write_text("nope: [", encoding="utf-8")
    assert main(["exceptions", "check", str(f)]) == 2
    assert main(["exceptions", "check", str(EXAMPLE), "--today", "28/10/2026"]) == 2
    capsys.readouterr()


def test_duplicate_ids_are_refused() -> None:
    entry = {
        "id": "EXC-1",
        "rule": "KN-S009",
        "owner": "obs",
        "reason": "host metrics need it",
        "expires": FUTURE,
        "scope": {"namespace": "monitoring"},
    }
    rev = exc.review(
        yaml.safe_dump({"apiVersion": "kube-noob.io/v1", "kind": "ExceptionList", "exceptions": [entry, entry]}), TODAY
    )
    assert [e.status for e in rev.entries] == ["active", "refused"] and "duplicate" in rev.entries[1].reason


# --- exceptions in generated admission policies -------------------------------------------------------------------


def _ds(name: str, ns: str = "monitoring", kind: str = "DaemonSet", owner: tuple[str, str] | None = None) -> dict:
    spec = {"hostNetwork": True, "containers": [{"name": "c", "image": "quay.io/acme/x:1"}]}
    meta: dict = {"name": name, "namespace": ns}
    if owner:
        meta["ownerReferences"] = [
            {"apiVersion": "apps/v1", "kind": owner[0], "name": owner[1], "uid": "1", "controller": True}
        ]
    if kind == "Pod":
        return {"apiVersion": "v1", "kind": "Pod", "metadata": meta, "spec": spec}
    return {
        "apiVersion": "apps/v1",
        "kind": kind,
        "metadata": meta,
        "spec": {
            "selector": {"matchLabels": {"a": "b"}},
            "template": {"metadata": {"labels": {"a": "b"}}, "spec": spec},
        },
    }


def test_active_exceptions_become_exemptions_for_the_workload_and_what_it_makes() -> None:
    from kube_noob.generate import policies as pol
    from tests.policy_cel import failures

    rev = _review()
    policy = pol.generate(rules=["KN-S009"], engines=("vap",), mode="enforce", exceptions=rev.entries).documents[0]
    assert failures(policy, _ds("node-exporter")) == []
    assert failures(policy, _ds("node-exporter-x7k2p", kind="Pod", owner=("DaemonSet", "node-exporter"))) == []
    assert failures(policy, _ds("log-agent")), "same namespace, other workload"
    assert failures(policy, _ds("log-agent-x", kind="Pod", owner=("DaemonSet", "log-agent")))
    assert failures(policy, _ds("node-exporter", ns="shop")), "same name, other namespace"
    expired_only = pol.generate(rules=["KN-S001"], engines=("vap",), exceptions=rev.entries).documents[0]
    assert "monitoring" not in json.dumps(expired_only["spec"]["variables"]), "expired exceptions are not applied"
    ex = exc.review(EXAMPLE.read_text(encoding="utf-8"), TODAY)
    c007 = pol.generate(rules=["KN-C007"], engines=("kyverno",), exceptions=ex.entries).documents[0]
    canary = {
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": {"name": "web-canary", "namespace": "team-a"},
        "spec": {
            "replicas": 1,
            "selector": {"matchLabels": {"a": "b"}},
            "template": {"metadata": {"labels": {"a": "b"}}, "spec": {"containers": []}},
        },
    }
    assert failures(c007, canary) == []
    assert failures(c007, {**canary, "metadata": {"name": "web", "namespace": "team-a"}})
    assert failures(c007, {**canary, "metadata": {"name": "web-canary", "namespace": "shop"}})
    deploy = pol.generate(
        rules=["KN-S001"],
        engines=("vap",),
        mode="enforce",
        exceptions=exc.review(
            yaml.safe_dump(
                {
                    "apiVersion": "kube-noob.io/v1",
                    "kind": "ExceptionList",
                    "exceptions": [
                        {
                            "id": "E",
                            "rule": "KN-S001",
                            "owner": "o",
                            "reason": "debug image runs privileged",
                            "expires": "2027-01-01",
                            "scope": {"namespace": "shop", "kind": "Deployment", "name": "dbg"},
                        }
                    ],
                }
            ),
            TODAY,
        ).entries,
    ).documents[0]
    priv = {"name": "c", "image": "quay.io/acme/x:1", "securityContext": {"privileged": True}}
    rs = {
        "apiVersion": "apps/v1",
        "kind": "ReplicaSet",
        "metadata": {
            "name": "dbg-5d8f9",
            "namespace": "shop",
            "ownerReferences": [{"kind": "Deployment", "name": "dbg", "controller": True}],
        },
        "spec": {
            "selector": {"matchLabels": {"a": "b"}},
            "template": {"metadata": {"labels": {"a": "b"}}, "spec": {"containers": [priv]}},
        },
    }
    pod = {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {
            "name": "dbg-5d8f9-abcde",
            "namespace": "shop",
            "ownerReferences": [{"kind": "ReplicaSet", "name": "dbg-5d8f9", "controller": True}],
        },
        "spec": {"containers": [priv]},
    }
    assert failures(deploy, rs) == [] and failures(deploy, pod) == []
    stray = {**pod, "metadata": {**pod["metadata"], "ownerReferences": [{"kind": "ReplicaSet", "name": "other-1"}]}}
    assert failures(deploy, stray)


def test_exemption_cel_agrees_with_the_audit_on_random_objects() -> None:
    import random

    from kube_noob.generate import policies as pol
    from tests.policy_cel import failures

    rng = random.Random(11)
    entries = []
    for i in range(40):
        scope: dict = {}
        if rng.random() < 0.85:
            scope["namespace"] = rng.choice(["shop", "team-a", "team-*", "monitoring"])
            if rng.random() < 0.6:
                scope["kind"] = rng.choice(["Deployment", "DaemonSet", "StatefulSet"])
            if rng.random() < 0.6:
                scope["name"] = rng.choice(["web", "web-*", "*-canary", "agent"])
        else:
            scope = {"kind": "ClusterRole", "name": rng.choice(["reader", "admin-x"])}
        entries.append(
            {
                "id": f"E{i}",
                "rule": "KN-S009" if "namespace" in scope else "KN-S015",
                "owner": "o",
                "reason": "random exception for the test",
                "expires": "2027-01-01",
                "scope": scope,
            }
        )
    rev = exc.review(
        yaml.safe_dump({"apiVersion": "kube-noob.io/v1", "kind": "ExceptionList", "exceptions": entries}), TODAY
    )
    assert all(e.status == "active" for e in rev.entries)
    s009 = pol.generate(rules=["KN-S009"], engines=("vap",), exceptions=rev.entries).documents[0]
    checked = 0
    for _ in range(300):
        kind = rng.choice(["Deployment", "DaemonSet", "StatefulSet"])
        ns = rng.choice(["shop", "team-a", "team-b", "monitoring", "other"])
        name = rng.choice(["web", "web-canary", "web-1", "agent", "db"])
        excepted = exc.match(rev, "KN-S009", f"{kind}/{ns}/{name}") is not None
        refused = bool(failures(s009, _ds(name, ns=ns, kind=kind)))
        assert refused == (not excepted), (kind, ns, name)
        checked += 1
    s015 = pol.generate(rules=["KN-S015"], engines=("vap",), exceptions=rev.entries).documents[0]
    for name in ("reader", "admin-x", "other"):
        role = {
            "apiVersion": "rbac.authorization.k8s.io/v1",
            "kind": "ClusterRole",
            "metadata": {"name": name},
            "rules": [{"apiGroups": ["*"], "resources": ["*"], "verbs": ["get"]}],
        }
        excepted = exc.match(rev, "KN-S015", f"ClusterRole/{name}") is not None
        assert bool(failures(s015, role)) == (not excepted), name
    assert checked == 300


def test_policy_generate_cli_reports_exceptions(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    out = tmp_path / "p.yaml"
    mixed = tmp_path / "mixed.yaml"
    mixed.write_text(_relative((FIX / "mixed.yaml").read_text(encoding="utf-8")), encoding="utf-8")
    argv = ["policy", "generate", "--rule", "KN-S009", "--rule", "KN-S001", "--engine", "vap"]
    assert main([*argv, "--exceptions", str(mixed), "-o", str(out)]) == 0
    text = out.read_text(encoding="utf-8")
    assert "# Exceptions applied as exemptions:" in text and "not applied, expired: expired-priv" in text
    capsys.readouterr()
    kit = tk.Toolkit(load_settings())
    res = kit.policy_generate(
        tk.PolicyGenerateIn(rules=["KN-S009"], engines=["vap"], exceptions=mixed.read_text(encoding="utf-8"))
    )
    assert res["generated"][0].get("exceptions") == "ok-hostnet"
