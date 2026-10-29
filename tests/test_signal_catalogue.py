"""The signal catalogue stays consistent: unique ids, real playbooks, known components, a source for every entry."""

from __future__ import annotations

import yaml

from kube_noob.debug.playbooks import PLAYBOOKS
from kube_noob.signals import catalogue, extract
from kube_noob.signals.vocab import COMPONENTS, EVENT_REASONS, POD_REASONS


def test_catalogue_schema() -> None:
    entries = catalogue.entries()
    assert len(entries) >= 60
    ids = [e.id for e in entries]
    assert len(ids) == len(set(ids))
    playbooks = {p.pid for p in PLAYBOOKS}
    for e in entries:
        assert e.kind in catalogue.KINDS
        assert e.sources and all(s.startswith("https://github.com/") for s in e.sources), e.id
        assert set(e.playbooks) <= playbooks, (e.id, set(e.playbooks) - playbooks)
        assert set(e.components) <= set(COMPONENTS), (e.id, set(e.components) - set(COMPONENTS))
        assert all(a == a.lower() and a.strip() == a for a in e.aliases), e.id
        assert e.terms, e.id
        if e.kind == "event_reason":
            assert e.name in EVENT_REASONS, e.id
        if e.kind == "pod_reason":
            assert e.name in POD_REASONS, e.id


def test_every_named_source_is_declared() -> None:
    from importlib import resources

    doc = yaml.safe_load(resources.files("kube_noob").joinpath("data", "signals.yaml").read_text())
    declared = set(doc["sources"])
    for item in doc["signals"]:
        assert set(item["sources"]) <= declared, item["id"]


def test_openshift_and_upstream_names_both_exist_where_they_differ() -> None:
    for name in ("etcdGRPCRequestsSlow", "etcdGRPCReadRequestsSlow", "etcdGRPCWriteRequestsSlow", "MCCDrainError"):
        assert catalogue.get("alert", name) is not None, name
    assert catalogue.get("alert", "MCDDrainError") is None  # the operator names it MCCDrainError


def test_prose_implies_signals_and_expands_terms() -> None:
    found = catalogue.infer("etcd leader changed frequently, apiserver timeouts after upgrade")
    assert [(s.kind, s.name) for s in found] == [
        ("alert", "KubeAPIErrorBudgetBurn"),
        ("alert", "etcdHighNumberOfLeaderChanges"),
    ]
    terms = catalogue.terms_for(found)
    assert "election" in terms and "high i/o" in terms
    assert catalogue.infer("everything is fine today") == []
    assert [s.name for s in catalogue.infer("etcdNoLeader fired at 3am")] == ["etcdNoLeader"]


def test_catalogued_alert_names_in_prose_are_alert_signals() -> None:
    names = [s.name for s in extract("etcdHighNumberOfLeaderChanges is firing on master-0") if s.kind == "alert"]
    assert names == ["etcdHighNumberOfLeaderChanges"]
