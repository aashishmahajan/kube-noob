"""Fleet view (MEM5): outcomes carry a cluster label, `memory stats --by cluster` counts them, and a match says "seen
on N of your clusters, fixed on M"."""

from __future__ import annotations

import json
from datetime import date, timedelta
from pathlib import Path

import pytest

from kube_noob.cli import main
from kube_noob.memory import dump_entry, load_entry, repo
from kube_noob.memory import match as mmatch

DAY = date(2026, 10, 1)


@pytest.fixture
def fleet(tmp_path: Path) -> Path:
    root = tmp_path / "team"
    repo.init_repo(root)
    path, entry = repo.add_entry(
        root,
        {
            "kind": "fix",
            "signals": [{"kind": "alert", "name": "KubePodCrashLooping"}, {"kind": "pod_reason", "name": "OOMKilled"}],
            "symptom": "orders-api pods OOMKilled during the nightly batch import",
            "platform": "openshift",
            "cause": "The batch import loads the whole catalogue into memory.",
            "fix": {"text": "Raise the memory limit to 1Gi and stream the import in pages."},
            "owners": ["orders-team"],
        },
        DAY,
    )
    path.write_text(dump_entry(entry.model_copy(update={"status": "approved"})), encoding="utf-8")
    outcomes = [
        ("resolved", "prod-east"),
        ("resolved", "prod-east"),
        ("not-resolved", "prod-west"),
        ("resolved", "prod-west"),
        ("partial", "staging"),
        ("resolved", None),
    ]
    for n, (result, cluster) in enumerate(outcomes):
        repo.add_outcome(root, "MEM-1", result, ticket=f"INC-{100 + n}", cluster=cluster, day=DAY + timedelta(days=n))
    return root


def test_three_clusters_in_match_and_outcomes(fleet: Path) -> None:
    e = load_entry(fleet / "entries" / "MEM-1.yaml")
    assert [o.cluster for o in e.outcomes] == ["prod-east", "prod-east", "prod-west", "prod-west", "staging", None]
    assert e.updated == DAY + timedelta(days=5)
    m = mmatch.match([fleet], "Last State: Terminated Reason: OOMKilled Exit Code: 137")["matches"][0]
    o = m["outcomes"]
    assert (o["applied"], o["resolved"], o["partial"], o["notResolved"]) == (6, 4, 1, 1)
    assert o["clusters"] == ["prod-east", "prod-west", "staging"]
    assert o["summary"] == "matched 6 times, resolved 4; seen on 3 of your clusters, fixed on 2"


def test_stats_by_cluster(fleet: Path, capsys: pytest.CaptureFixture[str]) -> None:
    groups = {g["key"]: g for g in mmatch.stats(fleet, "cluster")["groups"]}
    assert set(groups) == {"prod-east", "prod-west", "staging", "(no cluster)"}
    assert (groups["prod-east"]["applied"], groups["prod-east"]["resolved"]) == (2, 2)
    assert (groups["prod-west"]["resolved"], groups["prod-west"]["notResolved"]) == (1, 1)
    assert (groups["staging"]["partial"], groups["(no cluster)"]["resolved"]) == (1, 1)
    assert [g["key"] for g in mmatch.stats(fleet, "cluster")["groups"]][:2] == ["prod-east", "prod-west"]
    assert main(["memory", "stats", str(fleet), "--by", "cluster"]) == 0
    text = capsys.readouterr().out
    assert "prod-east" in text and "applied 2, resolved 2" in text
    assert main(["memory", "match", "Reason: OOMKilled", "--dir", str(fleet), "--format", "json"]) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["matches"][0]["outcomes"]["summary"].endswith("seen on 3 of your clusters, fixed on 2")


def test_cluster_labels_are_labels_not_free_text(fleet: Path) -> None:
    for bad in ("Prod East", "prod/east", "x" * 64, "-prod"):
        with pytest.raises(ValueError, match="cluster"):
            repo.add_outcome(fleet, "MEM-1", "resolved", cluster=bad)
