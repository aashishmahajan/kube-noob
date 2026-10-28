"""Memory sources in every runtime (MEM3): `memory.paths` in the config and the environment, `doctor` lists each
repository with its entry counts, the CLI matches against them by default, and the chart's values schema guards the
three in-cluster sources (rendering is checked in CI, where helm runs)."""

from __future__ import annotations

import json
from datetime import date
from pathlib import Path

import jsonschema
import pytest
import yaml

from kube_noob.cli import main
from kube_noob.config import load_settings
from kube_noob.errors import ConfigError
from kube_noob.memory import dump_entry, load_entry, repo
from kube_noob.posture import posture, render_text

ROOT = Path(__file__).resolve().parents[1]
CHART = ROOT / "deploy" / "helm" / "kube-noob"


def _repo(path: Path, approved: int, proposed: int) -> Path:
    repo.init_repo(path)
    for n in range(approved + proposed):
        p, _ = repo.add_entry(
            path,
            {
                "kind": "fix",
                "signals": [{"kind": "alert", "name": "etcdHighNumberOfLeaderChanges"}],
                "symptom": f"etcd leader changes on cluster group {n} after the update",
                "platform": "openshift",
                "cause": "Catalog sync I/O on the control-plane disks.",
                "fix": {"text": "Update to 4.21.1."},
                "owners": ["platform-team"],
            },
            date(2026, 10, 28),
        )
        if n < approved:
            p.write_text(dump_entry(load_entry(p).model_copy(update={"status": "approved"})), encoding="utf-8")
    return path


def test_paths_come_from_the_config_file_and_the_environment(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    cfg = tmp_path / "config.yaml"
    cfg.write_text(f"memory:\n  paths: [{tmp_path / 'a'}, '~/team-memory']\n", encoding="utf-8")
    s = load_settings(cfg)
    assert s.memory.paths == [tmp_path / "a", Path("~/team-memory").expanduser()]
    monkeypatch.setenv("KUBE_NOOB_MEMORY_PATHS", f"{tmp_path / 'b'}:{tmp_path / 'c'}")
    assert load_settings(cfg).memory.paths == [tmp_path / "b", tmp_path / "c"]
    monkeypatch.setenv("KUBE_NOOB_MEMORY_PATHS", "")
    assert load_settings(cfg).memory.paths == []
    with pytest.raises(ConfigError, match="at most 10"):
        load_settings(overrides={"memory": {"paths": [str(tmp_path)] * 11}})
    with pytest.raises(ConfigError, match="surprise"):
        load_settings(overrides={"memory": {"paths": [], "surprise": 1}})


def test_doctor_lists_each_repository_with_counts_and_warns_about_bad_paths(tmp_path: Path) -> None:
    good = _repo(tmp_path / "team", approved=2, proposed=1)
    s = load_settings(overrides={"dataDir": str(tmp_path / "d"), "memory": {"paths": [str(good), str(tmp_path / "x")]}})
    p = posture(s)
    assert p["memory"][0] == {"path": str(good), "entries": 3, "approved": 2, "proposed": 1, "unreadable": 0}
    assert "not a memory repository" in p["memory"][1]["error"]
    assert any(w.startswith(f"memory path {tmp_path / 'x'}") for w in p["warnings"])
    text = render_text(p)
    assert f"memory         {good}: 3 entries (2 approved, 1 proposed)" in text
    assert f"memory         {tmp_path / 'x'}: unreadable" in text
    none = render_text(posture(load_settings(overrides={"dataDir": str(tmp_path / "d")})))
    assert "memory         none (memory.paths)" in none


def test_match_reads_memory_paths_by_default(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    good = _repo(tmp_path / "team", approved=1, proposed=0)
    monkeypatch.setenv("KUBE_NOOB_MEMORY_PATHS", str(good))
    assert main(["memory", "match", "etcdHighNumberOfLeaderChanges is firing", "--format", "json"]) == 0
    out = json.loads(capsys.readouterr().out)
    assert [m["id"] for m in out["matches"]] == ["MEM-1"] and out["repositories"][0]["path"] == str(good)
    monkeypatch.delenv("KUBE_NOOB_MEMORY_PATHS")
    assert main(["memory", "match", "etcdHighNumberOfLeaderChanges is firing"]) == 2
    assert "set memory.paths" in capsys.readouterr().err


def _chart_values(**memory: object) -> dict[str, object]:
    values = yaml.safe_load((CHART / "values.yaml").read_text())
    values["memory"] = {**values["memory"], **memory}
    return values


def test_chart_schema_accepts_the_sources_and_refuses_unsafe_git_settings() -> None:
    schema = jsonschema.Draft7Validator(json.loads((CHART / "values.schema.json").read_text()))
    schema.validate(_chart_values())
    schema.validate(_chart_values(source="configMap", configMap={"name": "team-memory"}))
    schema.validate(_chart_values(source="pvc", pvc={"claimName": "team-memory", "subPath": "repo"}))
    git = {
        "url": "ssh://git@git.example.com:2222/team/memory.git",
        "ref": "main",
        "image": {"repository": "quay.io/acme/git", "tag": "2.47.1", "digest": ""},
        "sshSecret": "memory-deploy-key",
        "egressCIDRs": ["203.0.113.10/32"],
        "port": None,
    }
    schema.validate(_chart_values(source="git", git=git))
    for bad in (
        {"source": "s3"},
        {"git": {**git, "url": "https://user:token@git.example.com/team/memory.git"}},
        {"git": {**git, "url": "https://git.example.com/x?private_token=abc"}},
        {"git": {**git, "url": "git@git.example.com:team/memory.git"}},
        {"git": {**git, "ref": "--upload-pack=touch /tmp/x"}},
        {"git": {**git, "egressCIDRs": ["0.0.0.0/0; rm"]}},
        {"pvc": {"claimName": "../etc", "subPath": ""}},
        {"pvc": {"claimName": "x", "subPath": "../../etc"}},
    ):
        with pytest.raises(jsonschema.ValidationError):
            schema.validate(_chart_values(**bad))


def test_chart_templates_mount_memory_read_only_and_guard_the_git_source() -> None:
    deployment = (CHART / "templates" / "deployment.yaml").read_text()
    assert deployment.count("mountPath: /srv/kube-noob/memory") >= 3
    for line in deployment.splitlines():
        if "name: memory," in line and "mountPath: /srv/kube-noob/memory" in line and "memory-clone" not in line:
            assert "readOnly: true" in line or "/srv/kube-noob/memory}" in line
    for message in (
        "memory.source configMap needs memory.configMap.name",
        "memory.source pvc needs memory.pvc.claimName",
        "memory.source git needs memory.git.url",
        "needs memory.git.sshSecret",
        "config.offline allows memory.git only from an in-cluster host",
        "memory.source git needs memory.git.egressCIDRs",
    ):
        assert message in deployment
    assert '--branch "$MEMORY_REF" --' in deployment and "StrictHostKeyChecking=yes" in deployment
    assert "paths: [/srv/kube-noob/memory]" in (CHART / "templates" / "configmap.yaml").read_text()
    ci = (ROOT / ".github" / "workflows" / "ci.yml").read_text()
    assert "memory values must fail to render" in ci and "memory-clone" in ci
