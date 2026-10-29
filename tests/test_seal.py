"""DB2: a Jira snapshot sealed with the organisation's key (AES-256-GCM in chunks) opens only with that key, fails
closed with a clear message otherwise, and seeds a pod with no Jira egress (requirements R1.4, R1.5)."""

from __future__ import annotations

import json
import os
import random
from pathlib import Path
from typing import Any

import pytest
import yaml

from kube_noob import tickets
from kube_noob.cli import main
from kube_noob.sources import seal
from kube_noob.sources.corpus import write_shard
from kube_noob.sources.jira_snapshot import export_snapshot, seed_on_start

ROOT = Path(__file__).resolve().parents[1]
KEY = b"q3Vt0p8Hn1sXx0b9yZ2kLmR4cW6eT7uA"


def _snapshot(tmp: Path) -> Path:
    data = tmp / "copy"
    base = {
        "sourceId": "jira:OCPBUGS",
        "license": "public, not redistributable",
        "redistributable": False,
        "issueType": "Bug",
        "status": "Closed",
        "resolution": "Not a Bug",
        "retrievedAt": "2026-10-28T00:00:00Z",
    }
    write_shard(
        data,
        "jira-ocpbugs",
        [{**base, "id": "jira-OCPBUGS-900", "title": "OCPBUGS-900: router cannot load its certificate", "text": "x"}],
    )
    export_snapshot(data, tmp / "jira-snapshot.tgz")
    return tmp / "jira-snapshot.tgz"


def _key(tmp: Path, value: bytes = KEY) -> Path:
    tmp.mkdir(parents=True, exist_ok=True)
    k = tmp / "seed.key"
    k.write_bytes(value + b"\n")
    return k


@pytest.mark.parametrize("size", [0, 1, 1023, 1024, 1025, 5000])
def test_round_trip_at_every_chunk_boundary(tmp_path: Path, size: int) -> None:
    src = tmp_path / "plain"
    src.write_bytes(random.Random(size).randbytes(size))
    out = seal.seal(src, tmp_path / "s.enc", KEY, iterations=10_000, chunk=1024)
    assert out["chunks"] == max(1, -(-size // 1024))
    assert oct((tmp_path / "s.enc").stat().st_mode & 0o777) == "0o600" and seal.is_sealed(tmp_path / "s.enc")
    seal.unseal(tmp_path / "s.enc", tmp_path / "back", KEY)
    assert (tmp_path / "back").read_bytes() == src.read_bytes()


def test_every_tampering_fails_closed(tmp_path: Path) -> None:
    src = tmp_path / "plain"
    src.write_bytes(os.urandom(4000))
    sealed = tmp_path / "s.enc"
    seal.seal(src, sealed, KEY, iterations=10_000, chunk=1024)
    blob = sealed.read_bytes()
    size = 1024 + 16
    head = seal.HEADER_LEN
    cases: dict[str, bytes] = {
        "flipped": blob[:-5] + bytes([blob[-5] ^ 1]) + blob[-4:],
        "truncated at a chunk": blob[: head + 2 * size],
        "chunk dropped": blob[:head] + blob[head + size :],
        "chunks swapped": blob[:head]
        + blob[head + size : head + 2 * size]
        + blob[head : head + size]
        + blob[head + 2 * size :],
        "header edited": blob[: len(seal.MAGIC)] + bytes([blob[len(seal.MAGIC)] ^ 1]) + blob[len(seal.MAGIC) + 1 :],
    }
    for name, body in cases.items():
        bad = tmp_path / f"{name}.enc"
        bad.write_bytes(body)
        with pytest.raises(seal.SealError, match=r"nothing was imported|does not open"):
            seal.unseal(bad, tmp_path / "out", KEY)
        assert not (tmp_path / "out").exists(), name  # nothing written in place of the output
    with pytest.raises(seal.SealError, match=r"the key does not open s\.enc"):
        seal.unseal(sealed, tmp_path / "out", b"x" * 32)
    with pytest.raises(seal.SealError, match="not a sealed kube-noob snapshot"):
        seal.unseal(src, tmp_path / "out", KEY)
    odd = tmp_path / "odd.enc"
    odd.write_bytes(seal.MAGIC + seal._HEADER.pack(b"s" * 16, 1, 1 << 30))
    with pytest.raises(seal.SealError, match="header out of range"):
        seal.unseal(odd, tmp_path / "out", KEY)


def test_keys_come_from_a_file_and_must_be_long_enough(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(seal.KEY_ENV, raising=False)
    with pytest.raises(seal.SealError, match=r"jira\.seed\.keySecret"):
        seal.read_secret()
    short = _key(tmp_path, b"short")
    with pytest.raises(seal.SealError, match="shorter than 16 characters"):
        seal.read_secret(short)
    monkeypatch.setenv(seal.KEY_ENV, str(_key(tmp_path)))
    assert seal.read_secret() == KEY
    with pytest.raises(seal.SealError, match="cannot read the key file"):
        seal.read_secret(tmp_path / "missing")


def test_a_sealed_seed_opens_with_the_right_key_only(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    snap = _snapshot(tmp_path)
    pod = tmp_path / "pod"
    seal.seal(snap, pod / "seed" / "jira-snapshot.tgz.enc", KEY)
    monkeypatch.delenv(seal.KEY_ENV, raising=False)
    with pytest.raises(seal.SealError, match="needs its key"):
        seed_on_start(pod)
    monkeypatch.setenv(seal.KEY_ENV, str(_key(tmp_path / "wrong", b"w" * 32)))
    with pytest.raises(seal.SealError, match=r"the key does not open jira-snapshot\.tgz\.enc"):
        seed_on_start(pod)
    assert not (pod / "corpus").exists() or not list((pod / "corpus").glob("jira-*.jsonl"))
    assert not list(pod.glob(".seed-*"))  # the temporary plaintext is gone
    monkeypatch.setenv(seal.KEY_ENV, str(_key(tmp_path)))
    out = seed_on_start(pod)
    assert out and out["sealed"] and out["imported"] == ["jira-ocpbugs"]
    t = tickets.ticket("OCPBUGS-900", pod)
    assert t["found"] and t["verdict"] == "not-a-bug"
    assert seed_on_start(pod) is None  # the copy exists now
    assert not list(pod.glob(".seed-*"))


def test_cli_seal_import_and_serve(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: Any) -> None:
    snap = _snapshot(tmp_path)
    key = _key(tmp_path)
    out = tmp_path / "jira-snapshot.tgz.enc"
    assert main(["corpus", "seal", str(snap), "-o", str(out), "--key-file", str(key)]) == 0
    assert "chunks" in capsys.readouterr().out
    pod = tmp_path / "pod"
    monkeypatch.setenv("KUBE_NOOB_DATA_DIR", str(pod))
    monkeypatch.delenv(seal.KEY_ENV, raising=False)
    assert main(["corpus", "import", str(out)]) == 4  # no key: refused, nothing imported
    assert "needs its key" in capsys.readouterr().err
    assert main(["corpus", "import", str(out), "--key-file", str(key), "--format", "json"]) == 0
    assert json.loads(capsys.readouterr().out)["sealed"] is True
    assert main(["corpus", "unseal", str(out), "-o", str(tmp_path / "plain.tgz"), "--key-file", str(key)]) == 0
    assert (tmp_path / "plain.tgz").read_bytes() == snap.read_bytes()
    served = tmp_path / "served"
    seal.seal(snap, served / "seed" / "jira-snapshot.tgz.enc", KEY)
    monkeypatch.setenv("KUBE_NOOB_DATA_DIR", str(served))
    monkeypatch.setenv(seal.KEY_ENV, str(_key(tmp_path / "bad", b"b" * 32)))
    ran: list[str] = []
    monkeypatch.setattr("uvicorn.run", lambda *a, **k: ran.append("uvicorn"))
    main(["serve", "--allow-unauthenticated"])
    err = capsys.readouterr().err
    assert ran == ["uvicorn"]  # a wrong key never stops the server
    assert "jira seed not imported: the key does not open jira-snapshot.tgz.enc" in err
    assert "jira sync: off (the copy changes only when a newer seed is imported)" in err
    monkeypatch.setenv(seal.KEY_ENV, str(key))
    main(["serve", "--allow-unauthenticated"])
    assert "jira seed imported from" in capsys.readouterr().err
    assert tickets.ticket("OCPBUGS-900", served)["found"]


def test_sync_on_states_its_jittered_schedule(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: Any) -> None:
    from kube_noob.sources import jira

    monkeypatch.setenv("KUBE_NOOB_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("KUBE_NOOB_CONFIG", str(tmp_path / "c.yaml"))
    (tmp_path / "c.yaml").write_text("jira:\n  syncEnabled: true\n  intervalHours: 48\n")
    monkeypatch.setattr(jira, "run_sync", lambda s: pytest.fail("the first run must wait"))
    monkeypatch.setattr("uvicorn.run", lambda *a, **k: None)
    started: list[Any] = []
    real_start = jira.start_background

    def spy(settings: Any, rng: Any = None) -> Any:
        stop = real_start(settings, rng)
        started.append(stop)
        return stop

    monkeypatch.setattr(jira, "start_background", spy)
    try:
        main(["serve", "--allow-unauthenticated"])
    finally:  # the thread would otherwise run a real sync 30-600 s later, holding the sync lock (CI 40669926452)
        for stop in started:
            stop.set()
    assert len(started) == 1
    err = capsys.readouterr().err
    line = next(x for x in err.splitlines() if x.startswith("jira sync: first run in"))
    first = int(line.split()[5])
    assert 30 <= first <= 600 and line.endswith("then every 48 h +/- 10%")


def test_chart_wires_the_key_from_a_secret_only() -> None:
    import jsonschema

    values = yaml.safe_load((ROOT / "deploy/helm/kube-noob/values.yaml").read_text())
    schema = json.loads((ROOT / "deploy/helm/kube-noob/values.schema.json").read_text())
    validator = jsonschema.Draft7Validator(schema)
    validator.validate(values)
    assert values["jira"]["seed"]["keySecret"] == {"name": "", "key": "key"}
    for bad in ({"name": "Bad_Name"}, {"key": "../x"}, {"value": "the-key-itself"}):
        v = yaml.safe_load(yaml.safe_dump(values))
        v["jira"]["seed"]["keySecret"].update(bad)
        with pytest.raises(jsonschema.ValidationError):
            validator.validate(v)
    v = yaml.safe_load(yaml.safe_dump(values))
    v["jira"]["seed"]["path"] = "/seed/jira-snapshot.tgz.enc"
    validator.validate(v)
    dep = (ROOT / "deploy/helm/kube-noob/templates/deployment.yaml").read_text()
    assert "KUBE_NOOB_SEED_KEY_FILE" in dep and "defaultMode: 288" in dep
    assert 'fail "jira.seed.keySecret opens a sealed seed; set jira.seed.source (image or pvc) too"' in dep
    wf = yaml.safe_load((ROOT / ".github/workflows/jira-db-image.yml").read_text())
    names = [s.get("name", "") for s in wf["jobs"]["seed"]["steps"]]
    assert (
        names.index("Refuse a public repository (before anything is pushed)")
        < names.index("Build and push to your private registry")
        < names.index("Refuse a public image (after the push)")
    )
    assert names.index("Check the copy (imports cleanly, no person left in it)") < names.index("Seal with your key")
    assert wf["permissions"] == {"contents": "read", "actions": "read"}
    cf = (ROOT / "Containerfile.seed").read_text()
    assert "USER 1001" in cf and "org.opencontainers.image.source=" not in cf
    assert "COPY --chown=0:0 --chmod=0444 dist/seed/${SEED}" in cf  # the snapshot is owner-only on the build host
