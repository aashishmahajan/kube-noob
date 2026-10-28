"""G1: a must-gather is opened safely: nothing extracted or run, Secrets never read, hostile archives refused."""

from __future__ import annotations

import gzip
import importlib.util
import io
import json
import os
import sys
import tarfile
from pathlib import Path

import pytest

from kube_noob.cli import main
from kube_noob.mustgather import ingest

FIX = Path(__file__).resolve().parent / "fixtures" / "must-gather"


@pytest.fixture(scope="module")
def mg(tmp_path_factory: pytest.TempPathFactory) -> object:
    out = tmp_path_factory.mktemp("mg")
    spec = importlib.util.spec_from_file_location("mg_generate", FIX / "generate.py")
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules["mg_generate"] = mod
    spec.loader.exec_module(mod)
    mod.main(out)
    mod.OUT = out  # type: ignore[attr-defined]
    return mod


def _dir(mg: object) -> Path:
    return Path(mg.OUT) / mg.TOP  # type: ignore[attr-defined]


def _tgz(mg: object) -> Path:
    return Path(mg.OUT) / "must-gather.tar.gz"  # type: ignore[attr-defined]


def _tar(path: Path, members: list[tuple[tarfile.TarInfo, bytes | None]], mode: str = "w:gz") -> Path:
    with tarfile.open(path, mode) as tf:  # type: ignore[call-overload]
        for info, data in members:
            if data is not None:
                info.size = len(data)
                tf.addfile(info, io.BytesIO(data))
            else:
                tf.addfile(info)
    return path


def _file(name: str) -> tarfile.TarInfo:
    info = tarfile.TarInfo(name)
    info.mode = 0o644
    return info


GOOD = "mg/img/cluster-scoped-resources/core/nodes/n1.yaml"


def test_directory_and_archive_read_the_same(mg: object) -> None:
    d, t = ingest.open_bundle(_dir(mg)), ingest.open_bundle(_tgz(mg))
    top = mg.TOP + "/"  # type: ignore[attr-defined]
    assert sorted(d.files) == sorted(k.removeprefix(top) for k in t.files)
    assert (d.listed, t.listed) == (23, 23) and d.skipped == t.skipped
    (root,) = d.roots.values()
    assert root.version == "openshift/must-gather 4.20.3" and root.timestamp.startswith("2026-10-28 10:00:05")
    assert root.resources["config.openshift.io/clusteroperators"] == 2 and len(root.pods) == 2 and root.logs == 2
    assert root.namespaces == {"openshift-etcd", "shop", "openshift-operator-lifecycle-manager"}


def test_secrets_are_never_read(mg: object, capsys: pytest.CaptureFixture[str]) -> None:
    marker = mg.MARKER.encode()  # type: ignore[attr-defined]
    for path in (_dir(mg), _tgz(mg)):
        b = ingest.open_bundle(path)
        assert b.skipped["Secret data (never read)"] == 2
        assert not any(marker in v for v in b.files.values())
        assert not any("secret" in k.lower() for k in b.files)
        for fmt in ("text", "json"):
            assert main(["--format", fmt, "must-gather", "analyze", str(path)]) == 0
            assert mg.MARKER not in capsys.readouterr().out  # type: ignore[attr-defined]
    assert all(
        ingest.secret_like(p)
        for p in ("a/core/secrets.yaml", "a/core/secrets/x.yaml", "a/secret-db.yaml", "SECRETS.YML", "x/secrets/y")
    )
    assert not any(ingest.secret_like(p) for p in ("a/core/configmaps.yaml", "secretary.log", "a/kube-secrets-ui.yaml"))


def test_nested_archives_links_and_specials_are_not_followed(tmp_path: Path) -> None:
    root = tmp_path / "mg" / "img"
    (root / "cluster-scoped-resources" / "core" / "nodes").mkdir(parents=True)
    (root / "cluster-scoped-resources" / "core" / "nodes" / "n1.yaml").write_text("kind: Node\n")
    outside = tmp_path / "outside.yaml"
    outside.write_text("kind: Secret\ndata: {k: TOP}\n")
    (root / "cluster-scoped-resources" / "core" / "nodes" / "n2.yaml").symlink_to(outside)
    (root / "namespaces").symlink_to(tmp_path)  # a directory link out of the root
    os.mkfifo(root / "cluster-scoped-resources" / "core" / "nodes" / "fifo.yaml")  # never opened: no hang
    b = ingest.open_bundle(tmp_path / "mg")
    assert sorted(b.files) == ["img/cluster-scoped-resources/core/nodes/n1.yaml"]
    assert b.skipped["link (never followed)"] == 2 and b.skipped["device, FIFO or sparse file (not read)"] == 1
    link = tmp_path / "link.tar.gz"
    link.symlink_to(tmp_path / "x.tar.gz")
    with pytest.raises(ingest.MustGatherError, match="symbolic link"):
        ingest.open_bundle(link)


@pytest.mark.parametrize(
    ("name", "why"),
    [
        ("/etc/passwd", "absolute member path"),
        ("mg/../../etc/cron.d/x", "leaves the archive root"),
        ("../x.yaml", "leaves the archive root"),
        ("C:/Windows/x.yaml", "absolute member path"),
        ("mg\\..\\..\\x.yaml", "leaves the archive root"),
    ],
)
def test_traversal_refuses_the_archive(tmp_path: Path, name: str, why: str) -> None:
    path = _tar(tmp_path / "bad.tgz", [(_file(GOOD), b"kind: Node\n"), (_file(name), b"x")])
    with pytest.raises(ingest.MustGatherError, match=why):
        ingest.open_bundle(path)
    assert main(["must-gather", "analyze", str(path)]) == 2
    assert not (tmp_path / "etc").exists()


def test_link_and_device_members_are_skipped(tmp_path: Path) -> None:
    sym = _file("mg/img/cluster-scoped-resources/core/nodes/evil.yaml")
    sym.type, sym.linkname = tarfile.SYMTYPE, "/etc/shadow"
    hard = _file("mg/img/cluster-scoped-resources/core/nodes/hard.yaml")
    hard.type, hard.linkname = tarfile.LNKTYPE, "mg/img/cluster-scoped-resources/core/nodes/n1.yaml"
    dev = _file("mg/img/cluster-scoped-resources/core/nodes/dev.yaml")
    dev.type, dev.devmajor, dev.devminor = tarfile.CHRTYPE, 1, 3
    fifo = _file("mg/img/cluster-scoped-resources/core/nodes/fifo.yaml")
    fifo.type = tarfile.FIFOTYPE
    path = _tar(
        tmp_path / "links.tgz", [(_file(GOOD), b"kind: Node\n"), (sym, None), (hard, None), (dev, None), (fifo, None)]
    )
    b = ingest.open_bundle(path)
    assert sorted(b.files) == [GOOD]
    assert b.skipped["link (never followed)"] == 2 and b.skipped["device, FIFO or sparse file (not read)"] == 2


def test_bombs_and_caps(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    many = [(_file(f"mg/img/namespaces/ns/core/f{i}.yaml"), b"x") for i in range(30)]
    monkeypatch.setattr(ingest, "MAX_MEMBERS", 20)
    with pytest.raises(ingest.MustGatherError, match="more than 20 files"):
        ingest.open_bundle(_tar(tmp_path / "count.tgz", many))
    monkeypatch.setattr(ingest, "MAX_MEMBERS", 300_000)
    zeros = b"\0" * (4 * 2**20)  # compresses to a few KiB: the cap is on bytes processed, not the archive size
    bomb = _tar(tmp_path / "size.tgz", [(_file(GOOD), b"kind: Node\n"), (_file("mg/img/blob.bin"), zeros)])
    assert bomb.stat().st_size < 64 * 1024
    monkeypatch.setattr(ingest, "MAX_TOTAL_BYTES", 2**20)
    with pytest.raises(ingest.MustGatherError, match="more than 0 GiB"):
        ingest.open_bundle(bomb)
    monkeypatch.setattr(ingest, "MAX_TOTAL_BYTES", 16 * 2**30)
    monkeypatch.setattr(ingest, "MAX_FILE_BYTES", 10)
    big = ingest.open_bundle(_tar(tmp_path / "big.tgz", [(_file(GOOD), b"kind: Node\nmetadata: {}\n")]))
    assert not big.files and any(r.startswith("larger than") for r in big.skipped)
    monkeypatch.setattr(ingest, "MAX_FILE_BYTES", 64 * 2**20)
    monkeypatch.setattr(ingest, "LOG_TAIL_BYTES", 64)
    log = "".join(f"line {i:04d}\n" for i in range(200)).encode()
    logs = ingest.open_bundle(
        _tar(
            tmp_path / "log.tgz",
            [(_file(GOOD), b"kind: Node\n"), (_file("mg/img/namespaces/ns/pods/p/c/c/logs/current.log"), log)],
        )
    )
    kept = logs.files["mg/img/namespaces/ns/pods/p/c/c/logs/current.log"]
    assert len(kept) <= 64 and kept.endswith(b"line 0199\n") and kept.startswith(b"line ")
    assert logs.truncated == ["mg/img/namespaces/ns/pods/p/c/c/logs/current.log"]
    deep = "mg/img/namespaces/" + "d/" * 50 + "x.yaml"
    d = ingest.open_bundle(_tar(tmp_path / "deep.tgz", [(_file(GOOD), b"kind: Node\n"), (_file(deep), b"x")]))
    assert any("nested deeper" in r for r in d.skipped)


def test_not_a_must_gather(tmp_path: Path) -> None:
    (tmp_path / "plain").mkdir()
    (tmp_path / "plain" / "a.yaml").write_text("x: 1\n")
    for path, why in (
        (tmp_path / "plain", "not a must-gather"),
        (tmp_path / "nope", "no such file"),
        (tmp_path / "x.zip", "pass a must-gather directory"),
    ):
        if path.suffix == ".zip":
            path.write_bytes(b"PK\x03\x04")
        with pytest.raises(ingest.MustGatherError, match=why):
            ingest.open_bundle(path)
    (tmp_path / "garbage.tgz").write_bytes(b"not a tar at all" * 100)
    with pytest.raises(ingest.MustGatherError, match=r"not a tar archive|damaged"):
        ingest.open_bundle(tmp_path / "garbage.tgz")
    good = _tar(tmp_path / "good.tgz", [(_file(GOOD), b"kind: Node\n" * 2000)])
    cut = tmp_path / "cut.tgz"
    cut.write_bytes(good.read_bytes()[: len(good.read_bytes()) // 2])
    with pytest.raises(ingest.MustGatherError, match=r"damaged|not a tar"):
        ingest.open_bundle(cut)
    raw = gzip.compress(b"\0" * 1024)
    (tmp_path / "zero.tar.gz").write_bytes(raw)
    with pytest.raises(ingest.MustGatherError):
        ingest.open_bundle(tmp_path / "zero.tar.gz")


def test_cli_json(mg: object, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["--format", "json", "must-gather", "analyze", str(_tgz(mg))]) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["kind"] == "tar" and out["gatherRoots"][0]["version"] == "openshift/must-gather 4.20.3"
    assert {s["reason"] for s in out["skipped"]} == {"Secret data (never read)", "nested archive (not opened)"}
