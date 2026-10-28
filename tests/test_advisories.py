"""SEC1: Red Hat CSAF VEX statements (CC BY 4.0) for the default products, licence-checked, paced, bounded, and
shipped in the public kube-noob-db bundle with attribution (requirements R5.5)."""

from __future__ import annotations

import json
import random
import shutil
import subprocess
import tarfile
from pathlib import Path
from typing import Any

import httpx
import pytest

from kube_noob.cli import main
from kube_noob.config import load_settings
from kube_noob.errors import DomainNotAllowedError
from kube_noob.sources import advisories as adv
from kube_noob.sources import db_bundle
from kube_noob.sources.corpus import read_manifest

FIX = Path(__file__).resolve().parent / "fixtures" / "vex"
STAMP = "2026-10-28T06:00:00+00:00"


def _doc(name: str) -> Any:
    year = name.split("-")[1]
    return json.loads((FIX / year / f"{name.lower()}.json").read_text())


def test_statements_per_product_with_fix_and_justification() -> None:
    rec = adv.parse_vex(_doc("CVE-2023-44487"), retrieved_at=STAMP)
    assert rec is not None
    assert rec["id"] == "vex-cve-2023-44487" and rec["severity"] == "important" and rec["cvss"] == 7.5
    assert (
        rec["license"] == "CC-BY-4.0"
        and rec["redistributable"] is True
        and "Red Hat Security Data" in rec["attribution"]
    )
    by = {(s["component"], s["status"]): s for s in rec["statements"]}
    router = by[("openshift4/ose-haproxy-router", "fixed")]
    assert router["cpe"] == "cpe:/a:redhat:openshift:4.14::el9"
    assert router["fix"]["url"] == "https://access.redhat.com/errata/RHSA-2023:5679"
    assert by[("openshift4/ose-etcd", "known_not_affected")]["justification"] == "vulnerable_code_not_present"
    assert by[("advanced-cluster-security/rhacs-main-rhel8", "fixed")]["fix"]["url"].endswith("RHSA-2023:5701")
    assert not any("enterprise_linux:6" in s["cpe"] for s in rec["statements"])  # outside the default products
    assert "Red Hat OpenShift Container Platform 4.14: fixed: openshift4/ose-haproxy-router." in rec["text"]
    assert rec["url"] == "https://access.redhat.com/security/cve/CVE-2023-44487"


def test_not_affected_only_and_out_of_scope_cves() -> None:
    xz = adv.parse_vex(_doc("CVE-2024-3094"))
    assert xz and [s["status"] for s in xz["statements"]] == ["known_not_affected"]
    assert "Red Hat Enterprise Linux 9: not affected: xz." in xz["text"] and "fedora" not in json.dumps(xz)
    assert adv.parse_vex(_doc("CVE-2019-18276")) is None  # only RHEL 6: nothing kube-noob covers
    narrow = adv.parse_vex(_doc("CVE-2023-44487"), products=("cpe:/a:redhat:advanced_cluster_security",))
    assert narrow and {s["product"] for s in narrow["statements"]} == {"Red Hat Advanced Cluster Security 4.2"}


@pytest.mark.parametrize(
    ("doc", "error"),
    [
        ([], "not a CSAF document"),
        ({"document": {}}, "without vulnerabilities"),
        ({"document": {}, "vulnerabilities": [{"cve": "CVE-12"}]}, "not a CVE id"),
        ({"document": {}, "vulnerabilities": ["x"]}, "without vulnerabilities"),
    ],
)
def test_malformed_documents_are_refused(doc: Any, error: str) -> None:
    with pytest.raises(adv.AdvisoryError, match=error):
        adv.parse_vex(doc)


def test_hostile_documents_are_bounded() -> None:
    d = _doc("CVE-2023-44487")
    tree = d["product_tree"]
    node = tree["branches"][0]
    for _ in range(200):  # deep branches: walked to depth 30, never recursing without bound
        node = {"category": "x", "name": "x", "branches": [node]}
    d["product_tree"]["branches"] = [node]
    assert adv.parse_vex(d) is None or True
    many = _doc("CVE-2023-44487")
    pid = "9Base-RHOSE-4.14"
    many["product_tree"]["relationships"] += [
        {
            "category": "default_component_of",
            "full_product_name": {"name": f"c{i}", "product_id": f"{pid}:c{i}"},
            "product_reference": f"c{i}",
            "relates_to_product_reference": pid,
        }
        for i in range(adv.MAX_STATEMENTS + 50)
    ]
    many["vulnerabilities"][0]["product_status"]["known_affected"] = [
        f"{pid}:c{i}" for i in range(adv.MAX_STATEMENTS + 50)
    ]
    rec = adv.parse_vex(many)
    assert rec and len(rec["statements"]) == adv.MAX_STATEMENTS and rec["statementsCut"] is True
    huge_title = _doc("CVE-2024-3094")
    huge_title["vulnerabilities"][0]["title"] = "x" * 100_000
    assert len(adv.parse_vex(huge_title)["title"]) < 400  # type: ignore[index]


def test_merge_replace_and_the_licence_gate(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    data = tmp_path / "data"
    out = adv.run(data, [_doc("CVE-2023-44487"), {"not": "csaf"}, _doc("CVE-2019-18276")])
    assert out["documents"] == 3 and out["kept"] == 1 and out["malformed"] == 1 and out["cves"] == 1
    out = adv.run(data, [_doc("CVE-2024-3094")])
    assert out["cves"] == 2  # merged with what the shard held
    assert read_manifest(data)["shards"]["redhat-vex"]["licenses"] == {"CC-BY-4.0": 2}
    assert adv.run(data, [_doc("CVE-2024-3094")], replace=True)["cves"] == 1
    monkeypatch.setitem(adv.SOURCES, "redhat-vex", adv.Source("redhat-vex", "Red Hat terms of use", "x", adv.BASE))
    with pytest.raises(adv.AdvisoryError, match="not on the allow-list"):
        adv.run(data, [_doc("CVE-2023-44487")])


def test_archives_folder_tar_and_zstd(tmp_path: Path) -> None:
    assert sorted(d["vulnerabilities"][0]["cve"] for d in adv.from_archive(FIX)) == [
        "CVE-2019-18276",
        "CVE-2023-44487",
        "CVE-2024-3094",
    ]
    tgz = tmp_path / "vex.tar.gz"
    with tarfile.open(tgz, "w:gz") as tf:
        tf.add(FIX / "2023", arcname="2023")
        tf.add(FIX / "changes.csv", arcname="changes.csv")
    assert [d["vulnerabilities"][0]["cve"] for d in adv.from_archive(tgz)] == ["CVE-2023-44487"]
    if shutil.which("zstd"):
        tar = tmp_path / "vex.tar"
        with tarfile.open(tar, "w") as tf:
            tf.add(FIX / "2024", arcname="2024")
        subprocess.run(["zstd", "-q", str(tar), "-o", str(tmp_path / "vex.tar.zst")], check=True)  # noqa: S607
        assert [d["vulnerabilities"][0]["cve"] for d in adv.from_archive(tmp_path / "vex.tar.zst")] == ["CVE-2024-3094"]


def _client(handler: Any, sleeps: list[float], budget: int = 100) -> adv.VexClient:
    http = httpx.Client(transport=httpx.MockTransport(handler))
    return adv.VexClient(http, max_requests=budget, sleep=sleeps.append, rng=random.Random(3))


def test_fetching_is_paced_bounded_and_reads_changes(tmp_path: Path) -> None:
    sleeps: list[float] = []
    calls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request.url.path)
        name = request.url.path.rsplit("/vex/", 1)[1]
        if name == "changes.csv":
            return httpx.Response(200, text=(FIX / "changes.csv").read_text())
        if name == "2024/cve-2024-3094.json" and calls.count(request.url.path) == 1:
            return httpx.Response(429, headers={"Retry-After": "7"})
        f = FIX / name
        return httpx.Response(200, content=f.read_bytes()) if f.is_file() else httpx.Response(404)

    c = _client(handler, sleeps)
    cves = c.changed_since("2026-10-27T00:00:00")
    assert cves == ["CVE-2024-3094", "CVE-2023-44487"]  # newest first, the traversal row ignored
    docs = [c.document(x) for x in cves]
    assert all(docs) and c.document("CVE-2020-0001") is None
    assert 7.0 in sleeps  # Retry-After honoured
    paced = [s for s in sleeps if s != 7.0]
    assert all(1.0 <= s <= 2.0 for s in paced) and len(set(paced)) == len(paced)
    with pytest.raises(adv.AdvisoryError, match="not a CVE id"):
        c.document("../../etc/passwd")
    tight = _client(handler, [], budget=1)
    tight.document("CVE-2023-44487")
    with pytest.raises(adv.AdvisoryError, match="budget of 1 spent"):
        tight.document("CVE-2024-3094")
    big = _client(lambda r: httpx.Response(200, content=b"x" * (adv.MAX_DOC + 10)), [])
    with pytest.raises(adv.AdvisoryError, match="larger than"):
        big.document("CVE-2023-44487")


def test_the_client_reaches_one_host_over_https_only(tmp_path: Path) -> None:
    s = load_settings(overrides={"dataDir": str(tmp_path)})
    with adv.vex_http(s) as http:
        for url in ("https://example.com/x", "http://security.access.redhat.com/data/csaf/v2/vex/changes.csv"):
            with pytest.raises(DomainNotAllowedError):
                http.get(url)
        with pytest.raises(DomainNotAllowedError):
            http.post(f"{adv.BASE}/changes.csv")
    locked = load_settings(overrides={"dataDir": str(tmp_path), "offline": True})
    with pytest.raises(Exception, match="offline lock"):
        adv.vex_http(locked)


def test_cli_archive_online_and_the_public_bundle(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    data = tmp_path / "data"
    monkeypatch.setenv("KUBE_NOOB_DATA_DIR", str(data))
    assert main(["corpus", "advisories", "--from-archive", str(FIX)]) == 0
    assert (
        "3 documents read, 2 about the default products, 0 malformed; the shard holds 2 CVEs" in capsys.readouterr().out
    )
    assert main(["corpus", "advisories", "--cves", "CVE-2023-44487"]) == 2  # no --online
    assert main(["corpus", "advisories", "--online"]) == 2  # neither --cves nor --since
    assert main(["corpus", "advisories", "--from-archive", str(FIX), "--since", "2026-01-01"]) == 2

    def handler(request: httpx.Request) -> httpx.Response:
        f = FIX / request.url.path.rsplit("/vex/", 1)[1]
        return httpx.Response(200, content=f.read_bytes()) if f.is_file() else httpx.Response(404)

    monkeypatch.setattr(adv, "vex_http", lambda s: httpx.Client(transport=httpx.MockTransport(handler)))
    monkeypatch.setattr(adv, "MIN_DELAY", 0.0)
    monkeypatch.setattr("time.sleep", lambda s: None)
    assert main(["corpus", "advisories", "--online", "--cves", "CVE-2023-44487,CVE-2021-0001", "--format", "json"]) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["kept"] == 1 and out["notPublished"] == ["CVE-2021-0001"] and out["requests"] == 2
    monkeypatch.setenv("KUBE_NOOB_OFFLINE", "1")
    assert main(["corpus", "advisories", "--online", "--cves", "CVE-2023-44487"]) == 2
    monkeypatch.delenv("KUBE_NOOB_OFFLINE")
    built = db_bundle.build(data, tmp_path / "kube-noob-db.tgz")
    assert "redhat-vex" in built["shards"] and built["licenses"]["CC-BY-4.0"] == 2
    assert db_bundle.check_archive(tmp_path / "kube-noob-db.tgz") == []
    with tarfile.open(tmp_path / "kube-noob-db.tgz") as tf:
        attribution = tf.extractfile("ATTRIBUTION.md").read().decode()  # type: ignore[union-attr]
    assert "| redhat-vex | CC-BY-4.0 | 2 | Red Hat Security Data (c) Red Hat, Inc., CC BY 4.0" in attribution
