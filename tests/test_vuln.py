"""VUL1 (R5.1-R5.4): scanner and SBOM input, Red Hat VEX, reachability ranking, STRIDE threat model."""

from __future__ import annotations

import copy
import importlib.util
import json
import random
import sys
from pathlib import Path
from typing import Any

import httpx
import pytest

from kube_noob.attack_paths import Inventory, workload_reach
from kube_noob.cli import main
from kube_noob.config import load_settings
from kube_noob.errors import ConfigError, WebDisabledError
from kube_noob.vuln import assess, attack, kev, rank, reports, rpmver, threat, vex
from kube_noob.yamlio import load_documents

ROOT = Path(__file__).resolve().parents[1]
FIX = ROOT / "tests" / "fixtures" / "vuln"
SCANNERS = ("trivy.json", "grype.json", "cyclonedx-trivy.json", "cyclonedx-grype.json", "rhacs-image.json")
VEX_FORMATS = (
    "trivy.json",
    "grype.json",
    "cyclonedx-trivy.json",
    "cyclonedx-grype.json",
    "cyclonedx-sbom.json",
    "spdx.json",
)


@pytest.fixture(scope="module")
def fx(tmp_path_factory: pytest.TempPathFactory) -> Path:
    out = tmp_path_factory.mktemp("vuln")
    spec = importlib.util.spec_from_file_location("vuln_generate", FIX / "generate.py")
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules["vuln_generate"] = mod
    spec.loader.exec_module(mod)
    mod.main(out)
    return out


def _expected(fx: Path) -> dict[str, Any]:
    return dict(json.loads((fx / "expected.json").read_text()))


def _parse(fx: Path, *names: str) -> list[reports.ScanReport]:
    return [reports.parse((fx / n).read_bytes(), n) for n in names]


def _tuples(rows: list[dict[str, str]]) -> list[tuple[str, str, str, str]]:
    return sorted((r["package"], r["version"], r["cve"], r["fixVersion"]) for r in rows)


def _kept(out: dict[str, Any]) -> list[tuple[str, str, str, str]]:
    return sorted(
        (f["package"]["name"], f["package"]["version"], f["cve"], f["fixVersion"] or "") for f in out["findings"]
    )


# -- RPM version comparison -------------------------------------------------------------------------------------------

# rpm's own vectors (https://github.com/rpm-software-management/rpm, tests/rpmvercmp.at, commit 4f7be32e)
RPM_VECTORS = """1.0 1.0 0|1.0 2.0 -1|2.0 1.0 1|2.0.1 2.0.1 0|2.0 2.0.1 -1|2.0.1 2.0 1|2.0.1a 2.0.1a 0|2.0.1a 2.0.1 1
|2.0.1 2.0.1a -1|5.5p1 5.5p1 0|5.5p1 5.5p2 -1|5.5p2 5.5p1 1|5.5p10 5.5p10 0|5.5p1 5.5p10 -1|5.5p10 5.5p1 1
|10xyz 10.1xyz -1|10.1xyz 10xyz 1|xyz10 xyz10 0|xyz10 xyz10.1 -1|xyz10.1 xyz10 1|xyz.4 xyz.4 0|xyz.4 8 -1|8 xyz.4 1
|xyz.4 2 -1|2 xyz.4 1|5.5p2 5.6p1 -1|5.6p1 5.5p2 1|5.6p1 6.5p1 -1|6.5p1 5.6p1 1|6.0.rc1 6.0 1|6.0 6.0.rc1 -1
|10b2 10a1 1|10a2 10b2 -1|1.0aa 1.0aa 0|1.0a 1.0aa -1|1.0aa 1.0a 1|10.0001 10.0001 0|10.0001 10.1 0|10.1 10.0001 0
|10.0001 10.0039 -1|10.0039 10.0001 1|4.999.9 5.0 -1|5.0 4.999.9 1|20101121 20101121 0|20101121 20101122 -1
|20101122 20101121 1|2_0 2_0 0|2.0 2_0 0|2_0 2.0 0|a a 0|a+ a+ 0|a+ a_ 0|a_ a+ 0|+a +a 0|+a _a 0|_a +a 0|+_ +_ 0
|_+ +_ 0|_+ _+ 0|+ _ 0|_ + 0|1.0~rc1 1.0~rc1 0|1.0~rc1 1.0 -1|1.0 1.0~rc1 1|1.0~rc1 1.0~rc2 -1|1.0~rc2 1.0~rc1 1
|1.0~rc1~git123 1.0~rc1~git123 0|1.0~rc1~git123 1.0~rc1 -1|1.0~rc1 1.0~rc1~git123 1|1.0^ 1.0^ 0|1.0^ 1.0 1
|1.0 1.0^ -1|1.0^git1 1.0^git1 0|1.0^git1 1.0 1|1.0 1.0^git1 -1|1.0^git1 1.0^git2 -1|1.0^git2 1.0^git1 1
|1.0^git1 1.01 -1|1.01 1.0^git1 1|1.0^20160101 1.0^20160101 0|1.0^20160101 1.0.1 -1|1.0.1 1.0^20160101 1
|1.0^20160101^git1 1.0^20160101^git1 0|1.0^20160102 1.0^20160101^git1 1|1.0^20160101^git1 1.0^20160102 -1
|1.0~rc1^git1 1.0~rc1^git1 0|1.0~rc1^git1 1.0~rc1 1|1.0~rc1 1.0~rc1^git1 -1|1.0^git1~pre 1.0^git1~pre 0
|1.0^git1 1.0^git1~pre 1|1.0^git1~pre 1.0^git1 -1"""


def test_rpmvercmp_matches_rpms_own_vectors() -> None:
    cases = [c.split() for c in RPM_VECTORS.replace("\n", "").split("|")]
    assert len(cases) == 91
    for a, b, want in cases:
        assert rpmver.rpmvercmp(a, b) == int(want), (a, b)


def test_epoch_version_release() -> None:
    assert rpmver.compare_evr("1:3.0.7-27.el9", "3.0.7-99.el9") == 1, "an epoch beats any version"
    assert rpmver.compare_evr("0:1.2-3", "1.2-3") == 0
    assert rpmver.compare_evr("1.2-3.el9_4", "1.2-3.el9") == 1
    assert rpmver.compare_evr("1.2", "1.2-1") == -1, "rpmverCmp: a present release sorts after a missing one"
    assert rpmver.compare_evr("6.2-10.20210508.el9", "6.2-9.20210508.el9") == 1
    assert rpmver.normalise("0:1.2-3") == "1.2-3" and rpmver.normalise("2:4.9-8") == "2:4.9-8"
    for bad in ("", "a:b:c", "1:", "x" * 300):
        with pytest.raises(ValueError):
            rpmver.split_evr(bad)


# -- R5.1 ------------------------------------------------------------------------------------------------------------


def test_every_scanner_format_gives_the_same_normalised_findings(fx: Path) -> None:
    want = _tuples(_expected(fx)["normalised"])
    assert len(want) == 40
    for name in SCANNERS:
        (r,) = _parse(fx, name)
        got = sorted(tuple(f.normalised().values()) for f in reports.merge(r.findings))
        assert got == want, name
        assert r.image.distro and r.image.distro[0] == "rhel", name
    trivy, grype = _parse(fx, "trivy.json", "grype.json")
    assert {f.package.source for f in trivy.findings if f.package.name == "openssl-libs"} == {"openssl"}
    assert {f.package.source for f in grype.findings if f.package.name == "openssl-libs"} == {"openssl"}
    shadow = next(f for f in trivy.findings if f.package.name == "shadow-utils")
    assert shadow.package.version == "2:4.9-8.el9", "Trivy's epoch kept, the same as syft writes it"
    for name in ("cyclonedx-sbom.json", "spdx.json"):
        (r,) = _parse(fx, name)
        assert r.sbom and not r.findings and len(r.packages) == 24
        libs = next(p for p in r.packages if p.name == "openssl-libs")
        assert libs.version == "1:3.0.7-27.el9" and libs.source == "openssl", "epoch and SRPM from the purl"


def test_purls_and_versions() -> None:
    p = reports.parse_purl(
        "pkg:rpm/redhat/openssl-libs@3.0.7-27.el9?arch=x86_64&epoch=1&upstream=openssl-3.0.7-27.el9.src.rpm"
    )
    assert p and (p.type, p.namespace, p.name, p.version) == ("rpm", "redhat", "openssl-libs", "3.0.7-27.el9")
    pkg = reports.make_package(
        "", "", "", "pkg:rpm/redhat/openssl-libs@3.0.7-27.el9?epoch=1&upstream=openssl-3.0.7-27.el9.src.rpm"
    )
    assert (pkg.name, pkg.version, pkg.source) == ("openssl-libs", "1:3.0.7-27.el9", "openssl")
    npm = reports.parse_purl("pkg:npm/%40angular/core@17.0.1")
    assert npm and npm.namespace == "@angular" and npm.name == "core" and npm.version == "17.0.1"
    for junk in ("", "pkg:", "pkg:rpm", "http://x", "pkg:/@", "pkg:" + "a/" * 1500):
        assert reports.parse_purl(junk) is None
    assert reports.srpm_name("glibc-2.34-100.el9.src.rpm") == "glibc"
    assert reports.severity("IMPORTANT_VULNERABILITY_SEVERITY") == "high" and reports.severity(None) == "unknown"


def test_hostile_reports(monkeypatch: pytest.MonkeyPatch) -> None:
    for data, msg in (
        (b"not json", "not JSON"),
        (b"[1, 2]", "not a JSON object"),
        (b"[" * 100_000 + b"]" * 100_000, "nested too deeply|not JSON"),
        (b'{"hello": "world"}', "not a Trivy or Grype JSON report"),
        (b'{"document": {"category": "csaf_vex"}}', "pass VEX with --vex"),
        (b'{"catalogVersion": "1", "vulnerabilities": []}', "pass it with --kev"),
        (b'{"@context": "https://spdx.org/rdf/3.0.1/spdx-context.jsonld"}', "SPDX 3"),
        (b'{"SchemaVersion": 2, "Results": {"a": 1}}', "Results is not a list"),
    ):
        with pytest.raises(reports.ReportError, match=msg):
            reports.parse(data)
    with pytest.raises(reports.ReportError, match="larger than"):
        reports.parse(b" " * (reports.MAX_BYTES + 1))
    junk = {
        "SchemaVersion": 2,
        "Results": [
            {"Vulnerabilities": [{"VulnerabilityID": "$(touch x)", "PkgName": "a"}, {"PkgName": "b"}, "x", None]},
            "y",
        ],
    }
    assert reports.parse(json.dumps(junk)).findings == [], "ids that are not ids, and wrong types, are dropped"
    monkeypatch.setattr(reports, "MAX_FINDINGS", 3)
    many = {
        "SchemaVersion": 2,
        "Results": [{"Vulnerabilities": [{"VulnerabilityID": f"CVE-2099-{i:04d}", "PkgName": "a"} for i in range(5)]}],
    }
    with pytest.raises(reports.ReportError, match="more than 3 findings"):
        reports.parse(json.dumps(many))
    deep: dict[str, Any] = {"name": "leaf", "type": "library"}
    for _ in range(50):
        deep = {"name": "n", "type": "library", "components": [deep]}
    sbom = reports.parse(json.dumps({"bomFormat": "CycloneDX", "components": [deep]}))
    assert len(sbom.packages) == reports.MAX_DEPTH + 1, "nested components stop at the depth bound"


# -- R5.2 ------------------------------------------------------------------------------------------------------------


@pytest.fixture(scope="module")
def index(fx: Path) -> vex.VexIndex:
    return vex.load(None, [fx / "vex"])


def test_vex_drops_the_12_not_affected_and_keeps_28_in_every_format(fx: Path, index: vex.VexIndex) -> None:
    exp = _expected(fx)
    kept, excluded = _tuples(exp["kept"]), sorted(tuple(x) for x in exp["excluded"])
    assert len(kept) == 28 and len(excluded) == 12
    for name in VEX_FORMATS:
        out = assess.assess(_parse(fx, name), vex=index)
        assert out["counts"]["reported"] == 40 and out["counts"]["findings"] == 28, name
        assert _kept(out) == kept, name
        assert sorted((x["finding"]["package"]["name"], x["finding"]["cve"]) for x in out["excluded"]) == excluded
        for x in out["excluded"]:
            (st,) = x["statements"]
            assert st["status"] == "known_not_affected" and st["cpe"] == "cpe:/o:redhat:enterprise_linux:9"
            assert st["justification"] == exp["excludedJustification"][st["cve"]], "the VEX flag is cited"
            assert st["url"] == f"https://access.redhat.com/security/cve/{st['cve']}"
            assert st["document"].endswith(f"/2099/{st['cve'].lower()}.json")
    tar = next(f for f in assess.assess(_parse(fx, "trivy.json"), vex=index)["findings"] if f["cve"] == "CVE-2099-1018")
    assert tar["fixState"] == "wont-fix" and tar["vex"][0]["remediation"] == "no_fix_planned"


def test_rhacs_names_binaries_only_and_an_sbom_fills_them_in(fx: Path, index: vex.VexIndex) -> None:
    alone = assess.assess(_parse(fx, "rhacs-image.json"), vex=index)
    assert alone["counts"]["findings"] == 32, "four binaries named unlike their source RPM are not matched"
    assert any("no source RPM name" in n for n in alone["images"][0]["notes"])
    both = assess.assess(_parse(fx, "rhacs-image.json", "spdx.json"), vex=index)
    assert len(both["images"]) == 1 and _kept(both) == _tuples(_expected(fx)["kept"])


def test_vex_from_the_corpus_shard_and_product_scoping(fx: Path, tmp_path: Path) -> None:
    from kube_noob.sources import advisories

    docs = [json.loads(p.read_text()) for p in sorted((fx / "vex").rglob("*.json"))]
    advisories.run(tmp_path, docs)
    idx = vex.load(tmp_path)
    assert idx.origins == ["corpus shard redhat-vex: 34 CVEs"]
    out = assess.assess(_parse(fx, "grype.json"), vex=idx)
    assert out["counts"]["findings"] == 28 and out["excluded"][0]["statements"][0]["source"].startswith(
        "kube-noob corpus"
    )
    rhel8 = assess.assess(_parse(fx, "grype.json"), vex=idx, products=("cpe:/o:redhat:enterprise_linux:8",))
    assert rhel8["counts"]["findings"] == 40, "RHEL 9 statements do not apply to a RHEL 8 product"
    assert not vex.load(tmp_path, use_corpus=False).by_cve


def test_fixed_in_the_installed_version_drops_out_and_other_vendors_stay(fx: Path, index: vex.VexIndex) -> None:
    doc = json.loads((fx / "trivy.json").read_text())
    vulns = doc["Results"][0]["Vulnerabilities"]
    bash = next(v for v in vulns if v["VulnerabilityID"] == "CVE-2099-1001")
    bash["InstalledVersion"] = bash["FixedVersion"]  # the scanner is behind: the image already has the fix
    fedora = copy.deepcopy(next(v for v in vulns if v["VulnerabilityID"] == "CVE-2099-1024"))
    fedora["PkgIdentifier"]["PURL"] = fedora["PkgIdentifier"]["PURL"].replace("/redhat/", "/fedora/")
    fedora["PkgName"] = "bash-fedora"
    vulns.append(fedora)
    out = assess.assess([reports.parse(json.dumps(doc))], vex=index)
    dropped = next(x for x in out["excluded"] if x["finding"]["cve"] == "CVE-2099-1001")
    assert dropped["reason"].startswith("Red Hat VEX: fixed in 5.1.8-10.el9")
    assert dropped["statements"][0]["erratum"].endswith("RHSA-2099:1001")
    assert any(f["package"]["name"] == "bash-fedora" for f in out["findings"]), "VEX for RHEL says nothing of it"
    assert out["images"][0]["outsideVex"] == 1


def test_no_vex_no_sbom_findings(fx: Path) -> None:
    out = assess.assess(_parse(fx, "trivy.json"), vex=vex.VexIndex())
    assert out["counts"]["findings"] == 40 and "no VEX statements loaded" in out["images"][0]["notes"][0]
    with pytest.raises(assess.AssessError, match="needs Red Hat VEX"):
        assess.assess(_parse(fx, "spdx.json"), vex=vex.VexIndex())
    with pytest.raises(assess.AssessError, match="at least one"):
        assess.assess([])


def test_vex_input_bounds(tmp_path: Path) -> None:
    bad = tmp_path / "bad.json"
    bad.write_text('{"document": {}, "vulnerabilities": [{"cve": "nope"}]}')
    with pytest.raises(vex.VexError, match="not a CVE id"):
        vex.load(None, [bad])
    with pytest.raises(vex.VexError, match="no such file"):
        vex.load(None, [tmp_path / "missing"])
    with pytest.raises(vex.VexError, match="not JSON"):
        vex.load(None, texts=["{"])


# -- KEV and R5.3 ----------------------------------------------------------------------------------------------------


def test_kev_catalog(fx: Path) -> None:
    catalog = kev.load(fx / "kev.json")
    entry = catalog.get("cve-2099-1005")
    assert entry and entry.date_added == "2099-01-01" and entry.ransomware == "Unknown"
    assert catalog.describe() == "CISA KEV 2099.01.01 (2099-01-01), 1 CVEs"
    for text in ("[]", '{"vulnerabilities": []}', "{"):
        with pytest.raises(kev.KevError):
            kev.parse(text)


def _reach() -> dict[str, Any]:
    text = (FIX / "shop.yaml").read_text()
    return dict(workload_reach(Inventory.from_documents(d.data for d in load_documents(text))))


def test_the_exposed_privileged_kev_finding_ranks_first(fx: Path, index: vex.VexIndex) -> None:
    out = assess.assess(
        _parse(fx, "trivy.json", "api-trivy.json"), vex=index, kev=kev.load(fx / "kev.json"), reach=_reach()
    )
    top = out["ranking"]["ranked"][0]
    planted = _expected(fx)["plantedKev"]
    assert (top["finding"]["cve"], top["finding"]["package"]["name"]) == (planted["cve"], planted["package"])
    fx_ = top["factors"]
    assert (fx_["base"]["value"], fx_["exposure"]["value"], fx_["privileges"]["value"], fx_["exploited"]["value"]) == (
        planted["score"],
        3.0,
        1.9,
        2.0,
    )
    assert top["score"] == round(6.5 * 3 * 1.9 * 2, 2)
    assert top["attackPath"]["summary"] == (
        "internet -> Route/shop/web -> Service/shop/web -> Deployment/shop/web -> code execution in "
        "Deployment/shop/web -> node"
    )
    assert fx_["exploited"]["kev"]["dateAdded"] == "2099-01-01"
    api = [r for r in out["ranking"]["ranked"] if r["image"].endswith("/api:2.1")]
    assert api and all(r["finding"]["severity"] == "critical" for r in api)
    assert all(r["rank"] > 10 for r in api), "an internal critical ranks below the exposed, privileged web image"
    assert api[0]["factors"]["privileges"]["capability"].startswith("read Secrets")
    assert out["ranking"]["imagesPlaced"] == 2
    assert out["ranking"]["workloads"]["Deployment/shop/api"] == {"findings": 2, "fixableHighOrExploited": 2}
    unplaced = assess.assess(_parse(fx, "trivy.json"), vex=index)
    assert "not placed" in unplaced["ranking"]["ranked"][0]["attackPath"]["summary"]


def test_image_references() -> None:
    assert rank.parse_ref("nginx") == rank.ImageRef("docker.io", "library/nginx", "", "")
    assert rank.parse_ref("localhost:5000/a/b:1") == rank.ImageRef("localhost:5000", "a/b", "1", "")
    d = "sha256:" + "f" * 64
    assert rank.parse_ref(f"quay.io/x/y:2@{d}") == rank.ImageRef("quay.io", "x/y", "2", d)
    img = reports.ImageInfo(names=["docker.io/library/nginx:latest"], digests=[f"quay.io/x/y@{d}"])
    assert rank.same_image(img, "nginx") and rank.same_image(img, f"quay.io/x/y@{d}")
    assert not rank.same_image(img, "nginx:1.25") and not rank.same_image(img, f"quay.io/x/z@{d}")


# -- R5.4 ------------------------------------------------------------------------------------------------------------


def test_threat_model_of_the_three_tier_app_is_the_reviewed_list(fx: Path, index: vex.VexIndex) -> None:
    text = (FIX / "shop.yaml").read_text()
    out = assess.assess(_parse(fx, "trivy.json", "api-trivy.json"), vex=index, reach=_reach())
    model = threat.model(
        text, platform="openshift", version="4.20", vulnerable_images=assess.summary_for_workloads(out)
    )
    want = json.loads((FIX / "threat-expected.json").read_text())
    (app,) = model["applications"]
    assert app["application"] == want["application"] and app["counts"] == want["counts"]
    got = [
        {
            "id": t["id"],
            "status": t["status"],
            "evidence": sorted({e.get("rule", "grant") for e in t["evidence"]}),
            "attack": [a["id"] for a in t["attack"]],
            "policies": t["policies"],
        }
        for t in app["threats"]
    ]
    assert got == want["threats"]
    assert app["entryPoints"] == [{"ref": "Route/shop/web", "exposure": "internet (Route)"}]
    assert app["dataStores"] == ["StatefulSet/shop/db"] and app["identities"] == ["ServiceAccount/shop/api"]
    again = threat.model(
        text, platform="openshift", version="4.20", vulnerable_images=assess.summary_for_workloads(out)
    )
    assert again == model, "deterministic"
    assert model["attribution"] == attack.ATTRIBUTION and "MITRE Corporation" in model["attribution"]
    for t in app["threats"]:
        for a in t["attack"]:
            assert a["id"] in attack.TECHNIQUES and a["url"].startswith("https://attack.mitre.org/techniques/T")
    no_report = threat.model(text, platform="openshift", version="4.20")
    e01 = next(t for t in no_report["applications"][0]["threats"] if t["threat"] == "TM-E01")
    assert e01["status"] == "not assessed"


def test_threat_model_never_reads_secrets() -> None:
    text = (FIX / "shop.yaml").read_text()
    planted = "c2VjcmV0LXZhbHVlLXRoYXQtbXVzdC1ub3QtbGVhaw"
    secret = f"\n---\napiVersion: v1\nkind: Secret\nmetadata:\n  name: s\n  namespace: shop\ndata:\n  k: {planted}\n"
    model = threat.model(text + secret, platform="openshift", version="4.20")
    assert model["secretsIgnored"] == 1 and planted not in json.dumps(model)


def test_markdown_table_is_one_row_per_threat() -> None:
    model = threat.model((FIX / "shop.yaml").read_text(), platform="kubernetes")
    md = threat.render_markdown(model)
    assert md.count("\n| ") == len(model["applications"][0]["threats"]) + 2 and attack.ATTRIBUTION in md


# -- surfaces --------------------------------------------------------------------------------------------------------


def test_cli_report_threat_and_gate(fx: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    common = ["-r", str(fx / "trivy.json"), "--vex", str(fx / "vex"), "--kev", str(fx / "kev.json")]
    assert main(["vuln", "report", *common, "-m", str(FIX / "shop.yaml"), "--top", "1"]) == 0
    text = capsys.readouterr().out
    assert "40 reported, 12 excluded by VEX, 28 findings" in text and "1. 74.1 CVE-2099-1005 curl-minimal" in text
    assert main(["vuln", "report", *common, "--fail-on", "critical"]) == 1, "fixable criticals fail"
    capsys.readouterr()
    assert main(["vuln", "report", "-r", str(fx / "spdx.json"), "--vex", str(fx / "vex"), "--format", "json"]) == 0
    assert json.loads(capsys.readouterr().out)["counts"]["findings"] == 28
    assert main(["vuln", "report"]) == 2
    assert main(["vuln", "threat", "-f", str(FIX / "shop.yaml"), "--platform", "openshift"]) == 0
    assert "| Elevation of privilege | Deployment/shop/web |" in capsys.readouterr().out
    sarif = tmp_path / "gate.sarif"
    args = ["gate", "-f", str(FIX / "shop.yaml"), "--platform", "openshift", "--version", "4.20", "--sarif", str(sarif)]
    vuln_args = ["--scanner-report", str(fx / "trivy.json"), "--vex", str(fx / "vex")]
    assert main([*args, *vuln_args, "--fail-on", "never", "--format", "json"]) == 0
    rep = json.loads(capsys.readouterr().out)
    assert not any(n.startswith("vulnerability checks") for n in rep["notRun"]), rep["notRun"]
    assert rep["vulnerabilities"]["findings"] == 28
    ids = {r["ruleId"] for r in json.loads(sarif.read_text())["runs"][0]["results"]}
    assert "CVE-2099-1010" in ids and "CVE-2099-1024" not in ids, "VEX-excluded findings are not in SARIF"
    assert main([*args, *vuln_args, "--fail-on", "critical", "--format", "json"]) == 1
    why = json.loads(capsys.readouterr().out)["failures"]
    assert any("vulnerability finding(s) at critical or above that are fixable or known exploited" in w for w in why)
    assert not any(w.startswith("6 finding") for w in why), "unfixable vulnerabilities are reported, not counted"
    assert main([*args, "--fail-on", "never", "--format", "json"]) == 0
    assert "--scanner-report" in json.loads(capsys.readouterr().out)["notRun"][0]


def test_mcp_tools(fx: Path, tmp_path: Path) -> None:
    from kube_noob import toolkit as tk

    kit = tk.Toolkit(load_settings(overrides={"dataDir": str(tmp_path)}))
    names = {s.name for s in kit.specs()}
    assert {"vuln_report", "threat_model"} <= names
    vex_texts = [p.read_text() for p in sorted((fx / "vex").rglob("*.json"))][:20]
    out = kit.vuln_report(
        tk.VulnReportIn(
            reports=[(fx / "grype.json").read_text()], vex=vex_texts, manifests=(FIX / "shop.yaml").read_text()
        )
    )
    assert out["counts"]["reported"] == 40 and out["findingsTotal"] == out["counts"]["findings"]
    with pytest.raises(ValueError, match="not a Trivy"):
        kit.vuln_report(tk.VulnReportIn(reports=['{"a": 1}']))
    with pytest.raises(Exception, match="String should match pattern"):
        tk.VulnReportIn(reports=["{}"], products=["not-a-cpe"])
    with pytest.raises(Exception, match="Extra inputs"):
        tk.VulnReportIn(reports=["{}"], url="https://example.com")  # type: ignore[call-arg]
    model = kit.threat_model(tk.ThreatModelIn(manifests=(FIX / "shop.yaml").read_text(), platform="openshift"))
    assert model["applications"][0]["counts"]["open"] >= 10


def test_insight_reads_a_pasted_report(fx: Path, tmp_path: Path) -> None:
    from kube_noob import toolkit as tk
    from kube_noob.insight import insight

    kit = tk.Toolkit(load_settings(overrides={"dataDir": str(tmp_path)}))
    out = insight(kit, (fx / "trivy.json").read_text())
    assert "vulnerabilities" in out["ran"] and out["findings"][0]["source"] == "vulnerability"
    assert out["context"]["vulnerabilities"]["reported"] == 40
    sbom = insight(kit, (fx / "spdx.json").read_text())
    assert any(s["kind"] == "sbom" and "needs Red Hat VEX" in s["why"] for s in sbom["skipped"])
    table = "Total: 2 (HIGH: 2)\n| Library | Vulnerability | Severity |\n| openssl | CVE-2099-1001 | HIGH |\n"
    seen = insight(kit, table)
    assert "scanner-report" in {k["kind"] for k in seen["kinds"]}
    assert any(s["kind"] == "scanner-report" and "scanner tables" in s["why"] for s in seen["skipped"])


# -- RHACS Central image scans ---------------------------------------------------------------------------------------


def test_rhacs_image_scan_read(fx: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from kube_noob import rhacs, rhacs_central

    token = "rox-" + "k9" * 20
    monkeypatch.setenv("ROX_API_TOKEN", token)
    s = load_settings(overrides={"rhacs": {"enabled": True, "endpoint": "https://central.example.com"}})
    image = json.loads((fx / "rhacs-image.json").read_text())
    seen: list[httpx.Request] = []

    def handler(req: httpx.Request) -> httpx.Response:
        seen.append(req)
        return httpx.Response(200, json=image)

    pauses: list[float] = []
    digest = image["id"]
    docs, src = rhacs_central.read_images(
        s, [digest, digest], transport=httpx.MockTransport(handler), sleep=pauses.append
    )
    assert len(docs) == 2 and src["requests"] == 2
    assert [r.url.path for r in seen] == [f"/v1/images/{digest}"] * 2 and {r.method for r in seen} == {"GET"}
    assert seen[0].headers["authorization"] == f"Bearer {token}"
    assert len(pauses) == 1 and 0.1 <= pauses[0] <= 0.3, "jittered"
    assert reports.parse(json.dumps(docs[0])).format == "rhacs"
    with pytest.raises(rhacs.RhacsError, match="not an image digest"):
        rhacs_central.read_images(s, ["../../v1/secrets"], transport=httpx.MockTransport(handler))
    empty = httpx.MockTransport(lambda r: httpx.Response(200, json={"id": digest}))
    with pytest.raises(rhacs.RhacsError, match="no scan"):
        rhacs_central.read_images(s, [digest], transport=empty, sleep=lambda _: None)
    with pytest.raises(WebDisabledError):
        rhacs_central.read_images(load_settings(), [digest])
    monkeypatch.delenv("ROX_API_TOKEN")
    with pytest.raises(ConfigError, match="policies and images"):
        rhacs_central.read_images(s, [digest])
    reader = rhacs_central.CentralClient(object(), "https://c", rng=random.Random(1))
    assert 0.1 <= reader.rng.uniform(0.1, 0.3) <= 0.3
