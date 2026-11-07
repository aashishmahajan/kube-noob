"""The SBOM is generated from the lock file, offline, and is reproducible.

A security team cannot inventory what a tool installs unless the tool says so. kube-noob is offline by
default, so it states its own bill of materials from the hash-locked file the release actually installs
rather than scanning whatever happened to be on a build machine.

Reproducibility is the property that makes it checkable: two runs of the generator on one input produce
byte-identical output, so a stale document is a diff rather than a judgement call.
"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[1]
DOC = ROOT / "docs" / "sbom.spdx.json"


@pytest.fixture(scope="module")
def sbom() -> Any:
    spec = importlib.util.spec_from_file_location("kn_sbom", ROOT / "scripts" / "sbom.py")
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_the_committed_document_is_current(sbom: Any) -> None:
    assert DOC.is_file(), "run: python scripts/sbom.py"
    assert DOC.read_text(encoding="utf-8") == sbom.render(), "run: python scripts/sbom.py"


def test_generation_is_reproducible(sbom: Any) -> None:
    """No timestamp, no UUID: the same input must give the same bytes, or staleness cannot be detected."""
    assert sbom.render() == sbom.render()


def test_it_is_well_formed_spdx(sbom: Any) -> None:
    d = json.loads(DOC.read_text(encoding="utf-8"))
    assert d["spdxVersion"] == "SPDX-2.3" and d["dataLicense"] == "CC0-1.0"
    assert d["SPDXID"] == "SPDXRef-DOCUMENT" and d["documentNamespace"].startswith("https://")
    ids = {p["SPDXID"] for p in d["packages"]}
    assert len(ids) == len(d["packages"]), "SPDXIDs must be unique"
    for rel in d["relationships"]:
        for key in ("spdxElementId", "relatedSpdxElement"):
            assert rel[key] in ids | {"SPDXID", "SPDXRef-DOCUMENT"}, rel


def test_every_locked_dependency_is_listed(sbom: Any) -> None:
    """The inventory has to be the inventory: no pin may be missing from it."""
    d = json.loads(DOC.read_text(encoding="utf-8"))
    listed = {(p["name"], p["versionInfo"]) for p in d["packages"]}
    for name, ver, _ in sbom.dependencies():
        assert (name, ver) in listed, f"{name}=={ver} is locked but absent from the SBOM"


def test_the_pinned_hashes_are_recorded(sbom: Any) -> None:
    """Versions alone do not say which artifact may be installed; the lock pins hashes, so record them."""
    d = json.loads(DOC.read_text(encoding="utf-8"))
    with_hashes = [p for p in d["packages"] if p.get("checksums")]
    assert with_hashes, "the lock pins hashes and none reached the document"
    for p in with_hashes:
        for c in p["checksums"]:
            assert c["algorithm"] == "SHA256" and len(c["checksumValue"]) == 64, p["name"]


def test_the_project_itself_is_the_described_package(sbom: Any) -> None:
    d = json.loads(DOC.read_text(encoding="utf-8"))
    root = d["packages"][0]
    assert root["name"] == "kube-noob" and root["licenseDeclared"] == "Apache-2.0"
    assert root["versionInfo"] == sbom.version()
    describes = [r for r in d["relationships"] if r["relationshipType"] == "DESCRIBES"]
    assert len(describes) == 1 and describes[0]["relatedSpdxElement"] == root["SPDXID"]


def test_check_mode_reports_staleness(sbom: Any, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sbom, "OUT", tmp_path / "missing.json")
    assert sbom.main(["--check"]) == 1
    assert sbom.main([]) == 0
    assert sbom.main(["--check"]) == 0
