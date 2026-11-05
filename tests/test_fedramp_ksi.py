"""The FedRAMP 20x Key Security Indicator crosswalk (N3, G217).

Every number and every id in `kube_noob.audit.fedramp` is generated from the vendored dataset, because the
previous version of this work was written against a file that no longer exists: a separate
`FRMR.KSI.key-security-indicators.json` at 25.11C, eleven families, indicators keyed by number, seven of them
flagged retired. None of that is true of the consolidated dataset, and a hand-maintained copy would have gone on
saying it. These tests hold the shape, not the contents: they re-derive from the vendored file and compare.
"""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

from kube_noob.audit import fedramp
from kube_noob.audit.controls import TITLES
from kube_noob.oscal import control_id

ROOT = Path(__file__).resolve().parents[1]
VENDOR = ROOT / "vendor/fedramp/fedramp-ksi.json"
DOC = ROOT / "docs/fedramp-ksi.md"
ID = re.compile(r"\AKSI-[A-Z]{3}-[A-Z]{3}\Z")


@pytest.fixture(scope="module")
def vendored() -> dict[str, Any]:
    return json.loads(VENDOR.read_text())


def test_the_vendored_extract_hashes_to_what_it_records(vendored: dict[str, Any]) -> None:
    """The recorded upstream hash cannot be checked offline; the extract's own hash can, and is what a reader of
    this repository is actually trusting. A vendored file nobody can verify is a file anybody can edit."""
    extract = json.dumps(vendored["KSI"], indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    assert hashlib.sha256(extract.encode()).hexdigest() == vendored["source"]["extract_sha256"]
    assert re.fullmatch(r"[0-9a-f]{64}", vendored["source"]["sha256"])


def test_the_module_states_the_version_it_was_generated_from(vendored: dict[str, Any]) -> None:
    assert vendored["source"]["version"] == fedramp.DATASET_VERSION
    assert vendored["source"]["last_updated"] == fedramp.DATASET_UPDATED
    assert vendored["source"]["sha256"] == fedramp.DATASET_SHA256
    assert vendored["source"]["extract_sha256"] == fedramp.EXTRACT_SHA256


def test_every_indicator_is_keyed_by_mnemonic_not_by_number() -> None:
    """`KSI-CMT-05` was the old shape. An id that no longer exists cannot be marked retired -- it is simply gone,
    which is why the seven "retired" ids this work once carried had to be deleted rather than updated."""
    assert fedramp.INDICATORS
    for ind in fedramp.INDICATORS:
        assert ID.match(ind), ind


def test_no_family_or_indicator_carries_a_retirement_flag(vendored: dict[str, Any]) -> None:
    text = json.dumps(vendored["KSI"]).lower()
    for word in ("retired", "withdrawn", "deprecated", "sunset"):
        assert word not in text, word
    for fam in vendored["KSI"].values():
        assert fam["status"] == "stable", fam["id"]


def test_the_crosswalk_uses_the_same_id_transformation_as_oscal(vendored: dict[str, Any]) -> None:
    """`AC-6(10)` -> `ac-6.10` is `oscal.control_id`. Two transformations would mean two answers."""
    cited: dict[str, set[str]] = {}
    for fam in vendored["KSI"].values():
        for ind, body in fam["indicators"].items():
            for c in body["controls"]:
                cited.setdefault(c, set()).add(ind)
    for control in TITLES:
        assert fedramp.BY_CONTROL[control] == tuple(sorted(cited.get(control_id(control), ())))


def test_a_control_no_indicator_cites_is_named_not_dropped() -> None:
    """The absence is the finding. A crosswalk that lists only what matched reads as full coverage."""
    assert set(fedramp.BY_CONTROL) == set(TITLES)
    assert tuple(sorted(c for c in TITLES if not fedramp.BY_CONTROL[c])) == fedramp.UNMAPPED_CONTROLS
    for control in fedramp.UNMAPPED_CONTROLS:
        assert fedramp.BY_CONTROL[control] == ()


def test_every_curated_indicator_exists_in_the_dataset() -> None:
    for ind in fedramp.EVIDENCE:
        assert ind in fedramp.INDICATORS, ind


def test_a_curated_entry_says_what_the_evidence_does_not_show() -> None:
    """An indicator is about an organisation's practice; kube-noob reads manifests. The half it cannot see has to
    be written down next to the half it can, or the mapping becomes the claim."""
    assert len(fedramp.EVIDENCE) >= 10
    for ind, body in fedramp.EVIDENCE.items():
        assert body["shows"].strip() and body["doesNotShow"].strip(), ind
        assert fedramp.indicator_rules(ind), f"{ind} is curated but no kube-noob rule is evidence for it"


def test_an_indicator_kube_noob_cannot_evidence_is_listed_as_such() -> None:
    rep = fedramp.summary([])
    rows = {r["id"]: r for r in rep["indicators"]}
    assert len(rows) == len(fedramp.INDICATORS)
    assert any(not r["evidenced"] for r in rows.values())
    for row in rows.values():
        if not row["evidenced"]:
            assert row["rules"] == []
            assert "findings" not in row


def test_an_indicator_that_varies_by_service_class_carries_its_classes(vendored: dict[str, Any]) -> None:
    """`varies_by_class` is not a flag. It is a block of per-class statements, and for one of the two classes the
    statement is marked optional -- so the same evidence speaks to a required indicator for one service class and
    an optional one for another. A boolean would have erased that, which is why this asserts the classes."""
    varies = {i: b for i, b in fedramp.INDICATORS.items() if b["variesByClass"]}
    assert varies
    rows = {r["id"]: r for r in fedramp.summary([])["indicators"]}
    for ind, body in varies.items():
        upstream = next(
            f["indicators"][ind]["varies_by_class"] for f in vendored["KSI"].values() if ind in f["indicators"]
        )
        assert body["variesByClass"] == tuple(sorted(upstream))
        assert rows[ind]["variesByClass"] == sorted(upstream)
        assert body["optionalFor"] == tuple(
            sorted(k for k, v in upstream.items() if str(v.get("statement", "")).startswith("**Optional:**"))
        )
        assert body["optionalFor"], f"{ind} varies by class but no class marks it optional"
    assert "service class" in fedramp.APPLICABILITY


def test_an_indicator_that_does_not_vary_claims_no_class(vendored: dict[str, Any]) -> None:
    for ind, body in fedramp.INDICATORS.items():
        upstream = next(f["indicators"][ind] for f in vendored["KSI"].values() if ind in f["indicators"])
        if "varies_by_class" not in upstream:
            assert body["variesByClass"] == ()
            assert body["optionalFor"] == ()


def test_findings_become_evidence_against_the_indicators_their_controls_cite() -> None:
    rep = fedramp.summary(["KN-S001"], evaluated_rule_ids=["KN-S001"])
    rows = {r["id"]: r for r in rep["indicators"]}
    # KN-S001 is evidence about AC-6, CM-7 and SC-39; every indicator citing one of those must count it.
    expected = set(fedramp.BY_CONTROL["AC-6"]) | set(fedramp.BY_CONTROL["CM-7"]) | set(fedramp.BY_CONTROL["SC-39"])
    assert expected
    for ind in expected:
        assert rows[ind]["findings"] >= 1, ind
        assert "KN-S001" in rows[ind]["rules"]
    for ind, row in rows.items():
        if ind not in expected and row["evidenced"]:
            assert row["findings"] == 0


def test_the_mapping_is_never_presented_as_a_compliance_claim() -> None:
    rep = fedramp.summary([])
    assert "never a compliance claim" in rep["note"]
    assert "an assessment decides" in rep["note"]
    # The caveat is kube-noob's, not a quotation: the consolidated dataset makes no such statement, and
    # attributing one to FedRAMP would be exactly the invention this work exists to avoid.
    assert "FedRAMP says" not in rep["note"]


def test_the_module_and_the_document_are_generated(tmp_path: Path) -> None:
    r = subprocess.run(
        [sys.executable, str(ROOT / "scripts/fedramp_ksi.py"), "--check"],
        capture_output=True,
        text=True,
        cwd=ROOT,
        check=False,
    )
    assert r.returncode == 0, r.stdout + r.stderr


def test_the_document_names_the_version_and_the_unmapped_controls() -> None:
    text = DOC.read_text()
    assert fedramp.DATASET_VERSION in text
    for control in fedramp.UNMAPPED_CONTROLS:
        assert control in text


def _cli(*args: str) -> tuple[int, str]:
    r = subprocess.run(
        [sys.executable, "-m", "kube_noob.cli", *args],
        capture_output=True,
        text=True,
        cwd=ROOT,
        env={"PATH": "/usr/bin:/bin", "PYTHONPATH": str(ROOT / "src"), "HOME": str(ROOT)},
        check=False,
    )
    return r.returncode, r.stdout + r.stderr


def test_the_command_reports_every_indicator_with_no_input() -> None:
    code, out = _cli("ksi", "--format", "json")
    assert code == 0, out
    rep = json.loads(out)
    assert len(rep["indicators"]) == len(fedramp.INDICATORS)
    assert rep["dataset"]["version"] == fedramp.DATASET_VERSION


def test_the_command_audits_the_manifests_it_is_given() -> None:
    code, out = _cli("ksi", "-f", "examples/insecure-deployment.yaml", "--format", "json")
    assert code == 0, out
    rows = {r["id"]: r for r in json.loads(out)["indicators"]}
    assert any(r.get("findings", 0) > 0 for r in rows.values())
    # Every evidenced row gets the full set of buckets once something was audited: a findings count on its own
    # cannot distinguish a clean indicator from one nothing evaluated.
    for row in rows.values():
        if row["evidenced"]:
            assert {"findings", "clean", "notEvaluated", "withheld"} <= set(row)


def test_an_indicator_id_that_does_not_exist_is_a_configuration_error() -> None:
    code, out = _cli("ksi", "--indicator", "KSI-CMT-05")
    assert code == 2, out
    assert "mnemonic" in out


def test_asking_for_one_control_returns_only_the_indicators_citing_it() -> None:
    code, out = _cli("ksi", "--control", "AC-6", "--format", "json")
    assert code == 0, out
    rep = json.loads(out)
    assert {r["id"] for r in rep["indicators"]} == set(fedramp.BY_CONTROL["AC-6"])
    assert rep["forControl"]["id"] == "AC-6"


def test_a_control_no_indicator_cites_returns_an_empty_set_not_an_error() -> None:
    code, out = _cli("ksi", "--control", "SC-6", "--format", "json")
    assert code == 0, out
    assert json.loads(out)["indicators"] == []


def test_the_prose_documents_state_the_measured_coverage_numbers() -> None:
    """Three documents carry these counts in hand-written prose, and I got one of them wrong by guessing: "20 of
    the 46" when it is 18. A number in a sentence is a claim, and this is the gate for it (G212, G217)."""
    unevidenced = sum(1 for i in fedramp.INDICATORS if not fedramp.indicator_rules(i))
    mapped = sum(1 for c in TITLES if fedramp.BY_CONTROL[c])

    def flat(path: Path) -> str:
        return re.sub(r"\s+", " ", path.read_text())

    for path in (ROOT / "docs/use-cases.md", ROOT / "docs/compliance.md", DOC):
        assert f"{unevidenced} of the {len(fedramp.INDICATORS)} indicators" in flat(path), path.name
    assert f"{mapped} of the {len(TITLES)} controls kube-noob maps" in flat(ROOT / "docs/compliance.md")
    assert f"{mapped} of kube-noob's {len(TITLES)} controls" in flat(DOC)
