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
import pathlib
import re
import subprocess
import sys
import tempfile
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
            assert row["rulesFired"] == []
            assert "rulesBehind" not in row
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
        assert "KN-S001" in rows[ind]["rulesFired"]
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


#: A HOME outside the repository, because HOME=ROOT makes the CLI write its learning state into the working tree
#: -- an untracked `.local/share/kube-noob/` that a later `git add -A` picks up and commits.
_HOME = tempfile.mkdtemp(prefix="kube-noob-ksi-home-")


def _cli(*args: str) -> tuple[int, str]:
    r = subprocess.run(
        [sys.executable, "-m", "kube_noob.cli", *args],
        capture_output=True,
        text=True,
        cwd=ROOT,
        env={
            "PATH": "/usr/bin:/bin",
            "PYTHONPATH": str(ROOT / "src"),
            "HOME": _HOME,
            "KUBE_NOOB_DATA_DIR": str(pathlib.Path(_HOME) / "data"),
        },
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


# ---------------------------------------------------------------------------
# Red team, 2026-11-05: 25 reproduced defects. The eight worst were in the part I hand-wrote -- curated prose
# describing evidence the rules behind that indicator do not produce -- and the rest were the `ksi` command
# taking a shortcut past the input pipeline `audit` uses. (G219)
# ---------------------------------------------------------------------------


def test_every_rule_a_curated_sentence_names_is_behind_that_indicator() -> None:
    """The defect that produced this test: eight of thirteen sentences named evidence that does not reach their
    indicator, because they were written from the CONTROL names. `KSI-CNA-MAT` ("Minimizing Attack Surface")
    claimed privileged containers, host namespaces, hostPath and capabilities -- none of which cite `sc-7.5`,
    `sc-8` or `si-10` -- and `KSI-SVC-SIN` claimed a volume-encryption rule the catalogue does not contain."""
    from kube_noob.audit.rules import RULES

    catalogue = {r.rule_id for r in (RULES.values() if isinstance(RULES, dict) else RULES)}
    for ind, body in fedramp.EVIDENCE.items():
        behind = set(fedramp.indicator_rules(ind))
        assert body["rules"], ind
        for rule in body["rules"]:
            assert rule in catalogue, f"{ind} names {rule}, which is not a rule"
            assert rule in behind, f"{ind} names {rule}, which is not evidence for it"


def test_every_rule_a_curated_entry_lists_is_named_in_its_prose() -> None:
    """The tuple is what the sentences are about, so a rule in it that no sentence mentions is a rule nobody can
    check -- and the sentence would be describing something else."""
    for ind, body in fedramp.EVIDENCE.items():
        prose = f"{body['shows']} {body['doesNotShow']}"
        for rule in body["rules"]:
            assert rule in prose, f"{ind} lists {rule} but neither sentence names it"


def test_an_indicator_whose_rules_share_only_a_control_says_so() -> None:
    """`KSI-IAM-SNU` is about how non-user credentials are issued. It cites `ac-4`, Information Flow Enforcement,
    and kube-noob maps NetworkPolicy rules to `ac-4` because that is what `ac-4` is -- so eight traffic and RBAC
    rules land under an authentication indicator. The join is arithmetically correct and about nothing."""
    off = [i for i, b in fedramp.EVIDENCE.items() if not b["onSubject"]]
    assert "KSI-IAM-SNU" in off
    rows = {r["id"]: r for r in fedramp.summary([])["indicators"]}
    for ind in off:
        assert rows[ind]["onSubject"] is False
    assert "shared control is not shared subject matter" in fedramp.SHARED_CONTROL_IS_NOT_SHARED_SUBJECT
    assert fedramp.SHARED_CONTROL_IS_NOT_SHARED_SUBJECT in fedramp.summary([])["sharedControlCaveat"]


def test_the_applicability_quotation_names_the_document_that_contains_it() -> None:
    """The phrase is in the FedRAMP/rules README under "Using The Information". The first version of this cited
    `info.description`, which contains nothing of the kind -- and `info` is not vendored, so no check could have
    caught it. Attributing a statement to FedRAMP that FedRAMP did not make is this feature's own failure mode."""
    assert "README" in fedramp.APPLICABILITY
    assert "info.description" not in fedramp.APPLICABILITY
    assert "not vendored" in fedramp.APPLICABILITY, "say that this citation is dated, not hash-checked"
    vendored_text = VENDOR.read_text()
    assert "account for framework applicability" not in vendored_text.lower()


def test_withheld_is_absent_when_the_caller_did_not_say_what_fired() -> None:
    """`controls.summary` omits the column in that case for a reason: without the fired list a filtered rule is
    indistinguishable from a clean one, so `withheld: 0` asserts that none was filtered (G199)."""
    from kube_noob.audit.controls import RULE_CONTROLS

    rep = fedramp.summary(["KN-S001"], evaluated_rule_ids=sorted(RULE_CONTROLS))
    for row in rep["indicators"]:
        if row["evidenced"]:
            assert "withheld" not in row
            assert "clean" in row
    with_fired = fedramp.summary(["KN-S001"], evaluated_rule_ids=["KN-S001"], fired_rule_ids=["KN-S001"])
    assert all("withheld" in r for r in with_fired["indicators"] if r["evidenced"])


def test_a_finding_that_reaches_no_indicator_is_counted_not_dropped() -> None:
    """Three ways a finding reaches nothing: its rule maps to no control (KN-V007, a schema error), it maps only
    to controls no indicator cites (KN-C004 -> SC-6), or it is not a rule id at all (a scanner's CVE id). All
    three used to vanish between the audit and this page, so a bundle with findings could render as zeroes."""
    rep = fedramp.summary(["KN-V007", "KN-C004", "KN-C004", "CVE-2099-0001"])
    missed = {m["ruleId"]: m for m in rep["findingsNotMapped"]}
    assert set(missed) == {"KN-V007", "KN-C004", "CVE-2099-0001"}
    assert missed["KN-C004"]["findings"] == 2
    assert "SC-6" in missed["KN-C004"]["why"]
    assert "no control is mapped" in missed["KN-V007"]["why"]
    assert "findingsNotMapped" not in fedramp.summary(["KN-S001"])


def test_a_control_in_the_wrong_spelling_is_an_error_not_an_empty_answer() -> None:
    """`SC-6` returns `()` because no indicator cites it, which is a fact. `ac-6` used to return `()` as well --
    the same answer to a different question, from which a caller could conclude that kube-noob has no evidence
    for a control it has thirty rules for."""
    assert fedramp.indicators_for("SC-6") == ()
    for wrong in ("ac-6", "ac-6.10", "AC6", ""):
        with pytest.raises(KeyError):
            fedramp.indicators_for(wrong)
    with pytest.raises(KeyError):
        fedramp.controls_for("ksi-iam-elp")


def test_the_summary_docstring_does_not_guess_a_count() -> None:
    """It said "the 20 or so no kube-noob rule touches". It is 18 -- the same guess the documents were corrected
    for, two files away."""
    doc = fedramp.summary.__doc__ or ""
    assert "20" not in doc and "or so" not in doc


def test_the_claim_about_cm6_is_true_of_the_rules() -> None:
    from kube_noob.audit.controls import RULE_CONTROLS

    share = sum(1 for cs in RULE_CONTROLS.values() if "CM-6" in cs) / len(RULE_CONTROLS)
    assert 0.28 <= share <= 0.40, share
    assert "a third of kube-noob's rules" in fedramp.EVIDENCE["KSI-CMT-RMV"]["doesNotShow"]


def _write(tmp_path: Path, name: str, text: str) -> Path:
    p = tmp_path / name
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")
    return p


VALUES = "replicaCount: 2\nimage:\n  repository: nginx\n  tag: latest\nresources: {}\nsecurityContext: {}\n"


def test_a_helm_values_file_is_refused_not_given_a_clean_page(tmp_path: Path) -> None:
    """It used to be read as one object, every rule ran over it, and KSI-IAM-ELP reported "31 clean" -- a count
    of rules that passed on a file none of them can read. `audit` has refused this input since G191."""
    f = _write(tmp_path, "values.yaml", VALUES)
    code, out = _cli("ksi", "-f", str(f), "--format", "json")
    assert code == 2, out
    assert "Helm values file" in out


def test_one_file_does_not_count_the_partial_bundle_rules_as_clean() -> None:
    """G202 through a second door. The handler called `analyze()` without `partial_bundle`, so for a single file
    KN-C008 (no PodDisruptionBudget) and KN-N013 (DNS egress) ran as if the file were the whole namespace: this
    page said CP-10 was 6 clean where `audit` on the same input says 4 clean and 2 not evaluated."""
    code, ksi = _cli("ksi", "-f", "examples/insecure-deployment.yaml", "--indicator", "KSI-RPL-ABO", "--format", "json")
    assert code == 0, ksi
    row = json.loads(ksi)["indicators"][0]
    code, audit = _cli("audit", "-f", "examples/insecure-deployment.yaml", "--format", "json")
    assert code in (0, 1), audit
    cp10 = next(c for c in json.loads(audit)["controlSummary"]["controls"] if c["id"] == "CP-10")
    for bucket in ("findings", "clean", "notEvaluated"):
        assert row[bucket] == cp10[bucket], (bucket, row, cp10)
    assert row["notEvaluated"] > 0


def test_one_file_does_not_report_the_absences_audit_declines_to_judge() -> None:
    """The mirror image of the same bug: `ksi` reported KN-N001 "no NetworkPolicy" against four indicators for a
    single file, which says a gap exists when the user simply did not pass the policy."""
    code, out = _cli("ksi", "-f", "examples/insecure-deployment.yaml", "--format", "json")
    assert code == 0, out
    assert not any("KN-N001" in r.get("rules", []) for r in json.loads(out)["indicators"])


def test_an_unreadable_file_in_a_directory_is_not_silently_dropped(tmp_path: Path) -> None:
    """`_read` discarded the list of files it could not read, so a partial audit was presented as a complete one
    at exit 0. `audit` exits 5 and names the file; 5 means the run is not trustworthy enough to act on."""
    _write(tmp_path, "good.yaml", (ROOT / "examples/insecure-deployment.yaml").read_text())
    (tmp_path / "zz-bad.yaml").write_bytes(b"\xff\xfe\x00bad")
    code, out = _cli("ksi", "-f", str(tmp_path), "--format", "json")
    assert code == 5, out
    assert "zz-bad.yaml" in out
    code, out = _cli("ksi", "-f", str(tmp_path), "--skip-unreadable", "--format", "json")
    assert code == 0, out
    rep = json.loads(out)
    assert [u["path"] for u in rep["unreadable"]] == ["zz-bad.yaml"]


def test_an_empty_input_is_refused_rather_than_reported(tmp_path: Path) -> None:
    (tmp_path / "empty").mkdir()
    code, out = _cli("ksi", "-f", str(tmp_path / "empty"), "--format", "json")
    assert code == 2, out
    assert "no readable manifest here" in out


def test_the_assumptions_the_audit_made_are_carried_into_the_view() -> None:
    """ "No Kubernetes version given; assumed 1.35." decides what KSI-SCR-MIT's "API removed in the target
    version" findings mean, and the partial-bundle note is why a row says notEvaluated. Both were dropped."""
    code, out = _cli("ksi", "-f", "examples/insecure-deployment.yaml", "--format", "json")
    assert code == 0, out
    assumed = json.loads(out)["assumptions"]
    assert any("assumed" in a for a in assumed)
    assert any("part of a namespace" in a for a in assumed)
    code, text = _cli("ksi", "-f", "examples/insecure-deployment.yaml")
    assert "assumed:" in text


def test_a_filter_says_how_many_rows_it_hid() -> None:
    """G215 in another costume: a reader counts what is on the page. `--evidenced-only` dropped 18 of 46 rows
    and said nothing in either format."""
    code, out = _cli("ksi", "--evidenced-only", "--format", "json")
    assert code == 0, out
    rep = json.loads(out)
    assert rep["filtered"]["evidencedOnly"] == sum(1 for i in fedramp.INDICATORS if not fedramp.indicator_rules(i))
    assert rep["filtered"]["of"] == len(fedramp.INDICATORS)
    code, text = _cli("ksi", "--evidenced-only")
    assert f"showing {rep['filtered']['shown']} of {len(fedramp.INDICATORS)} indicators" in text


def test_filters_that_match_nothing_say_so_instead_of_printing_a_header() -> None:
    """Both of these exited 0 with an empty list and no mention of the id the user typed."""
    for args in (
        ("ksi", "--indicator", "KSI-CED-RAT", "--evidenced-only"),
        ("ksi", "--indicator", "KSI-IAM-ELP", "--control", "CP-10"),
    ):
        code, text = _cli(*args)
        assert code == 0, text
        assert "no indicator matches these filters" in text, args


def test_a_refresh_stamps_the_day_it_actually_fetched(tmp_path: Path) -> None:
    """`refresh()` spread the old `source` and rewrote every field but this one, so after a future refresh the
    module, every `ksi` run and the generated page would all assert a retrieval that did not happen that day."""
    import datetime as dt
    import importlib.util
    from unittest import mock

    spec = importlib.util.spec_from_file_location("fedramp_ksi_gen", ROOT / "scripts/fedramp_ksi.py")
    assert spec and spec.loader
    gen = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(gen)

    stale = json.loads(VENDOR.read_text())
    stale["source"]["retrieved"] = "2020-01-01"
    vendored_copy = tmp_path / "vendored.json"
    vendored_copy.write_text(json.dumps(stale, indent=2, sort_keys=True, ensure_ascii=False) + "\n")
    upstream = json.dumps(
        {
            "info": {"title": stale["source"]["name"], "version": "2099.01.01.01", "last_updated": "2099-01-01"},
            "KSI": stale["KSI"],
        }
    ).encode()

    class _Response:
        def __enter__(self) -> _Response:
            return self

        def __exit__(self, *exc: object) -> bool:
            return False

        def read(self) -> bytes:
            return upstream

    with (
        mock.patch.object(gen, "VENDOR", vendored_copy),
        mock.patch("urllib.request.urlopen", lambda *a, **k: _Response()),
    ):
        assert gen.refresh() == 0
    got = json.loads(vendored_copy.read_text())["source"]
    assert got["retrieved"] == dt.datetime.now(dt.UTC).date().isoformat()
    assert got["version"] == "2099.01.01.01"


def test_a_refresh_notices_an_edited_extract_even_when_upstream_has_not_moved(tmp_path: Path) -> None:
    """The upstream file matching its recorded hash says nothing about whether the vendored extract still equals
    upstream's KSI section: an edited extract with a recomputed `extract_sha256` passes `--check` happily, and
    this was the one place that could notice."""
    import importlib.util
    from unittest import mock

    spec = importlib.util.spec_from_file_location("fedramp_ksi_gen2", ROOT / "scripts/fedramp_ksi.py")
    assert spec and spec.loader
    gen = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(gen)

    real = json.loads(VENDOR.read_text())
    upstream_bytes = json.dumps({"info": {"title": "t", "version": "v", "last_updated": "d"}, "KSI": real["KSI"]})
    tampered = json.loads(json.dumps(real))
    fam = next(iter(tampered["KSI"]))
    ind = next(iter(tampered["KSI"][fam]["indicators"]))
    tampered["KSI"][fam]["indicators"][ind]["controls"] = ["ac-6"]
    text = json.dumps(tampered["KSI"], indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    tampered["source"]["extract_sha256"] = hashlib.sha256(text.encode()).hexdigest()
    tampered["source"]["sha256"] = hashlib.sha256(upstream_bytes.encode()).hexdigest()
    copy = tmp_path / "vendored.json"
    copy.write_text(json.dumps(tampered, indent=2, sort_keys=True, ensure_ascii=False) + "\n")

    class _Response:
        def __enter__(self) -> _Response:
            return self

        def __exit__(self, *exc: object) -> bool:
            return False

        def read(self) -> bytes:
            return upstream_bytes.encode()

    with (
        mock.patch.object(gen, "VENDOR", copy),
        mock.patch("urllib.request.urlopen", lambda *a, **k: _Response()),
    ):
        assert gen.refresh() == 0
    restored = json.loads(copy.read_text())
    assert restored["KSI"][fam]["indicators"][ind]["controls"] != ["ac-6"], "the edit survived a refresh"


# ---------------------------------------------------------------------------
# The MCP tool. The CLI was the whole of N3 as first shipped, which left the crosswalk unreachable from the
# interface this project is mostly used through. (G220)
# ---------------------------------------------------------------------------


def _kit() -> Any:
    from kube_noob.config import Settings
    from kube_noob.toolkit import Toolkit

    return Toolkit(Settings())


def test_the_crosswalk_is_a_tool_and_is_read_only() -> None:
    specs = {s.name: s for s in _kit().specs()}
    spec = specs["fedramp_ksi"]
    assert spec.read_only is True
    assert "compliance" in spec.description.lower(), "the tool's own description must carry the caveat"


def test_the_tool_answers_without_manifests() -> None:
    kit = _kit()
    spec = next(s for s in kit.specs() if s.name == "fedramp_ksi")
    out = spec.fn(spec.model())
    assert len(out["indicators"]) == len(fedramp.INDICATORS)
    assert out["note"] == fedramp.NOT_A_COMPLIANCE_CLAIM


def test_the_tool_refuses_what_the_audit_tool_refuses() -> None:
    from kube_noob.errors import ConfigError

    kit = _kit()
    spec = next(s for s in kit.specs() if s.name == "fedramp_ksi")
    with pytest.raises(ConfigError, match="Kubernetes manifest"):
        spec.fn(spec.model(manifests=VALUES))


def test_the_tool_agrees_with_the_command_on_the_same_input() -> None:
    """One crosswalk, two front doors. If they disagree, one of them is wrong and a reader cannot tell which."""
    manifests = (ROOT / "examples/insecure-deployment.yaml").read_text()
    kit = _kit()
    spec = next(s for s in kit.specs() if s.name == "fedramp_ksi")
    tool = spec.fn(spec.model(manifests=manifests, partial_bundle=True))
    code, out = _cli("ksi", "-f", "examples/insecure-deployment.yaml", "--format", "json")
    assert code == 0, out
    cli = json.loads(out)
    assert {r["id"]: r.get("findings") for r in tool["indicators"]} == {
        r["id"]: r.get("findings") for r in cli["indicators"]
    }
    assert tool["assumptions"] == cli["assumptions"]


def test_the_tool_carries_the_partial_bundle_question_to_the_caller() -> None:
    """A tool given a pasted manifest cannot know whether it is the whole namespace, so the flag is the caller's
    to set and the default is the safe one: absences are not evaluated rather than reported as gaps."""
    manifests = (ROOT / "examples/insecure-deployment.yaml").read_text()
    kit = _kit()
    spec = next(s for s in kit.specs() if s.name == "fedramp_ksi")
    assert spec.model(manifests=manifests).partial_bundle is True
    whole = spec.fn(spec.model(manifests=manifests, partial_bundle=False))
    part = spec.fn(spec.model(manifests=manifests, partial_bundle=True))
    rows = {r["id"]: r for r in part["indicators"]}
    full = {r["id"]: r for r in whole["indicators"]}
    assert rows["KSI-RPL-ABO"]["notEvaluated"] > full["KSI-RPL-ABO"]["notEvaluated"]


def test_the_tool_rejects_an_id_that_does_not_exist() -> None:
    """Ruff found this before a test did: both branches raised an undefined name, so a caller passing a numeric
    id -- the shape the previous dataset used -- would have got an unhandled NameError instead of an answer."""
    from kube_noob.errors import ConfigError

    kit = _kit()
    spec = next(s for s in kit.specs() if s.name == "fedramp_ksi")
    with pytest.raises(ConfigError, match="mnemonics"):
        spec.fn(spec.model(indicator="KSI-CMT-05"))
    with pytest.raises(ConfigError, match=re.escape("ac-6.10")):
        spec.fn(spec.model(control="ac-6"))
    out = spec.fn(spec.model(control="SC-6"))
    assert out["indicators"] == [] and out["filtered"]["why"]


# ---------------------------------------------------------------------------
# Red team, 2026-11-06: 10 more defects on the tool and the engine beneath it. The worst was that the curated
# prose -- the half of this feature that says what the counts are NOT evidence of -- was printed only by the
# command's text renderer and never reached the JSON an assistant reads. (G221)
# ---------------------------------------------------------------------------


def test_every_row_carries_the_prose_not_just_the_counts() -> None:
    """The tool returns JSON and nothing else. With the sentences living in the CLI renderer, an assistant saw
    `KSI-SVC-VRI: clean 3` and had no way to know that kube-noob fetches no signature and verifies nothing."""
    rows = {r["id"]: r for r in fedramp.summary([])["indicators"]}
    for ind, body in fedramp.EVIDENCE.items():
        ev = rows[ind]["evidence"]
        assert ev["shows"] == body["shows"]
        assert ev["doesNotShow"] == body["doesNotShow"]
        assert ev["rulesNamed"] == list(body["rules"])
    for ind, body in fedramp.EVIDENCE.items():
        if not body["onSubject"]:
            assert rows[ind]["warning"] == fedramp.OFF_SUBJECT_WARNING, ind
        else:
            assert "warning" not in rows[ind], ind


def test_the_crosswalk_alone_asserts_no_counts() -> None:
    """28 rows reading `findings: 0` when nothing was audited are indistinguishable from 28 clean results -- the
    same argument that already kept counts off the rows no rule can evidence."""
    rep = fedramp.summary([])
    assert rep["audited"] is False
    for row in rep["indicators"]:
        for key in ("findings", "clean", "notEvaluated", "withheld", "excepted"):
            assert key not in row, (row["id"], key)
    audited = fedramp.summary([], evaluated_rule_ids=["KN-S001"])
    assert audited["audited"] is True
    assert all("findings" in r for r in audited["indicators"] if r["evidenced"])


def test_an_evidenced_row_says_how_many_rules_are_behind_it() -> None:
    """`rules: []` beside `evidenced: true` read as "no rules"; it meant "no rule fired"."""
    rows = {r["id"]: r for r in fedramp.summary([], evaluated_rule_ids=[])["indicators"]}
    row = rows["KSI-SVC-VRI"]
    assert row["rulesFired"] == []
    assert row["rulesBehind"] == len(fedramp.indicator_rules("KSI-SVC-VRI"))


def test_a_declining_rule_is_named_so_the_caller_can_supply_what_it_wanted() -> None:
    """A bare `notEvaluated: 1` on an AdminNetworkPolicy bundle is KN-N014 -- the one rule that knows the policy
    may be inert -- and a caller who cannot see which rule declined cannot pass the CNI it was asking for."""
    anp = (
        "apiVersion: policy.networking.k8s.io/v1alpha1\nkind: AdminNetworkPolicy\n"
        "metadata:\n  name: deny-all\nspec:\n  priority: 10\n  subject:\n    namespaces: {}\n"
        "  ingress:\n  - action: Deny\n    from:\n    - namespaces: {}\n"
    )
    kit = _kit()
    spec = next(s for s in kit.specs() if s.name == "fedramp_ksi")
    blind = spec.fn(spec.model(manifests=anp, partial_bundle=False, indicator="KSI-CNA-RNT"))
    row = blind["indicators"][0]
    assert "KN-N014" in row["notEvaluatedRules"]
    told = spec.fn(spec.model(manifests=anp, partial_bundle=False, indicator="KSI-CNA-RNT", cni="calico:3.32"))
    assert "KN-N014" not in told["indicators"][0].get("notEvaluatedRules", [])
    assert "KN-N014" in told["indicators"][0]["rulesFired"]


def test_a_target_past_the_removal_table_is_not_a_clean_result() -> None:
    """KSI-SCR-MIT's evidence is the removed-API rules. `audit` says "no finding here means none through 1.37,
    not none in 1.40"; this view dropped that and reported the row clean."""
    kit = _kit()
    spec = next(s for s in kit.specs() if s.name == "fedramp_ksi")
    manifests = (ROOT / "examples/insecure-deployment.yaml").read_text()
    out = spec.fn(spec.model(manifests=manifests, version="1.40"))
    assert out["notCheckedBeyond"]["target"] == "1.40"
    code, text = _cli("ksi", "-f", "examples/insecure-deployment.yaml", "--version", "1.40")
    assert code == 0, text
    assert "not checked:" in text


def test_blank_manifests_are_refused_rather_than_crosswalked() -> None:
    """The model strips whitespace, so an empty file was indistinguishable from omitting the argument: a caller
    who passed an empty manifest was told there were no findings."""
    from kube_noob.errors import ConfigError

    kit = _kit()
    spec = next(s for s in kit.specs() if s.name == "fedramp_ksi")
    for blank in ("", "   ", "\n\n"):
        with pytest.raises(ConfigError):
            spec.fn(spec.model(manifests=blank))


def test_the_tool_uses_the_configured_default_platform() -> None:
    """A fixed "kubernetes" default made the two front doors disagree on a configured server: a Route audited as
    Kubernetes picks up KN-V003 ("Route only exists on OpenShift"), which lands on six indicators as a finding
    that is an artefact of the wrong platform."""
    from kube_noob.config import Settings
    from kube_noob.toolkit import Toolkit

    route = (
        "apiVersion: route.openshift.io/v1\nkind: Route\nmetadata:\n  name: web\n  namespace: shop\n"
        "spec:\n  to:\n    kind: Service\n    name: web\n"
    )
    kit = Toolkit(Settings(defaultPlatform="openshift"))
    spec = next(s for s in kit.specs() if s.name == "fedramp_ksi")
    assert spec.model(manifests=route).platform is None
    out = spec.fn(spec.model(manifests=route))
    assert not any("KN-V003" in r.get("rulesFired", []) for r in out["indicators"])


def test_the_text_view_omits_the_excepted_column_when_no_list_was_read() -> None:
    """`ksi` takes no exception list, so a column of zeros asserted that nothing was excepted when nothing was
    even looked at (G199)."""
    code, text = _cli("ksi", "-f", "examples/insecure-deployment.yaml")
    assert code == 0, text
    assert "excepted" not in text


def test_the_partial_bundle_advice_fits_both_front_doors() -> None:
    """The remedy said "Audit the directory", which an MCP caller holding pasted YAML cannot do -- and
    partial_bundle defaults to true there, so every default call carried advice its caller could not follow."""
    kit = _kit()
    spec = next(s for s in kit.specs() if s.name == "fedramp_ksi")
    out = spec.fn(spec.model(manifests=(ROOT / "examples/insecure-deployment.yaml").read_text()))
    note = next(a for a in out["assumptions"] if "part of a namespace" in a)
    assert "partial_bundle=false" in note
    assert "Audit the directory to evaluate them." not in note


def test_a_control_character_is_refused_not_an_internal_error() -> None:
    """`yaml.SafeLoader(text)` validates the whole string in its constructor, and that line sat outside the
    handler -- so ESC or NUL in a manifest raised a YAMLError that escaped as an unhandled exception and the MCP
    server returned 500 "internal error" for input it simply could not parse. A caller cannot act on a 500."""
    from kube_noob.errors import ManifestError
    from kube_noob.yamlio import load_documents

    for ch in ("\x1b", "\x00"):
        with pytest.raises(ManifestError, match="Invalid YAML"):
            load_documents(f"apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: 'a{ch}b'\n")


def test_an_undeclared_storage_class_is_not_clean_on_a_partial_bundle() -> None:
    """The rule skipped its one cross-object branch under `partial_bundle` without declining, so it stayed in
    `evaluated_rules` and a per-control summary counted it clean -- while the same report's assumptions said an
    undeclared StorageClass was not evaluated. Two halves of one report disagreeing, reassuring half first."""
    from kube_noob.audit.engine import analyze

    pvc = (
        "apiVersion: v1\nkind: PersistentVolumeClaim\nmetadata:\n  name: shared\n  namespace: team\n"
        "spec:\n  accessModes: [ReadWriteMany]\n  storageClassName: team-nfs\n"
        "  resources: {requests: {storage: 1Gi}}\n"
    )
    part = analyze(pvc, "kubernetes", partial_bundle=True)
    assert "KN-ST001" not in part.evaluated_rules
    whole = analyze(pvc, "kubernetes", partial_bundle=False)
    assert "KN-ST001" in {f.rule_id for f in whole.findings}
