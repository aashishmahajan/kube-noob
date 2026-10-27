"""The self-test battery is part of CI: every case must pass, and every category must be covered."""

from __future__ import annotations

import json

import pytest

from kube_noob.cli import main
from kube_noob.config import load_settings
from kube_noob.evals.selftest import cases, run


def test_selftest_battery_passes_in_full() -> None:
    rep = run(load_settings())
    assert rep["failures"] == [] and rep["total"] >= 60
    assert set(rep["byCategory"]) == {"kubernetes", "helm", "openshift", "rosa-hcp", "rhacs", "everyday"}


def test_selftest_cases_are_well_formed() -> None:
    ids = [c["id"] for c in cases()]
    assert len(ids) == len(set(ids))
    for c in cases():
        assert c["kind"] in {"search", "diagnose", "audit", "protocol"} and c["expect"], c["id"]


def test_selftest_cli_exit_codes(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["selftest", "--category", "rosa-hcp", "--format", "json"]) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["total"] == out["passed"] >= 10
