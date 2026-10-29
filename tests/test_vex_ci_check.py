"""The CI check of the live Red Hat VEX step: one withdrawn document is reported, not failed, as long as another
published record names OpenShift; no OpenShift record, a malformed statement or a real fetch failure fails it."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location("vex_ci_check", ROOT / "scripts" / "vex_ci_check.py")
assert _spec and _spec.loader
check = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(check)

OPENSHIFT = {
    "cve": "CVE-2024-7387",
    "statements": [{"product": "Red Hat OpenShift Container Platform 4", "status": "fixed"}],
}
RHEL = {"cve": "CVE-2024-3094", "statements": [{"product": "Red Hat Enterprise Linux 9", "status": "not_affected"}]}


def _run(tmp_path: Path, out: dict[str, Any], records: list[dict[str, Any]]) -> int:
    (tmp_path / "out.json").write_text(json.dumps(out), encoding="utf-8")
    (tmp_path / "shard.jsonl").write_text("".join(json.dumps(r) + "\n" for r in records), encoding="utf-8")
    argv = ["vex_ci_check.py", str(tmp_path / "out.json"), str(tmp_path / "shard.jsonl"), str(tmp_path / "raw.json")]
    return int(check.main(argv))


def test_a_withdrawn_document_is_reported_not_failed(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    out = {
        "documents": 4,
        "kept": 3,
        "malformed": 0,
        "cves": 2,
        "requests": 6,
        "notPublished": ["CVE-2024-21626"],
        "failed": ["CVE-2023-44487: GET 2023/cve-2023-44487.json: larger than 25000000 bytes"],
    }
    assert _run(tmp_path, out, [RHEL, OPENSHIFT]) == 0
    assert "::notice title=Red Hat VEX live::" in capsys.readouterr().out


@pytest.mark.parametrize(
    ("out", "records", "why"),
    [
        ({"kept": 1, "malformed": 0, "notPublished": ["CVE-2024-21626"]}, [RHEL], "no record names an OpenShift"),
        ({"kept": 2, "malformed": 1}, [RHEL, OPENSHIFT], "1 malformed"),
        ({"kept": 2, "malformed": 0, "failed": ["CVE-2024-7387: GET x: HTTP 403"]}, [OPENSHIFT], "fetch failed"),
        ({"kept": 0, "malformed": 0}, [], "no statement kept"),
    ],
)
def test_what_still_fails_the_step(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], out: dict[str, Any], records: list[dict[str, Any]], why: str
) -> None:
    assert _run(tmp_path, out, records) == 1
    assert why in capsys.readouterr().out
