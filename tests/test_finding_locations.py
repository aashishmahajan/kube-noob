"""A finding's line number has to be a line of a file somebody can open (G251).

`kube-noob audit -f dir/` reads one string, because the audit does: the directory's files are concatenated with
`---` between them. Every line number after the first file was therefore a line of that concatenation -- for a
three-file directory the second file's findings were reported ten or twenty lines past the end of the file they
were in, against no path at all. `_dir_yaml`'s own docstring already said what an unreadable file deserved:
"a path anyone could open". This is the same argument for the findings.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from kube_noob.cli import main

FIRST = """apiVersion: v1
kind: ConfigMap
metadata:
  name: first
  namespace: shop
data:
  hello: world
"""

#: `privileged: true` is on line 11 of this file, and nowhere near line 11 of a concatenation.
SECOND = """apiVersion: v1
kind: Pod
metadata:
  name: second
  namespace: shop
spec:
  containers:
  - name: c
    image: nginx
    securityContext:
      privileged: true
"""

#: No trailing newline, which is what broke the first attempt at the arithmetic.
THIRD = """apiVersion: v1
kind: Pod
metadata: {name: third, namespace: shop}
spec: {containers: [{name: c, image: nginx, securityContext: {privileged: true}}]}"""


def _bundle(tmp_path: Path) -> Path:
    d = tmp_path / "manifests"
    d.mkdir()
    (d / "a.yaml").write_text(FIRST, encoding="utf-8")
    (d / "b.yaml").write_text(SECOND, encoding="utf-8")
    (d / "c.yml").write_text(THIRD, encoding="utf-8")
    return d


def _audit(path: Path, *extra: str) -> dict:
    import contextlib
    import io

    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        main(["audit", "-f", str(path), "--platform", "kubernetes", "--format", "json", *extra])
    return json.loads(out.getvalue())


def test_every_finding_names_its_own_file_and_that_files_line(tmp_path: Path) -> None:
    d = _bundle(tmp_path)
    report = _audit(d)
    by_resource = {f["resource"]: f for f in report["findings"] if f["ruleId"] == "KN-S001"}
    assert set(by_resource) == {"Pod/shop/second", "Pod/shop/third"}
    assert by_resource["Pod/shop/second"]["file"] == "b.yaml"
    assert by_resource["Pod/shop/second"]["line"] == 11, "the line of b.yaml, not of the concatenation"
    assert by_resource["Pod/shop/third"]["file"] == "c.yml"
    assert by_resource["Pod/shop/third"]["line"] == 4
    # Every finding's line must be inside the file it names, which is the property the old numbers broke.
    lengths = {p.name: len(p.read_text(encoding="utf-8").splitlines()) for p in d.iterdir()}
    for f in report["findings"]:
        assert f.get("file") in lengths, f
        if f.get("line"):
            assert 1 <= f["line"] <= lengths[f["file"]], f


def test_one_file_is_named_too_and_its_lines_are_unchanged(tmp_path: Path) -> None:
    d = _bundle(tmp_path)
    report = _audit(d / "b.yaml")
    finding = next(f for f in report["findings"] if f["ruleId"] == "KN-S001")
    assert finding["file"].endswith("b.yaml") and finding["line"] == 11


def test_stdin_claims_no_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Nothing to name, so nothing is named -- and the line is still the line of what was piped in."""
    import io

    monkeypatch.setattr("sys.stdin", io.StringIO(SECOND))
    report = _audit(Path("-"))
    finding = next(f for f in report["findings"] if f["ruleId"] == "KN-S001")
    assert "file" not in finding and finding["line"] == 11


def test_the_text_report_prints_the_path_and_the_line(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    d = _bundle(tmp_path)
    main(["audit", "-f", str(d), "--platform", "kubernetes", "--min-severity", "critical"])
    out = capsys.readouterr().out
    assert "b.yaml:11" in out and "c.yml:4" in out
    assert " L11 " not in out, "a bare line number says which file only by accident"


def test_oscal_names_the_file_and_deliberately_not_the_line(tmp_path: Path) -> None:
    """An assessor needs the path. The line would make the document depend on document order, which another
    invariant forbids (`test_the_document_does_not_depend_on_the_order_the_documents_arrived_in`), so it stays
    in the JSON report where reordering a bundle is allowed to change it."""
    import contextlib
    import io

    d = _bundle(tmp_path)
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        main(["audit", "-f", str(d), "--platform", "kubernetes", "--oscal"])
    doc = json.loads(out.getvalue())
    props = [p for o in doc["assessment-results"]["results"][0]["observations"] for p in o.get("props", [])]
    files = {p["value"] for p in props if p["name"] == "file"}
    assert files <= {"a.yaml", "b.yaml", "c.yml"} and files
    assert not [p for p in props if p["name"] == "line"]


def test_an_excepted_finding_is_located_too(tmp_path: Path) -> None:
    d = _bundle(tmp_path)
    import datetime as dt

    exceptions = tmp_path / "exc.yaml"
    expires = (dt.date.today() + dt.timedelta(days=90)).isoformat()
    exceptions.write_text(
        "apiVersion: kube-noob.io/v1\nkind: ExceptionList\nexceptions:\n"
        "- id: EXC-001\n  rule: KN-S001\n  scope: {kind: Pod, namespace: shop, name: second}\n"
        "  owner: team-web\n  reason: the legacy agent needs it until the rewrite lands\n"
        f"  expires: {expires}\n",
        encoding="utf-8",
    )
    report = _audit(d, "--exceptions", str(exceptions))
    excepted = next(f for f in report["excepted"] if f["ruleId"] == "KN-S001")
    assert excepted["file"] == "b.yaml" and excepted["line"] == 11
