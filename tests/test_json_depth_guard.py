"""The nesting guard has to reach every parser that reads an untrusted file, not only the pasted-text paths.

`sanitize.json_nesting_ok` was added because `json.loads` recurses and what stops it differs by interpreter: up to
CPython 3.13 a deep document raises `RecursionError`, which these parsers catch; from 3.14 it is parsed instead. It
was wired into the paste paths (`rest`, `insight`, `alertmanager`, `problems`) and not into the three parsers that
read scanner output and ticket exports, so on 3.14 those three stopped refusing a bracket bomb -- and one of them
stopped refusing it at all, reporting zero tickets imported from a file it could not read.

From 3.14 it is worse than "differs by interpreter": `sys.getrecursionlimit()` no longer bounds `json.loads`, so
the depth at which it gives up is whatever C stack the process has -- measured, 10 000 levels parse on 3.14.6 at
the default limit of 1000 -- and `yaml.CSafeLoader` segfaults rather than raising, on 3.13 already. There is no
depth a handler can be written against, so the depth is counted before anything recurses.

These tests assert the refusal itself, never a particular interpreter's error message, so they hold on every
version; and the frozen inventory at the end keeps a new raw loader from landing unnoticed.
"""

from __future__ import annotations

import json
import pathlib
import re

import pytest

from kube_noob import sanitize
from kube_noob.code import sarif
from kube_noob.memory import importers
from kube_noob.sanitize import MAX_JSON_DEPTH, MAX_JSON_DEPTH_FILE
from kube_noob.vuln import reports

ROOT = pathlib.Path(__file__).resolve().parent.parent

BOMB = "[" * 100_000 + "]" * 100_000
# Just past each ceiling, so the guard and not a byte limit is what refuses it. Files get the higher one, because
# a scanner's nested components are a dependency tree and the parsers bound their own walk instead of refusing.
DEEP_FILE = "[" * (MAX_JSON_DEPTH_FILE + 1) + "]" * (MAX_JSON_DEPTH_FILE + 1)
DEEP_PASTE = "[" * (MAX_JSON_DEPTH + 1) + "]" * (MAX_JSON_DEPTH + 1)


def test_a_sarif_file_nested_past_the_limit_is_refused_as_too_deep() -> None:
    for payload in (BOMB, DEEP_FILE):
        with pytest.raises(sarif.SarifError, match="nested too deeply"):
            sarif.parse(payload, "t")
        with pytest.raises(sarif.SarifError, match="nested too deeply"):
            sarif.parse(payload.encode(), "t")


def test_a_scanner_report_nested_past_the_limit_is_refused_as_too_deep() -> None:
    for payload in (BOMB, DEEP_FILE):
        with pytest.raises(reports.ReportError, match="nested too deeply"):
            reports.parse(payload)
        with pytest.raises(reports.ReportError, match="nested too deeply"):
            reports.parse(payload.encode())


def test_a_ticket_export_nested_past_the_limit_is_refused_rather_than_read_as_empty() -> None:
    """The one that was not merely a different message: `issues = doc` accepted the outer list, every element
    failed the dict check, and `parse` returned [] -- so `memory import` reported zero tickets imported from a file
    it had not read. An unreadable export has to raise."""
    for fmt in ("jira-json", "servicenow-json"):
        for payload in (BOMB, DEEP_FILE):
            with pytest.raises(importers.TicketImportError, match="nested too deeply"):
                importers.parse(fmt, payload)


def test_a_document_just_inside_the_limit_is_still_read() -> None:
    """The guard refuses past the limit, not at it. A real payload nests under ten deep, so a document that sits
    just inside the ceiling has to keep parsing -- otherwise the fix for the bomb breaks every ordinary report."""
    nested: object = []
    for _ in range(MAX_JSON_DEPTH_FILE - 4):  # the wrapper object and runs array take the rest
        nested = [nested]
    doc = {"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "x"}}, "results": []}], "properties": nested}
    text = json.dumps(doc)
    assert sanitize.json_nesting_ok(text, MAX_JSON_DEPTH_FILE) is True
    assert sarif.parse(text, "t", max_depth=MAX_JSON_DEPTH_FILE).tools == ["x"]


BASELINE = ROOT / "tests" / "fixtures" / "raw_parser_baseline.json"
_RAW = re.compile(
    r"\b(json\.loads?|json\.JSONDecoder|yaml\.safe_load_all|yaml\.safe_load|yaml\.load_all|yaml\.load)\s*\("
)


def _raw_parser_counts() -> dict[str, int]:
    """Raw loader calls per module, excluding `sanitize` itself, which implements the bounded ones."""
    out: dict[str, int] = {}
    src = ROOT / "src" / "kube_noob"
    for path in sorted(src.rglob("*.py")):
        rel = str(path.relative_to(src))
        if rel == "sanitize.py":
            continue
        found = len(_RAW.findall(path.read_text()))
        if found:
            out[rel] = found
    return out


def test_no_module_gains_a_raw_json_or_yaml_loader() -> None:
    """A frozen inventory of every unbounded `json.loads` / `yaml.safe_load` left in the tree.

    This test does NOT claim the listed calls are safe. It claims only that the list may shrink and never grow:
    `json.loads` and `yaml.safe_load` both recurse, and from Python 3.14 the depth at which `json.loads` gives up
    is whatever C stack the process has, while `yaml.CSafeLoader` segfaults outright. So a new raw call is a new
    place where the refusal depends on the machine, and it has to be a deliberate, reviewed act rather than
    something that lands unnoticed.

    An earlier version of this test matched only `doc|raw_doc|payload = json.loads(` and so could see 1 of 54
    sites while its name promised all of them -- which is G147: a test that polices a rule is itself a claim, and
    it is checked by trying to evade it.

    Adding a bounded call (`sanitize.loads_bounded`, `sanitize.safe_load_bounded`) never trips this. Converting a
    raw call to a bounded one lowers a count, and the baseline is then updated down.
    """
    baseline = json.loads(BASELINE.read_text())
    now = _raw_parser_counts()
    grew = {f: (baseline.get(f, 0), n) for f, n in now.items() if n > baseline.get(f, 0)}
    assert not grew, (
        "a raw json.loads/yaml.safe_load was added where the refusal depth depends on the machine: "
        + ", ".join(f"{f} {was} -> {is_}" for f, (was, is_) in sorted(grew.items()))
        + ". Use sanitize.loads_bounded / sanitize.safe_load_bounded, or update the baseline deliberately."
    )
    shrank = {f: (baseline[f], now.get(f, 0)) for f in baseline if now.get(f, 0) < baseline[f]}
    assert not shrank, (
        "raw loaders were removed, which is the point -- lower the baseline in "
        "tests/fixtures/raw_parser_baseline.json to lock the gain in: "
        + ", ".join(f"{f} {was} -> {is_}" for f, (was, is_) in sorted(shrank.items()))
    )


def test_the_bounded_loaders_are_actually_used_by_the_parsers_that_take_untrusted_input() -> None:
    """The positive half: the readers this change was written for must name a bounded loader. Without this, the
    frozen baseline above could be satisfied by deleting a parser rather than guarding it."""
    src = ROOT / "src" / "kube_noob"
    for rel in (
        "code/sarif.py",
        "vuln/reports.py",
        "vuln/kev.py",
        "vuln/vex.py",
        "memory/importers.py",
        "rhacs.py",
        "admission.py",
        "audit/exceptions.py",
        "gate.py",
        "build/containerfile.py",
        "code/ship.py",
    ):
        text = (src / rel).read_text()
        assert "sanitize.loads_bounded" in text or "sanitize.safe_load" in text, rel


def test_a_string_argument_gets_the_tight_ceiling_and_a_file_read_the_loose_one() -> None:
    """The split only means anything if it falls where input arrives. `parse()` defaults to the tight ceiling
    because a string argument is a paste until proven otherwise; the callers that read a path ask for the loose
    one. Before this, the defaults were the other way round and a 503-deep SARIF pasted over MCP was accepted."""
    import inspect

    for mod, fn in ((sarif, "parse"), (reports, "parse")):
        sig = inspect.signature(getattr(mod, fn))
        assert sig.parameters["max_depth"].default == MAX_JSON_DEPTH, f"{mod.__name__}.{fn} defaults loose"
    deep = "[" * (MAX_JSON_DEPTH + 1) + "]" * (MAX_JSON_DEPTH + 1)
    with pytest.raises(sarif.SarifError, match="nested too deeply"):
        sarif.parse(deep, "pasted")
    # the same text with the file ceiling is a parse error about its shape, not a depth refusal
    with pytest.raises(sarif.SarifError, match="not SARIF"):
        sarif.parse(deep, "from a file", max_depth=MAX_JSON_DEPTH_FILE)


def test_the_shared_server_refuses_a_deep_rhacs_policy_export() -> None:
    """`rhacs_compare` is read_only, so it is offered by the shared HTTP server, and it had no depth count at all.
    On 3.13 it survived only because CPython raised `RecursionError`, which it caught and relabelled "not JSON"."""
    from kube_noob import rhacs

    with pytest.raises(rhacs.RhacsError):
        rhacs.load(BOMB)
    assert sanitize.json_nesting_ok(BOMB) is False


def test_a_deep_exception_list_is_refused_rather_than_crashing_the_tool() -> None:
    """YAML, pasted, on a tool the browser playground offers. `yaml.YAMLError` is not a `ValueError`, so catching
    only it let a `RecursionError` out of the tool -- and `yaml.CSafeLoader` segfaults rather than raising."""
    from kube_noob.audit import exceptions as exc

    deep = "apiVersion: kube-noob.io/v1\nkind: ExceptionList\nexceptions: " + "[" * 20_000 + "]" * 20_000
    with pytest.raises(exc.ExceptionsError, match="nested too deeply"):
        exc.review(deep)


def test_a_deep_json_array_inside_a_pasted_containerfile_does_not_escape() -> None:
    """`COPY ["a","b"]` is read as JSON, so a pasted Containerfile could carry a bomb into `containerfile_audit`
    and the `RecursionError` left the tool uncaught."""
    from kube_noob.build import containerfile as cf

    body = "FROM registry.access.redhat.com/ubi9:latest\nCOPY " + "[" * 20_000 + "]" * 20_000 + " /app\n"
    report = cf.audit(body)  # must return a report, not raise
    assert report is not None


def test_gate_reports_a_deep_manifest_instead_of_crashing() -> None:
    """`gate` read operator-supplied YAML with `except yaml.YAMLError` only, so a deep file ended the command
    rather than being reported against the path it came from."""
    from kube_noob import gate

    deep = "a: " + "[" * 20_000 + "]" * 20_000
    reason = gate.unreadable_reason(deep)
    assert reason is not None and "deep" in reason.lower(), reason
