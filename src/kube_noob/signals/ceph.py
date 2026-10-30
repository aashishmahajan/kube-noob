"""Ceph health checks on Rook-Ceph and OpenShift Data Foundation: the catalogue (``kube_noob/data/ceph_health.yaml``),
the codes in ``ceph health detail``, ``ceph status`` and ``ceph health`` output (text and JSON) and in the CephCluster
status Rook writes, and the read-only advice ``diagnose`` and ``insight`` show for them.

Read-only by construction: every step is checked when the catalogue loads. A Kubernetes step must be a read
(``classify_step``) that touches no Secret; a Ceph step must match ``READ_ONLY_TOOLBOX`` and runs in the Rook toolbox,
which needs approval because it executes in a container. Commands that can lose data (declaring OSDs or objects lost,
purging or destroying OSDs, monitor map surgery, object store and CephFS recovery tools, forcing recovery, repairing
placement groups) are refused anywhere in the catalogue's text. A code whose usual fix risks data loss carries
``escalate``, and the answer then says to stop and involve storage support (``STOP``).

Formats, at the Ceph commit the catalogue cites: ``ceph health detail`` (HealthMonitor::get_health_status in
src/mon/HealthMonitor.cc) prints "[WRN] CODE: summary", possibly after "(MUTED ...)", with detail lines indented by four
spaces; ``ceph status`` (Monitor::get_cluster_status in src/mon/Monitor.cc) prints one summary per line under
"health:", and ``ceph health`` joins the summaries with "; ". Summaries name no code, so they are mapped through the
wording the source composes (each code's ``summary``), and only inside a health report. The JSON is
health_check_t::dump (src/mon/health_check.h) keyed by code under "checks": at the top of
``ceph health detail -f json``, under "health" in ``ceph status -f json``. Rook copies the same checks into the
CephCluster's status.ceph.details (pkg/apis/ceph.rook.io/v1/types.go, CephStatus).
"""

from __future__ import annotations

import functools
import re
from collections.abc import Sequence
from importlib import resources
from typing import TYPE_CHECKING, Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from kube_noob.debug.steps import classify_step

if TYPE_CHECKING:
    from kube_noob.signals.core import Signal

MAX_CHECKS = 200  # checks read from one JSON document
MAX_SCAN = 400_000  # characters of text looked at to decide whether it is Ceph health output
MAX_ENTRIES = 30  # codes explained in one answer
MAX_WORDS = 50  # code-shaped words read from one line

STOP = (
    "Stop and involve storage support (Red Hat support for OpenShift Data Foundation, your Ceph experts for Rook) "
    "before changing anything."
)
TOOLBOX = "deploy/rook-ceph-tools"
ODF_NAMESPACE = "openshift-storage"  # where ODF runs Ceph (ocs-operator localcephrules.yaml relabels to it)
ROOK_NAMESPACE = "rook-ceph"  # Rook's default (deploy/examples/toolbox.yaml)
# The CRUSH types a new cluster has (OSDMap::_build_crush_types, src/osd/OSDMap.cc): OSD_<TYPE>_DOWN names one.
CRUSH_TYPES = ("host", "chassis", "rack", "row", "pdu", "pod", "room", "datacenter", "zone", "region", "root")

CODE = re.compile(r"^[A-Z][A-Z0-9_]{2,63}\Z")
_ALERT = re.compile(r"^[A-Za-z][A-Za-z0-9_]{1,127}\Z")
_CITE = re.compile(r"^([a-z][a-z0-9]{1,15}):(\d{1,6})\Z")
_STEP_ID = re.compile(r"^[a-z][a-z0-9-]{1,40}\Z")
_COMMIT = re.compile(r"^[0-9a-f]{40}\Z")
_REPOSITORY = re.compile(r"^https://github\.com/[\w.-]{1,100}/[\w.-]{1,100}\Z")
_DATE = re.compile(r"^\d{4}-\d{2}-\d{2}\Z")
_PATH = re.compile(r"^[\w.-]{1,100}(?:/[\w.-]{1,100}){0,10}\Z")
_RUNBOOK = re.compile(r"^https://github\.com/openshift/runbooks/blob/master/alerts/[\w./-]{1,200}\.md\Z")

# Ceph commands that only read, in the forms the catalogue's toolbox steps use. Nothing that prints a key.
READ_ONLY_TOOLBOX = re.compile(
    r"^(?:ceph (?:health detail|status|versions|df detail|quorum_status|time-sync-status|mon dump|mgr module ls"
    r"|osd (?:tree|df|dump|perf|pool ls detail|pool autoscale-status|erasure-code-profile ls|find \S+|metadata \S+)"
    r"|pg (?:dump_stuck(?: (?:inactive|unclean|stale|undersized|degraded)){1,5}|ls inconsistent|\S+ query"
    r"|\S+ list_unfound)|crash (?:ls|ls-new|info \S+)|fs (?:status|dump)|tell mds\.\S+ damage ls"
    r"|device (?:ls|info \S+)|config (?:get \S+ \S+|show \S+))"
    r"|rados list-inconsistent-obj \S+ --format=json-pretty)\Z"
)
# Commands whose usual use can lose data, the cluster map or access. Refused anywhere in the catalogue.
_DESTRUCTIVE = re.compile(
    r"\bosd\s+(?:lost|purge|destroy|out|rm|crush\s+rm)\b|\bmark_unfound_lost\b|\bforce-(?:recovery|backfill|create-pg)\b"
    r"|\bceph-(?:objectstore|bluestore)-tool\b|\bceph-volume\s+lvm\s+zap\b|\bmon\s+(?:remove|rm)\b|\bmonmaptool\b"
    r"|\binject-monmap\b|\bcephfs-(?:journal|data|table)-(?:tool|scan)\b|\bfs\s+(?:reset|rm|fail)\b"
    r"|\bpool\s+(?:delete|rm)\b|\brados\s+(?:rm|purge)\b|\bauth\s+(?:rm|del)\b|\bwipe-rotating-service-keys\b"
    r"|\bset-(?:near|backfill)?full-ratio\b|\bpg\s+repair\b"
)
_SHELL = re.compile(r"[;&|`$\\]|\s#")
_SECRET = re.compile(r"(?i)\bsecrets?\b|\bauth\s+(?:ls|get|export|print-key)\b|\bconfig-key\b")

_PLACEHOLDERS = {
    "{n}": r"\d{1,9}",
    "{names}": r"[a-z0-9][a-z0-9,._-]{0,200}",
    "{is}": "(?:is|are)",
    "{has}": "(?:has|have)",
    "{s}": "s?",
    "{crush}": "(" + "|".join(CRUSH_TYPES) + ")",
    "{x}": r"'[^'\n]{1,100}'",
    "{flags}": r"[a-z_]{2,20}(?:,[a-z_]{2,20}){0,20}",
}


def _clean(text: str, where: str) -> str:
    if _DESTRUCTIVE.search(text):
        raise ValueError(f"{where}: names a command that can lose data: {text!r}")
    return text


class Step(BaseModel):
    """A read-only step: an ``oc`` read (kubectl on plain Kubernetes) or a Ceph command for the toolbox."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    run: str = Field(min_length=3, max_length=200)
    why: str = Field(min_length=3, max_length=300)
    platforms: list[Literal["openshift", "kubernetes"]] = []

    @field_validator("run")
    @classmethod
    def _read_only(cls, run: str) -> str:
        _clean(run, "step")
        if _SHELL.search(run) or _SECRET.search(run):
            raise ValueError(f"step must be one command that reads no Secret or key: {run!r}")
        if run.startswith(("ceph ", "rados ")):
            if not READ_ONLY_TOOLBOX.match(run):
                raise ValueError(f"Ceph step is not a known read-only command: {run!r}")
        elif not (run.startswith("oc ") and classify_step(run) == "read"):
            raise ValueError(f"step must be a read-only oc command: {run!r}")
        return run

    @field_validator("why")
    @classmethod
    def _why(cls, why: str) -> str:
        return _clean(why, "step why")


class Code(BaseModel):
    """One health check: what it means, its causes, its fix in words, its read-only steps, and why to escalate."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    code: str
    also: list[str] = []
    aliases: list[str] = []
    doc: str | None = None
    section: str | None = Field(None, max_length=120)
    src: list[str] = []
    summary: list[str] = []
    meaning: str = Field(min_length=10, max_length=240)
    causes: list[str] = Field(min_length=1, max_length=6)
    fix: str = Field(min_length=10, max_length=400)
    escalate: str | None = Field(None, min_length=10, max_length=400)
    steps: list[str] = Field(min_length=1, max_length=12)
    after: list[str] = []
    terms: list[str] = Field(min_length=1, max_length=8)

    @field_validator("code")
    @classmethod
    def _code(cls, value: str) -> str:
        if not CODE.match(value):
            raise ValueError(f"bad code {value!r}")
        return value

    @field_validator("also", "aliases", "after")
    @classmethod
    def _codes(cls, values: list[str]) -> list[str]:
        bad = [v for v in values if not CODE.match(v)]
        if bad:
            raise ValueError(f"bad code names {bad}")
        return values

    @field_validator("doc")
    @classmethod
    def _doc(cls, value: str | None) -> str | None:
        if value is not None and not _CITE.match(value):
            raise ValueError(f"bad citation {value!r}")
        return value

    @field_validator("src")
    @classmethod
    def _src(cls, values: list[str]) -> list[str]:
        bad = [v for v in values if not _CITE.match(v)]
        if bad:
            raise ValueError(f"bad citations {bad}")
        return values

    @field_validator("summary")
    @classmethod
    def _summary(cls, values: list[str]) -> list[str]:
        for s in values:
            unknown = set(re.findall(r"\{[a-z]+\}", s)) - set(_PLACEHOLDERS)
            if unknown or not 4 <= len(s) <= 120:
                raise ValueError(f"bad summary {s!r}")
        return values

    @model_validator(mode="after")
    def _texts(self) -> Code:
        for text in (self.meaning, self.fix, self.escalate or "", *self.causes, *self.summary):
            _clean(text, self.code)
        if not (self.doc or self.src):
            raise ValueError(f"{self.code}: no citation")
        return self


class Alert(BaseModel):
    """A Prometheus alert Rook or ODF ships, and the health codes it watches."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    alert: str
    rules: list[str] = Field(min_length=1, max_length=4)
    watches: list[str] = []
    how: Literal["health", "metric", "state"]
    expr: list[str] = []
    note: str | None = Field(None, min_length=10, max_length=400)
    steps: list[str] = []
    runbook: str | None = None

    @field_validator("alert")
    @classmethod
    def _name(cls, value: str) -> str:
        if not _ALERT.match(value):
            raise ValueError(f"bad alert name {value!r}")
        return value

    @field_validator("rules")
    @classmethod
    def _rules(cls, values: list[str]) -> list[str]:
        bad = [v for v in values if not (_CITE.match(v) and v.split(":")[0] in {"rook", "odf"})]
        if bad:
            raise ValueError(f"bad rule citations {bad}")
        return values

    @field_validator("runbook")
    @classmethod
    def _runbook(cls, value: str | None) -> str | None:
        if value is not None and not _RUNBOOK.match(value):
            raise ValueError(f"bad runbook {value!r}")
        return value

    @model_validator(mode="after")
    def _shape(self) -> Alert:
        _clean(self.note or "", self.alert)
        if self.how == "state" and (self.watches or not self.steps or not self.note):
            raise ValueError(f"{self.alert}: a state alert watches no code and needs a note and steps")
        if self.how != "state" and not self.watches:
            raise ValueError(f"{self.alert}: name the codes it watches")
        return self

    @property
    def shipped_by(self) -> set[str]:
        return {r.split(":")[0] for r in self.rules}


class Source(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    repository: str
    commit: str
    checked: str
    files: dict[str, str]

    @model_validator(mode="after")
    def _pinned(self) -> Source:
        if not (_REPOSITORY.match(self.repository) and _COMMIT.match(self.commit) and _DATE.match(self.checked)):
            raise ValueError(f"source needs a GitHub repository, a full commit and a date: {self.repository}")
        bad = [p for p in self.files.values() if not _PATH.match(p)]
        if bad:
            raise ValueError(f"bad file paths {bad}")
        return self


class Catalogue(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    version: Literal[1]
    sources: dict[str, Source]
    steps: dict[str, Step]
    codes: list[Code]
    alerts: list[Alert]

    @model_validator(mode="after")
    def _consistent(self) -> Catalogue:
        if set(self.sources) != {"ceph", "rook", "odf"}:
            raise ValueError("sources must be ceph, rook and odf")
        bad_ids = [s for s in self.steps if not _STEP_ID.match(s)]
        if bad_ids:
            raise ValueError(f"bad step ids {bad_ids}")
        names: list[str] = [n for c in self.codes for n in (c.code, *c.also, *c.aliases)]
        dupes = sorted({n for n in names if names.count(n) > 1})
        if dupes:
            raise ValueError(f"codes named twice: {dupes}")
        emitted = {n for c in self.codes for n in (c.code, *c.also)}
        files = self.sources["ceph"].files
        for c in self.codes:
            missing = [s for s in c.steps if s not in self.steps]
            unknown = [a for a in c.after if a not in emitted]
            cites = [x.split(":")[0] for x in ([c.doc] if c.doc else []) + c.src if x.split(":")[0] not in files]
            if missing or unknown or cites:
                raise ValueError(f"{c.code}: unknown steps {missing}, codes {unknown} or files {cites}")
        alerts = [a.alert for a in self.alerts]
        if len(alerts) != len(set(alerts)):
            raise ValueError("an alert is listed twice")
        for a in self.alerts:
            if set(a.watches) - emitted or set(a.steps) - set(self.steps):
                raise ValueError(f"{a.alert}: unknown codes or steps")
        return self


_LOADER: Any = getattr(yaml, "CSafeLoader", yaml.SafeLoader)  # libyaml when present: a tenth of the start-up time


@functools.cache
def catalogue() -> Catalogue:
    raw = resources.files("kube_noob").joinpath("data", "ceph_health.yaml").read_text(encoding="utf-8")
    try:
        data = yaml.load(raw, Loader=_LOADER)  # noqa: S506 - a safe loader, bundled data
    except yaml.YAMLError:
        # libyaml and PyYAML's own scanner do not agree on every document, and this catalogue is bundled data that
        # every install parses: `diagnose` and `known_issues` both reach it through signals.catalogue. One such
        # disagreement (an unquoted colon in a flow sequence, which the libyaml in the browser runtime refuses) broke
        # both tools after 0.7.0, so the file is now kept free of them by
        # tests/test_distribution.py::test_bundled_yaml_parses_under_every_yaml_parser -- and if a stricter parser
        # still objects to something, the tools keep working on the scanner that ships with PyYAML rather than
        # raising. No fallback for a file this is not: the data is ours, and a parse failure here is a bug in it.
        if _LOADER is yaml.SafeLoader:
            raise
        data = yaml.load(raw, Loader=yaml.SafeLoader)
    return Catalogue.model_validate(data)


@functools.cache
def _index() -> tuple[dict[str, Code], dict[str, str], dict[str, Alert]]:
    by_name: dict[str, Code] = {}
    aliases: dict[str, str] = {}
    for c in catalogue().codes:
        for name in (c.code, *c.also):
            by_name[name] = c
        for name in c.aliases:
            aliases[name] = c.code
    return by_name, aliases, {a.alert: a for a in catalogue().alerts}


def canonical(name: str) -> str | None:
    """The code Ceph emits for ``name``: itself when catalogued, the code for a documented or alert-rule alias
    (MDS_HEALTH_READ_ONLY is MDS_READ_ONLY), else None."""
    by_name, aliases, _ = _index()
    return name if name in by_name else aliases.get(name)


def entry(name: str) -> Code | None:
    by_name, _, _ = _index()
    code = canonical(name)
    return by_name[code] if code else None


def alert(name: str) -> Alert | None:
    return _index()[2].get(name)


def code_names() -> list[str]:
    """Every emitted code the catalogue covers (family members and _MANY variants included)."""
    return sorted(_index()[0])


def _url(source: str, key: str, line: str) -> str:
    s = catalogue().sources[source]
    return f"{s.repository}/blob/{s.commit}/{s.files[key]}#L{line}"


def citations(c: Code) -> list[str]:
    """The Ceph doc section and the source lines for a code, at the catalogue's commit."""
    return [_url("ceph", *cite.split(":")) for cite in ([c.doc] if c.doc else []) + c.src]


def anchor(c: Code) -> str | None:
    """The documentation anchor of the code's section (docutils ids: lower case, other characters to hyphens)."""
    if not c.doc:
        return None
    return re.sub(r"[^a-z0-9]+", "-", (c.section or c.code).lower()).strip("-")


def alert_sources(a: Alert) -> list[str]:
    return [_url(r.split(":")[0], "rules", r.split(":")[1]) for r in a.rules]


# --- recognition ------------------------------------------------------------------------------------------------
_BRACKET = re.compile(r"^[ \t]{0,8}(\(MUTED[^)\n]{0,80}\)[ \t]{0,4})?\[(WRN|ERR)\][ \t]{1,4}([A-Z][A-Z0-9_]{2,63}):")
_STATUS_HEALTH = re.compile(r"^[ \t]{0,8}health:[ \t]{1,8}HEALTH_(?:OK|WARN|ERR)[ \t]*\Z")
_STATUS_LINE = re.compile(r"^[ \t]{8,40}(\S[^\n]{0,400})")
_ONE_LINE = re.compile(r"^[ \t]{0,8}HEALTH_(?:WARN|ERR)[ \t]{1,4}(\S[^\n]{0,4000})")
_WORD = re.compile(r"(?<![A-Za-z0-9_])[A-Z][A-Z0-9]{1,20}(?:_[A-Z0-9]{1,30}){1,8}(?![A-Za-z0-9_])")
_REPORT = re.compile(r"\bHEALTH_(?:WARN|ERR)\b")
# Words that say the text is about Ceph; a code named in prose without them counts only when its own name does.
_CEPH_CONTEXT = re.compile(
    r"(?i)ceph|\brook\b|\bodf\b|openshift data foundation|openshift-storage|\bHEALTH_[A-Z]{2,4}\b"
)
_CEPH_TOKENS = frozenset(
    {"OSD", "OSDS", "OSDMAP", "PG", "PGS", "PGP", "MON", "MONS", "MDS", "MGR", "BLUESTORE", "BLUEFS", "OMAP", "CRUSH"}
)
_RANK = {"bracket": 0, "summary": 1, "word": 2}


@functools.cache
def _summaries() -> tuple[tuple[re.Pattern[str], str], ...]:
    out: list[tuple[re.Pattern[str], str]] = []
    for c in catalogue().codes:
        for s in c.summary:
            parts = re.split(r"(\{[a-z]+\})", s)
            out.append((re.compile("".join(_PLACEHOLDERS.get(p, re.escape(p)) for p in parts)), c.code))
    return tuple(out)


def _summary_code(text: str) -> str | None:
    for rx, code in _summaries():
        m = rx.match(text)
        if m:
            return f"OSD_{m.group(1).upper()}_DOWN" if m.groups() else code
    return None


def text_signals(text: str, max_lines: int = 20_000, max_line: int = 4_000) -> list[tuple[str, str, int]]:
    """The codes in ``text`` as (code, detail, line number), one per code, sorted. ``[WRN] CODE:`` lines name any code
    (catalogued or not) with its severity; summaries in a health report and catalogued codes named as words map to
    catalogued codes only. The first, most exact sighting of a code wins."""
    best: dict[str, tuple[int, str, int]] = {}

    def keep(code: str, how: str, detail: str, n: int) -> None:
        rank = _RANK[how]
        if code not in best or rank < best[code][0]:
            best[code] = (rank, detail[:280], n)

    report = bool(_REPORT.search(text[:200_000]))
    context = bool(_CEPH_CONTEXT.search(text[:200_000]))
    in_status = False
    for n, raw in enumerate(text.splitlines()[:max_lines], 1):
        line = raw[:max_line]
        m = _BRACKET.match(line)
        if m:
            severity = "HEALTH_WARN" if m.group(2) == "WRN" else "HEALTH_ERR"
            code = canonical(m.group(3)) or m.group(3)
            muted = " (muted)" if m.group(1) else ""
            keep(code, "bracket", f"{severity} {line[m.end() :].strip()}{muted}", n)
            in_status = False
            continue
        if report:
            if _STATUS_HEALTH.match(line):
                in_status = True
                continue
            status = _STATUS_LINE.match(line) if in_status else None
            in_status = status is not None
            pieces = [status.group(1)] if status else []
            if not status and (one := _ONE_LINE.match(line)):
                pieces = one.group(1).split("; ")[:50]
            for piece in pieces:
                code = _summary_code(piece)
                if code:
                    keep(code, "summary", piece.strip(), n)
        if "_" in line:
            for word in _WORD.findall(line)[:MAX_WORDS]:
                code = canonical(word)
                if code and (context or _CEPH_TOKENS & set(word.split("_"))):
                    keep(code, "word", "" if code == word else f"written as {word}", n)
    return sorted((code, detail, n) for code, (_, detail, n) in best.items())


def looks_like_health_output(text: str) -> str | None:
    """What makes ``text`` Ceph health output (for the insight recogniser), or None: a ``[WRN] CODE:`` line, the health
    section of ``ceph status``, or a ``ceph health`` line whose summaries are Ceph's wording."""
    for raw in text.splitlines()[:20_000]:
        line = raw[:4_000]
        if _BRACKET.match(line):
            return "ceph health detail output"
        if _STATUS_HEALTH.match(line):
            return "ceph status output"
        one = _ONE_LINE.match(line)
        if one and any(_summary_code(p) for p in one.group(1).split("; ")[:50]):
            return "ceph health output"
    return None


def json_checks(doc: dict[str, Any]) -> list[tuple[str, str, str]] | None:
    """The codes in a parsed Ceph or Rook document as (code, detail, path), or None when it is neither: ``ceph health
    detail -f json`` (status and checks), ``ceph status -f json`` (health.checks), a CephCluster
    (status.ceph.details) or that details map alone, as ``-o jsonpath='{.status.ceph.details}'`` prints it. Keys that
    are not code-shaped and values that are not objects are skipped."""
    if doc.get("kind") == "CephCluster":
        status = doc.get("status")
        ceph = status.get("ceph") if isinstance(status, dict) else None
        checks = ceph.get("details") if isinstance(ceph, dict) else None
        where = "status.ceph.details"
        if not isinstance(checks, dict):
            return []
    else:
        checks, where, overall = doc.get("checks"), "checks", doc.get("status")
        health = doc.get("health")
        if not isinstance(checks, dict) and isinstance(health, dict):
            checks, where, overall = health.get("checks"), "health.checks", health.get("status")
        if not isinstance(checks, dict) and doc and all(isinstance(k, str) and CODE.match(k) for k in list(doc)[:50]):
            checks, where, overall = doc, "details", None  # the CephCluster's details map on its own (jsonpath)
        if not isinstance(checks, dict):
            return None
        shaped = any(isinstance(v, dict) and "severity" in v for v in list(checks.values())[:MAX_CHECKS])
        if not (shaped or (isinstance(overall, str) and overall.startswith("HEALTH_"))):
            return None
    out: list[tuple[str, str, str]] = []
    for name, value in list(checks.items())[:MAX_CHECKS]:
        if not (isinstance(name, str) and CODE.match(name) and isinstance(value, dict)):
            continue
        severity = value.get("severity")
        summary = value.get("summary")
        message = summary.get("message") if isinstance(summary, dict) else value.get("message")
        parts = [p for p in (severity, message) if isinstance(p, str) and p]
        detail = " ".join(parts)[:260] + (" (muted)" if value.get("muted") is True else "")
        out.append((canonical(name) or name, detail, f"{where}.{name}"))
    return out


# --- advice -----------------------------------------------------------------------------------------------------
_OSD_ID = re.compile(r"(?<![\w.-])osd\.(\d{1,6})(?=[\s,:)\]]|\Z)")
_PG_ID = re.compile(r"(?<![\w.-])pg (\d{1,6}\.[0-9a-f]{1,8})(?=[\s,:)\]]|\Z)")
_MON_ID = re.compile(r"(?<![\w.-])mon\.([a-z]{1,4})(?=[\s,:)\]]|\Z)")
_SAFE = {
    "osd": re.compile(r"^\d{1,6}\Z"),
    "pg": re.compile(r"^\d{1,6}\.[0-9a-f]{1,8}\Z"),
    "mon": re.compile(r"^[a-z]{1,4}\Z"),
}
_PLACEHOLDER = {"osd": "<osd-id>", "pg": "<pgid>", "mon": "<mon>"}
_ROOK_NS_TEXT = re.compile(r"(?:-n[ =]|--namespace[ =]|namespace:?[ \t]{0,4}\"?)rook-ceph\b")
_SEVERITY = {"HEALTH_ERR": 0, "HEALTH_WARN": 1}


def _context(text: str) -> dict[str, str]:
    """The OSD, placement group and monitor the input names first, when each passes its validator."""
    out: dict[str, str] = {}
    for key, rx in (("osd", _OSD_ID), ("pg", _PG_ID), ("mon", _MON_ID)):
        m = rx.search(text[:400_000])
        if m and _SAFE[key].match(m.group(1)):
            out[key] = m.group(1)
    return out


def _severity(detail: str) -> str | None:
    head = detail.split(" ", 1)[0]
    return head if head in _SEVERITY else None


def _order(codes: dict[str, str | None]) -> list[str]:
    """Errors before warnings, then by name; a code comes after the codes present that usually cause it."""
    pending = sorted(codes, key=lambda c: (_SEVERITY.get(codes[c] or "", 2), c))

    def waits(code: str) -> bool:
        c = entry(code)
        return c is not None and any(a in pending and a != code for a in c.after)

    out: list[str] = []
    while pending:
        ready = next((c for c in pending if not waits(c)), pending[0])
        out.append(ready)
        pending.remove(ready)
    return out


class _Renderer:
    def __init__(self, text: str, platform: str | None, openshift: bool, odf_only: bool) -> None:
        from kube_noob.catalog import OPENSHIFT_FAMILY

        self.on_openshift = platform in OPENSHIFT_FAMILY if platform else (openshift or odf_only)
        self.platform = platform or ("openshift" if self.on_openshift else "kubernetes")
        rook_named = bool(_ROOK_NS_TEXT.search(text[:200_000]))
        odf_named = ODF_NAMESPACE in text[:400_000]
        self.namespace = ODF_NAMESPACE if odf_named or (self.on_openshift and not rook_named) else ROOK_NAMESPACE
        self.context = _context(text)

    def step(self, sid: str) -> tuple[str, dict[str, Any]] | None:
        from kube_noob.debug.diagnose import _for_platform

        st = catalogue().steps[sid]
        if st.platforms and ("openshift" if self.on_openshift else "kubernetes") not in st.platforms:
            return None
        cmd = st.run.replace("{ns}", self.namespace)
        for key, default in _PLACEHOLDER.items():
            cmd = cmd.replace("{" + key + "}", self.context.get(key, default))
        if st.run.startswith(("ceph ", "rados ")):
            cmd = f"oc exec -n {self.namespace} {TOOLBOX} -- {cmd}"
        rendered = _for_platform(cmd, self.platform)
        if rendered is None:
            return None
        kind = classify_step(rendered)
        if kind == "change":  # never: the catalogue only holds reads; kept as a last guard
            return None
        step: dict[str, Any] = {"command": rendered, "why": st.why}
        if kind == "exec":
            step["requiresApproval"] = True
        return kind, step

    def steps(self, ids: Sequence[str], skip: set[str]) -> dict[str, list[dict[str, Any]]]:
        out: dict[str, list[dict[str, Any]]] = {"readOnlyNextSteps": [], "diagnosticCommands": []}
        for sid in ids:
            if sid in skip:
                continue
            done = self.step(sid)
            if done:
                out["readOnlyNextSteps" if done[0] == "read" else "diagnosticCommands"].append(done[1])
        return out


COMMON_STEPS = ("cephcluster-health", "storagecluster", "health")


def advice(
    signals: Sequence[Signal], text: str, platform: str | None = None, openshift: bool = False
) -> dict[str, Any] | None:
    """What the Ceph health codes and the Rook or ODF alerts among ``signals`` mean, with read-only steps for the
    platform: oc and openshift-storage for OpenShift Data Foundation, kubectl and rook-ceph for Rook on Kubernetes.
    ``openshift`` says the text is about OpenShift when no platform is given; an alert only ODF ships says so too.
    None when no signal is a Ceph code or a catalogued alert."""
    codes: dict[str, str | None] = {}
    seen_as: dict[str, str] = {}
    unknown: list[str] = []
    fired: list[Alert] = []
    for s in signals:
        if s.kind == "alert" and (a := alert(s.name)) is not None and a not in fired:
            fired.append(a)
        if s.kind != "ceph_health":
            continue
        code = canonical(s.name)
        if code is None:
            if s.name not in unknown:
                unknown.append(s.name)
        elif code not in codes or (codes[code] is None and _severity(s.detail)):
            codes[code] = _severity(s.detail)
            if s.detail.startswith("written as "):
                seen_as[code] = s.detail.removeprefix("written as ")
    if not (codes or fired or unknown):
        return None
    r = _Renderer(text, platform, openshift, any(a.shipped_by == {"odf"} for a in fired))
    common = r.steps(COMMON_STEPS, set())
    entries: list[dict[str, Any]] = []
    stop = False
    for code in _order(codes)[:MAX_ENTRIES]:
        c = entry(code)
        if c is None:
            continue
        item: dict[str, Any] = {"code": code, "severity": codes[code]}
        if code in seen_as:
            item["seenAs"] = seen_as[code]
        item |= {"meaning": c.meaning, "likelyCauses": list(c.causes), "fix": c.fix}
        if c.escalate:
            item["escalate"] = f"{STOP} {c.escalate}"
            stop = True
        item |= r.steps(c.steps, set(COMMON_STEPS))
        watching = [a for a in fired if code in a.watches]
        if watching:
            item["alerts"] = [_alert_ref(a) for a in watching]
        item["source"] = citations(c)
        if anchor(c):
            item["section"] = anchor(c)
        entries.append(item)
    states = [
        {"alert": a.alert, "meaning": a.note, **_runbook(a), **r.steps(a.steps, set()), "source": alert_sources(a)}
        for a in fired
        if a.how == "state"
    ]
    note = (
        f"The ceph commands run in the Rook toolbox ({TOOLBOX} in {r.namespace}) and need approval because they "
        "execute in a container."
    )
    if r.on_openshift:
        note += (
            " On OpenShift Data Foundation the toolbox exists only when the StorageCluster sets enableCephTools (off "
            "by default; turning it on is a change that needs approval). The CephCluster status shows the same codes "
            "without it."
        )
    out: dict[str, Any] = {
        "platform": "openshift" if r.on_openshift else "kubernetes",
        "namespace": r.namespace,
        "note": note,
        **({"stop": STOP} if stop else {}),
        **common,
        "entries": entries,
        "alerts": states,
        "notCatalogued": sorted(unknown),
    }
    return out


def _runbook(a: Alert) -> dict[str, str]:
    return {"runbook": a.runbook} if a.runbook else {}


def _alert_ref(a: Alert) -> dict[str, Any]:
    out: dict[str, Any] = {"alert": a.alert, "how": a.how, **_runbook(a)}
    if a.note:
        out["note"] = a.note
    return out
