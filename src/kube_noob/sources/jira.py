"""Jira Cloud ingestion with paced, rate-limit-aware pulls of Red Hat's public Jira (redhat.atlassian.net).

* Supported interfaces only: projects from ``/rest/api/3/project/search`` and issues from the enhanced search API
  ``/rest/api/3/search/jql`` with ``nextPageToken`` pagination. Atlassian's Acceptable Use Policy forbids reaching the
  service "by any means other than our publicly supported interfaces" (scraping is its example), so the web pages
  (``/jira/projects?page=N``) are never fetched.
* Polite by design: one request at a time, at least ``CRAWL_DELAY`` seconds apart (the site's robots.txt asks every
  crawler for one second) plus random jitter, exponential backoff with full jitter on 429/5xx, ``Retry-After``
  honoured, and a request budget per run so a sync never turns into a flood.
* ``sync_project`` keeps a local copy of every issue in a project, whatever its status or resolution: changes since
  the last run first, then older issues by key until the project is complete. ``pull_project`` is the older
  version-filtered pull (RHACS 4.10+).
* Privacy: reporter/assignee/author identities are never stored; emails and account ids are scrubbed from text;
  @mentions become ``@user``.
* Records are marked ``redistributable: false`` - public visibility is not a redistribution license. They stay in the
  local data folder of the install that pulled them; packages, plugins and dataset exports never include them.
"""

from __future__ import annotations

import contextlib
import json
import os
import random
import re
import tempfile
import time
from collections import Counter
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx

from kube_noob.errors import KubeNoobError
from kube_noob.jira_catalog import (  # noqa: F401 - re-exported for callers of the sync
    DEFAULT_BASE_URL,
    DEFAULT_PROJECTS,
    ISSUE_KEY,
    PROJECT_KEY,
    parse_version,
    product_of,
)

DEFAULT_FIELDS = (
    "summary,description,issuetype,status,priority,resolution,labels,components,fixVersions,versions,"
    "created,updated,resolutiondate,comment,parent"
)
SYNC_FIELDS = DEFAULT_FIELDS + ",issuelinks"
# Red Hat's Jira Cloud exposes "Target Version" as customfield_10855 (verified on ROX-36348, 2026-10-27).
DEFAULT_TARGET_FIELD = "customfield_10855"
_NON_PRODUCT_HINT = re.compile(r"(?i)\b(ocp|openshift|k8s|kubernetes|rhel|go|golang|python|node|helm|java|ubi)\b")
_EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
_ACCOUNT = re.compile(r"\[~accountid:[^\]]+\]|accountId[\"=:]\s*\"?[0-9a-f:-]{10,}\"?", re.IGNORECASE)
MAX_COMMENTS = 20
MAX_TEXT = 20_000
SYNC_MAX_TEXT = 12_000  # per issue in a full-project copy: description and the latest comments carry the signal
LONG_JQL = 1500  # characters; above this the search request is sent as POST
MAX_RETRY_AFTER = 120.0  # seconds; a larger Retry-After is capped so a pull cannot hang for hours
CRAWL_DELAY = 1.0  # robots.txt on redhat.atlassian.net: "Crawl-delay: 1" for every crawler (checked 2026-10-28)
OVERLAP_MINUTES = 10  # forward syncs reach this far before the last run, so clock skew cannot lose an update


class JiraError(KubeNoobError):
    pass


class BudgetExhausted(JiraError):
    """The run's request budget is spent; the sync stops cleanly and resumes next time."""


def scrub(text: str) -> str:
    text = _EMAIL.sub("<email>", text)
    return _ACCOUNT.sub("<account>", text)


def adf_to_text(node: Any) -> str:
    """Atlassian Document Format -> plain text (Markdown-ish)."""
    if node is None:
        return ""
    if isinstance(node, str):
        return node
    if isinstance(node, list):
        return "".join(adf_to_text(n) for n in node)
    if not isinstance(node, dict):
        return ""
    t = node.get("type")
    content = node.get("content") or []
    if t == "text":
        return str(node.get("text", ""))
    if t == "hardBreak":
        return "\n"
    if t == "mention":
        return "@user"
    if t == "emoji":
        return str((node.get("attrs") or {}).get("text", ""))
    if t in {"inlineCard", "blockCard", "embedCard"}:
        return str((node.get("attrs") or {}).get("url", ""))
    if t == "paragraph":
        return adf_to_text(content) + "\n\n"
    if t == "heading":
        level = int((node.get("attrs") or {}).get("level", 2))
        return "#" * min(max(level, 1), 6) + " " + adf_to_text(content) + "\n\n"
    if t == "codeBlock":
        return "```\n" + adf_to_text(content) + "\n```\n\n"
    if t == "blockquote":
        return "".join("> " + ln + "\n" for ln in adf_to_text(content).strip().splitlines()) + "\n"
    if t in {"bulletList", "orderedList"}:
        items = []
        for i, li in enumerate(content):
            prefix = f"{i + 1}. " if t == "orderedList" else "- "
            items.append(prefix + adf_to_text(li).strip().replace("\n\n", "\n"))
        return "\n".join(items) + "\n\n"
    if t == "listItem":
        return adf_to_text(content)
    if t == "table":
        rows = []
        for row in content:
            cells = [adf_to_text(c).strip().replace("\n", " ") for c in (row.get("content") or [])]
            rows.append("| " + " | ".join(cells) + " |")
        return "\n".join(rows) + "\n\n"
    return adf_to_text(content)


@dataclass
class PullStats:
    requests: int = 0
    retries: int = 0
    pages: int = 0
    scanned: int = 0
    kept: int = 0
    strategy: str = ""
    errors: list[str] = field(default_factory=list)


class JiraClient:
    def __init__(
        self,
        client: httpx.Client,
        base_url: str,
        *,
        min_delay: float = CRAWL_DELAY,
        jitter: float = 1.0,
        max_retries: int = 6,
        sleep: Callable[[float], None] = time.sleep,
        rng: random.Random | None = None,
        auth: tuple[str, str] | None = None,
        max_requests: int | None = None,
    ) -> None:
        if auth is not None and not base_url.startswith("https://"):
            raise JiraError("Jira credentials are only sent over https; use an https:// base URL")
        self.http = client
        self.auth = httpx.BasicAuth(*auth) if auth else None
        self.base = base_url.rstrip("/")
        self.min_delay = max(min_delay, CRAWL_DELAY)  # never faster than the site's robots.txt asks
        self.jitter = max(jitter, 0.0)
        self.max_retries = max_retries
        self.sleep = sleep
        self.rng = rng or random.Random()  # noqa: S311 - jitter, not crypto
        self.max_requests = max_requests
        self.stats = PullStats()

    def _pause(self) -> None:
        self.sleep(self.min_delay + self.rng.random() * self.jitter)

    @property
    def remaining(self) -> int | None:
        return None if self.max_requests is None else max(0, self.max_requests - self.stats.requests)

    def get(self, path: str, params: dict[str, Any] | None = None) -> Any:
        return self._request("GET", path, params=params)

    def post(self, path: str, body: dict[str, Any]) -> Any:
        return self._request("POST", path, body=body)

    def _request(
        self, method: str, path: str, params: dict[str, Any] | None = None, body: dict[str, Any] | None = None
    ) -> Any:
        url = f"{self.base}{path}"
        headers = {"Accept": "application/json"}
        if self.stats.requests:
            self._pause()  # every request after the first waits at least CRAWL_DELAY
        for attempt in range(self.max_retries + 1):
            if self.max_requests is not None and self.stats.requests >= self.max_requests:
                raise BudgetExhausted(f"request budget of {self.max_requests} spent")
            self.stats.requests += 1
            try:
                if method == "POST":
                    resp = self.http.post(
                        url, json=body, headers={**headers, "Content-Type": "application/json"}, auth=self._auth()
                    )
                else:
                    resp = self.http.get(url, params=params, headers=headers, auth=self._auth())
            except httpx.TransportError as exc:
                if attempt == self.max_retries:
                    raise JiraError(f"{method} {path} failed: {exc}") from exc
                self._backoff(attempt, None)
                continue
            if resp.status_code == 200:
                return resp.json()
            if resp.status_code in {429, 500, 502, 503, 504} and attempt < self.max_retries:
                self._backoff(attempt, resp.headers.get("Retry-After"))
                continue
            if resp.status_code in {401, 403}:
                raise JiraError(
                    f"{method} {path}: HTTP {resp.status_code}. The project may not allow anonymous "
                    "access; set JIRA_EMAIL and JIRA_API_TOKEN for authenticated pulls."
                )
            raise JiraError(f"{method} {path}: HTTP {resp.status_code}: {resp.text[:400]}")
        raise JiraError(f"{method} {path}: retries exhausted")

    def _auth(self) -> Any:
        return self.auth if self.auth is not None else httpx.USE_CLIENT_DEFAULT

    def _backoff(self, attempt: int, retry_after: str | None) -> None:
        self.stats.retries += 1
        delay = min(60.0, (2**attempt) * 1.0)
        delay = self.rng.uniform(0, delay)  # full jitter
        if retry_after:
            with contextlib.suppress(ValueError):
                delay = max(delay, min(float(retry_after), MAX_RETRY_AFTER))
        self.sleep(delay)

    def versions(self, project: str) -> list[dict[str, Any]]:
        data = self.get(f"/rest/api/3/project/{project}/versions")
        return data if isinstance(data, list) else []

    def search(self, jql: str, fields: str = DEFAULT_FIELDS, page_size: int = 100) -> Iterator[dict[str, Any]]:
        """Enhanced JQL search. Long JQL goes in a POST body so it never hits URL length limits."""
        token: str | None = None
        use_post = len(jql) > LONG_JQL
        while True:
            if use_post:
                body: dict[str, Any] = {"jql": jql, "fields": fields.split(","), "maxResults": page_size}
                if token:
                    body["nextPageToken"] = token
                data = self.post("/rest/api/3/search/jql", body)
            else:
                params: dict[str, Any] = {"jql": jql, "fields": fields, "maxResults": page_size}
                if token:
                    params["nextPageToken"] = token
                data = self.get("/rest/api/3/search/jql", params)
            self.stats.pages += 1
            issues = data.get("issues") or []
            yield from issues
            token = data.get("nextPageToken")
            if data.get("isLast", token is None) or not token or not issues:
                return

    def projects(self, page_size: int = 100) -> list[dict[str, str]]:
        """Every project this caller can see, from the supported project search API (paged by startAt)."""
        out: list[dict[str, str]] = []
        start = 0
        while True:
            data = self.get("/rest/api/3/project/search", {"startAt": start, "maxResults": page_size})
            if not isinstance(data, dict):
                return out
            values = [v for v in data.get("values") or [] if isinstance(v, dict)]
            for v in values:
                key = str(v.get("key") or "")
                if PROJECT_KEY.fullmatch(key):
                    out.append({"key": key, "name": scrub(str(v.get("name") or ""))[:200]})
            start += len(values)
            total = data.get("total")
            if not values or data.get("isLast") is True or (isinstance(total, int) and start >= total):
                return out
            if "isLast" not in data and not isinstance(total, int):
                return out  # no paging information: one page is all we can trust


def _names(items: Any) -> list[str]:
    return [str(i.get("name")) for i in items or [] if isinstance(i, dict) and i.get("name")]


def _links(items: Any) -> list[dict[str, str]]:
    """Issue links as {type, relation, key}: "duplicates", "clones", "blocks"... (at most 20, keys validated)."""
    out: list[dict[str, str]] = []
    for link in items or []:
        if not isinstance(link, dict):
            continue
        ltype = link.get("type") or {}
        for side, phrase in (("outwardIssue", "outward"), ("inwardIssue", "inward")):
            other = link.get(side)
            key = str((other or {}).get("key") or "") if isinstance(other, dict) else ""
            if ISSUE_KEY.fullmatch(key):
                out.append(
                    {
                        "type": str(ltype.get("name") or "")[:40],
                        "relation": str(ltype.get(phrase) or phrase)[:60],
                        "key": key,
                    }
                )
    return out[:20]


def issue_to_record(
    issue: dict[str, Any],
    base_url: str,
    project: str,
    matched: list[str],
    basis: str,
    retrieved_at: str,
    target_field: str = DEFAULT_TARGET_FIELD,
    max_text: int = MAX_TEXT,
) -> dict[str, Any]:
    f = issue.get("fields") or {}
    target = _names(f.get(target_field)) if isinstance(f.get(target_field), list) else []
    key = issue.get("key", "")
    desc = f.get("description")
    desc_text = adf_to_text(desc) if isinstance(desc, dict | list) else str(desc or "")
    comments = ((f.get("comment") or {}).get("comments") or [])[-MAX_COMMENTS:]
    comment_text = "\n".join(
        f"Comment ({str(c.get('created', ''))[:10]}): "
        + (adf_to_text(c.get("body")) if isinstance(c.get("body"), dict | list) else str(c.get("body") or "")).strip()
        for c in comments
    )
    fix, aff = _names(f.get("fixVersions")), _names(f.get("versions"))
    comps, labels = _names(f.get("components")), [str(x) for x in f.get("labels") or []]
    status = (f.get("status") or {}).get("name")
    itype = (f.get("issuetype") or {}).get("name")
    prio = (f.get("priority") or {}).get("name")
    resolution = (f.get("resolution") or {}).get("name")
    header = [
        f"# {key}: {f.get('summary', '')}",
        f"Type: {itype} | Status: {status} | Priority: {prio} | Resolution: {resolution or 'Unresolved'}",
        f"Fix versions: {', '.join(fix) or '-'} | Affects versions: {', '.join(aff) or '-'} | "
        f"Target versions: {', '.join(target) or '-'}",
        f"Components: {', '.join(comps) or '-'} | Labels: {', '.join(labels) or '-'}",
        f"Created: {str(f.get('created', ''))[:10]} | Updated: {str(f.get('updated', ''))[:10]}",
    ]
    if comment_text and len(desc_text) + len(comment_text) > max_text:
        # keep the latest comments (where fixes, workarounds and "not a bug" verdicts are written) within budget
        room = max(max_text // 2, max_text - len(desc_text) - 600)
        comment_text = "...\n" + comment_text[-room:].split("\n", 1)[-1]
    text = scrub(
        "\n".join(header)
        + "\n\n## Description\n\n"
        + desc_text.strip()
        + ("\n\n## Comments\n\n" + comment_text if comment_text else "")
    )[:max_text]
    status_category = ((f.get("status") or {}).get("statusCategory") or {}).get("key")
    return {
        "id": f"jira-{key}",
        "title": scrub(f"{key}: {f.get('summary', '')}"),
        "text": text,
        "url": f"{base_url.rstrip('/')}/browse/{key}",
        "sourceId": f"jira:{project}",
        "license": "Red Hat public Jira content - no redistribution license; local retrieval/evaluation only",
        "redistributable": False,
        "retrievedAt": retrieved_at,
        "issueType": itype,
        "status": status,
        "priority": prio,
        "fixVersions": fix,
        "affectsVersions": aff,
        "targetVersions": target,
        "labels": labels,
        "components": comps,
        "updated": f.get("updated"),
        "created": f.get("created"),
        "resolution": resolution,
        "resolved": f.get("resolutiondate"),
        "statusCategory": status_category,
        "links": _links(f.get("issuelinks")),
        "version": ",".join(matched) or None,
        "versionBasis": basis,
    }


def classify(
    issue: dict[str, Any], min_v: tuple[int, int, int], ga_floor: str | None, target_field: str = DEFAULT_TARGET_FIELD
) -> tuple[list[str], str] | None:
    """Return (matched version names, basis) if the issue concerns ``min_v`` or later, else None."""
    f = issue.get("fields") or {}
    target = f.get(target_field) if isinstance(f.get(target_field), list) else []
    explicit_names = _names(f.get("fixVersions")) + _names(f.get("versions")) + _names(target)
    label_names = [str(x) for x in f.get("labels") or [] if re.fullmatch(r"v?\d+\.\d+(\.\d+)?", str(x))]

    def eligible(names: list[str]) -> tuple[list[str], bool]:
        out, any_product = [], False
        for n in names:
            if _NON_PRODUCT_HINT.search(n):
                continue
            v = parse_version(n)
            if v is None:
                continue
            any_product = True
            if v >= min_v:
                out.append(n)
        return out, any_product

    exp, exp_any = eligible(explicit_names)
    lab, lab_any = eligible(label_names)
    matched = sorted(set(exp + lab), key=lambda n: parse_version(n) or (0, 0, 0))
    if matched:
        return matched, "explicit-version" if exp else "version-label"
    if exp_any or lab_any:
        return None  # explicitly targets an older release
    created = str(f.get("created") or "")[:10]
    if ga_floor and created and created >= ga_floor:
        return [], f"created-after-{min_v[0]}.{min_v[1]}-release"
    return None


@dataclass
class PullResult:
    records: list[dict[str, Any]]
    stats: PullStats
    versions_considered: list[str]
    ga_floor: str | None


def pull_project(
    client: JiraClient,
    project: str,
    min_version: str,
    target: int,
    max_scan: int,
    base_url: str,
    now: datetime | None = None,
    target_field: str = DEFAULT_TARGET_FIELD,
) -> PullResult:
    mv = parse_version(min_version)
    if mv is None:
        raise JiraError(f"min_version {min_version!r} is not a version like 4.10")
    retrieved_at = (now or datetime.now(UTC)).isoformat(timespec="seconds")
    versions = client.versions(project)
    eligible = [
        v
        for v in versions
        if not _NON_PRODUCT_HINT.search(str(v.get("name", "")))
        and (pv := parse_version(str(v.get("name", "")))) is not None
        and pv >= mv
    ]
    names = sorted({str(v["name"]) for v in eligible})
    dated = sorted(str(v["releaseDate"]) for v in eligible if v.get("releaseDate"))
    ga_floor = dated[0] if dated else None
    records: list[dict[str, Any]] = []
    seen: set[str] = set()

    def consume(jql: str, strategy: str) -> None:
        client.stats.strategy = (client.stats.strategy + "+" if client.stats.strategy else "") + strategy
        fields = f"{DEFAULT_FIELDS},{target_field}" if target_field else DEFAULT_FIELDS
        for issue in client.search(jql, fields=fields):
            client.stats.scanned += 1
            key = issue.get("key", "")
            if key in seen:
                continue
            cls = classify(issue, mv, ga_floor, target_field)
            if cls is not None:
                seen.add(key)
                records.append(issue_to_record(issue, base_url, project, cls[0], cls[1], retrieved_at, target_field))
            if len(records) >= target or client.stats.scanned >= max_scan:
                return

    if names:
        # 1) Compact range JQL: version fields compare by the project's version order (verified on ROX, 2026-10-27).
        #    classify() re-checks every issue numerically, so out-of-order versions cannot leak in.
        lowest = min(names, key=lambda n: parse_version(n) or (0, 0, 0))
        fields_cmp = ["fixVersion", "affectedVersion"]
        if target_field.startswith("customfield_"):
            fields_cmp.append(f"cf[{target_field.removeprefix('customfield_')}]")
        ranged = " OR ".join(f"{f} >= {json.dumps(lowest)}" for f in fields_cmp)
        range_failed = False
        try:
            consume(f"project = {project} AND ({ranged}) ORDER BY updated DESC", "version-range")
        except JiraError as exc:
            client.stats.errors.append(f"version-range: {exc}")
            range_failed = True
        # 2) Explicit version list (POSTed when long) only if the range query was rejected.
        if range_failed and len(records) < target and client.stats.scanned < max_scan:
            quoted = ", ".join(json.dumps(n) for n in names)
            clauses = [f"{f} in ({quoted})" for f in fields_cmp]
            for label, cl in (("version-list", clauses), ("version-list-no-target", clauses[:2])):
                try:
                    consume(f"project = {project} AND ({' OR '.join(cl)}) ORDER BY updated DESC", label)
                    break
                except JiraError as exc:
                    client.stats.errors.append(f"{label}: {exc}")
                    if len(cl) == 2:
                        break
    if len(records) < target and client.stats.scanned < max_scan:
        consume(f"project = {project} ORDER BY updated DESC", "recent-scan")
    client.stats.kept = len(records)
    return PullResult(records, client.stats, names, ga_floor)


def insights(records: list[dict[str, Any]], project: str) -> dict[str, Any]:
    """Aggregate, non-identifying statistics - safe to share as derived insight."""

    def count(key: str, multi: bool = False) -> list[tuple[str, int]]:
        c: Counter[str] = Counter()
        for r in records:
            v = r.get(key)
            if multi:
                c.update(v or [])
            elif v:
                c[str(v)] += 1
        return c.most_common(15)

    version_counter: Counter[str] = Counter()
    for r in records:
        for v in (r.get("version") or "").split(","):
            if v:
                version_counter[v] += 1
    open_bugs = [r for r in records if r.get("issueType") == "Bug" and r.get("resolution") in (None, "Unresolved")]
    return {
        "project": project,
        "issues": len(records),
        "byType": count("issueType"),
        "byStatus": count("status"),
        "byPriority": count("priority"),
        "byComponent": count("components", multi=True),
        "byVersion": version_counter.most_common(20),
        "topLabels": count("labels", multi=True),
        "openBugs": len(open_bugs),
        "basis": count("versionBasis"),
    }


def insights_markdown(ins: dict[str, Any], retrieved_at: str, min_version: str) -> str:
    def table(rows: list[tuple[str, int]]) -> str:
        return "\n".join(f"- {k}: {v}" for k, v in rows) or "- (none)"

    return (
        f"# {ins['project']} issue insights ({min_version}+)\n\n"
        f"Aggregated from {ins['issues']} public issues retrieved {retrieved_at}. Counts only; see individual issues "
        "for details.\n\n"
        f"## By version\n\n{table(ins['byVersion'])}\n\n## By component\n\n{table(ins['byComponent'])}\n\n"
        f"## By type\n\n{table(ins['byType'])}\n\n## By status\n\n{table(ins['byStatus'])}\n\n"
        f"## By priority\n\n{table(ins['byPriority'])}\n\n## Top labels\n\n{table(ins['topLabels'])}\n\n"
        f"Open bugs: {ins['openBugs']}\n"
    )


# ---------------------------------------------------------------------------------------------------------------------
# Full-project sync: every issue, any status, kept up to date run after run.


def select_projects(spec: str, available: list[dict[str, str]] | None = None) -> list[str]:
    """``default`` (Kubernetes/OpenShift/RHACS set), ``all`` (every visible project) or ``KEY,KEY``."""
    known = [p["key"] for p in available or []]
    wanted = spec.strip()
    if wanted == "all":
        if not known:
            raise JiraError("'all' needs the project list from the server; none was returned")
        return known
    if wanted in {"", "default"}:
        keys = list(DEFAULT_PROJECTS)
        return [k for k in keys if k in known] if known else keys
    keys = list(dict.fromkeys(k.strip().upper() for k in wanted.split(",") if k.strip()))
    bad = [k for k in keys if not PROJECT_KEY.fullmatch(k)]
    if bad:
        raise JiraError(f"not Jira project keys: {', '.join(bad)}")
    if known:
        missing = [k for k in keys if k not in known]
        if missing:
            raise JiraError(
                f"projects not visible on this Jira: {', '.join(missing)} "
                "(list them with: kube-noob corpus jira-projects --online)"
            )
    return keys


def key_number(key: str) -> int:
    m = ISSUE_KEY.fullmatch(key)
    return int(m.group(2)) if m else -1


def jira_time(value: Any) -> datetime | None:
    """Jira timestamps look like 2026-10-27T10:21:33.123-0400."""
    for fmt in ("%Y-%m-%dT%H:%M:%S.%f%z", "%Y-%m-%dT%H:%M:%S%z"):
        try:
            return datetime.strptime(str(value), fmt).astimezone(UTC)
        except ValueError:
            continue
    return None


def _iso(t: datetime) -> str:
    return t.astimezone(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")


def _parse_iso(value: Any) -> datetime | None:
    try:
        t = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    return t if t.tzinfo else t.replace(tzinfo=UTC)


def shard_name(project: str) -> str:
    return f"jira-{project.lower().replace('_', '-')}"


def jira_dir(data_dir: Path) -> Path:
    d = data_dir / "jira"
    d.mkdir(parents=True, exist_ok=True, mode=0o700)
    return d


def load_shard(data_dir: Path, project: str) -> dict[str, dict[str, Any]]:
    path = data_dir / "corpus" / f"{shard_name(project)}.jsonl"
    out: dict[str, dict[str, Any]] = {}
    if not path.is_file():
        return out
    with path.open(encoding="utf-8") as fh:
        for line in fh:
            with contextlib.suppress(ValueError):
                rec = json.loads(line)
                if isinstance(rec, dict) and isinstance(rec.get("id"), str):
                    out[rec["id"]] = rec
    return out


def load_state(data_dir: Path) -> dict[str, Any]:
    path = data_dir / "jira" / "state.json"
    if not path.is_file():
        return {}
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return doc if isinstance(doc, dict) else {}


def save_state(data_dir: Path, state: dict[str, Any]) -> None:
    d = jira_dir(data_dir)
    fd, tmp = tempfile.mkstemp(dir=d, prefix=".state.", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(state, fh, indent=1, sort_keys=True)
        os.chmod(tmp, 0o600)
        os.replace(tmp, d / "state.json")
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise


def state_from_records(records: dict[str, dict[str, Any]]) -> dict[str, Any]:
    """Resume from a copy that came without a state file (``corpus import``): the lowest key held and the oldest
    retrieval time, so the next run only fetches what is missing or changed since."""
    keys = [str(r.get("id", "")).removeprefix("jira-") for r in records.values()]
    keys = [k for k in keys if ISSUE_KEY.fullmatch(k)]
    times = [t for r in records.values() if (t := _parse_iso(r.get("retrievedAt")))]
    st: dict[str, Any] = {"complete": False}
    if keys:
        st["lowestKey"] = min(keys, key=key_number)
    if times:
        st["lastSyncAt"] = _iso(min(times))
    return st


@dataclass
class ProjectSync:
    project: str
    fetched: int = 0
    total: int = 0
    complete: bool = False
    stopped: str | None = None
    error: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {k: v for k, v in self.__dict__.items() if v is not None}


def sync_project(
    client: JiraClient,
    project: str,
    records: dict[str, dict[str, Any]],
    state: dict[str, Any],
    base_url: str,
    now: datetime | None = None,
    target_field: str = DEFAULT_TARGET_FIELD,
) -> ProjectSync:
    """Update ``records`` (id -> record) and ``state`` for one project, in place.

    1. Forward: issues updated since the last run (``updated >= -Nm`` is relative to the server's clock, so time zones
       never matter), oldest change first, so an interrupted run resumes where it stopped.
    2. Backfill: issues below the lowest key held, newest first, until the project is complete.
    """
    if not PROJECT_KEY.fullmatch(project):
        raise JiraError(f"not a Jira project key: {project!r}")
    now = now or datetime.now(UTC)
    retrieved = _iso(now)
    fields = f"{SYNC_FIELDS},{target_field}" if target_field else SYNC_FIELDS
    res = ProjectSync(project)

    def keep(issue: dict[str, Any]) -> str:
        key = str(issue.get("key") or "")
        if not ISSUE_KEY.fullmatch(key) or not key.startswith(project + "-"):
            return ""
        rec = issue_to_record(issue, base_url, project, [], "sync", retrieved, target_field, SYNC_MAX_TEXT)
        records[rec["id"]] = rec
        res.fetched += 1
        return key

    last = _parse_iso(state.get("lastSyncAt")) if state.get("lastSyncAt") else None
    try:
        if last is not None:
            minutes = max(0, int((now - last).total_seconds() // 60)) + OVERLAP_MINUTES
            through: datetime | None = None
            for issue in client.search(f"project = {project} AND updated >= -{minutes}m ORDER BY updated ASC", fields):
                if keep(issue):
                    through = jira_time((issue.get("fields") or {}).get("updated")) or through
                    if through is not None:
                        state["lastSyncAt"] = _iso(min(through, now))
            state["lastSyncAt"] = retrieved
        else:
            state["lastSyncAt"] = retrieved  # changes after this moment are picked up by the next forward pass
        if not state.get("complete"):
            lowest = str(state.get("lowestKey") or "")
            below = f" AND key < {lowest}" if ISSUE_KEY.fullmatch(lowest) and lowest.startswith(project + "-") else ""
            for issue in client.search(f"project = {project}{below} ORDER BY key DESC", fields):
                key = keep(issue)
                if key and (not state.get("lowestKey") or key_number(key) < key_number(str(state["lowestKey"]))):
                    state["lowestKey"] = key
            state["complete"] = True
    except BudgetExhausted:
        res.stopped = "budget"
    except JiraError as exc:
        res.error = str(exc)[:400]
    res.complete = bool(state.get("complete"))
    res.total = len(records)
    return res


def sync_projects(
    client: JiraClient,
    projects: list[str],
    data_dir: Path,
    base_url: str,
    now: datetime | None = None,
    target_field: str = DEFAULT_TARGET_FIELD,
) -> dict[str, Any]:
    """Sync each project in turn, writing its shard and the state after every project so progress is never lost."""
    from kube_noob.sources.corpus import write_shard

    with _sync_lock(data_dir):
        return _sync_projects_locked(client, projects, data_dir, base_url, now, target_field, write_shard)


@contextlib.contextmanager
def _sync_lock(data_dir: Path) -> Iterator[None]:
    """One sync per data folder at a time: two would double the load on the server and race on the same files."""
    try:
        import fcntl
    except ImportError:  # pragma: no cover - Windows: no cross-process lock
        yield
        return
    with open(jira_dir(data_dir) / ".sync.lock", "a", encoding="utf-8") as fh:
        try:
            fcntl.flock(fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise JiraError("another Jira sync is running on this data folder; try again when it finishes") from exc
        try:
            yield
        finally:
            fcntl.flock(fh.fileno(), fcntl.LOCK_UN)


def _sync_projects_locked(
    client: JiraClient,
    projects: list[str],
    data_dir: Path,
    base_url: str,
    now: datetime | None,
    target_field: str,
    write_shard: Callable[[Path, str, list[dict[str, Any]]], dict[str, Any]],
) -> dict[str, Any]:
    state = load_state(data_dir)
    per = state.setdefault("projects", {})
    state["baseUrl"] = base_url
    results: list[dict[str, Any]] = []
    all_records: list[dict[str, Any]] = []
    for project in projects:
        records = load_shard(data_dir, project)
        if project not in per:
            per[project] = state_from_records(records) if records else {}
        res = sync_project(client, project, records, per[project], base_url, now, target_field)
        if records:
            ordered = sorted(records.values(), key=lambda r: -key_number(str(r["id"]).removeprefix("jira-")))
            write_shard(data_dir, shard_name(project), ordered)
            all_records.extend(ordered)
        per[project]["total"] = res.total
        save_state(data_dir, state)
        results.append(res.as_dict())
        if res.stopped == "budget":
            break
    done = {r["project"] for r in results}
    skipped = [p for p in projects if p not in done]
    return {
        "projects": results,
        "skipped": skipped,
        "requests": client.stats.requests,
        "retries": client.stats.retries,
        "stoppedBy": "budget" if any(r.get("stopped") == "budget" for r in results) else None,
        "records": all_records,
    }


# ---------------------------------------------------------------------------------------------------------------------
# Running a sync: the CLI (`kube-noob corpus jira`) and the background sync in `kube-noob serve`.


def jira_http(settings: Any, base_url: str) -> httpx.Client:
    """An HTTP client that can only talk to ``base_url``'s host over https: GET, plus POST to the search endpoint
    (long JQL). Built on the single outbound choke point, so the offline lock and proxies apply as everywhere."""
    from kube_noob.errors import DomainNotAllowedError
    from kube_noob.net import Purpose, host_allowed, http_client

    host = httpx.URL(base_url).host
    if not host_allowed(host, list(settings.web.allowed_domains)):
        raise DomainNotAllowedError(f"{host} (add it to web.allowedDomains to sync from it)")
    client = http_client(settings, Purpose.SOURCES, allow_sources=True, timeout=60)

    def _guard(request: httpx.Request) -> None:
        if request.url.scheme != "https" or request.url.host != host:
            raise DomainNotAllowedError(f"{request.url.host} (the Jira sync only reaches {host})")
        if request.method != "GET" and not (request.method == "POST" and request.url.path == "/rest/api/3/search/jql"):
            raise DomainNotAllowedError(f"{request.method} {request.url.path} (the Jira sync only reads)")

    hooks = client.event_hooks
    client.event_hooks = {"request": [*hooks.get("request", []), _guard], "response": hooks.get("response", [])}
    return client


def run_sync(
    settings: Any,
    projects: str | None = None,
    max_requests: int | None = None,
    auth: tuple[str, str] | None = None,
    now: datetime | None = None,
    http: httpx.Client | None = None,
) -> dict[str, Any]:
    """Sync the chosen projects into ``settings.data_dir``, write per-project insights, and rebuild the ticket index.
    Returns a summary without the records."""
    from kube_noob import tickets
    from kube_noob.sources.corpus import write_shard

    base_url = settings.jira.base_url
    spec = projects if projects is not None else settings.jira.projects
    budget = max_requests if max_requests is not None else settings.jira.max_requests
    now = now or datetime.now(UTC)
    own = http is None
    client_http = http if http is not None else jira_http(settings, base_url)
    try:
        client = JiraClient(client_http, base_url, auth=auth, max_requests=budget)
        available = client.projects()
        chosen = select_projects(spec, available)
        out = sync_projects(client, chosen, settings.data_dir, base_url, now)
    finally:
        if own:
            client_http.close()
    records = out.pop("records")
    by_project: dict[str, list[dict[str, Any]]] = {}
    for r in records:
        by_project.setdefault(str(r["sourceId"]).removeprefix("jira:"), []).append(r)
    stamp = _iso(now)
    insight_records = []
    for project, recs in sorted(by_project.items()):
        ins = insights(recs, project)
        insight_records.append(
            {
                "id": f"insights-jira-{project.lower()}",
                "title": f"{project} issue insights",
                "text": insights_markdown(ins, stamp, "all versions"),
                "url": f"{base_url}/browse/{project}",
                "sourceId": f"jira-insights:{project}",
                "license": "aggregate statistics derived by kube-noob",
                "redistributable": True,
                "retrievedAt": stamp,
            }
        )
    if insight_records:
        write_shard(settings.data_dir, "jira-insights", insight_records)
    index = tickets.stats(settings.data_dir)
    out.update(
        {
            "baseUrl": base_url,
            "visibleProjects": len(available),
            "selected": chosen,
            "budget": budget,
            "index": {k: index[k] for k in ("tickets", "asOf", "byVerdict")} if index else None,
        }
    )
    return out


def start_background(settings: Any) -> Any:
    """Keep the copy current from ``kube-noob serve``: one run now, then every ``jira.interval_hours``."""
    import logging
    import threading

    log = logging.getLogger("kube_noob.jira")
    stop = threading.Event()

    def loop() -> None:
        while not stop.is_set():
            try:
                out = run_sync(settings)
                fetched = sum(int(p.get("fetched") or 0) for p in out["projects"])
                log.info(
                    "jira sync: %d tickets fetched in %d requests; %s",
                    fetched,
                    out["requests"],
                    "budget reached, resumes next run" if out.get("stoppedBy") else "up to date",
                )
            except Exception:  # one failed run must not stop the service
                log.exception("jira sync failed")
            stop.wait(settings.jira.interval_hours * 3600)

    threading.Thread(target=loop, name="kube-noob-jira-sync", daemon=True).start()
    return stop
