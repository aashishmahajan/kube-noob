"""Jira Cloud ingestion with jittered, rate-limit-aware pulls (e.g. Red Hat's public ROX / RHACS project).

* Uses the Jira Cloud enhanced search API ``/rest/api/3/search/jql`` with ``nextPageToken`` pagination.
* Polite by design: one request at a time, jittered delay between pages, exponential backoff with full jitter on
  429/5xx, honours ``Retry-After``.
* Version focus: keeps issues whose fixVersions / affectsVersions / version-like labels are >= ``min_version``.
* Privacy: reporter/assignee/author identities are never stored; emails and account ids are scrubbed from text;
  @mentions become ``@user``.
* Records are marked ``redistributable: false`` - public visibility is not a redistribution license. They are for
  local retrieval and evaluation; dataset exports exclude them unless explicitly requested.
"""

from __future__ import annotations

import contextlib
import json
import random
import re
import time
from collections import Counter
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

import httpx

from kube_noob.errors import KubeNoobError

DEFAULT_FIELDS = (
    "summary,description,issuetype,status,priority,resolution,labels,components,fixVersions,versions,"
    "created,updated,resolutiondate,comment,parent"
)
# Red Hat's Jira Cloud exposes "Target Version" as customfield_10855 (verified on ROX-36348, 2026-10-27).
DEFAULT_TARGET_FIELD = "customfield_10855"
_VERSION_RE = re.compile(r"(?<![\d.])(\d{1,2})\.(\d{1,2})(?:\.(\d{1,3}))?(?![\d])")
_NON_PRODUCT_HINT = re.compile(r"(?i)\b(ocp|openshift|k8s|kubernetes|rhel|go|golang|python|node|helm|java|ubi)\b")
_EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
_ACCOUNT = re.compile(r"\[~accountid:[^\]]+\]|accountId[\"=:]\s*\"?[0-9a-f:-]{10,}\"?", re.IGNORECASE)
MAX_COMMENTS = 20
MAX_TEXT = 20_000
LONG_JQL = 1500  # characters; above this the search request is sent as POST
MAX_RETRY_AFTER = 120.0  # seconds; a larger Retry-After is capped so a pull cannot hang for hours


class JiraError(KubeNoobError):
    pass


def parse_version(s: str) -> tuple[int, int, int] | None:
    m = _VERSION_RE.search(s)
    if not m:
        return None
    return int(m.group(1)), int(m.group(2)), int(m.group(3) or 0)


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
        min_delay: float = 0.4,
        jitter: float = 0.6,
        max_retries: int = 6,
        sleep: Callable[[float], None] = time.sleep,
        rng: random.Random | None = None,
        auth: tuple[str, str] | None = None,
    ) -> None:
        if auth is not None and not base_url.startswith("https://"):
            raise JiraError("Jira credentials are only sent over https; use an https:// base URL")
        self.http = client
        self.auth = httpx.BasicAuth(*auth) if auth else None
        self.base = base_url.rstrip("/")
        self.min_delay = min_delay
        self.jitter = jitter
        self.max_retries = max_retries
        self.sleep = sleep
        self.rng = rng or random.Random()  # noqa: S311 - jitter, not crypto
        self.stats = PullStats()

    def _pause(self) -> None:
        self.sleep(self.min_delay + self.rng.random() * self.jitter)

    def get(self, path: str, params: dict[str, Any] | None = None) -> Any:
        return self._request("GET", path, params=params)

    def post(self, path: str, body: dict[str, Any]) -> Any:
        return self._request("POST", path, body=body)

    def _request(
        self, method: str, path: str, params: dict[str, Any] | None = None, body: dict[str, Any] | None = None
    ) -> Any:
        url = f"{self.base}{path}"
        headers = {"Accept": "application/json"}
        for attempt in range(self.max_retries + 1):
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
            self._pause()


def _names(items: Any) -> list[str]:
    return [str(i.get("name")) for i in items or [] if isinstance(i, dict) and i.get("name")]


def issue_to_record(
    issue: dict[str, Any],
    base_url: str,
    project: str,
    matched: list[str],
    basis: str,
    retrieved_at: str,
    target_field: str = DEFAULT_TARGET_FIELD,
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
    text = scrub(
        "\n".join(header)
        + "\n\n## Description\n\n"
        + desc_text.strip()
        + ("\n\n## Comments\n\n" + comment_text if comment_text else "")
    )[:MAX_TEXT]
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
