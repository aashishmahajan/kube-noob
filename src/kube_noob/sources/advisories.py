"""Red Hat CSAF VEX statements for the products kube-noob covers, as redistributable corpus records (R5.5).

Red Hat publishes one CSAF VEX document per CVE at ``https://security.access.redhat.com/data/csaf/v2/vex/<year>/
<cve>.json`` under CC BY 4.0 ("Security Data", https://access.redhat.com/security/data, checked 2026-10-28), with
``changes.csv`` listing what changed (the CSAF 2.0 directory distribution). For each CVE kube-noob keeps the title,
severity, CVSS base score and, per product in the default set (OpenShift, RHACS, ACM and the layered products, RHEL
8 and 9 that their images build on), each component's status: fixed (with the erratum), known affected (with the
remediation category), known not affected (with the VEX justification flag) or under investigation. Matching a CVE
to an image (VUL1) reads these statements; search reads the summary text.

Every source is checked against the licence allow-list before anything is written: a source whose licence is not on
it stops the build. Fetching is paced (one request a second plus jitter), budgeted, HTTPS to one host only, and
blocked by the offline lock; ``--from-archive`` reads a downloaded archive offline.
"""

from __future__ import annotations

import csv
import io
import json
import random
import re
import subprocess
import tarfile
import time
from collections.abc import Callable, Iterable, Iterator
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx

HOST = "security.access.redhat.com"
BASE = f"https://{HOST}/data/csaf/v2/vex"
MIN_DELAY = 1.0
MAX_DOC = 25_000_000  # bytes: one VEX document (OpenShift CVEs list thousands of components)
MAX_STATEMENTS = 4000  # kept per CVE after filtering to the default products
MAX_CHANGES = 2_000_000  # bytes of changes.csv read
_CVE = re.compile(r"^CVE-(\d{4})-(\d{4,7})$")
_PATH = re.compile(r"^(\d{4})/cve-\d{4}-\d{4,7}\.json$")


@dataclass(frozen=True)
class Source:
    source_id: str
    license: str
    attribution: str
    url: str


SOURCES = {
    "redhat-vex": Source(
        "redhat-vex",
        "CC-BY-4.0",
        "Red Hat Security Data (c) Red Hat, Inc., CC BY 4.0, https://access.redhat.com/security/data",
        BASE,
    ),
}
PRODUCTS = (
    "cpe:/a:redhat:openshift",
    "cpe:/a:redhat:advanced_cluster_security",
    "cpe:/a:redhat:acm",
    "cpe:/a:redhat:multicluster_engine",
    "cpe:/a:redhat:openshift_gitops",
    "cpe:/a:redhat:openshift_pipelines",
    "cpe:/a:redhat:service_mesh",
    "cpe:/a:redhat:logging",
    "cpe:/a:redhat:openshift_data_foundation",
    "cpe:/o:redhat:enterprise_linux:8",
    "cpe:/o:redhat:enterprise_linux:9",
    "cpe:/a:redhat:enterprise_linux:8",
    "cpe:/a:redhat:enterprise_linux:9",
)
STATUS = {
    "fixed": "fixed",
    "first_fixed": "fixed",
    "known_affected": "known_affected",
    "first_affected": "known_affected",
    "last_affected": "known_affected",
    "known_not_affected": "known_not_affected",
    "under_investigation": "under_investigation",
}


class AdvisoryError(ValueError):
    """A source is not allowed, a document is malformed, or the network refused."""


def check_license(source: Source) -> None:
    from kube_noob.sources.db_bundle import LICENSES

    if source.license not in LICENSES:
        raise AdvisoryError(
            f"{source.source_id}: licence {source.license!r} is not on the allow-list ({', '.join(sorted(LICENSES))}); "
            "the build stops rather than ship it"
        )


def _walk(node: Any, out: dict[str, dict[str, str]], depth: int = 0) -> None:
    if depth > 30 or not isinstance(node, dict):
        return
    product = node.get("product")
    if isinstance(product, dict) and isinstance(product.get("product_id"), str):
        helper = product.get("product_identification_helper") or {}
        out[product["product_id"]] = {
            "name": str(product.get("name", ""))[:300],
            "cpe": str(helper.get("cpe", ""))[:300] if isinstance(helper, dict) else "",
            "purl": str(helper.get("purl", ""))[:500] if isinstance(helper, dict) else "",
        }
    for child in node.get("branches") or []:
        _walk(child, out, depth + 1)


def _index(tree: Any) -> tuple[dict[str, dict[str, str]], dict[str, tuple[str, str]]]:
    products: dict[str, dict[str, str]] = {}
    full: dict[str, tuple[str, str]] = {}
    if not isinstance(tree, dict):
        return products, full
    for branch in tree.get("branches") or []:
        _walk(branch, products)
    for rel in tree.get("relationships") or []:
        if not isinstance(rel, dict):
            continue
        fpn = rel.get("full_product_name") or {}
        pid = fpn.get("product_id") if isinstance(fpn, dict) else None
        if isinstance(pid, str):
            full[pid] = (str(rel.get("product_reference", "")), str(rel.get("relates_to_product_reference", "")))
    return products, full


def _component_name(purl: str, fallback: str) -> str:
    m = re.match(r"pkg:[a-z]+/(?:[^/@?]+/)*?([^/@?]+)(?:@|\?|$)", purl)
    if purl.startswith("pkg:oci/"):
        repo = re.search(r"repository_url=[^&]*?/([^&/]+/[^&/]+)(?:&|$)", purl)
        if repo:
            return repo.group(1)
    return m.group(1) if m else fallback


def parse_vex(doc: Any, products: Iterable[str] = PRODUCTS, retrieved_at: str | None = None) -> dict[str, Any] | None:
    """One corpus record for a CSAF VEX document, keeping statements about ``products`` (CPE prefixes); None when
    the document names none of them."""
    if not isinstance(doc, dict) or not isinstance(doc.get("document"), dict):
        raise AdvisoryError("not a CSAF document")
    vulns = doc.get("vulnerabilities")
    if not isinstance(vulns, list) or not vulns or not isinstance(vulns[0], dict):
        raise AdvisoryError("a CSAF VEX document without vulnerabilities")
    vuln = vulns[0]
    cve = str(vuln.get("cve", ""))
    if not _CVE.match(cve):
        raise AdvisoryError(f"not a CVE id: {cve[:40]!r}")
    prefixes = tuple(products)
    names, full = _index(doc.get("product_tree"))

    def describe(pid: str) -> tuple[dict[str, str], dict[str, str]]:
        comp_id, prod_id = full.get(pid, (pid, pid))
        return names.get(prod_id, {}), names.get(comp_id, {})

    flags: dict[str, str] = {}
    for f in vuln.get("flags") or []:
        if isinstance(f, dict):
            for pid in f.get("product_ids") or []:
                flags[str(pid)] = str(f.get("label", ""))[:80]
    fixes: dict[str, dict[str, str]] = {}
    for r in vuln.get("remediations") or []:
        if isinstance(r, dict):
            fix = {
                "category": str(r.get("category", ""))[:40],
                **({"url": str(r["url"])[:300]} if r.get("url") else {}),
                **({"details": " ".join(str(r["details"]).split())[:300]} if r.get("details") else {}),
            }
            for pid in r.get("product_ids") or []:
                fixes.setdefault(str(pid), fix)
    statements: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str]] = set()
    total = 0
    status_map = vuln.get("product_status") if isinstance(vuln.get("product_status"), dict) else {}
    for raw_status, pids in (status_map or {}).items():
        status = STATUS.get(str(raw_status))
        if status is None or not isinstance(pids, list):
            continue
        for raw_pid in pids:
            pid = str(raw_pid)
            product, component = describe(pid)
            cpe = product.get("cpe", "")
            if not cpe.startswith(prefixes):
                continue
            purl = component.get("purl", "")
            name = _component_name(purl, component.get("name", "") or pid.split(":", 1)[-1])
            key = (cpe, name, status)
            total += 1
            if key in seen:
                continue
            seen.add(key)
            st: dict[str, Any] = {"product": product.get("name", ""), "cpe": cpe, "component": name, "status": status}
            if purl:
                st["purl"] = purl
            if status == "known_not_affected" and pid in flags:
                st["justification"] = flags[pid]
            if status in {"fixed", "known_affected"} and pid in fixes:
                st["fix"] = fixes[pid]
            statements.append(st)
    if not statements:
        return None
    statements.sort(key=lambda s: (s["cpe"], s["component"], s["status"]))
    cut = len(statements) > MAX_STATEMENTS
    statements = statements[:MAX_STATEMENTS]
    title = " ".join(str(vuln.get("title") or doc["document"].get("title") or cve).split())[:300]
    severity = ""
    agg = doc["document"].get("aggregate_severity")
    if isinstance(agg, dict):
        severity = str(agg.get("text", "")).lower()[:20]
    score = None
    for s in vuln.get("scores") or []:
        v3 = s.get("cvss_v3") if isinstance(s, dict) else None
        if isinstance(v3, dict) and isinstance(v3.get("baseScore"), (int, float)):
            score = float(v3["baseScore"])
            break
    tracking = doc["document"].get("tracking") if isinstance(doc["document"].get("tracking"), dict) else {}
    source = SOURCES["redhat-vex"]
    return {
        "id": f"vex-{cve.lower()}",
        "title": f"{cve}: {title}" if not title.startswith(cve) else title,
        "text": summary(cve, title, severity, score, statements),
        "url": f"https://access.redhat.com/security/cve/{cve}",
        "sourceId": source.source_id,
        "license": source.license,
        "attribution": source.attribution,
        "redistributable": True,
        "retrievedAt": retrieved_at or datetime.now(UTC).isoformat(timespec="seconds"),
        "cve": cve,
        "severity": severity or None,
        "cvss": score,
        "vexUpdated": str((tracking or {}).get("current_release_date", ""))[:40] or None,
        "statements": statements,
        "statementsSeen": total,
        **({"statementsCut": True} if cut else {}),
    }


def summary(cve: str, title: str, severity: str, score: float | None, statements: list[dict[str, Any]]) -> str:
    """Search text: what Red Hat says about the CVE for each product, grouped by status."""
    lines = [f"{cve}: {title}", f"Red Hat severity: {severity or 'not rated'}; CVSS v3 base score: {score or 'n/a'}."]
    by: dict[str, dict[str, list[str]]] = {}
    for s in statements:
        by.setdefault(s["product"] or s["cpe"], {}).setdefault(s["status"], []).append(s["component"])
    words = {
        "fixed": "fixed",
        "known_affected": "affected",
        "known_not_affected": "not affected",
        "under_investigation": "under investigation",
    }
    for product, statuses in sorted(by.items()):
        parts = []
        for status in ("fixed", "known_affected", "under_investigation", "known_not_affected"):
            comps = statuses.get(status)
            if comps:
                shown = ", ".join(sorted(set(comps))[:8]) + (
                    f" and {len(set(comps)) - 8} more" if len(set(comps)) > 8 else ""
                )
                parts.append(f"{words[status]}: {shown}")
        lines.append(f"{product}: " + "; ".join(parts) + ".")
    return "\n".join(lines)


# ---------------------------------------------------------------------------------------------------------------------
# Fetching


def vex_http(settings: Any) -> httpx.Client:
    """GET-only, HTTPS to the security data host only, through the single outbound choke point."""
    from kube_noob.errors import DomainNotAllowedError
    from kube_noob.net import Purpose, http_client

    client = http_client(settings, Purpose.SOURCES, allow_sources=True, timeout=60)

    def _guard(request: httpx.Request) -> None:
        if request.url.scheme != "https" or request.url.host != HOST or request.method != "GET":
            raise DomainNotAllowedError(f"{request.method} {request.url.host} (advisories only read from {HOST})")

    hooks = client.event_hooks
    client.event_hooks = {"request": [*hooks.get("request", []), _guard], "response": hooks.get("response", [])}
    return client


class VexClient:
    def __init__(
        self,
        client: httpx.Client,
        max_requests: int = 3000,
        sleep: Callable[[float], None] = time.sleep,
        rng: random.Random | None = None,
    ) -> None:
        self.http = client
        self.max_requests = max_requests
        self.requests = 0
        self.sleep = sleep
        self.rng = rng or random.Random()  # noqa: S311 - jitter, not crypto

    def _get(self, path: str, limit: int) -> bytes | None:
        if self.requests >= self.max_requests:
            raise AdvisoryError(f"request budget of {self.max_requests} spent")
        if self.requests:
            self.sleep(MIN_DELAY + self.rng.random())
        for attempt in range(5):
            self.requests += 1
            try:
                with self.http.stream("GET", f"{BASE}/{path}") as resp:
                    if resp.status_code == 404:
                        return None
                    if resp.status_code in {429, 502, 503, 504} and attempt < 4:
                        wait = resp.headers.get("Retry-After", "")
                        self.sleep(min(float(wait), 300.0) if wait.isdigit() else 2.0**attempt * 5)
                        continue
                    if resp.status_code != 200:
                        raise AdvisoryError(f"GET {path}: HTTP {resp.status_code}")
                    body = bytearray()
                    for chunk in resp.iter_bytes():
                        body += chunk
                        if len(body) > limit:
                            raise AdvisoryError(f"GET {path}: larger than {limit} bytes")
                    return bytes(body)
            except httpx.TransportError as exc:
                if attempt == 4:
                    raise AdvisoryError(f"GET {path}: {exc}") from exc
                self.sleep(2.0**attempt * 5)
        raise AdvisoryError(f"GET {path}: still refused after retries")

    def document(self, cve: str) -> Any | None:
        m = _CVE.match(cve)
        if not m:
            raise AdvisoryError(f"not a CVE id: {cve!r}")
        body = self._get(f"{m.group(1)}/{cve.lower()}.json", MAX_DOC)
        return None if body is None else json.loads(body)

    def changed_since(self, since: str) -> list[str]:
        """CVE ids whose VEX changed after ``since`` (ISO 8601), newest first, from changes.csv."""
        body = self._get("changes.csv", MAX_CHANGES * 50)
        return changed_cves(body.decode("utf-8", errors="replace") if body else "", since)


def changed_cves(text: str, since: str) -> list[str]:
    out: list[str] = []
    for row in csv.reader(io.StringIO(text)):
        if len(row) < 2 or not _PATH.match(row[0].strip()):
            continue
        if row[1].strip() > since:
            cve = Path(row[0].strip()).stem.upper()
            if cve not in out:
                out.append(cve)
    return out


def from_archive(path: Path) -> Iterator[Any]:
    """Every VEX document in a downloaded archive: a folder of ``<year>/<cve>.json``, a ``.tar`` or ``.tar.gz``, or
    a ``.tar.zst`` (read through the ``zstd`` program)."""
    if path.is_dir():
        for f in sorted(path.rglob("cve-*.json")):
            if f.stat().st_size <= MAX_DOC:
                yield json.loads(f.read_bytes())
        return
    if path.name.endswith(".zst"):
        proc = subprocess.Popen(["zstd", "-dc", "--", str(path)], stdout=subprocess.PIPE)  # noqa: S607
        if proc.stdout is None:  # pragma: no cover
            raise AdvisoryError("zstd produced no output")
        try:
            with tarfile.open(fileobj=proc.stdout, mode="r|") as tf:
                yield from _members(tf)
        finally:
            proc.stdout.close()
            if proc.wait() != 0:
                raise AdvisoryError(f"zstd could not read {path.name}")
        return
    with tarfile.open(path, "r:*") as tf:
        yield from _members(tf)


def _members(tf: tarfile.TarFile) -> Iterator[Any]:
    for m in tf:
        if not m.isfile() or not m.name.endswith(".json") or "cve-" not in m.name or m.size > MAX_DOC:
            continue
        fh = tf.extractfile(m)
        if fh is not None:
            try:
                yield json.loads(fh.read())
            except (ValueError, RecursionError):
                continue


def run(
    data_dir: Path,
    docs: Iterable[Any],
    products: Iterable[str] = PRODUCTS,
    now: datetime | None = None,
    replace: bool = False,
) -> dict[str, Any]:
    """Parse ``docs`` and merge their records into the ``redhat-vex`` shard (``replace`` starts it over)."""
    from kube_noob.sources.corpus import read_manifest, write_shard

    source = SOURCES["redhat-vex"]
    check_license(source)
    stamp = (now or datetime.now(UTC)).isoformat(timespec="seconds")
    current: dict[str, dict[str, Any]] = {}
    shard = data_dir / "corpus" / "redhat-vex.jsonl"
    if shard.is_file() and not replace and "redhat-vex" in (read_manifest(data_dir).get("shards") or {}):
        for line in shard.read_text(encoding="utf-8").splitlines():
            if line.strip():
                rec = json.loads(line)
                current[rec["cve"]] = rec
    seen = kept = bad = 0
    for doc in docs:
        seen += 1
        try:
            rec = parse_vex(doc, products, stamp)
        except (AdvisoryError, KeyError, TypeError, AttributeError):
            bad += 1
            continue
        if rec is not None:
            current[rec["cve"]] = rec
            kept += 1
    records = [current[k] for k in sorted(current)]
    if records:
        write_shard(data_dir, "redhat-vex", records)
    return {
        "source": source.source_id,
        "license": source.license,
        "documents": seen,
        "kept": kept,
        "malformed": bad,
        "cves": len(records),
        "retrievedAt": stamp,
    }
