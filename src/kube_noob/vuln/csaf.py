"""Red Hat CSAF VEX documents read into kube-noob statements, with no network and no file access (R5.2, R5.5).

``parse_vex`` keeps, per CVE, the title, severity, CVSS base score and each component's status for the products in
``PRODUCTS`` (or the CPE prefixes given): fixed (with the erratum), known affected (with the remediation category),
known not affected (with the VEX justification flag) or under investigation. ``kube_noob.sources.advisories`` fetches
and stores the documents; ``kube_noob.vuln.vex`` applies the statements to findings. This module is what the Claude
plugin ships of both.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

HOST = "security.access.redhat.com"
BASE = f"https://{HOST}/data/csaf/v2/vex"
MAX_DOC = 25_000_000  # bytes: one VEX document (OpenShift CVEs list thousands of components)
MAX_STATEMENTS = 4000  # kept per CVE after filtering to the default products
_CVE = re.compile(r"^CVE-(\d{4})-(\d{4,7})\Z")


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
    for child in _list(node.get("branches")):
        _walk(child, out, depth + 1)


def _index(tree: Any) -> tuple[dict[str, dict[str, str]], dict[str, tuple[str, str]]]:
    products: dict[str, dict[str, str]] = {}
    full: dict[str, tuple[str, str]] = {}
    if not isinstance(tree, dict):
        return products, full
    for branch in _list(tree.get("branches")):
        _walk(branch, products)
    for rel in _list(tree.get("relationships")):
        if not isinstance(rel, dict):
            continue
        fpn = rel.get("full_product_name") or {}
        pid = fpn.get("product_id") if isinstance(fpn, dict) else None
        if isinstance(pid, str):
            full[pid] = (str(rel.get("product_reference", "")), str(rel.get("relates_to_product_reference", "")))
    return products, full


def _list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def module_stream(purl: str, component: str = "") -> str:
    """The RPM module stream (``nodejs:20``) a statement is about: the purl's ``rpmmod`` qualifier, or Red Hat's
    ``<module>:<stream>/<package>`` component name; empty for a package outside a module."""
    m = re.search(r"[?&]rpmmod=([^&#]+)", purl)
    if m:
        parts = m.group(1).replace("%3A", ":").replace("%3a", ":").split(":")
        if len(parts) >= 2 and parts[0] and parts[1]:
            return f"{parts[0]}:{parts[1]}"[:120]
    m = re.match(r"^([A-Za-z0-9_.+-]+):([A-Za-z0-9_.+-]+)/[^/]+$", component)
    return f"{m.group(1)}:{m.group(2)}"[:120] if m else ""


def _component_name(purl: str, fallback: str) -> str:
    m = re.match(r"pkg:[a-z]+/(?:[^/@?]+/)*?([^/@?]+)(?:@|\?|$)", purl)
    if purl.startswith("pkg:oci/"):
        repo = re.search(r"repository_url=[^&]*?/([^&/]+/[^&/]+)(?:&|$)", purl)
        if repo:
            return repo.group(1)
    if m:
        return m.group(1)
    return fallback.rsplit("/", 1)[-1] if re.match(r"^[A-Za-z0-9_.+-]+:[A-Za-z0-9_.+-]+/[^/]+$", fallback) else fallback


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
    for f in _list(vuln.get("flags")):
        if isinstance(f, dict):
            for pid in _list(f.get("product_ids")):
                flags[str(pid)] = str(f.get("label", ""))[:80]
    fixes: dict[str, dict[str, str]] = {}
    for r in _list(vuln.get("remediations")):
        if isinstance(r, dict):
            fix = {
                "category": str(r.get("category", ""))[:40],
                **({"url": str(r["url"])[:300]} if r.get("url") else {}),
                **({"details": " ".join(str(r["details"]).split())[:300]} if r.get("details") else {}),
            }
            for pid in _list(r.get("product_ids")):
                fixes.setdefault(str(pid), fix)
    statements: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str, str, str]] = set()
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
            raw_name = component.get("name", "") or pid.split(":", 1)[-1]
            name = _component_name(purl, raw_name)
            stream = module_stream(purl, raw_name)
            # one statement per product, package, status, module stream and fixed build: two streams of a module
            # (nodejs:18 and nodejs:20) are fixed in different versions and must not collapse into one
            key = (cpe, name, status, stream, purl if status == "fixed" else "")
            total += 1
            if key in seen:
                continue
            seen.add(key)
            st: dict[str, Any] = {"product": product.get("name", ""), "cpe": cpe, "component": name, "status": status}
            if stream:
                st["stream"] = stream
            if purl:
                st["purl"] = purl
            if status == "known_not_affected" and pid in flags:
                st["justification"] = flags[pid]
            if status in {"fixed", "known_affected"} and pid in fixes:
                st["fix"] = fixes[pid]
            statements.append(st)
    if not statements:
        return None
    statements.sort(key=lambda s: (s["cpe"], s["component"], s.get("stream", ""), s["status"], s.get("purl", "")))
    cut = len(statements) > MAX_STATEMENTS
    statements = statements[:MAX_STATEMENTS]
    title = " ".join(str(vuln.get("title") or doc["document"].get("title") or cve).split())[:300]
    severity = ""
    agg = doc["document"].get("aggregate_severity")
    if isinstance(agg, dict):
        severity = str(agg.get("text", "")).lower()[:20]
    score = None
    for s in _list(vuln.get("scores")):
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
