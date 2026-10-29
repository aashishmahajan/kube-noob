"""Apply Red Hat VEX to findings, and match SBOM packages against it (requirements R5.2).

Statements come from the ``redhat-vex`` corpus shard (``kube-noob corpus advisories``) and from CSAF VEX documents
given on the command line (a file, a folder of ``<year>/cve-*.json``, or Red Hat's ``csaf_vex`` archive), parsed by
``kube_noob.vuln.csaf.parse_vex``. A statement applies to a finding when its CVE is the finding's, its
product CPE is one of the image's (RHEL ``N`` -> ``cpe:/o:redhat:enterprise_linux:N`` and
``cpe:/a:redhat:enterprise_linux:N``, or ``--product``), and its component is the package's source RPM or the binary
package itself (Red Hat names the source RPM in not-affected statements, and both in fixed ones).

- known not affected: the finding drops out, citing the statement and its VEX justification.
- fixed: the finding drops out when the installed version is at or above every matching fixed version (``rpm``'s
  comparison); otherwise it stays, with the fixed version when the scanner had none.
- known affected and under investigation: the finding stays, citing the statement.

Only RPMs are matched, and only Red Hat's (purl namespace ``redhat``, or none given): VEX for RHEL says nothing about
Python, Java or JavaScript packages in the image, or about RPMs from other vendors. Those findings are kept as they
are, and the output says how many were outside VEX.
"""

from __future__ import annotations

import functools
import json
import re
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from kube_noob.vuln import rpmver
from kube_noob.vuln.csaf import module_stream
from kube_noob.vuln.reports import Finding, Package, parse_purl, severity

MAX_SHARD_BYTES = 2_000_000_000
MAX_LINE = 30_000_000
MAX_DOCUMENTS = 100_000


class VexError(ValueError):
    """VEX input that cannot be read."""


@dataclass(frozen=True)
class Statement:
    cve: str
    status: str  # fixed | known_affected | known_not_affected | under_investigation
    product: str
    cpe: str
    component: str
    purl: str = ""
    justification: str = ""
    fix_category: str = ""
    fix_url: str = ""
    severity: str = ""
    cvss: float | None = None
    updated: str = ""
    origin: str = ""
    stream: str = ""  # the RPM module stream (nodejs:20), empty for a package outside a module

    @property
    def fixed_version(self) -> str:
        p = parse_purl(self.purl)
        if not p or not p.version:
            return ""
        epoch = p.qualifiers.get("epoch", "")
        v = f"{epoch}:{p.version}" if epoch.isdigit() and epoch != "0" else p.version
        return rpmver.normalise(v)

    def cite(self) -> dict[str, Any]:
        year = self.cve.split("-")[1] if self.cve.count("-") >= 2 else ""
        out: dict[str, Any] = {
            "cve": self.cve,
            "status": self.status,
            "product": self.product,
            "cpe": self.cpe,
            "component": self.component,
            "url": f"https://access.redhat.com/security/cve/{self.cve}",
            "document": f"https://security.access.redhat.com/data/csaf/v2/vex/{year}/{self.cve.lower()}.json",
            "source": self.origin,
        }
        if self.stream:
            out["stream"] = self.stream
        if self.justification:
            out["justification"] = self.justification
        if self.status == "fixed" and self.fixed_version:
            out["fixedIn"] = self.fixed_version
        if self.fix_url:
            out["erratum"] = self.fix_url
        if self.fix_category and self.status != "fixed":
            out["remediation"] = self.fix_category
        if self.updated:
            out["vexUpdated"] = self.updated
        return out


def rhel_products(distro: tuple[str, str] | None) -> tuple[str, ...]:
    """CPE prefixes of the RHEL release an image is built on, from its distro (``("rhel", "9.4")``)."""
    if not distro or distro[0] != "rhel":
        return ()
    major = distro[1].split(".")[0]
    if not major.isdigit():
        return ()
    return (f"cpe:/o:redhat:enterprise_linux:{major}", f"cpe:/a:redhat:enterprise_linux:{major}")


def _cpe_matches(cpe: str, prefixes: Iterable[str]) -> bool:
    return any(cpe == p or cpe.startswith(p + ":") for p in prefixes)


@dataclass
class VexIndex:
    by_cve: dict[str, list[Statement]] = field(default_factory=dict)
    by_component: dict[str, set[str]] = field(default_factory=dict)
    origins: list[str] = field(default_factory=list)
    documents: int = 0

    def add_record(self, rec: dict[str, Any], origin: str) -> None:
        cve = str(rec.get("cve") or "")
        statements = rec.get("statements")
        if not cve.startswith("CVE-") or not isinstance(statements, list):
            return
        sev = severity(rec.get("severity"))
        cvss = rec.get("cvss") if isinstance(rec.get("cvss"), (int, float)) else None
        updated = str(rec.get("vexUpdated") or "")[:40]
        out = self.by_cve.setdefault(cve, [])
        out.clear()  # the newest record for a CVE wins (documents after the corpus)
        for st in statements:
            if not isinstance(st, dict):
                continue
            fix = st.get("fix") if isinstance(st.get("fix"), dict) else {}
            component = str(st.get("component") or "")[:300]
            purl = str(st.get("purl") or "")[:2000]
            stream = str(st.get("stream") or "")[:120] or module_stream(purl, component)
            if "/" in component and module_stream("", component):  # records written before streams were kept
                component = component.rsplit("/", 1)[-1]
            s = Statement(
                cve=cve,
                status=str(st.get("status") or ""),
                product=str(st.get("product") or "")[:300],
                cpe=str(st.get("cpe") or "")[:300],
                component=component,
                purl=purl,
                stream=stream,
                justification=str(st.get("justification") or "")[:80],
                fix_category=str((fix or {}).get("category") or "")[:40],
                fix_url=str((fix or {}).get("url") or "")[:300],
                severity=sev,
                cvss=float(cvss) if cvss is not None else None,
                updated=updated,
                origin=origin,
            )
            out.append(s)
            self.by_component.setdefault(s.component, set()).add(cve)

    def statements(self, cve: str, names: Iterable[str], prefixes: tuple[str, ...]) -> list[Statement]:
        wanted = {n for n in names if n}
        return [s for s in self.by_cve.get(cve, []) if s.component in wanted and _cpe_matches(s.cpe, prefixes)]

    def cves_for(self, names: Iterable[str]) -> list[str]:
        out: set[str] = set()
        for n in names:
            out |= self.by_component.get(n, set())
        return sorted(out)


def _corpus_records(data_dir: Path) -> Iterator[dict[str, Any]]:
    shard = data_dir / "corpus" / "redhat-vex.jsonl"
    if not shard.is_file():
        return
    if shard.stat().st_size > MAX_SHARD_BYTES:
        raise VexError(f"{shard}: larger than {MAX_SHARD_BYTES} bytes")
    with shard.open(encoding="utf-8") as fh:
        for line in fh:
            if not line.strip() or len(line) > MAX_LINE:
                continue
            try:
                rec = json.loads(line)
            except ValueError:
                continue
            if isinstance(rec, dict):
                yield rec


def _documents(path: Path) -> Iterator[Any]:
    from kube_noob.vuln.csaf import MAX_DOC

    if path.is_file() and path.suffix == ".json":
        if path.stat().st_size > MAX_DOC:
            raise VexError(f"{path}: larger than {MAX_DOC} bytes")
        try:
            yield json.loads(path.read_bytes())
        except (ValueError, RecursionError) as exc:
            raise VexError(f"{path}: not JSON") from exc
        return
    if path.is_dir():
        files = sorted(p for p in path.rglob("*.json") if p.is_file() and not p.is_symlink())
        if len(files) > MAX_DOCUMENTS:
            raise VexError(
                f"{path}: {len(files)} VEX documents, more than {MAX_DOCUMENTS}: point --vex at the years you need "
                "(csaf_vex/2024 csaf_vex/2025), or load them once with kube-noob corpus advisories"
            )
        for f in files:
            if f.stat().st_size > MAX_DOC:
                continue
            try:
                yield json.loads(f.read_bytes())
            except (ValueError, RecursionError):
                continue
        return
    if path.is_file():
        try:
            from kube_noob.sources.advisories import from_archive
        except ImportError as exc:  # the Claude plugin ships the parser, not the archive reader
            raise VexError(f"{path}: VEX archives are read by the kube-noob CLI; pass the documents instead") from exc
        yield from from_archive(path)
        return
    raise VexError(f"{path}: no such file or folder")


def load(
    data_dir: Path | None,
    paths: Iterable[Path] = (),
    texts: Iterable[str] = (),
    products: Iterable[str] = (),
    use_corpus: bool = True,
) -> VexIndex:
    """Statements from the corpus shard, then from ``paths`` and ``texts`` (CSAF VEX JSON); later ones win per CVE."""
    from kube_noob.vuln.csaf import PRODUCTS, AdvisoryError, parse_vex

    index = VexIndex()
    if use_corpus and data_dir is not None:
        n = 0
        for rec in _corpus_records(data_dir):
            index.add_record(rec, "kube-noob corpus (redhat-vex)")
            n += 1
        if n:
            index.origins.append(f"corpus shard redhat-vex: {n} CVEs")
    keep = tuple(dict.fromkeys([*PRODUCTS, *products]))

    def take(doc: Any, origin: str) -> None:
        try:
            rec = parse_vex(doc, keep)
        except AdvisoryError as exc:
            raise VexError(f"{origin}: {exc}") from exc
        index.documents += 1
        if rec is not None:
            index.add_record(rec, origin)

    for path in paths:
        before = index.documents
        for doc in _documents(path):
            if index.documents >= MAX_DOCUMENTS:
                raise VexError(f"more than {MAX_DOCUMENTS} VEX documents")
            take(doc, f"VEX file {path.name}")
        index.origins.append(f"{path}: {index.documents - before} VEX documents")
    for i, text in enumerate(texts):
        try:
            doc = json.loads(text)
        except (ValueError, RecursionError) as exc:
            raise VexError(f"VEX document {i + 1}: not JSON") from exc
        take(doc, f"VEX document {i + 1}")
    if list(texts):
        index.origins.append(f"{len(list(texts))} VEX documents given inline")
    return index


_CPE_PREFIX = re.compile(r"^cpe:/[aho]:[a-z0-9_.-]+:[a-z0-9_.-]+:[0-9][a-z0-9_.-]*(?::[A-Za-z0-9_.:-]*)?\Z")
# Red Hat's dist tags: el9, el9_4, el9_4.1, and module builds (module+el9.3.0+...); a vendor suffix (.ngx) is not one
_RED_HAT_RELEASE = re.compile(r"(?:^|\.)el\d+(?:_\d+)*(?:\.\d+)*\Z|\.module[+_]el\d+[.\d]*(?:\+[A-Za-z0-9.+_]+)?\Z")
_MODULAR = re.compile(r"\.module[+_]el\d")


def validate_products(products: Iterable[str]) -> tuple[str, ...]:
    """CPE prefixes down to a release (cpe:/o:redhat:enterprise_linux:9): a prefix without one would let a RHEL 8
    statement speak for a RHEL 9 image."""
    out = tuple(products)
    bad = [p for p in out if not _CPE_PREFIX.match(p)]
    if bad:
        raise VexError(
            f"product CPE prefixes must name a release, like cpe:/o:redhat:enterprise_linux:9: {', '.join(bad[:3])}"
        )
    return out


def _red_hat_rpm(pkg: Package) -> bool:
    """An RPM Red Hat built: purl namespace redhat or none (Trivy and syft write redhat for every RPM of a RHEL image,
    RHACS writes no purl), and a Red Hat dist tag in the release, which a vendor's own build (nginx.org's
    1.26.1-2.el9.ngx, Fedora's fc40) does not end with."""
    if pkg.ecosystem != "rpm" or pkg.namespace not in {"", "redhat"}:
        return False
    release = pkg.version.rsplit("-", 1)[-1] if "-" in pkg.version else ""
    return bool(_RED_HAT_RELEASE.search(release))


def _names(pkg: Package) -> list[str]:
    return list(dict.fromkeys(n for n in (pkg.source, pkg.name) if n))


def _package_stream(pkg: Package, candidates: set[str]) -> str:
    """The module stream of an installed package: its purl's rpmmod qualifier, else the one stream among the
    statements whose stream version is the package's version or a dotted prefix of it (nodejs:20 for 20.5.0)."""
    p = parse_purl(pkg.purl)
    label = (p.qualifiers.get("rpmmod") or p.qualifiers.get("modularitylabel") or "") if p else ""
    if label:
        parts = label.split(":")
        if len(parts) >= 2:
            return f"{parts[0]}:{parts[1]}"
    upstream = pkg.version.split(":", 1)[-1].rsplit("-", 1)[0]
    hits = [s for s in candidates if upstream == s.split(":", 1)[-1] or upstream.startswith(s.split(":", 1)[-1] + ".")]
    return hits[0] if len(hits) == 1 else ""


def _valid_versions(stmts: list[Statement]) -> list[str]:
    out = []
    for s in stmts:
        v = s.fixed_version
        try:
            rpmver.split_evr(v)
        except ValueError:
            continue
        out.append(v)
    return sorted(set(out), key=_evr_key)


@dataclass
class Decision:
    drop: str | None = None  # why the finding drops out, when it does
    cited: list[Statement] = field(default_factory=list)
    fix: str | None = None  # the fixed version Red Hat names, when the installed one is older
    state: str | None = None
    note: str = ""


def decide(pkg: Package, stmts: list[Statement]) -> Decision:
    """What Red Hat's statements (already this CVE, this package and this product) say about this installed package.
    Statements for a module stream apply only to that stream's packages, and stream-less ones only to packages
    outside a module. A finding drops out only when every applicable statement agrees it is not affected or fixed at
    or below the installed version; statements that disagree keep it."""
    streams = {s.stream for s in stmts if s.stream}
    modular = bool(_MODULAR.search(pkg.version)) or "rpmmod=" in pkg.purl
    stream = _package_stream(pkg, streams) if (modular or streams) else ""
    if modular or stream:
        use = [s for s in stmts if s.stream and s.stream == stream]
        if not use:
            why = f"module stream {stream or 'unknown'}: no Red Hat statement for it" if streams or modular else ""
            return Decision(note=why)
    else:
        use = [s for s in stmts if not s.stream]
        if not use:
            return Decision()
    not_affected = [s for s in use if s.status == "known_not_affected"]
    fixed = [s for s in use if s.status == "fixed"]
    affected = [s for s in use if s.status in {"known_affected", "under_investigation"}]
    versions = _valid_versions(fixed)
    installed_has_fix = bool(versions) and _installed_has_fix(pkg.version, versions)
    still_vulnerable = bool(affected) or (bool(versions) and not installed_has_fix)
    if not_affected and still_vulnerable:
        return Decision(cited=use, note="Red Hat VEX statements disagree (not affected and affected): kept")
    if not_affected:
        just = not_affected[0].justification
        return Decision("Red Hat VEX: known not affected" + (f" ({just})" if just else ""), not_affected)
    if installed_has_fix and not affected:
        return Decision(f"Red Hat VEX: fixed in {versions[-1]}, installed {pkg.version}", fixed)
    d = Decision(cited=use)
    if versions and not installed_has_fix:
        d.fix, d.state = versions[-1], "fixed"
    elif affected:
        no_plan = any(s.fix_category == "no_fix_planned" for s in affected)
        d.state = "wont-fix" if no_plan else "not-fixed"
    if fixed and not versions:
        d.note = "a fixed statement names no readable version"
    return d


@dataclass
class Applied:
    kept: list[Finding]
    excluded: list[dict[str, Any]]
    outside: int  # findings VEX does not speak to (not a Red Hat RPM)
    unmatched: int  # Red Hat RPM findings with no statement
    notes: list[str]


def _installed_has_fix(installed: str, fixed: list[str]) -> bool:
    try:
        return all(rpmver.compare_evr(installed, f) >= 0 for f in fixed)
    except ValueError:
        return False


def _status_note(stmts: list[Statement]) -> str:
    return "Red Hat VEX: " + ", ".join(sorted({s.status.replace("_", " ") for s in stmts}))


def apply(findings: list[Finding], index: VexIndex, prefixes: tuple[str, ...]) -> Applied:
    kept: list[Finding] = []
    excluded: list[dict[str, Any]] = []
    outside = unmatched = 0
    notes: list[str] = []
    if not prefixes:
        notes.append("the image's Red Hat product is not known (no RHEL distro in the report): pass --product")
    no_source = vendor = 0
    for f in findings:
        if not prefixes or not _red_hat_rpm(f.package):
            outside += 1
            vendor += bool(prefixes) and f.package.ecosystem == "rpm"
            kept.append(f)
            continue
        no_source += not f.package.source
        stmts = index.statements(f.cve, _names(f.package), prefixes)
        if not stmts:
            unmatched += 1
            kept.append(f)
            continue
        d = decide(f.package, stmts)
        if d.drop:
            excluded.append({"finding": f.as_dict(), "reason": d.drop, "statements": [s.cite() for s in d.cited]})
            continue
        if d.fix and not f.fix_versions:
            f.fix_versions = (d.fix,)
        if f.fix_versions:
            f.fix_state = "fixed"
        elif d.state:
            f.fix_state = d.state
        if d.cited:
            f.notes.append(_status_note(d.cited))
            f.vex = [s.cite() for s in d.cited]
        if d.note:
            f.notes.append(d.note)
        kept.append(f)
    if no_source:
        notes.append(
            f"{no_source} Red Hat RPM findings carry no source RPM name (RHACS, and Trivy JSON without "
            "--list-all-pkgs, name binary packages only); Red Hat's not-affected statements name source RPMs, so "
            "some may be missed: give the image's SBOM too"
        )
    if vendor:
        notes.append(f"{vendor} RPM findings are not Red Hat builds (no Red Hat dist tag): Red Hat VEX not applied")
    return Applied(kept, excluded, outside, unmatched, notes)


_EVR_KEY = functools.cmp_to_key(rpmver.compare_evr)


def _evr_key(v: str) -> Any:
    return _EVR_KEY(v)


def match_packages(packages: list[Package], index: VexIndex, prefixes: tuple[str, ...]) -> Applied:
    """Findings for SBOM packages: each Red Hat RPM against every statement naming it for the image's product."""
    findings: list[Finding] = []
    excluded: list[dict[str, Any]] = []
    outside = 0
    notes: list[str] = []
    if not prefixes:
        notes.append("the image's Red Hat product is not known (no RHEL distro in the SBOM): pass --product")
    seen: set[tuple[str, str, str]] = set()
    for pkg in packages:
        if pkg.key in seen:
            continue
        seen.add(pkg.key)
        if not prefixes or not _red_hat_rpm(pkg):
            outside += 1
            continue
        names = _names(pkg)
        for cve in index.cves_for(names):
            stmts = index.statements(cve, names, prefixes)
            if not stmts:
                continue
            d = decide(pkg, stmts)
            first = stmts[0]
            finding = Finding(
                cve, cve, pkg, severity=first.severity or "unknown", cvss=first.cvss, sources=["sbom+vex"]
            )
            if d.drop:
                if d.drop.startswith("Red Hat VEX: known not affected"):
                    excluded.append(
                        {"finding": finding.as_dict(), "reason": d.drop, "statements": [s.cite() for s in d.cited]}
                    )
                continue  # fixed in the installed version: not a finding
            if not d.cited:
                continue  # no statement for this package's stream: nothing to say
            finding.fix_versions = (d.fix,) if d.fix else ()
            finding.fix_state = d.state or "unknown"
            finding.notes.append(_status_note(d.cited))
            if d.note:
                finding.notes.append(d.note)
            finding.vex = [s.cite() for s in d.cited]
            findings.append(finding)
    return Applied(findings, excluded, outside, 0, notes)
