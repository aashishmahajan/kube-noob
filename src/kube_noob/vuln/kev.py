"""The CISA Known Exploited Vulnerabilities catalog, read from a file (requirements R5.3).

CISA publishes the catalog under CC0 1.0 (https://github.com/cisagov/kev-data, LICENSE checked 2026-10-28) as
``known_exploited_vulnerabilities.json``: ``title``, ``catalogVersion``, ``dateReleased``, ``count`` and
``vulnerabilities[]`` with ``cveID``, ``vendorProject``, ``product``, ``vulnerabilityName``, ``dateAdded``,
``shortDescription``, ``requiredAction``, ``dueDate``, ``knownRansomwareCampaignUse``, ``notes`` and ``cwes``.
kube-noob reads a copy on disk (``--kev``); it does not download it here (VUL2 adds it to the database build).
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

MAX_BYTES = 20_000_000
MAX_ENTRIES = 100_000
_CVE = re.compile(r"^CVE-\d{4}-\d{4,7}\Z")
SOURCE_URL = "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"


class KevError(ValueError):
    """Not the KEV catalog, or one over its bounds."""


@dataclass(frozen=True)
class KevEntry:
    cve: str
    vendor: str
    product: str
    name: str
    date_added: str
    due_date: str
    required_action: str
    ransomware: str  # Known | Unknown

    def as_dict(self) -> dict[str, Any]:
        return {
            "cve": self.cve,
            "vendorProject": self.vendor,
            "product": self.product,
            "vulnerabilityName": self.name,
            "dateAdded": self.date_added,
            "dueDate": self.due_date,
            "requiredAction": self.required_action,
            "knownRansomwareCampaignUse": self.ransomware,
            "source": SOURCE_URL,
        }


@dataclass
class Kev:
    entries: dict[str, KevEntry] = field(default_factory=dict)
    catalog_version: str = ""
    date_released: str = ""
    origin: str = ""

    def get(self, cve: str) -> KevEntry | None:
        return self.entries.get(cve.upper())

    def describe(self) -> str:
        if not self.entries:
            return "no KEV catalog given"
        return f"CISA KEV {self.catalog_version or '?'} ({self.date_released[:10] or '?'}), {len(self.entries)} CVEs"


def _s(v: Any, n: int = 300) -> str:
    return str(v)[:n] if isinstance(v, (str, int)) and not isinstance(v, bool) else ""


def parse(data: str | bytes, origin: str = "KEV catalog") -> Kev:
    raw = data.encode("utf-8") if isinstance(data, str) else data
    if len(raw) > MAX_BYTES:
        raise KevError(f"{origin}: larger than {MAX_BYTES} bytes")
    try:
        doc = json.loads(raw)
    except (ValueError, RecursionError) as exc:
        raise KevError(f"{origin}: not JSON") from exc
    if not isinstance(doc, dict) or not isinstance(doc.get("vulnerabilities"), list) or "catalogVersion" not in doc:
        raise KevError(f"{origin}: not the CISA KEV catalog (no catalogVersion and vulnerabilities)")
    vulns = doc["vulnerabilities"]
    if len(vulns) > MAX_ENTRIES:
        raise KevError(f"{origin}: more than {MAX_ENTRIES} entries")
    kev = Kev(catalog_version=_s(doc.get("catalogVersion"), 40), date_released=_s(doc.get("dateReleased"), 40))
    kev.origin = origin
    for v in vulns:
        if not isinstance(v, dict):
            continue
        cve = _s(v.get("cveID"), 40).strip().upper()
        if not _CVE.match(cve):
            continue
        kev.entries[cve] = KevEntry(
            cve,
            _s(v.get("vendorProject"), 120),
            _s(v.get("product"), 120),
            _s(v.get("vulnerabilityName"), 200),
            _s(v.get("dateAdded"), 20),
            _s(v.get("dueDate"), 20),
            _s(v.get("requiredAction"), 400),
            _s(v.get("knownRansomwareCampaignUse"), 20),
        )
    return kev


def load(path: Path) -> Kev:
    if not path.is_file():
        raise KevError(f"{path}: no such file")
    if path.stat().st_size > MAX_BYTES:
        raise KevError(f"{path}: larger than {MAX_BYTES} bytes")
    return parse(path.read_bytes(), str(path.name))
