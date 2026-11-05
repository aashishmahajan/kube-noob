#!/usr/bin/env python3
"""Write an SPDX 2.3 SBOM for the release, from `requirements.lock` and the package metadata.

Generated offline from the hash-locked file the release actually installs, so the inventory is the
inventory, not a scan of whatever happened to be on the build machine. No network, no new dependency,
nothing to pin: a tool that is offline by default should be able to state its own bill of materials
without reaching for one.

    python scripts/sbom.py --check    # exit 1 when the committed document is stale
    python scripts/sbom.py            # rewrite it
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
LOCK = ROOT / "requirements.lock"
OUT = ROOT / "docs" / "sbom.spdx.json"
_PIN = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)==([^\s\;]+)")


def version() -> str:
    text = (ROOT / "src" / "kube_noob" / "__init__.py").read_text(encoding="utf-8")
    m = re.search(r'__version__ = "(.+)"', text)
    if m is None:  # pragma: no cover - the package always declares one
        raise SystemExit("src/kube_noob/__init__.py declares no __version__")
    return m.group(1)


def dependencies() -> list[tuple[str, str, list[str]]]:
    """``(name, version, sha256 hashes)`` for every pin, in the order the lock file lists them."""
    out: list[tuple[str, str, list[str]]] = []
    for raw in LOCK.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if line.startswith("--hash=sha256:") and out:
            # A pin with several hashes continues with a trailing backslash on every line but the last.
            out[-1][2].append(line.removeprefix("--hash=sha256:").rstrip("\\").strip())
            continue
        m = _PIN.match(line)
        if m and not line.startswith("#"):
            out.append((m.group(1), m.group(2), []))
    return out


def _spdx_id(name: str) -> str:
    return "SPDXRef-Package-" + re.sub(r"[^A-Za-z0-9.-]", "-", name)


def document() -> dict[str, Any]:
    v = version()
    deps = dependencies()
    root = "SPDXRef-Package-kube-noob"
    packages: list[dict[str, Any]] = [
        {
            "SPDXID": root,
            "name": "kube-noob",
            "versionInfo": v,
            "downloadLocation": "https://pypi.org/project/kube-noob/",
            "filesAnalyzed": False,
            "licenseConcluded": "Apache-2.0",
            "licenseDeclared": "Apache-2.0",
            "supplier": "NOASSERTION",
            "externalRefs": [
                {
                    "referenceCategory": "PACKAGE-MANAGER",
                    "referenceType": "purl",
                    "referenceLocator": f"pkg:pypi/kube-noob@{v}",
                }
            ],
        }
    ]
    relationships: list[dict[str, str]] = [
        {"spdxElementId": "SPDXRef-DOCUMENT", "relationshipType": "DESCRIBES", "relatedSpdxElement": root}
    ]
    for name, dep_version, hashes in deps:
        sid = _spdx_id(f"{name}-{dep_version}")
        entry: dict[str, Any] = {
            "SPDXID": sid,
            "name": name,
            "versionInfo": dep_version,
            "downloadLocation": f"https://pypi.org/project/{name}/{dep_version}/",
            "filesAnalyzed": False,
            "licenseConcluded": "NOASSERTION",
            "licenseDeclared": "NOASSERTION",
            "supplier": "NOASSERTION",
            "externalRefs": [
                {
                    "referenceCategory": "PACKAGE-MANAGER",
                    "referenceType": "purl",
                    "referenceLocator": f"pkg:pypi/{name}@{dep_version}",
                }
            ],
        }
        if hashes:
            # The lock pins one hash per wheel or sdist. They are recorded so the SBOM states exactly
            # which artifacts the release is allowed to install, not merely which versions.
            entry["checksums"] = [{"algorithm": "SHA256", "checksumValue": h} for h in sorted(hashes)]
        packages.append(entry)
        relationships.append({"spdxElementId": root, "relationshipType": "DEPENDS_ON", "relatedSpdxElement": sid})
    # The namespace must be stable for a given content, or every regeneration is a diff. It is derived
    # from the version and a digest of the lock rather than from a timestamp or a random UUID.
    digest = hashlib.sha256(LOCK.read_bytes()).hexdigest()[:32]
    return {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": f"kube-noob-{v}",
        "documentNamespace": f"https://kube-noob.com/spdx/kube-noob/{v}/{digest}",
        "creationInfo": {
            "created": "1970-01-01T00:00:00Z",
            "creators": ["Tool: kube-noob-sbom"],
            "comment": "Generated offline from requirements.lock. The created timestamp is fixed so the "
            "document is reproducible: its identity is the namespace digest, not the time it was written.",
        },
        "packages": packages,
        "relationships": relationships,
    }


def render() -> str:
    return json.dumps(document(), indent=2, sort_keys=False) + "\n"


def _rel(path: Path) -> str:
    """The path as the reader sees it, without assuming it sits under the repository."""
    try:
        return str(path.relative_to(ROOT))
    except ValueError:
        return str(path)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--check", action="store_true", help="exit 1 when the committed document is stale")
    a = ap.parse_args(argv)
    text = render()
    if a.check:
        current = OUT.read_text(encoding="utf-8") if OUT.is_file() else ""
        if current != text:
            print(f"{_rel(OUT)} is stale: run python scripts/sbom.py", file=sys.stderr)
            return 1
        print(f"{_rel(OUT)} is current ({len(document()['packages'])} packages)")
        return 0
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(text, encoding="utf-8")
    print(f"wrote {_rel(OUT)} ({len(document()['packages'])} packages)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
