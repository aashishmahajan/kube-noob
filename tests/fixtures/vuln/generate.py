"""One image's vulnerability findings in every format kube-noob reads, the Red Hat VEX that speaks to them, and
what the assessment must say, computed here from the planted values (requirements R5.1-R5.3).

``python tests/fixtures/vuln/generate.py <dir>`` writes:

- ``trivy.json``, ``grype.json``, ``cyclonedx-trivy.json`` (Trivy's CycloneDX: fix as "recommendation"),
  ``cyclonedx-grype.json`` (Grype's CycloneDX: fix as an "unaffected" vers range), ``rhacs-image.json``
  (``GET /v1/images/{id}``): 40 findings on the image ``registry.example.com/shop/web``;
- ``cyclonedx-sbom.json`` and ``spdx.json``: the same image's packages, no findings (syft-style purls with
  ``epoch``, ``distro`` and ``upstream``);
- ``vex/2099/cve-2099-*.json``: Red Hat CSAF VEX in the shape Red Hat publishes, 22 fixed, 6 known affected and 12
  known not affected (one statement per finding);
- ``api-trivy.json``: two critical findings on ``registry.example.com/shop/api:2.1``;
- ``kev.json``: a KEV catalog listing one planted CVE (CVE-2099-1005, a medium curl finding on the web image);
- ``expected.json``: the 40 normalised findings, the 12 excluded and the 28 kept, from the planted data.

The CVE ids are in 2099 so they cannot be mistaken for real ones. The manifests (``shop.yaml``) are a fixture of
their own, written by hand.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

WEB = "registry.example.com/shop/web"
WEB_DIGEST = "sha256:" + "a1" * 32
WEB_IMAGE_ID = "sha256:" + "b2" * 32
API = "registry.example.com/shop/api"

# srpm -> (epoch, version, release, binaries installed)
PACKAGES: dict[str, tuple[int, str, str, tuple[str, ...]]] = {
    "bash": (0, "5.1.8", "9.el9", ("bash",)),
    "openssl": (1, "3.0.7", "27.el9", ("openssl-libs",)),
    "glibc": (0, "2.34", "100.el9", ("glibc", "glibc-common")),
    "curl": (0, "7.76.1", "29.el9", ("curl-minimal", "libcurl-minimal")),
    "libxml2": (0, "2.9.13", "6.el9", ("libxml2",)),
    "sqlite": (0, "3.34.1", "7.el9", ("sqlite-libs",)),
    "expat": (0, "2.5.0", "2.el9", ("expat",)),
    "krb5": (0, "1.21.1", "1.el9", ("krb5-libs",)),
    "systemd": (0, "252", "32.el9", ("systemd-libs",)),
    "zlib": (0, "1.2.11", "40.el9", ("zlib",)),
    "python3.9": (0, "3.9.18", "3.el9", ("python3", "python3-libs")),
    "gnutls": (0, "3.8.3", "4.el9", ("gnutls",)),
    "pam": (0, "1.5.1", "19.el9", ("pam",)),
    "shadow-utils": (2, "4.9", "8.el9", ("shadow-utils",)),
    "tar": (2, "1.34", "6.el9", ("tar",)),
    "coreutils": (0, "8.32", "35.el9", ("coreutils-single",)),
    "libssh": (0, "0.10.4", "13.el9", ("libssh", "libssh-config")),
    "ncurses": (0, "6.2", "10.20210508.el9", ("ncurses-base", "ncurses-libs")),
}
FIXED = {  # cve -> (srpm, fixed release)
    "CVE-2099-1001": ("bash", "10.el9"),
    "CVE-2099-1002": ("openssl", "28.el9"),
    "CVE-2099-1003": ("openssl", "29.el9"),
    "CVE-2099-1004": ("glibc", "105.el9"),
    "CVE-2099-1005": ("curl", "31.el9"),
    "CVE-2099-1006": ("curl", "31.el9"),
    "CVE-2099-1007": ("libxml2", "9.el9"),
    "CVE-2099-1008": ("sqlite", "8.el9"),
    "CVE-2099-1009": ("expat", "3.el9"),
    "CVE-2099-1010": ("krb5", "2.el9"),
    "CVE-2099-1011": ("systemd", "46.el9"),
    "CVE-2099-1012": ("zlib", "41.el9"),
    "CVE-2099-1013": ("python3.9", "4.el9"),
    "CVE-2099-1014": ("gnutls", "6.el9"),
    "CVE-2099-1015": ("pam", "20.el9"),
    "CVE-2099-1016": ("libssh", "15.el9"),
    "CVE-2099-1017": ("shadow-utils", "9.el9"),
}
AFFECTED = {  # cve -> (srpm, remediation category)
    "CVE-2099-1018": ("tar", "no_fix_planned"),
    "CVE-2099-1019": ("coreutils", "none_available"),
    "CVE-2099-1020": ("ncurses", "none_available"),
    "CVE-2099-1021": ("systemd", "none_available"),
    "CVE-2099-1022": ("zlib", "none_available"),
}
NOT_AFFECTED = {  # cve -> (srpm, VEX justification flag)
    "CVE-2099-1023": ("openssl", "vulnerable_code_not_present"),
    "CVE-2099-1024": ("bash", "vulnerable_code_not_present"),
    "CVE-2099-1025": ("krb5", "vulnerable_code_not_in_execute_path"),
    "CVE-2099-1026": ("libxml2", "component_not_present"),
    "CVE-2099-1027": ("expat", "vulnerable_code_not_present"),
    "CVE-2099-1028": ("pam", "inline_mitigations_already_exist"),
    "CVE-2099-1029": ("sqlite", "vulnerable_code_not_present"),
    "CVE-2099-1030": ("gnutls", "vulnerable_code_cannot_be_controlled_by_adversary"),
    "CVE-2099-1031": ("shadow-utils", "vulnerable_code_not_present"),
    "CVE-2099-1032": ("tar", "vulnerable_code_not_present"),
    "CVE-2099-1033": ("coreutils", "vulnerable_code_not_in_execute_path"),
    "CVE-2099-1034": ("zlib", "vulnerable_code_not_present"),
}
SCORES = [9.8, 7.5, 5.3, 8.1, 6.5, 4.3, 7.8, 9.1, 5.9, 3.7]
PLANTED_KEV = "CVE-2099-1005"
PLANTED_KEV_SCORE = 6.5


def cvss(cve: str) -> float:
    if cve == PLANTED_KEV:
        return PLANTED_KEV_SCORE
    return SCORES[int(cve[-4:]) % len(SCORES)]


def sev(score: float) -> str:
    return "critical" if score >= 9 else "high" if score >= 7 else "medium" if score >= 4 else "low"


def red_hat_severity(score: float) -> str:
    return {"critical": "Critical", "high": "Important", "medium": "Moderate", "low": "Low"}[sev(score)]


def evr(epoch: int, version: str, release: str) -> str:
    return f"{epoch}:{version}-{release}" if epoch else f"{version}-{release}"


def purl(name: str, srpm: str, epoch: int, version: str, release: str) -> str:
    q = "arch=x86_64&distro=rhel-9.4" + (f"&epoch={epoch}" if epoch else "")
    return f"pkg:rpm/redhat/{name}@{version}-{release}?{q}&upstream={srpm}-{version}-{release}.src.rpm"


def findings() -> list[dict[str, str]]:
    """Every (binary, CVE) the scanners report, with installed and fix version."""
    out = []
    for cve, (srpm, rel) in FIXED.items():
        e, v, r, bins = PACKAGES[srpm]
        out += [{"cve": cve, "srpm": srpm, "package": b, "version": evr(e, v, r), "fix": evr(e, v, rel)} for b in bins]
    for cve, (srpm, _) in {**AFFECTED, **NOT_AFFECTED}.items():
        e, v, r, bins = PACKAGES[srpm]
        out += [{"cve": cve, "srpm": srpm, "package": b, "version": evr(e, v, r), "fix": ""} for b in bins]
    return sorted(out, key=lambda f: (f["package"], f["cve"]))


def trivy(items: list[dict[str, str]]) -> dict:  # type: ignore[type-arg]
    vulns, pkgs = [], []
    for srpm, (e, v, r, bins) in PACKAGES.items():
        for b in bins:
            pkgs.append(
                {
                    "ID": f"{b}@{v}-{r}.x86_64",
                    "Name": b,
                    "Identifier": {"PURL": purl(b, srpm, e, v, r).replace("distro=rhel-9.4", "distro=redhat-9.4")},
                    "Version": v,
                    "Release": r,
                    **({"Epoch": e} if e else {}),
                    "Arch": "x86_64",
                    "SrcName": srpm,
                    "SrcVersion": v,
                    "SrcRelease": r,
                    **({"SrcEpoch": e} if e else {}),
                }
            )
    for f in items:
        e, v, r, _ = PACKAGES[f["srpm"]]
        s = cvss(f["cve"])
        vulns.append(
            {
                "VulnerabilityID": f["cve"],
                "PkgID": f"{f['package']}@{v}-{r}.x86_64",
                "PkgName": f["package"],
                "PkgIdentifier": {
                    "PURL": purl(f["package"], f["srpm"], e, v, r)
                    .split("&upstream=")[0]
                    .replace("distro=rhel-9.4", "distro=redhat-9.4")
                },
                "InstalledVersion": f["version"],
                **({"FixedVersion": f["fix"]} if f["fix"] else {}),
                "Status": "fixed" if f["fix"] else "affected",
                "Layer": {"Digest": "sha256:" + "c3" * 32},
                "SeveritySource": "redhat",
                "Title": f"{f['srpm']}: planted test vulnerability",
                "Severity": sev(s).upper(),
                "CVSS": {"redhat": {"V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "V3Score": s}},
            }
        )
    return {
        "SchemaVersion": 2,
        "ArtifactName": f"{WEB}:1.4",
        "ArtifactType": "container_image",
        "Metadata": {
            "OS": {"Family": "redhat", "Name": "9.4"},
            "ImageID": WEB_IMAGE_ID,
            "RepoTags": [f"{WEB}:1.4"],
            "RepoDigests": [f"{WEB}@{WEB_DIGEST}"],
        },
        "Results": [
            {
                "Target": f"{WEB}:1.4 (redhat 9.4)",
                "Class": "os-pkgs",
                "Type": "redhat",
                "Packages": pkgs,
                "Vulnerabilities": vulns,
            }
        ],
    }


def grype(items: list[dict[str, str]]) -> dict:  # type: ignore[type-arg]
    matches = []
    for f in items:
        e, v, r, _ = PACKAGES[f["srpm"]]
        s = cvss(f["cve"])
        matches.append(
            {
                "vulnerability": {
                    "id": f["cve"],
                    "dataSource": f"https://access.redhat.com/security/cve/{f['cve']}",
                    "namespace": "redhat:distro:redhat:9",
                    "severity": sev(s).capitalize(),
                    "urls": [],
                    "cvss": [
                        {
                            "source": "secalert@redhat.com",
                            "type": "Secondary",
                            "version": "3.1",
                            "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                            "metrics": {"baseScore": s},
                            "vendorMetadata": {},
                        }
                    ],
                    "fix": {"versions": [f["fix"]] if f["fix"] else [], "state": "fixed" if f["fix"] else "not-fixed"},
                    "advisories": [],
                    "risk": 0.0,
                },
                "relatedVulnerabilities": [],
                "matchDetails": [],
                "artifact": {
                    "id": f"{f['package']}-id",
                    "name": f["package"],
                    "version": f"{e}:{v}-{r}" if e else f"{v}-{r}",
                    "type": "rpm",
                    "locations": [],
                    "language": "",
                    "licenses": [],
                    "cpes": [],
                    "purl": purl(f["package"], f["srpm"], e, v, r),
                    "upstreams": [{"name": f["srpm"]}],
                },
            }
        )
    return {
        "matches": matches,
        "source": {
            "type": "image",
            "target": {
                "userInput": f"{WEB}:1.4",
                "imageID": WEB_IMAGE_ID,
                "manifestDigest": WEB_DIGEST,
                "tags": [f"{WEB}:1.4"],
                "repoDigests": [f"{WEB}@{WEB_DIGEST}"],
            },
        },
        "distro": {"name": "redhat", "version": "9.4", "idLike": ["fedora"]},
        "descriptor": {"name": "grype", "version": "0.100.0"},
    }


def _components(style: str) -> list[dict]:  # type: ignore[type-arg]
    comps = []
    for srpm, (e, v, r, bins) in PACKAGES.items():
        for b in bins:
            p = purl(b, srpm, e, v, r)
            ref = p if style != "grype" else p + "&package-id=" + b
            props = [{"name": "aquasecurity:trivy:SrcName", "value": srpm}] if style == "trivy" else []
            comps.append(
                {
                    "bom-ref": ref,
                    "type": "library",
                    "name": b,
                    "version": f"{e}:{v}-{r}" if e else f"{v}-{r}",
                    "purl": p,
                    **({"properties": props} if props else {}),
                }
            )
    comps.append(
        {
            "bom-ref": "pkg:pypi/requests@2.31.0",
            "type": "library",
            "name": "requests",
            "version": "2.31.0",
            "purl": "pkg:pypi/requests@2.31.0",
        }
    )
    comps.append({"bom-ref": "os-1", "type": "operating-system", "name": "rhel", "version": "9.4"})
    return comps


def cyclonedx(items: list[dict[str, str]] | None, style: str) -> dict:  # type: ignore[type-arg]
    comps = _components(style)
    doc: dict = {  # type: ignore[type-arg]
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "metadata": {
            "component": {
                "bom-ref": "image",
                "type": "container",
                "name": f"{WEB}:1.4",
                "properties": [
                    {"name": "aquasecurity:trivy:ImageID", "value": WEB_IMAGE_ID},
                    {"name": "aquasecurity:trivy:RepoDigest", "value": f"{WEB}@{WEB_DIGEST}"},
                ],
            }
        },
        "components": comps,
    }
    if items is None:
        return doc
    by_name = {c["name"]: c for c in comps}
    vulns: dict[str, dict] = {}  # type: ignore[type-arg]
    for f in items:
        c = by_name[f["package"]]
        s = cvss(f["cve"])
        v = vulns.setdefault(
            f["cve"],
            {
                "id": f["cve"],
                "source": {"name": "redhat", "url": f"https://access.redhat.com/security/cve/{f['cve']}"},
                "ratings": [{"source": {"name": "redhat"}, "score": s, "severity": sev(s), "method": "CVSSv31"}],
                "affects": [],
            },
        )
        versions: list[dict] = [{"version": c["version"], "status": "affected"}]  # type: ignore[type-arg]
        if f["fix"] and style == "grype":
            versions.append({"range": f"vers:rpm/>={f['fix']}", "status": "unaffected"})
        v["affects"].append({"ref": c["bom-ref"], "versions": versions})
        if f["fix"] and style == "trivy":
            rec = f"Upgrade {f['package']} to version {f['fix']}"
            recs = [x for x in v.get("recommendation", "").split("; ") if x]
            v["recommendation"] = "; ".join(sorted({*recs, rec}))
    doc["vulnerabilities"] = list(vulns.values())
    return doc


def spdx() -> dict:  # type: ignore[type-arg]
    packages = []
    for srpm, (e, v, r, bins) in PACKAGES.items():
        for b in bins:
            packages.append(
                {
                    "SPDXID": f"SPDXRef-Package-rpm-{b}",
                    "name": b,
                    "versionInfo": f"{e}:{v}-{r}" if e else f"{v}-{r}",
                    "downloadLocation": "NOASSERTION",
                    "externalRefs": [
                        {
                            "referenceCategory": "PACKAGE-MANAGER",
                            "referenceType": "purl",
                            "referenceLocator": purl(b, srpm, e, v, r),
                        }
                    ],
                }
            )
    packages.append(
        {
            "SPDXID": "SPDXRef-Package-python-requests",
            "name": "requests",
            "versionInfo": "2.31.0",
            "downloadLocation": "NOASSERTION",
            "externalRefs": [
                {
                    "referenceCategory": "PACKAGE-MANAGER",
                    "referenceType": "purl",
                    "referenceLocator": "pkg:pypi/requests@2.31.0",
                }
            ],
        }
    )
    return {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": f"{WEB}:1.4",
        "documentNamespace": "https://example.com/spdx/shop-web-1.4",
        "creationInfo": {"created": "2026-10-28T00:00:00Z", "creators": ["Tool: fixture"]},
        "packages": packages,
    }


def rhacs(items: list[dict[str, str]]) -> dict:  # type: ignore[type-arg]
    by_pkg: dict[str, list[dict[str, str]]] = {}
    for f in items:
        by_pkg.setdefault(f["package"], []).append(f)
    comps = []
    for srpm, (e, v, r, bins) in PACKAGES.items():
        for b in bins:
            comps.append(
                {
                    "name": b,
                    "version": f"{e}:{v}-{r}" if e else f"{v}-{r}",
                    "source": "OS",
                    "vulns": [
                        {
                            "cve": f["cve"],
                            "cvss": cvss(f["cve"]),
                            "summary": f"{srpm}: planted test vulnerability",
                            "link": f"https://access.redhat.com/security/cve/{f['cve']}",
                            **({"fixedBy": f["fix"]} if f["fix"] else {}),
                            "severity": {
                                "critical": "CRITICAL_VULNERABILITY_SEVERITY",
                                "high": "IMPORTANT_VULNERABILITY_SEVERITY",
                                "medium": "MODERATE_VULNERABILITY_SEVERITY",
                                "low": "LOW_VULNERABILITY_SEVERITY",
                            }[sev(cvss(f["cve"]))],
                            "cisaKev": False,
                        }
                        for f in by_pkg.get(b, [])
                    ],
                }
            )
    return {
        "id": WEB_DIGEST,
        "name": {"registry": "registry.example.com", "remote": "shop/web", "tag": "1.4", "fullName": f"{WEB}:1.4"},
        "scan": {"scannerVersion": "4.6.0", "operatingSystem": "rhel:9", "components": comps},
    }


def _vex(cve: str) -> dict:  # type: ignore[type-arg]
    """A CSAF VEX document in Red Hat's shape for one planted CVE."""
    s = cvss(cve)
    branches_products = [
        {
            "category": "product_name",
            "name": "Red Hat Enterprise Linux 9",
            "product": {
                "name": "Red Hat Enterprise Linux 9",
                "product_id": "red_hat_enterprise_linux_9",
                "product_identification_helper": {"cpe": "cpe:/o:redhat:enterprise_linux:9"},
            },
        },
        {
            "category": "product_name",
            "name": "Red Hat Enterprise Linux BaseOS (v. 9)",
            "product": {
                "name": "Red Hat Enterprise Linux BaseOS (v. 9)",
                "product_id": "BaseOS-9.4.0.Z.MAIN",
                "product_identification_helper": {"cpe": "cpe:/o:redhat:enterprise_linux:9::baseos"},
            },
        },
        {
            "category": "product_name",
            "name": "Red Hat Enterprise Linux 8",
            "product": {
                "name": "Red Hat Enterprise Linux 8",
                "product_id": "red_hat_enterprise_linux_8",
                "product_identification_helper": {"cpe": "cpe:/o:redhat:enterprise_linux:8"},
            },
        },
    ]
    versions, relationships = [], []
    status: dict[str, list[str]] = {}
    flags, remediations = [], []
    if cve in FIXED:
        srpm, rel = FIXED[cve]
        e, v, _, bins = PACKAGES[srpm]
        nevra = [(srpm, "src"), *((b, "x86_64") for b in bins)]
        ids = []
        for name, arch in nevra:
            pid = f"{name}-{e}:{v}-{rel}.{arch}" if e else f"{name}-{v}-{rel}.{arch}"
            q = f"arch={arch}" + (f"&epoch={e}" if e else "")
            versions.append(
                {
                    "category": "product_version",
                    "name": pid,
                    "product": {
                        "name": pid,
                        "product_id": pid,
                        "product_identification_helper": {"purl": f"pkg:rpm/redhat/{name}@{v}-{rel}?{q}"},
                    },
                }
            )
            full = f"BaseOS-9.4.0.Z.MAIN:{pid}"
            relationships.append(
                {
                    "category": "default_component_of",
                    "full_product_name": {
                        "name": f"{pid} as a component of Red Hat Enterprise Linux BaseOS (v. 9)",
                        "product_id": full,
                    },
                    "product_reference": pid,
                    "relates_to_product_reference": "BaseOS-9.4.0.Z.MAIN",
                }
            )
            ids.append(full)
        status["fixed"] = ids
        remediations.append(
            {
                "category": "vendor_fix",
                "details": "For details on how to apply this update, refer to the advisory.",
                "url": f"https://access.redhat.com/errata/RHSA-2099:{cve[-4:]}",
                "product_ids": ids,
            }
        )
    else:
        srpm, extra = AFFECTED.get(cve) or NOT_AFFECTED[cve]
        versions.append(
            {
                "category": "product_version",
                "name": srpm,
                "product": {
                    "name": srpm,
                    "product_id": srpm,
                    "product_identification_helper": {"purl": f"pkg:rpm/redhat/{srpm}?arch=src"},
                },
            }
        )
        full = f"red_hat_enterprise_linux_9:{srpm}"
        relationships.append(
            {
                "category": "default_component_of",
                "full_product_name": {
                    "name": f"{srpm} as a component of Red Hat Enterprise Linux 9",
                    "product_id": full,
                },
                "product_reference": srpm,
                "relates_to_product_reference": "red_hat_enterprise_linux_9",
            }
        )
        if cve in AFFECTED:
            status["known_affected"] = [full]
            remediations.append({"category": extra, "details": "Affected", "product_ids": [full]})
        else:
            status["known_not_affected"] = [full]
            flags.append({"label": extra, "product_ids": [full]})
        # the same component on RHEL 8 is affected: a statement for another product must not apply to RHEL 9
        full8 = f"red_hat_enterprise_linux_8:{srpm}"
        relationships.append(
            {
                "category": "default_component_of",
                "full_product_name": {
                    "name": f"{srpm} as a component of Red Hat Enterprise Linux 8",
                    "product_id": full8,
                },
                "product_reference": srpm,
                "relates_to_product_reference": "red_hat_enterprise_linux_8",
            }
        )
        status.setdefault("known_affected", []).append(full8)
    return {
        "document": {
            "category": "csaf_vex",
            "csaf_version": "2.0",
            "title": f"{cve}: planted test vulnerability",
            "aggregate_severity": {
                "namespace": "https://access.redhat.com/security/updates/classification/",
                "text": red_hat_severity(s),
            },
            "publisher": {
                "category": "vendor",
                "name": "Red Hat Product Security",
                "namespace": "https://www.redhat.com",
            },
            "distribution": {
                "text": "Copyright (c) Red Hat, Inc. Licensed under CC BY 4.0.",
                "tlp": {"label": "WHITE"},
            },
            "tracking": {
                "id": cve,
                "current_release_date": "2026-10-20T00:00:00+00:00",
                "initial_release_date": "2026-01-01T00:00:00+00:00",
                "status": "final",
                "version": "1",
                "revision_history": [],
            },
        },
        "product_tree": {
            "branches": [
                {
                    "category": "vendor",
                    "name": "Red Hat",
                    "branches": [
                        {
                            "category": "product_family",
                            "name": "Red Hat Enterprise Linux",
                            "branches": branches_products,
                        },
                        *versions,
                    ],
                }
            ],
            "relationships": relationships,
        },
        "vulnerabilities": [
            {
                "cve": cve,
                "title": "planted test vulnerability",
                "product_status": status,
                "flags": flags,
                "remediations": remediations,
                "scores": [
                    {
                        "cvss_v3": {
                            "version": "3.1",
                            "baseScore": s,
                            "baseSeverity": sev(s).upper(),
                            "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                        },
                        "products": [],
                    }
                ],
            }
        ],
    }


def api_trivy() -> dict:  # type: ignore[type-arg]
    vulns = [
        {
            "VulnerabilityID": cve,
            "PkgName": "openssl-libs",
            "PkgIdentifier": {"PURL": "pkg:rpm/redhat/openssl-libs@3.0.7-27.el9?arch=x86_64&distro=redhat-9.4&epoch=1"},
            "InstalledVersion": "1:3.0.7-27.el9",
            "FixedVersion": "1:3.0.7-30.el9",
            "Status": "fixed",
            "SeveritySource": "redhat",
            "Severity": "CRITICAL",
            "CVSS": {"redhat": {"V3Score": 9.8}},
        }
        for cve in ("CVE-2099-2001", "CVE-2099-2002")
    ]
    return {
        "SchemaVersion": 2,
        "ArtifactName": f"{API}:2.1",
        "ArtifactType": "container_image",
        "Metadata": {"OS": {"Family": "redhat", "Name": "9.4"}, "RepoTags": [f"{API}:2.1"]},
        "Results": [
            {"Target": f"{API}:2.1 (redhat 9.4)", "Class": "os-pkgs", "Type": "redhat", "Vulnerabilities": vulns}
        ],
    }


def kev() -> dict:  # type: ignore[type-arg]
    return {
        "title": "CISA Catalog of Known Exploited Vulnerabilities",
        "catalogVersion": "2099.01.01",
        "dateReleased": "2099-01-01T00:00:00.000Z",
        "count": 1,
        "vulnerabilities": [
            {
                "cveID": PLANTED_KEV,
                "vendorProject": "Planted",
                "product": "curl",
                "vulnerabilityName": "Planted curl vulnerability",
                "dateAdded": "2099-01-01",
                "shortDescription": "A planted test entry.",
                "requiredAction": "Apply mitigations per vendor instructions.",
                "dueDate": "2099-01-22",
                "knownRansomwareCampaignUse": "Unknown",
                "notes": "",
                "cwes": [],
            }
        ],
    }


def main(out: Path) -> None:
    out.mkdir(parents=True, exist_ok=True)
    items = findings()
    assert len(items) == 40, len(items)
    docs = {
        "trivy.json": trivy(items),
        "grype.json": grype(items),
        "cyclonedx-trivy.json": cyclonedx(items, "trivy"),
        "cyclonedx-grype.json": cyclonedx(items, "grype"),
        "rhacs-image.json": rhacs(items),
        "cyclonedx-sbom.json": cyclonedx(None, "syft"),
        "spdx.json": spdx(),
        "api-trivy.json": api_trivy(),
        "kev.json": kev(),
    }
    for name, doc in docs.items():
        (out / name).write_text(json.dumps(doc, indent=1, sort_keys=True) + "\n", encoding="utf-8")
    vex_dir = out / "vex" / "2099"
    vex_dir.mkdir(parents=True, exist_ok=True)
    for cve in sorted({*FIXED, *AFFECTED, *NOT_AFFECTED}):
        (vex_dir / f"{cve.lower()}.json").write_text(json.dumps(_vex(cve), indent=1) + "\n", encoding="utf-8")
    normalised = [
        {"package": f["package"], "version": f["version"], "cve": f["cve"], "fixVersion": f["fix"]} for f in items
    ]
    excluded = sorted((f["package"], f["cve"]) for f in items if f["cve"] in NOT_AFFECTED)
    kept = [n for n in normalised if n["cve"] not in NOT_AFFECTED]
    expected = {
        "normalised": sorted(normalised, key=lambda n: (n["package"], n["version"], n["cve"])),
        "excluded": [list(x) for x in excluded],
        "excludedJustification": {cve: j for cve, (_, j) in NOT_AFFECTED.items()},
        "kept": sorted(kept, key=lambda n: (n["package"], n["version"], n["cve"])),
        "wontFix": sorted(
            f["package"] + " " + f["cve"] for f in items if AFFECTED.get(f["cve"], ("", ""))[1] == "no_fix_planned"
        ),
        "plantedKev": {"cve": PLANTED_KEV, "package": "curl-minimal", "score": PLANTED_KEV_SCORE},
    }
    (out / "expected.json").write_text(json.dumps(expected, indent=1, sort_keys=True) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main(Path(sys.argv[1]))
