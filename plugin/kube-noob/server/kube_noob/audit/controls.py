"""NIST SP 800-53 Rev. 5 controls each audit rule gives evidence for.

FedRAMP (Rev5 baselines and the 20x Key Security Indicators) and most US federal frameworks are expressed in NIST SP
800-53 controls. Mapping every rule to the controls it supports lets an audit report double as configuration evidence
for CM-6, AC-6, SC-7 and the rest. A mapping says which control a finding is evidence about; it is not an assessment
and does not make a system compliant.

Source: NIST SP 800-53 Rev. 5 (https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final), control titles as published.
"""

from __future__ import annotations

from typing import Any

CATALOG = "NIST SP 800-53 Rev. 5"
CATALOG_URL = "https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final"

TITLES: dict[str, str] = {
    "AC-3": "Access Enforcement",
    "AC-4": "Information Flow Enforcement",
    "AC-5": "Separation of Duties",
    "AC-6": "Least Privilege",
    "AC-6(5)": "Least Privilege | Privileged Accounts",
    "AC-6(10)": "Least Privilege | Prohibit Non-privileged Users from Executing Privileged Functions",
    "CM-2": "Baseline Configuration",
    "CM-3(2)": "Configuration Change Control | Testing, Validation, and Documentation of Changes",
    "CM-6": "Configuration Settings",
    "CM-7": "Least Functionality",
    "CP-10": "System Recovery and Reconstitution",
    "IA-5": "Authenticator Management",
    "IA-5(7)": "Authenticator Management | No Embedded Unencrypted Static Authenticators",
    "SA-22": "Unsupported System Components",
    "SC-5": "Denial-of-service Protection",
    "SC-6": "Resource Availability",
    "SC-7": "Boundary Protection",
    "SC-7(5)": "Boundary Protection | Deny by Default — Allow by Exception",
    "SC-8": "Transmission Confidentiality and Integrity",
    "SC-8(1)": "Transmission Confidentiality and Integrity | Cryptographic Protection",
    "SC-28": "Protection of Information at Rest",
    "SC-36": "Distributed Processing and Storage",
    "SC-39": "Process Isolation",
    "SI-2": "Flaw Remediation",
    "SI-7": "Software, Firmware, and Information Integrity",
}

_VALIDATION = ("CM-3(2)", "CM-6")

RULE_CONTROLS: dict[str, tuple[str, ...]] = {
    # Security context and workload privileges
    "KN-S001": ("AC-6", "CM-7", "SC-39"),
    "KN-S002": ("AC-6", "AC-6(10)", "CM-7"),
    "KN-S003": ("AC-6", "CM-6"),
    "KN-S004": ("CM-6", "AC-6"),
    "KN-S005": ("AC-6", "CM-7"),
    "KN-S006": ("AC-6", "CM-7"),
    "KN-S007": ("CM-7", "SI-7"),
    "KN-S008": ("CM-6", "CM-7", "SC-39"),
    "KN-S009": ("SC-39", "AC-6"),
    "KN-S010": ("AC-6", "SC-39"),
    "KN-S011": ("SC-7", "CM-7"),
    "KN-S012": ("CM-2", "SI-7"),
    "KN-S013": ("IA-5(7)", "SC-28"),
    "KN-S014": ("AC-6", "IA-5", "CM-7"),
    "KN-S015": ("AC-3", "AC-6"),
    "KN-S016": ("AC-6", "AC-6(5)"),
    "KN-S017": ("AC-3", "AC-5", "AC-6"),
    "KN-S018": ("IA-5(7)", "SC-28"),
    "KN-S019": ("AC-6", "CM-7", "SC-39"),
    "KN-S020": ("SC-39", "CM-7"),
    # Network exposure
    "KN-N001": ("SC-7", "SC-7(5)", "AC-4"),
    "KN-N002": ("SC-8", "SC-8(1)"),
    "KN-N003": ("SC-8", "SC-8(1)"),
    "KN-N004": ("SC-7", "AC-4"),
    "KN-N005": ("SC-7", "CM-7"),
    "KN-N006": ("SC-7", "SC-7(5)", "AC-4"),
    "KN-N007": ("SC-7", "SC-7(5)", "AC-4"),
    # Storage
    "KN-ST001": ("CM-6",),
    "KN-ST002": ("CM-6", "CP-10"),
    "KN-ST003": ("SC-36", "CM-6"),
    "KN-ST004": ("CM-6",),
    "KN-ST005": ("CM-6", "SC-6"),
    # Reliability and capacity
    "KN-C001": ("CP-10",),
    "KN-C002": ("CP-10",),
    "KN-C003": ("CP-10", "SC-5"),
    "KN-C004": ("SC-6",),
    "KN-C005": ("SC-5", "SC-6"),
    "KN-C006": ("CM-6",),
    "KN-C007": ("CP-10", "SC-36"),
    "KN-C008": ("CP-10",),
    "KN-C009": ("SI-2", "CP-10"),  # a PDB that blocks every eviction blocks node patching
    "KN-C010": ("SC-36",),
    "KN-C011": ("CP-10",),
    "KN-C012": ("SC-6",),
    # Validation: changes are tested before they reach the cluster
    "KN-V001": _VALIDATION,
    "KN-V002": _VALIDATION,
    "KN-V003": _VALIDATION,
    "KN-V004": _VALIDATION,
    "KN-V005": ("CM-3(2)", "SA-22"),
    "KN-V006": ("SA-22",),
    "KN-V008": ("SA-22",),
    "KN-V009": _VALIDATION,
    "KN-V010": _VALIDATION,
    "KN-V011": _VALIDATION,
    "KN-V012": _VALIDATION,
    "KN-V014": _VALIDATION,
    "KN-V015": ("SC-7", "CM-6"),  # an EgressFirewall not named 'default' is ignored: no egress control at all
    "KN-V016": ("SC-8", "CM-6"),
    "KN-V017": ("CM-6",),
    "KN-V018": _VALIDATION,
}


def controls_for(rule_id: str) -> list[str]:
    return list(RULE_CONTROLS.get(rule_id, ()))


def describe(rule_id: str) -> list[dict[str, str]]:
    return [{"id": c, "title": TITLES[c]} for c in RULE_CONTROLS.get(rule_id, ())]


def summary(rule_ids: list[str]) -> dict[str, Any]:
    """Controls touched by a set of findings, most findings first: for an audit report."""
    counts: dict[str, int] = {}
    for rid in rule_ids:
        for c in RULE_CONTROLS.get(rid, ()):
            counts[c] = counts.get(c, 0) + 1
    ordered = sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))
    return {
        "catalog": CATALOG,
        "controls": [{"id": c, "title": TITLES[c], "findings": n} for c, n in ordered],
        "note": "Findings are evidence about these controls; an assessment decides whether a control is met.",
    }
