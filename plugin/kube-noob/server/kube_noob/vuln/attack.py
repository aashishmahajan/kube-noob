"""MITRE ATT&CK for Containers techniques kube-noob's threat model names (requirements R5.4).

Read from MITRE's STIX bundle (https://github.com/mitre-attack/attack-stix-data, ``enterprise-attack/
enterprise-attack.json`` at commit c2494b29dd268c46a5d0ea0990553e4327cd2253: Enterprise ATT&CK 20.0, 2026-10-13):
attack patterns whose ``x_mitre_platforms`` include Containers, not revoked or deprecated. Only the techniques the
model uses are listed, with their tactics as ATT&CK names them.

ATT&CK terms of use (https://github.com/mitre-attack/attack-stix-data/blob/master/LICENSE.txt): royalty-free for
research, development and commercial use, provided MITRE's copyright designation and the licence are reproduced
(THIRD_PARTY_NOTICES.md carries both). ``ATTRIBUTION`` travels with every threat model kube-noob writes.
"""

from __future__ import annotations

from typing import Any

VERSION = "Enterprise ATT&CK 20.0"
ATTRIBUTION = (
    "MITRE ATT&CK technique ids and names: © 2026 The MITRE Corporation. This work is reproduced and distributed "
    "with the permission of The MITRE Corporation. https://attack.mitre.org"
)

TECHNIQUES: dict[str, tuple[str, tuple[str, ...]]] = {
    "T1036.005": ("Match Legitimate Resource Name or Location", ("stealth",)),
    "T1046": ("Network Service Discovery", ("discovery",)),
    "T1068": ("Exploitation for Privilege Escalation", ("privilege-escalation",)),
    "T1098.006": ("Additional Container Cluster Roles", ("persistence", "privilege-escalation")),
    "T1190": ("Exploit Public-Facing Application", ("initial-access",)),
    "T1204.003": ("Malicious Image", ("execution",)),
    "T1485": ("Data Destruction", ("impact",)),
    "T1496.001": ("Compute Hijacking", ("impact",)),
    "T1499": ("Endpoint Denial of Service", ("impact",)),
    "T1525": ("Implant Internal Image", ("persistence",)),
    "T1528": ("Steal Application Access Token", ("credential-access",)),
    "T1550.001": ("Application Access Token", ("lateral-movement",)),
    "T1552.001": ("Credentials In Files", ("credential-access",)),
    "T1552.007": ("Container API", ("credential-access",)),
    "T1609": ("Container Administration Command", ("execution",)),
    "T1610": ("Deploy Container", ("execution",)),
    "T1611": ("Escape to Host", ("privilege-escalation",)),
    "T1613": ("Container and Resource Discovery", ("discovery",)),
}


def technique(tid: str) -> dict[str, Any]:
    name, tactics = TECHNIQUES[tid]
    return {
        "id": tid,
        "name": name,
        "tactics": list(tactics),
        "url": f"https://attack.mitre.org/techniques/{tid.replace('.', '/')}/",
    }
