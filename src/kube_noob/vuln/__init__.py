"""Vulnerability findings from what scanners already produce (requirements R5.1-R5.4).

- ``reports``: Trivy and Grype JSON, CycloneDX and SPDX SBOMs, RHACS image scans, read into one normalised finding
  (package, installed version, CVE, fix version) with bounded, hostile-tested parsers.
- ``vex``: Red Hat CSAF VEX statements (from the ``redhat-vex`` corpus shard or documents on disk) applied to those
  findings, and SBOM packages matched against them; every dropped finding cites its statement.
- ``kev``: the CISA Known Exploited Vulnerabilities catalog (CC0 1.0), read from a file.
- ``rank``: reachability ranking with the attack-path model (exposure, privileges, RBAC reach, exploitation).
- ``threat``: a STRIDE threat model per application from its manifests, with the rules and policies that mitigate
  each threat and MITRE ATT&CK for Containers technique ids.
"""
