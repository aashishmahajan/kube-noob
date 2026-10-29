"""What kube-noob knows about Red Hat's public Jira, shared by the sync (``sources.jira``) and the ticket index
(``tickets``) without pulling the network client into the Claude plugin: the site, key formats, the default project
set with the product each project is about, and version parsing."""

from __future__ import annotations

import re

DEFAULT_BASE_URL = "https://redhat.atlassian.net"
PROJECT_KEY = re.compile(r"^[A-Z][A-Z0-9_]{1,29}\Z")
ISSUE_KEY = re.compile(r"^([A-Z][A-Z0-9_]{1,29})-(\d{1,9})\Z")
_VERSION_RE = re.compile(r"(?<![\d.])(\d{1,2})\.(\d{1,2})(?:\.(\d{1,3}))?(?![\d])")

# Projects on Red Hat's Jira that track OpenShift, ROSA, ACM, RHACS and the operators people run on them; keys checked
# against /rest/api/3/project/search on 2026-10-28 (292 public projects then). The value is the product the tickets
# are about: "openshift" tickets only apply to OpenShift-family platforms, "any" ones to every Kubernetes.
DEFAULT_PROJECTS: dict[str, str] = {
    "OCPBUGS": "openshift",  # OpenShift Bugs: every OpenShift component, the main tracker since 2022
    "HOSTEDCP": "openshift",  # Hosted control planes (ROSA HCP, HyperShift)
    "OCMUI": "openshift",  # OpenShift Cluster Manager UI (ROSA, OSD)
    "RFE": "openshift",  # OpenShift requests for enhancement: "not supported yet" answers
    "OKD": "openshift",
    "CNV": "openshift",  # OpenShift Virtualization
    "OSSM": "openshift",  # Service Mesh
    "LOG": "openshift",  # Logging
    "NETOBSERV": "openshift",
    "COO": "openshift",  # Cluster Observability Operator
    "TRACING": "openshift",
    "OADP": "openshift",  # API for Data Protection (Velero)
    "GITOPS": "openshift",
    "SRVKP": "openshift",  # Pipelines
    "SRVKS": "openshift",  # Serverless
    "DFBUGS": "openshift",  # Data Foundation
    "MTV": "openshift",  # Migration Toolkit for Virtualization
    "USHIFT": "openshift",  # MicroShift
    "WINC": "openshift",  # Windows containers
    "ESO": "openshift",  # External Secrets Operator
    "CM": "openshift",  # cert-manager Operator
    "SSCSI": "openshift",  # Secrets Store CSI
    "KATA": "openshift",  # Sandboxed containers
    "OSSO": "openshift",  # Secondary scheduler
    "OCPKUEUE": "openshift",
    "ACM": "any",  # Advanced Cluster Management manages non-OpenShift clusters too
    "PROJQUAY": "any",  # Quay
    "ROX": "any",  # Advanced Cluster Security (RHACS / StackRox) runs on any Kubernetes
}


# Projects whose fixVersions are OpenShift releases (4.21.3), so they can be compared with the cluster's version.
# Operators (OADP 1.4, Logging 5.9, Pipelines 1.17, CNV's own z-streams...) and RHACS have their own version lines.
OPENSHIFT_VERSIONED = frozenset({"OCPBUGS", "OKD", "HOSTEDCP", "USHIFT"})


def product_of(project: str) -> str:
    """ "openshift" for projects whose tickets only concern OpenShift; "any" otherwise (including unknown projects)."""
    return DEFAULT_PROJECTS.get(project, "any")


def parse_version(s: str) -> tuple[int, int, int] | None:
    m = _VERSION_RE.search(s)
    if not m:
        return None
    return int(m.group(1)), int(m.group(2)), int(m.group(3) or 0)
