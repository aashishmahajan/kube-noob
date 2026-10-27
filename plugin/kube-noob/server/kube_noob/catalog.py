"""Static platform knowledge: API groups, kind -> apiVersion catalog, removed APIs, OCP<->Kubernetes
version map, storage provisioner capabilities.

Every table carries the source it was verified against (``SOURCES`` keys) so findings can credit it.
Update procedure: change the table, update the matching ``SOURCES`` entry, run ``pytest tests/test_catalog.py``.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

Platform = Literal["kubernetes", "openshift", "rosa-classic", "rosa-hcp"]
PLATFORMS: tuple[Platform, ...] = ("kubernetes", "openshift", "rosa-classic", "rosa-hcp")
OPENSHIFT_FAMILY: frozenset[str] = frozenset({"openshift", "rosa-classic", "rosa-hcp"})
ROSA_FAMILY: frozenset[str] = frozenset({"rosa-classic", "rosa-hcp"})


@dataclass(frozen=True)
class Citation:
    source_id: str
    title: str
    url: str
    license: str = "unknown"
    version: str | None = None

    def as_dict(self) -> dict[str, str | None]:
        return {
            "sourceId": self.source_id,
            "title": self.title,
            "url": self.url,
            "license": self.license,
            "version": self.version,
        }


SOURCES: dict[str, Citation] = {
    "k8s-deprecation-guide": Citation(
        "k8s-deprecation-guide",
        "Kubernetes Deprecated API Migration Guide",
        "https://kubernetes.io/docs/reference/using-api/deprecation-guide/",
        "CC-BY-4.0",
    ),
    "k8s-pss": Citation(
        "k8s-pss",
        "Kubernetes Pod Security Standards",
        "https://kubernetes.io/docs/concepts/security/pod-security-standards/",
        "CC-BY-4.0",
    ),
    "k8s-probes": Citation(
        "k8s-probes",
        "Configure Liveness, Readiness and Startup Probes",
        "https://kubernetes.io/docs/tasks/configure-pod-container/configure-liveness-readiness-startup-probes/",
        "CC-BY-4.0",
    ),
    "k8s-resources": Citation(
        "k8s-resources",
        "Resource Management for Pods and Containers",
        "https://kubernetes.io/docs/concepts/configuration/manage-resources-containers/",
        "CC-BY-4.0",
    ),
    "k8s-pv-access-modes": Citation(
        "k8s-pv-access-modes",
        "Persistent Volumes - Access Modes",
        "https://kubernetes.io/docs/concepts/storage/persistent-volumes/#access-modes",
        "CC-BY-4.0",
    ),
    "k8s-storageclass-binding": Citation(
        "k8s-storageclass-binding",
        "Storage Classes - Volume Binding Mode",
        "https://kubernetes.io/docs/concepts/storage/storage-classes/#volume-binding-mode",
        "CC-BY-4.0",
    ),
    "k8s-networkpolicy": Citation(
        "k8s-networkpolicy",
        "Network Policies",
        "https://kubernetes.io/docs/concepts/services-networking/network-policies/",
        "CC-BY-4.0",
    ),
    "k8s-pdb": Citation(
        "k8s-pdb",
        "Specifying a Disruption Budget for your Application",
        "https://kubernetes.io/docs/tasks/run-application/configure-pdb/",
        "CC-BY-4.0",
    ),
    "k8s-topology-spread": Citation(
        "k8s-topology-spread",
        "Pod Topology Spread Constraints",
        "https://kubernetes.io/docs/concepts/scheduling-eviction/topology-spread-constraints/",
        "CC-BY-4.0",
    ),
    "k8s-rbac-good-practices": Citation(
        "k8s-rbac-good-practices",
        "Role Based Access Control Good Practices",
        "https://kubernetes.io/docs/concepts/security/rbac-good-practices/",
        "CC-BY-4.0",
    ),
    "k8s-secrets-good-practices": Citation(
        "k8s-secrets-good-practices",
        "Good practices for Kubernetes Secrets",
        "https://kubernetes.io/docs/concepts/security/secrets-good-practices/",
        "CC-BY-4.0",
    ),
    "k8s-images": Citation(
        "k8s-images", "Images", "https://kubernetes.io/docs/concepts/containers/images/", "CC-BY-4.0"
    ),
    "k8s-service-lb": Citation(
        "k8s-service-lb",
        "Service - type LoadBalancer",
        "https://kubernetes.io/docs/concepts/services-networking/service/#loadbalancer",
        "CC-BY-4.0",
    ),
    "ocp-scc": Citation(
        "ocp-scc",
        "OpenShift - Managing security context constraints",
        "https://docs.redhat.com/en/documentation/openshift_container_platform/latest/html/authentication_and_authorization/managing-pod-security-policies",
        "CC-BY-SA-3.0",
    ),
    "ocp-routes": Citation(
        "ocp-routes",
        "OpenShift - Route configuration",
        "https://docs.redhat.com/en/documentation/openshift_container_platform/latest/html/networking/configuring-routes",
        "CC-BY-SA-3.0",
    ),
    "ocp-egressfirewall": Citation(
        "ocp-egressfirewall",
        "OpenShift - Configuring an egress firewall for a project (OVN-Kubernetes)",
        "https://docs.redhat.com/en/documentation/openshift_container_platform/latest/html/network_security/egress-firewall",
        "CC-BY-SA-3.0",
    ),
    "ocp-deploymentconfig-deprecation": Citation(
        "ocp-deploymentconfig-deprecation",
        "OpenShift 4.14 release notes - DeploymentConfig deprecated",
        "https://docs.redhat.com/en/documentation/openshift_container_platform/4.14/html/release_notes/ocp-4-14-release-notes",
        "CC-BY-SA-3.0",
    ),
    "ocp-storage-access-modes": Citation(
        "ocp-storage-access-modes",
        "OpenShift - Understanding persistent storage (supported access modes)",
        "https://docs.redhat.com/en/documentation/openshift_container_platform/latest/html/storage/understanding-persistent-storage",
        "CC-BY-SA-3.0",
    ),
    "rosa-efs": Citation(
        "rosa-efs",
        "ROSA - Setting up the AWS EFS CSI Driver Operator",
        "https://docs.redhat.com/en/documentation/red_hat_openshift_service_on_aws/4/html/storage/using-container-storage-interface-csi",
        "CC-BY-SA-3.0",
    ),
    "rosa-hcp-architecture": Citation(
        "rosa-hcp-architecture",
        "ROSA with HCP - architecture",
        "https://docs.redhat.com/en/documentation/red_hat_openshift_service_on_aws/4/html/architecture/index",
        "CC-BY-SA-3.0",
    ),
    "aws-ebs-csi": Citation(
        "aws-ebs-csi",
        "AWS EBS CSI driver (ReadWriteOnce block storage, zonal)",
        "https://github.com/kubernetes-sigs/aws-ebs-csi-driver",
        "Apache-2.0",
    ),
    "aws-efs-csi": Citation(
        "aws-efs-csi",
        "AWS EFS CSI driver (ReadWriteMany NFS)",
        "https://github.com/kubernetes-sigs/aws-efs-csi-driver",
        "Apache-2.0",
    ),
    "odf-access-modes": Citation(
        "odf-access-modes",
        "OpenShift Data Foundation - storage classes (RBD block RWO / CephFS RWX)",
        "https://docs.redhat.com/en/documentation/red_hat_openshift_data_foundation/",
        "CC-BY-SA-3.0",
    ),
    "stackrox-policies": Citation(
        "stackrox-policies",
        "StackRox default security policies",
        "https://github.com/stackrox/stackrox/tree/master/pkg/defaults/policies/files",
        "Apache-2.0",
    ),
    "helm-best-practices": Citation(
        "helm-best-practices",
        "Helm Chart Best Practices",
        "https://helm.sh/docs/chart_best_practices/",
        "Apache-2.0",
    ),
}


# --- API groups --------------------------------------------------------------------------------------

# Groups served only by OpenShift (or by operators that ship with OpenShift by default).
OPENSHIFT_ONLY_GROUPS: frozenset[str] = frozenset(
    {
        "route.openshift.io",
        "security.openshift.io",
        "apps.openshift.io",
        "build.openshift.io",
        "image.openshift.io",
        "project.openshift.io",
        "template.openshift.io",
        "quota.openshift.io",
        "user.openshift.io",
        "oauth.openshift.io",
        "authorization.openshift.io",
        "config.openshift.io",
        "operator.openshift.io",
        "machineconfiguration.openshift.io",
        "machine.openshift.io",
        "console.openshift.io",
        "network.openshift.io",
        "cloudcredential.openshift.io",
        "imageregistry.operator.openshift.io",
        "ingress.operator.openshift.io",
        "samples.operator.openshift.io",
        "tuned.openshift.io",
    }
)

# Groups that are present on OpenShift by default but need an add-on on vanilla Kubernetes.
ADDON_GROUPS_ON_VANILLA: dict[str, str] = {
    "k8s.ovn.org": "OVN-Kubernetes CNI (default on OpenShift 4.12+, optional add-on elsewhere)",
    "monitoring.coreos.com": "Prometheus Operator (bundled with OpenShift monitoring)",
    "operators.coreos.com": "Operator Lifecycle Manager (bundled with OpenShift)",
    "platform.stackrox.io": "RHACS / StackRox Operator",
    "gateway.networking.k8s.io": "Gateway API CRDs (install separately on vanilla Kubernetes and OpenShift < 4.19)",
    "snapshot.storage.k8s.io": "CSI external-snapshotter CRDs",
}

# kind -> currently served apiVersions (group/version) on the newest supported platforms.
KIND_API_VERSIONS: dict[str, tuple[str, ...]] = {
    "Pod": ("v1",),
    "Service": ("v1",),
    "ConfigMap": ("v1",),
    "Secret": ("v1",),
    "Namespace": ("v1",),
    "ServiceAccount": ("v1",),
    "PersistentVolumeClaim": ("v1",),
    "PersistentVolume": ("v1",),
    "LimitRange": ("v1",),
    "ResourceQuota": ("v1",),
    "Endpoints": ("v1",),
    "Deployment": ("apps/v1",),
    "StatefulSet": ("apps/v1",),
    "DaemonSet": ("apps/v1",),
    "ReplicaSet": ("apps/v1",),
    "Job": ("batch/v1",),
    "CronJob": ("batch/v1",),
    "Ingress": ("networking.k8s.io/v1",),
    "IngressClass": ("networking.k8s.io/v1",),
    "NetworkPolicy": ("networking.k8s.io/v1",),
    "PodDisruptionBudget": ("policy/v1",),
    "HorizontalPodAutoscaler": ("autoscaling/v2", "autoscaling/v1"),
    "StorageClass": ("storage.k8s.io/v1",),
    "CSIDriver": ("storage.k8s.io/v1",),
    "Role": ("rbac.authorization.k8s.io/v1",),
    "RoleBinding": ("rbac.authorization.k8s.io/v1",),
    "ClusterRole": ("rbac.authorization.k8s.io/v1",),
    "ClusterRoleBinding": ("rbac.authorization.k8s.io/v1",),
    "CustomResourceDefinition": ("apiextensions.k8s.io/v1",),
    "PriorityClass": ("scheduling.k8s.io/v1",),
    "RuntimeClass": ("node.k8s.io/v1",),
    "EndpointSlice": ("discovery.k8s.io/v1",),
    "ValidatingWebhookConfiguration": ("admissionregistration.k8s.io/v1",),
    "MutatingWebhookConfiguration": ("admissionregistration.k8s.io/v1",),
    "Gateway": ("gateway.networking.k8s.io/v1",),
    "GatewayClass": ("gateway.networking.k8s.io/v1",),
    "HTTPRoute": ("gateway.networking.k8s.io/v1",),
    "GRPCRoute": ("gateway.networking.k8s.io/v1",),
    # OpenShift
    "Route": ("route.openshift.io/v1",),
    "DeploymentConfig": ("apps.openshift.io/v1",),
    "SecurityContextConstraints": ("security.openshift.io/v1",),
    "BuildConfig": ("build.openshift.io/v1",),
    "Build": ("build.openshift.io/v1",),
    "ImageStream": ("image.openshift.io/v1",),
    "ImageStreamTag": ("image.openshift.io/v1",),
    "Project": ("project.openshift.io/v1",),
    "ProjectRequest": ("project.openshift.io/v1",),
    "Template": ("template.openshift.io/v1",),
    "ClusterResourceQuota": ("quota.openshift.io/v1",),
    "MachineConfig": ("machineconfiguration.openshift.io/v1",),
    "MachineConfigPool": ("machineconfiguration.openshift.io/v1",),
    "KubeletConfig": ("machineconfiguration.openshift.io/v1",),
    "MachineSet": ("machine.openshift.io/v1beta1",),
    "EgressFirewall": ("k8s.ovn.org/v1",),
    "EgressIP": ("k8s.ovn.org/v1",),
    # RHACS / StackRox operator
    "Central": ("platform.stackrox.io/v1alpha1",),
    "SecuredCluster": ("platform.stackrox.io/v1alpha1",),
}

# Kinds whose apiVersion is ambiguous across groups: kind names that also exist in another group.


@dataclass(frozen=True)
class RemovedAPI:
    group_version: str
    kind: str
    deprecated_in: str
    removed_in: str
    replacement: str | None
    notes: str = ""


# Source: Kubernetes Deprecated API Migration Guide (k8s-deprecation-guide), kubernetes/website
# content/en/docs/reference/using-api/deprecation-guide.md, verified 2026-10-27. The guide lists no removals after
# v1.32 (as of Kubernetes 1.37); do not add rows without a citation.
REMOVED_APIS: tuple[RemovedAPI, ...] = (
    RemovedAPI("extensions/v1beta1", "Deployment", "1.9", "1.16", "apps/v1", "spec.selector is required"),
    RemovedAPI("apps/v1beta1", "Deployment", "1.9", "1.16", "apps/v1", "spec.selector is required"),
    RemovedAPI("apps/v1beta2", "Deployment", "1.9", "1.16", "apps/v1", "spec.selector is required"),
    RemovedAPI("extensions/v1beta1", "DaemonSet", "1.9", "1.16", "apps/v1"),
    RemovedAPI("apps/v1beta2", "DaemonSet", "1.9", "1.16", "apps/v1"),
    RemovedAPI("apps/v1beta1", "StatefulSet", "1.9", "1.16", "apps/v1"),
    RemovedAPI("apps/v1beta2", "StatefulSet", "1.9", "1.16", "apps/v1"),
    RemovedAPI("extensions/v1beta1", "ReplicaSet", "1.9", "1.16", "apps/v1"),
    RemovedAPI("apps/v1beta1", "ReplicaSet", "1.9", "1.16", "apps/v1"),
    RemovedAPI("apps/v1beta2", "ReplicaSet", "1.9", "1.16", "apps/v1"),
    RemovedAPI("extensions/v1beta1", "NetworkPolicy", "1.9", "1.16", "networking.k8s.io/v1"),
    RemovedAPI("extensions/v1beta1", "PodSecurityPolicy", "1.10", "1.16", "policy/v1beta1"),
    RemovedAPI(
        "extensions/v1beta1",
        "Ingress",
        "1.14",
        "1.22",
        "networking.k8s.io/v1",
        "backend.serviceName/servicePort -> backend.service.name/port; pathType is required",
    ),
    RemovedAPI(
        "networking.k8s.io/v1beta1",
        "Ingress",
        "1.19",
        "1.22",
        "networking.k8s.io/v1",
        "backend.serviceName/servicePort -> backend.service.name/port; pathType is required",
    ),
    RemovedAPI("networking.k8s.io/v1beta1", "IngressClass", "1.19", "1.22", "networking.k8s.io/v1"),
    RemovedAPI("rbac.authorization.k8s.io/v1beta1", "ClusterRole", "1.17", "1.22", "rbac.authorization.k8s.io/v1"),
    RemovedAPI(
        "rbac.authorization.k8s.io/v1beta1", "ClusterRoleBinding", "1.17", "1.22", "rbac.authorization.k8s.io/v1"
    ),
    RemovedAPI("rbac.authorization.k8s.io/v1beta1", "Role", "1.17", "1.22", "rbac.authorization.k8s.io/v1"),
    RemovedAPI("rbac.authorization.k8s.io/v1beta1", "RoleBinding", "1.17", "1.22", "rbac.authorization.k8s.io/v1"),
    RemovedAPI("apiextensions.k8s.io/v1beta1", "CustomResourceDefinition", "1.16", "1.22", "apiextensions.k8s.io/v1"),
    RemovedAPI(
        "admissionregistration.k8s.io/v1beta1",
        "ValidatingWebhookConfiguration",
        "1.16",
        "1.22",
        "admissionregistration.k8s.io/v1",
    ),
    RemovedAPI(
        "admissionregistration.k8s.io/v1beta1",
        "MutatingWebhookConfiguration",
        "1.16",
        "1.22",
        "admissionregistration.k8s.io/v1",
    ),
    RemovedAPI("scheduling.k8s.io/v1beta1", "PriorityClass", "1.14", "1.22", "scheduling.k8s.io/v1"),
    RemovedAPI("storage.k8s.io/v1beta1", "StorageClass", "1.19", "1.22", "storage.k8s.io/v1"),
    RemovedAPI("storage.k8s.io/v1beta1", "CSIDriver", "1.19", "1.22", "storage.k8s.io/v1"),
    RemovedAPI("storage.k8s.io/v1beta1", "CSINode", "1.19", "1.22", "storage.k8s.io/v1"),
    RemovedAPI("storage.k8s.io/v1beta1", "VolumeAttachment", "1.19", "1.22", "storage.k8s.io/v1"),
    RemovedAPI("apiregistration.k8s.io/v1beta1", "APIService", "1.19", "1.22", "apiregistration.k8s.io/v1"),
    RemovedAPI("authentication.k8s.io/v1beta1", "TokenReview", "1.19", "1.22", "authentication.k8s.io/v1"),
    RemovedAPI("authorization.k8s.io/v1beta1", "SubjectAccessReview", "1.19", "1.22", "authorization.k8s.io/v1"),
    RemovedAPI("authorization.k8s.io/v1beta1", "LocalSubjectAccessReview", "1.19", "1.22", "authorization.k8s.io/v1"),
    RemovedAPI("authorization.k8s.io/v1beta1", "SelfSubjectAccessReview", "1.19", "1.22", "authorization.k8s.io/v1"),
    RemovedAPI("authorization.k8s.io/v1beta1", "SelfSubjectRulesReview", "1.19", "1.22", "authorization.k8s.io/v1"),
    RemovedAPI("certificates.k8s.io/v1beta1", "CertificateSigningRequest", "1.19", "1.22", "certificates.k8s.io/v1"),
    RemovedAPI("coordination.k8s.io/v1beta1", "Lease", "1.19", "1.22", "coordination.k8s.io/v1"),
    RemovedAPI("batch/v1beta1", "CronJob", "1.21", "1.25", "batch/v1"),
    RemovedAPI("discovery.k8s.io/v1beta1", "EndpointSlice", "1.21", "1.25", "discovery.k8s.io/v1"),
    RemovedAPI("events.k8s.io/v1beta1", "Event", "1.19", "1.25", "events.k8s.io/v1"),
    RemovedAPI("autoscaling/v2beta1", "HorizontalPodAutoscaler", "1.23", "1.25", "autoscaling/v2"),
    RemovedAPI(
        "policy/v1beta1",
        "PodDisruptionBudget",
        "1.21",
        "1.25",
        "policy/v1",
        "an empty spec.selector now selects all pods in the namespace",
    ),
    RemovedAPI(
        "policy/v1beta1",
        "PodSecurityPolicy",
        "1.21",
        "1.25",
        None,
        "PodSecurityPolicy was removed; use Pod Security Admission (and SCCs on OpenShift)",
    ),
    RemovedAPI("node.k8s.io/v1beta1", "RuntimeClass", "1.20", "1.25", "node.k8s.io/v1"),
    RemovedAPI(
        "flowcontrol.apiserver.k8s.io/v1beta1",
        "FlowSchema",
        "1.23",
        "1.26",
        "flowcontrol.apiserver.k8s.io/v1",
        "flowcontrol v1 is GA from 1.29; on 1.26-1.28 use v1beta3",
    ),
    RemovedAPI(
        "flowcontrol.apiserver.k8s.io/v1beta1",
        "PriorityLevelConfiguration",
        "1.23",
        "1.26",
        "flowcontrol.apiserver.k8s.io/v1",
        "flowcontrol v1 is GA from 1.29; on 1.26-1.28 use v1beta3",
    ),
    RemovedAPI("autoscaling/v2beta2", "HorizontalPodAutoscaler", "1.23", "1.26", "autoscaling/v2"),
    RemovedAPI("storage.k8s.io/v1beta1", "CSIStorageCapacity", "1.24", "1.27", "storage.k8s.io/v1"),
    RemovedAPI("flowcontrol.apiserver.k8s.io/v1beta2", "FlowSchema", "1.26", "1.29", "flowcontrol.apiserver.k8s.io/v1"),
    RemovedAPI(
        "flowcontrol.apiserver.k8s.io/v1beta2",
        "PriorityLevelConfiguration",
        "1.26",
        "1.29",
        "flowcontrol.apiserver.k8s.io/v1",
    ),
    RemovedAPI("flowcontrol.apiserver.k8s.io/v1beta3", "FlowSchema", "1.29", "1.32", "flowcontrol.apiserver.k8s.io/v1"),
    RemovedAPI(
        "flowcontrol.apiserver.k8s.io/v1beta3",
        "PriorityLevelConfiguration",
        "1.29",
        "1.32",
        "flowcontrol.apiserver.k8s.io/v1",
    ),
)

# OpenShift Container Platform minor -> Kubernetes minor. Source: OCP release notes ("based on Kubernetes 1.x").
OCP_TO_K8S: dict[str, str] = {
    "4.12": "1.25",
    "4.13": "1.26",
    "4.14": "1.27",
    "4.15": "1.28",
    "4.16": "1.29",
    "4.17": "1.30",
    "4.18": "1.31",
    "4.19": "1.32",
    "4.20": "1.33",
    "4.21": "1.34",
    "4.22": "1.35",
}

DEFAULT_K8S_VERSION = "1.35"
DEFAULT_OCP_VERSION = "4.22"


def parse_minor(v: str) -> tuple[int, int]:
    """'1.29' / 'v1.29.3' / '4.16' -> (1, 29)."""
    s = v.strip().lstrip("vV")
    parts = s.split(".")
    if len(parts) < 2 or not parts[0].isdigit() or not parts[1].split("-")[0].isdigit():
        raise ValueError(f"Expected a version like '1.29' or '4.16', got {v!r}")
    return int(parts[0]), int(parts[1].split("-")[0])


def k8s_version_for(platform: str, version: str | None) -> str:
    """Resolve the Kubernetes minor version that a platform/version combination serves."""
    if platform in OPENSHIFT_FAMILY:
        ocp = version or DEFAULT_OCP_VERSION
        major, minor = parse_minor(ocp)
        if major == 1:  # caller passed a Kubernetes version for an OpenShift target
            return f"{major}.{minor}"
        key = f"{major}.{minor}"
        if key in OCP_TO_K8S:
            return OCP_TO_K8S[key]
        # Unknown future OCP minor: OCP 4.x tracks Kubernetes 1.(x+13) for every release since 4.12.
        if major == 4 and minor >= 12:
            return f"1.{minor + 13}"
        raise ValueError(f"Unknown OpenShift version {ocp!r}; supported: {', '.join(OCP_TO_K8S)}")
    if version is None:
        return DEFAULT_K8S_VERSION
    major, minor = parse_minor(version)
    return f"{major}.{minor}"


def removed_api(group_version: str, kind: str, k8s_version: str) -> RemovedAPI | None:
    target = parse_minor(k8s_version)
    for r in REMOVED_APIS:
        if r.group_version == group_version and r.kind == kind and target >= parse_minor(r.removed_in):
            return r
    return None


def deprecated_api(group_version: str, kind: str, k8s_version: str) -> RemovedAPI | None:
    """Deprecated in the target version but not yet removed."""
    target = parse_minor(k8s_version)
    for r in REMOVED_APIS:
        if (
            r.group_version == group_version
            and r.kind == kind
            and parse_minor(r.deprecated_in) <= target < parse_minor(r.removed_in)
        ):
            return r
    return None


def api_group(api_version: str) -> str:
    return api_version.split("/", 1)[0] if "/" in api_version else ""


# --- Storage -----------------------------------------------------------------------------------------


@dataclass(frozen=True)
class Provisioner:
    name: str
    rwx_filesystem: bool
    rwx_block: bool
    zonal: bool
    description: str
    citation: str


PROVISIONERS: dict[str, Provisioner] = {
    "ebs.csi.aws.com": Provisioner(
        "ebs.csi.aws.com", False, False, True, "AWS EBS block volumes (single node, single AZ)", "aws-ebs-csi"
    ),
    "kubernetes.io/aws-ebs": Provisioner(
        "kubernetes.io/aws-ebs", False, False, True, "legacy in-tree AWS EBS (migrated to CSI)", "aws-ebs-csi"
    ),
    "efs.csi.aws.com": Provisioner(
        "efs.csi.aws.com", True, False, False, "AWS EFS (NFSv4.1, multi-AZ, ReadWriteMany)", "aws-efs-csi"
    ),
    "openshift-storage.rbd.csi.ceph.com": Provisioner(
        "openshift-storage.rbd.csi.ceph.com",
        False,
        True,
        False,
        "ODF Ceph RBD block (RWO filesystem; RWX only with volumeMode: Block)",
        "odf-access-modes",
    ),
    "openshift-storage.cephfs.csi.ceph.com": Provisioner(
        "openshift-storage.cephfs.csi.ceph.com",
        True,
        False,
        False,
        "ODF CephFS shared filesystem (RWX)",
        "odf-access-modes",
    ),
    "rbd.csi.ceph.com": Provisioner(
        "rbd.csi.ceph.com", False, True, False, "Ceph RBD block (RWX only with volumeMode: Block)", "odf-access-modes"
    ),
    "cephfs.csi.ceph.com": Provisioner("cephfs.csi.ceph.com", True, False, False, "CephFS (RWX)", "odf-access-modes"),
    "csi.vsphere.vmware.com": Provisioner(
        "csi.vsphere.vmware.com",
        False,
        False,
        False,
        "vSphere CNS block (RWO); RWX file volumes need vSAN File Services",
        "ocp-storage-access-modes",
    ),
    "pd.csi.storage.gke.io": Provisioner(
        "pd.csi.storage.gke.io",
        False,
        False,
        True,
        "GCP Persistent Disk (zonal block, RWO)",
        "ocp-storage-access-modes",
    ),
    "disk.csi.azure.com": Provisioner(
        "disk.csi.azure.com", False, False, True, "Azure Disk (zonal block, RWO)", "ocp-storage-access-modes"
    ),
    "file.csi.azure.com": Provisioner(
        "file.csi.azure.com", True, False, False, "Azure Files (SMB/NFS, RWX)", "ocp-storage-access-modes"
    ),
    "topolvm.io": Provisioner(
        "topolvm.io", False, False, False, "LVM Storage / TopoLVM node-local volumes (RWO)", "ocp-storage-access-modes"
    ),
    "nfs.csi.k8s.io": Provisioner("nfs.csi.k8s.io", True, False, False, "NFS CSI driver (RWX)", "k8s-pv-access-modes"),
    "rancher.io/local-path": Provisioner(
        "rancher.io/local-path", False, False, False, "local-path provisioner (node-local, RWO)", "k8s-pv-access-modes"
    ),
}

# Well-known StorageClass names that ship by default on the respective platforms.
KNOWN_STORAGE_CLASSES: dict[str, str] = {
    "gp3-csi": "ebs.csi.aws.com",
    "gp2-csi": "ebs.csi.aws.com",
    "gp3": "ebs.csi.aws.com",
    "gp2": "kubernetes.io/aws-ebs",
    "efs-sc": "efs.csi.aws.com",
    "ocs-storagecluster-ceph-rbd": "openshift-storage.rbd.csi.ceph.com",
    "ocs-storagecluster-ceph-rbd-virtualization": "openshift-storage.rbd.csi.ceph.com",
    "ocs-storagecluster-cephfs": "openshift-storage.cephfs.csi.ceph.com",
    "thin-csi": "csi.vsphere.vmware.com",
    "standard-csi": "pd.csi.storage.gke.io",
    "managed-csi": "disk.csi.azure.com",
    "azurefile-csi": "file.csi.azure.com",
    "lvms-vg1": "topolvm.io",
    "local-path": "rancher.io/local-path",
    # "standard" is deliberately absent: it is local-path on kind, GCE PD on GKE and hostPath on minikube.
}

# Recommended StorageClass per platform and access mode for the generator.
DEFAULT_STORAGE_CLASS: dict[str, dict[str, str | None]] = {
    "kubernetes": {"ReadWriteOnce": None, "ReadWriteMany": None},
    "openshift": {"ReadWriteOnce": None, "ReadWriteMany": "ocs-storagecluster-cephfs"},
    "rosa-classic": {"ReadWriteOnce": "gp3-csi", "ReadWriteMany": "efs-sc"},
    "rosa-hcp": {"ReadWriteOnce": "gp3-csi", "ReadWriteMany": "efs-sc"},
}
