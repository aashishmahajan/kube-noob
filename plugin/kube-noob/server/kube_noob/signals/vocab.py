"""Kubernetes and OpenShift reason vocabularies, each name copied from the upstream source that emits it.

Checked on 2026-10-28 against these files (the URL is the citation):
- kubelet event reasons: https://github.com/kubernetes/kubernetes/blob/master/pkg/kubelet/events/event.go, and
  "FailedToRetrieveImagePullSecret" from https://github.com/kubernetes/kubernetes/blob/master/pkg/kubelet/kubelet.go
- image pull errors: https://github.com/kubernetes/kubernetes/blob/master/pkg/kubelet/images/types.go
- container sync errors: https://github.com/kubernetes/kubernetes/blob/master/pkg/kubelet/container/sync_result.go
- container creation errors:
  https://github.com/kubernetes/kubernetes/blob/master/pkg/kubelet/kuberuntime/kuberuntime_container.go
- scheduler: https://github.com/kubernetes/kubernetes/blob/master/pkg/scheduler/schedule_one.go ("FailedScheduling")
- controllers: https://github.com/kubernetes/kubernetes/blob/master/pkg/controller/controller_utils.go ("FailedCreate")
- eviction: https://github.com/kubernetes/kubernetes/blob/master/pkg/kubelet/eviction/helpers.go ("Evicted")
- termination reasons: https://github.com/cri-o/cri-o/blob/main/server/container_status.go ("OOMKilled")
- ClusterOperator conditions: https://github.com/openshift/api/blob/master/config/v1/types_cluster_operator.go
- Alertmanager webhook payload (version 4): https://github.com/prometheus/alertmanager/blob/main/docs/configuration.md
"""

from __future__ import annotations

# Event reasons worth a signal even on Normal events; Warning events contribute any reason.
EVENT_REASONS = frozenset(
    {
        "BackOff",
        "Failed",
        "FailedToRetrieveImagePullSecret",
        "FailedKillPod",
        "FailedCreatePodContainer",
        "NetworkNotReady",
        "InspectFailed",
        "ErrImageNeverPull",
        "NodeNotReady",
        "NodeNotSchedulable",
        "KubeletSetupFailed",
        "FailedAttachVolume",
        "FailedMount",
        "VolumeResizeFailed",
        "FileSystemResizeFailed",
        "FailedMapVolume",
        "Rebooted",
        "ContainerGCFailed",
        "ImageGCFailed",
        "FailedNodeAllocatableEnforcement",
        "FailedCreatePodSandBox",
        "FailedPodSandBoxStatus",
        "FailedMountOnFilesystemMismatch",
        "InvalidDiskCapacity",
        "FreeDiskSpaceFailed",
        "Unhealthy",
        "ProbeWarning",
        "FailedSync",
        "FailedScheduling",
        "FailedCreate",
        "Evicted",
        "ExceededGracePeriod",
    }
)
# Normal-only reasons that carry no signal on their own.
ROUTINE_REASONS = frozenset(
    {"Created", "Started", "Killing", "Pulling", "Pulled", "Scheduled", "SuccessfulCreate", "SuccessfulDelete"}
)

# Container waiting and terminated reasons (and the pod-level Evicted).
POD_REASONS = frozenset(
    {
        "CrashLoopBackOff",
        "ImagePullBackOff",
        "ErrImagePull",
        "ErrImageNeverPull",
        "InvalidImageName",
        "ImageInspectError",
        "CreateContainerConfigError",
        "CreateContainerError",
        "RunContainerError",
        "KillContainerError",
        "PreStartHookError",
        "PostStartHookError",
        "PreCreateHookError",
        "CreatePodSandboxError",
        "ConfigPodSandboxError",
        "KillPodSandboxError",
        "OOMKilled",
        "Evicted",
    }
)
# Reasons that only mean something in a structured status, never as a word in prose.
STRUCTURED_ONLY = frozenset({"Error", "Completed"})

CO_CONDITIONS = ("Available", "Progressing", "Degraded", "Upgradeable")
# The condition value that is a problem: Available=False, Degraded=True, Upgradeable=False.
CO_BAD = {"Available": "False", "Degraded": "True", "Upgradeable": "False"}

# Component names and the words people and logs use for them (lower case, matched as whole words).
COMPONENTS: dict[str, tuple[str, ...]] = {
    "etcd": ("etcd", "etcd-operator", "cluster-etcd-operator"),
    "kube-apiserver": ("kube-apiserver", "apiserver", "kube-apiserver-operator"),
    "openshift-apiserver": ("openshift-apiserver",),
    "kube-controller-manager": ("kube-controller-manager",),
    "kube-scheduler": ("kube-scheduler",),
    "kubelet": ("kubelet",),
    "cri-o": ("cri-o", "crio"),
    "ovn-kubernetes": ("ovnkube", "ovn-kubernetes", "ovnkube-node", "ovnkube-controller", "ovn"),
    "openvswitch": ("openvswitch", "ovs-vswitchd", "ovsdb-server"),
    "multus": ("multus",),
    "dns": ("coredns", "dns-default", "dns-operator"),
    "ingress": ("haproxy", "router-default", "ingress-operator", "openshift-ingress"),
    "authentication": ("oauth-openshift", "authentication-operator", "oauth-server"),
    "machine-config": ("machine-config", "machine-config-daemon", "machine-config-operator", "mcd", "mco"),
    "cluster-version": ("cluster-version-operator", "cvo"),
    "olm": ("olm-operator", "catalog-operator", "marketplace-operator", "catalogsource"),
    "monitoring": ("prometheus", "alertmanager", "thanos-querier", "prometheus-operator"),
    "image-registry": ("image-registry", "cluster-image-registry-operator"),
    "storage": ("csi", "ebs-csi", "efs-csi", "persistentvolume", "persistentvolumeclaim"),
}


# Fixed wording of messages Kubernetes components print (the variable parts are captured and kept). Words like
# "attempting", "succeed" or "machine" in these templates say nothing about which bug it is, so matching against
# reported issues reads the captured parts only. Copied from:
# - kubelet: pkg/kubelet/kubelet.go (pull secrets), pkg/kubelet/images/image_manager.go (image pulls),
#   pkg/kubelet/kuberuntime/kuberuntime_container.go (stopping)
# - kube-scheduler: pkg/scheduler/schedule_one.go (Scheduled)
MESSAGE_TEMPLATES: tuple[str, ...] = (
    r"Unable to retrieve some image pull secrets \(([^)]{0,500})\); attempting to pull the image may not succeed\.?",
    r"Container image (\"[^\"]{0,500}\") already present on machine(?: and can be accessed by the pod)?",
    r"Container image (\"[^\"]{0,500}\") is not present with pull policy of Never",
    r"Back-off pulling image (\"[^\"]{0,500}\")",
    r"Pulling image (\"[^\"]{0,500}\")",
    r"Failed to pull image (\"[^\"]{0,500}\"):",
    r"Successfully pulled image (\"[^\"]{0,500}\") in \S{1,40} \(\S{1,40} including waiting\)\. "
    r"Image size: \d{1,20} bytes\.",
    r"Successfully assigned (\S{1,320}) to (\S{1,253})",
    r"Back-off restarting failed container (\S{1,253}) in pod (\S{1,253})",
    r"Stopping container (\S{1,253})",
)
