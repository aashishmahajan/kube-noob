---
id: k8s-scheduling
title: Pods stuck Pending (0/N nodes are available)
tags: [kubernetes, openshift, scheduling, pending, resources, taints, troubleshooting]
platforms: [kubernetes, openshift, rosa-classic, rosa-hcp]
updated: 2026-10-27
license: Apache-2.0
# A question needs a word of this document's subject (and of Kubernetes, where generic words would pass).
requires:
  - [pending, failedscheduling, unschedulable, taint, taints, toleration, tolerations, affinity, nodeselector, insufficient, schedule, scheduler, scheduling]
  - [pod, pods, kubectl, oc, kubernetes, k8s, openshift, ocp, rosa, kubelet, kubeadm, deployment, deployments, statefulset, statefulsets, daemonset, daemonsets, replicaset, replicasets, namespace, namespaces, crashloopbackoff, configmap, configmaps, pvc, persistentvolumeclaim, helm]
sources:
  - {title: "Kubernetes: Resource Management for Pods and Containers", url: "https://kubernetes.io/docs/concepts/configuration/manage-resources-containers/", license: CC-BY-4.0}
  - {title: "Kubernetes: Assigning Pods to Nodes", url: "https://kubernetes.io/docs/concepts/scheduling-eviction/assign-pod-node/", license: CC-BY-4.0}
  - {title: "Kubernetes: Taints and Tolerations", url: "https://kubernetes.io/docs/concepts/scheduling-eviction/taint-and-toleration/", license: CC-BY-4.0}
  - {title: "Kubernetes: Debug Pods", url: "https://kubernetes.io/docs/tasks/debug/debug-application/debug-pods/", license: CC-BY-4.0}
---
# Pods stuck Pending: "0/3 nodes are available"

The scheduler explains every Pending pod in its `FailedScheduling` event, for example
`0/3 nodes are available: 3 Insufficient cpu`. Read it with `oc describe pod <pod>` or
`oc get events --field-selector reason=FailedScheduling`. Each clause names a reason and how many nodes it ruled out.

## Insufficient cpu or memory

The scheduler places pods by their **requests**, not by actual usage. `Insufficient cpu` means no node has enough
unrequested CPU left for this pod's requests. Compare the pod's requests with each node's allocatable capacity and
what is already requested: `oc describe node <node>` shows "Allocated resources". Fixes, in order:

1. Lower requests that are higher than the app needs (look at real usage with `oc adm top pod`).
2. Add capacity: more nodes, or enable the cluster autoscaler or machine pool autoscaling on ROSA.
3. Check a LimitRange that injects large default requests into containers that set none.

## Other reasons in the same message

- `node(s) had untolerated taint`: the nodes are tainted (for example infra or GPU nodes); add a toleration only if
  the pod belongs there.
- `node(s) didn't match Pod's node affinity/selector`: a `nodeSelector` or affinity names labels no node has.
- `node(s) had volume node affinity conflict`: the PVC's volume lives in another zone (EBS is zonal).
- `Too many pods`: the node reached its pod limit.
- `didn't match pod topology spread constraints`: `whenUnsatisfiable: DoNotSchedule` with too few zones or nodes.

A namespace ResourceQuota that is exhausted stops pods from being created at all (`exceeded quota` on the
ReplicaSet), which looks different: the pod never appears.
