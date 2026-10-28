---
id: k8s-topology-spread
title: Spreading replicas across zones and nodes
tags: [kubernetes, availability, scheduling]
platforms: [kubernetes, openshift, rosa-classic, rosa-hcp]
updated: 2026-10-27
license: Apache-2.0
# A question needs a word of this document's subject (and of Kubernetes, where generic words would pass).
requires:
  - [topologyspreadconstraints, topology, spread, zone, zones, antiaffinity, podantiaffinity, affinity]
  - [pod, pods, kubectl, oc, kubernetes, k8s, openshift, ocp, rosa, kubelet, kubeadm, deployment, deployments, statefulset, statefulsets, daemonset, daemonsets, replicaset, replicasets, namespace, namespaces, crashloopbackoff, configmap, configmaps, pvc, persistentvolumeclaim, helm]
sources:
  - {title: "Pod Topology Spread Constraints", url: "https://kubernetes.io/docs/concepts/scheduling-eviction/topology-spread-constraints/", license: CC-BY-4.0}
---
# Topology spread

To keep an app available when a node or a whole availability zone fails, run at least 3 replicas, spread them
across zones and nodes, and protect them with a PodDisruptionBudget ([kn:k8s-pdb#0]).


```yaml
topologySpreadConstraints:
- maxSkew: 1
  topologyKey: topology.kubernetes.io/zone
  whenUnsatisfiable: ScheduleAnyway
  labelSelector: {matchLabels: {app.kubernetes.io/name: orders-api}}
- maxSkew: 1
  topologyKey: kubernetes.io/hostname
  whenUnsatisfiable: ScheduleAnyway
  labelSelector: {matchLabels: {app.kubernetes.io/name: orders-api}}
```
- `ScheduleAnyway` prefers spreading without making pods unschedulable when a zone is short of capacity;
  `DoNotSchedule` is strict and can leave pods Pending.
- On ROSA HCP each machine pool lives in one AZ, so multi-AZ spreading needs a machine pool per AZ.
- Zonal block volumes (EBS) pin StatefulSet pods to their zone; plan replication at the application layer.
