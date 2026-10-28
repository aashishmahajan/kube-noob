---
id: k8s-deprecations
title: Removed Kubernetes APIs and how to migrate
tags: [kubernetes, deprecation, upgrades]
platforms: [kubernetes, openshift, rosa-classic, rosa-hcp]
updated: 2026-10-27
license: Apache-2.0
# A question needs a word of this document's subject (and of Kubernetes, where generic words would pass).
requires:
  - [apiversion, deprecated, deprecation, deprecations, removed, v1beta1, v1beta2, v2beta1, v2beta2, api, apis, upgrade, upgrading]
  - [pod, pods, kubectl, oc, kubernetes, k8s, openshift, ocp, rosa, kubelet, kubeadm, deployment, deployments, statefulset, statefulsets, daemonset, daemonsets, replicaset, replicasets, namespace, namespaces, crashloopbackoff, configmap, configmaps, pvc, persistentvolumeclaim, helm]
sources:
  - {title: "Deprecated API Migration Guide", url: "https://kubernetes.io/docs/reference/using-api/deprecation-guide/", license: CC-BY-4.0}
---
# Removed Kubernetes APIs

Removed APIs are rejected by the API server (`no matches for kind`). Map OpenShift versions to Kubernetes first (4.16 = 1.29, 4.19 = 1.32, 4.22 = 1.35). The guide lists no removals after 1.32 (as of 1.37). `kube-noob fix` performs the mechanical migrations; `kubectl convert` (plugin) is the upstream tool.

## Removed in 1.32

| Kind | Removed apiVersion | Use instead | Notes |
|---|---|---|---|
| FlowSchema | flowcontrol.apiserver.k8s.io/v1beta3 | flowcontrol.apiserver.k8s.io/v1 |  |
| PriorityLevelConfiguration | flowcontrol.apiserver.k8s.io/v1beta3 | flowcontrol.apiserver.k8s.io/v1 |  |

## Removed in 1.29

| Kind | Removed apiVersion | Use instead | Notes |
|---|---|---|---|
| FlowSchema | flowcontrol.apiserver.k8s.io/v1beta2 | flowcontrol.apiserver.k8s.io/v1 |  |
| PriorityLevelConfiguration | flowcontrol.apiserver.k8s.io/v1beta2 | flowcontrol.apiserver.k8s.io/v1 |  |

## Removed in 1.27

| Kind | Removed apiVersion | Use instead | Notes |
|---|---|---|---|
| CSIStorageCapacity | storage.k8s.io/v1beta1 | storage.k8s.io/v1 |  |

## Removed in 1.26

| Kind | Removed apiVersion | Use instead | Notes |
|---|---|---|---|
| FlowSchema | flowcontrol.apiserver.k8s.io/v1beta1 | flowcontrol.apiserver.k8s.io/v1 | flowcontrol v1 is GA from 1.29; on 1.26-1.28 use v1beta3 |
| PriorityLevelConfiguration | flowcontrol.apiserver.k8s.io/v1beta1 | flowcontrol.apiserver.k8s.io/v1 | flowcontrol v1 is GA from 1.29; on 1.26-1.28 use v1beta3 |
| HorizontalPodAutoscaler | autoscaling/v2beta2 | autoscaling/v2 |  |

## Removed in 1.25

| Kind | Removed apiVersion | Use instead | Notes |
|---|---|---|---|
| CronJob | batch/v1beta1 | batch/v1 |  |
| EndpointSlice | discovery.k8s.io/v1beta1 | discovery.k8s.io/v1 |  |
| Event | events.k8s.io/v1beta1 | events.k8s.io/v1 |  |
| HorizontalPodAutoscaler | autoscaling/v2beta1 | autoscaling/v2 |  |
| PodDisruptionBudget | policy/v1beta1 | policy/v1 | an empty spec.selector now selects all pods in the namespace |
| PodSecurityPolicy | policy/v1beta1 | no replacement | PodSecurityPolicy was removed; use Pod Security Admission (and SCCs on OpenShift) |
| RuntimeClass | node.k8s.io/v1beta1 | node.k8s.io/v1 |  |

## Removed in 1.22

| Kind | Removed apiVersion | Use instead | Notes |
|---|---|---|---|
| Ingress | extensions/v1beta1 | networking.k8s.io/v1 | backend.serviceName/servicePort -> backend.service.name/port; pathType is required |
| Ingress | networking.k8s.io/v1beta1 | networking.k8s.io/v1 | backend.serviceName/servicePort -> backend.service.name/port; pathType is required |
| IngressClass | networking.k8s.io/v1beta1 | networking.k8s.io/v1 |  |
| ClusterRole | rbac.authorization.k8s.io/v1beta1 | rbac.authorization.k8s.io/v1 |  |
| ClusterRoleBinding | rbac.authorization.k8s.io/v1beta1 | rbac.authorization.k8s.io/v1 |  |
| Role | rbac.authorization.k8s.io/v1beta1 | rbac.authorization.k8s.io/v1 |  |
| RoleBinding | rbac.authorization.k8s.io/v1beta1 | rbac.authorization.k8s.io/v1 |  |
| CustomResourceDefinition | apiextensions.k8s.io/v1beta1 | apiextensions.k8s.io/v1 |  |
| ValidatingWebhookConfiguration | admissionregistration.k8s.io/v1beta1 | admissionregistration.k8s.io/v1 |  |
| MutatingWebhookConfiguration | admissionregistration.k8s.io/v1beta1 | admissionregistration.k8s.io/v1 |  |
| PriorityClass | scheduling.k8s.io/v1beta1 | scheduling.k8s.io/v1 |  |
| StorageClass | storage.k8s.io/v1beta1 | storage.k8s.io/v1 |  |
| CSIDriver | storage.k8s.io/v1beta1 | storage.k8s.io/v1 |  |
| CSINode | storage.k8s.io/v1beta1 | storage.k8s.io/v1 |  |
| VolumeAttachment | storage.k8s.io/v1beta1 | storage.k8s.io/v1 |  |
| APIService | apiregistration.k8s.io/v1beta1 | apiregistration.k8s.io/v1 |  |
| TokenReview | authentication.k8s.io/v1beta1 | authentication.k8s.io/v1 |  |
| SubjectAccessReview | authorization.k8s.io/v1beta1 | authorization.k8s.io/v1 |  |
| LocalSubjectAccessReview | authorization.k8s.io/v1beta1 | authorization.k8s.io/v1 |  |
| SelfSubjectAccessReview | authorization.k8s.io/v1beta1 | authorization.k8s.io/v1 |  |
| SelfSubjectRulesReview | authorization.k8s.io/v1beta1 | authorization.k8s.io/v1 |  |
| CertificateSigningRequest | certificates.k8s.io/v1beta1 | certificates.k8s.io/v1 |  |
| Lease | coordination.k8s.io/v1beta1 | coordination.k8s.io/v1 |  |

## Removed in 1.16

| Kind | Removed apiVersion | Use instead | Notes |
|---|---|---|---|
| Deployment | extensions/v1beta1 | apps/v1 | spec.selector is required |
| Deployment | apps/v1beta1 | apps/v1 | spec.selector is required |
| Deployment | apps/v1beta2 | apps/v1 | spec.selector is required |
| DaemonSet | extensions/v1beta1 | apps/v1 |  |
| DaemonSet | apps/v1beta2 | apps/v1 |  |
| StatefulSet | apps/v1beta1 | apps/v1 |  |
| StatefulSet | apps/v1beta2 | apps/v1 |  |
| ReplicaSet | extensions/v1beta1 | apps/v1 |  |
| ReplicaSet | apps/v1beta1 | apps/v1 |  |
| ReplicaSet | apps/v1beta2 | apps/v1 |  |
| NetworkPolicy | extensions/v1beta1 | networking.k8s.io/v1 |  |
| PodSecurityPolicy | extensions/v1beta1 | policy/v1beta1 |  |
