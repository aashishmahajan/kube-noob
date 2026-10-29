---
id: k8s-pss
title: Pod Security Standards and the hardened securityContext
tags: [kubernetes, security, pss, psa, pod-security-admission]
platforms: [kubernetes, openshift, rosa-classic, rosa-hcp]
updated: 2026-10-28
license: Apache-2.0
# A question needs a word of this document's subject (and of Kubernetes, where generic words would pass).
requires:
  - [psa, pss, pod-security, podsecurity, restricted, baseline, privileged, securitycontext, pod-security.kubernetes.io]
sources:
  - {title: "Pod Security Standards", url: "https://kubernetes.io/docs/concepts/security/pod-security-standards/", license: CC-BY-4.0}
  - {title: "Pod Security Admission", url: "https://kubernetes.io/docs/concepts/security/pod-security-admission/", license: CC-BY-4.0}
  - {title: "Enforce Pod Security Standards with Namespace Labels", url: "https://kubernetes.io/docs/tasks/configure-pod-container/enforce-standards-namespace-labels/", license: CC-BY-4.0}
---
# Pod Security Standards (PSS)

Three profiles: **privileged** (unrestricted), **baseline** (blocks known privilege escalations: privileged, host
namespaces, hostPath, hostPort, dangerous capabilities, unmasked /proc) and **restricted** (baseline plus hardening).
Pod Security Admission enforces them per namespace with labels:

```yaml
metadata:
  labels:
    pod-security.kubernetes.io/enforce: restricted
    pod-security.kubernetes.io/warn: restricted
    pod-security.kubernetes.io/audit: restricted
```

## The restricted container securityContext
```yaml
securityContext:              # pod level
  runAsNonRoot: true
  seccompProfile:
    type: RuntimeDefault
containers:
- name: app
  securityContext:
    allowPrivilegeEscalation: false
    capabilities:
      drop: ["ALL"]           # only NET_BIND_SERVICE may be added back
    readOnlyRootFilesystem: true   # not required by PSS, strongly recommended
```

PodSecurityPolicy was removed in Kubernetes 1.25; Pod Security Admission replaced it. On OpenShift, SCCs perform
admission and the PSA label synchronizer sets namespace labels automatically for most namespaces.

## kubectl label --dry-run=server: preview a Pod Security level before enforcing it

Adding or changing a namespace's `enforce` label (or its `enforce-version`) makes the admission plugin check every
pod already in that namespace against the new level and return the violations as warnings. Run it as a server-side
dry run first: the checks still run and you see how existing pods would fare, but no label is changed.

```shell
kubectl label --dry-run=server --overwrite ns --all \
    pod-security.kubernetes.io/enforce=baseline
```

A gentle first step for all namespaces is audit and warn without enforce, which also leaves the namespaces nobody
has reviewed yet recognisable:

```shell
kubectl label --overwrite ns --all \
  pod-security.kubernetes.io/audit=baseline \
  pod-security.kubernetes.io/warn=baseline
```

`kubectl get namespaces --selector='!pod-security.kubernetes.io/enforce'` lists the namespaces with no explicit
enforce level. To enforce one namespace and pin the policy version (`<version>` is a Kubernetes minor version written
as `v1.<minor>`, or `latest`):

```shell
kubectl label --overwrite ns my-existing-namespace \
  pod-security.kubernetes.io/enforce=restricted \
  pod-security.kubernetes.io/enforce-version=<version>
```

## Deployment created but its pods never appear: enforce checks only Pods

Most pods come from a workload (Deployment, Job, ...) whose controller creates them from the pod template. Pod
Security Admission applies the `warn` and `audit` modes to the workload objects too, so `kubectl apply` of a
Deployment that breaks the level prints a `would violate PodSecurity` warning, and the object is still created.
`enforce` is applied only to the Pod objects the controller then creates, so in an enforcing namespace every one of
those pods is rejected and the Deployment shows no running pods. Fix the pod template (`spec.template.spec`) with the
restricted securityContext above.
