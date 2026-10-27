---
id: k8s-pss
title: Pod Security Standards and the hardened securityContext
tags: [kubernetes, security, pss]
platforms: [kubernetes, openshift, rosa-classic, rosa-hcp]
updated: 2026-10-27
license: Apache-2.0
sources:
  - {title: "Pod Security Standards", url: "https://kubernetes.io/docs/concepts/security/pod-security-standards/", license: CC-BY-4.0}
  - {title: "Pod Security Admission", url: "https://kubernetes.io/docs/concepts/security/pod-security-admission/", license: CC-BY-4.0}
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
