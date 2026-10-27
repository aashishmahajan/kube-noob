---
id: k8s-rbac
title: RBAC least privilege
tags: [kubernetes, rbac, security]
platforms: [kubernetes, openshift, rosa-classic, rosa-hcp]
updated: 2026-10-27
license: Apache-2.0
sources:
  - {title: "Role Based Access Control Good Practices", url: "https://kubernetes.io/docs/concepts/security/rbac-good-practices/", license: CC-BY-4.0}
---
# RBAC least privilege

- Prefer namespaced Role + RoleBinding over ClusterRole + ClusterRoleBinding.
- No wildcards (`*`) in apiGroups, resources or verbs - they also grant future resources (rule KN-S015).
- Never bind `cluster-admin` to application ServiceAccounts (rule KN-S016).
- Treat as privileged: `secrets` get/list/watch (list returns contents), `pods/exec` and `pods/attach` create,
  `escalate`, `bind`, `impersonate`, `nodes/proxy`, and create on workloads in privileged namespaces (rule KN-S017).
- Set `automountServiceAccountToken: false` for pods that never call the API.
- Verify: `kubectl auth can-i --list --as=system:serviceaccount:<ns>:<sa>`.
- Errors look like `User "system:serviceaccount:ns:sa" cannot list resource "pods" in API group "" in the namespace
  "ns"`: the message names the exact verb, resource and API group to grant.
