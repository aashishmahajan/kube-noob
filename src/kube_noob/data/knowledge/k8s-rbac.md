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
  `escalate`, `bind`, `impersonate` and `nodes/proxy` (rule KN-S017 flags these). Creating pods or workloads in a
  namespace whose ServiceAccounts are privileged is an escalation path too; review it manually.
- Set `automountServiceAccountToken: false` for pods that never call the API.
- Verify: `kubectl auth can-i --list --as=system:serviceaccount:<ns>:<sa>`.
- Errors look like `User "system:serviceaccount:ns:sa" cannot list resource "pods" in API group "" in the namespace
  "ns"`: the message names the exact verb, resource and API group to grant.

## Role or ClusterRole for a read-only ServiceAccount

- A Role grants permissions in one namespace; a ClusterRole defines permissions that can be granted in one
  namespace (bound with a RoleBinding) or cluster-wide (bound with a ClusterRoleBinding).
- For a read-only service account in one namespace, bind the built-in `view` ClusterRole with a RoleBinding:
  `kubectl create rolebinding app-view --clusterrole=view --serviceaccount=<ns>:<sa> -n <ns>`. `view` excludes
  Secrets.
- Cluster-wide read access (`ClusterRoleBinding` to `view`) is rarely needed; prefer one RoleBinding per namespace.
