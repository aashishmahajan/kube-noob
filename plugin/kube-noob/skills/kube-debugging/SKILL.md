---
name: kube-debugging
description: >
  Systematic Kubernetes/OpenShift debugging - CrashLoopBackOff, ImagePullBackOff, OOMKilled, Pending pods, PVC pending,
  Multi-Attach, SCC/PSA rejections, Route 503, RBAC forbidden, webhook denials, Helm failures, evictions, DNS and
  NetworkPolicy issues. Use when the user pastes errors, events, describe output or logs, or says something is broken.
---

# Debugging

1. Ask for (or use what was pasted): `oc describe pod`, `oc get events --sort-by=.lastTimestamp`, `oc logs --previous`.
2. Call `kubenoob_diagnose` with the raw text (and platform if known). It returns ranked root causes, read-only checks
   with names filled in, fixes, related audit rules and knowledge ids.
3. If live cluster access is enabled on the server (`kubenoob_config_status` shows `cluster.enabled: true`), call
   `kubenoob_cluster_debug_workload` for the workload - it is read-only, never reads Secrets and redacts sensitive values.
4. Explain the most likely cause first, give the confirming check, then the fix. Cite `[kn:...]` chunks.
5. If the fix is a manifest change, run the master controller protocol on the corrected YAML before presenting it.
Never suggest destructive commands (delete, patch, scale to zero) without stating the impact and asking first.
