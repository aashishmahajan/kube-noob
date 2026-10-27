---
name: kube-debugging
description: >
  Systematic Kubernetes/OpenShift debugging - CrashLoopBackOff, ImagePullBackOff, OOMKilled, Pending pods, PVC pending,
  Multi-Attach, SCC/PSA rejections, Route 503, RBAC forbidden, webhook denials, Helm failures, evictions, DNS and
  NetworkPolicy issues. Use when the user pastes errors, events, describe output or logs, or says something is broken.
---

# Debugging

Diagnose before change. Never lead with a command that executes in a container or changes the cluster.

1. Collect read-only evidence: `oc describe pod`, `oc get events --sort-by=.lastTimestamp`, `oc logs --previous`, or a
   redacted bundle (`kube-noob bundle deployment/<name> -n <ns> --cluster-enabled`).
2. Call `kubenoob_diagnose` with the raw text (and platform if known). Present its `readOnlyNextSteps` first.
3. If `kubenoob_config_status` shows `cluster.enabled: true`, call `kubenoob_cluster_debug_workload` (read-only, never
   reads Secrets, redacts values).
4. Explain the most likely cause with the confirming read-only check, citing `[kn:...]` chunks.
5. Only then offer `diagnosticCommands` (rsh, exec, curl) and `proposedChanges`; for each, state the impact and ask for
   approval.
6. If the fix is a manifest change, run `kubenoob_run_protocol` on the corrected YAML before presenting it.
