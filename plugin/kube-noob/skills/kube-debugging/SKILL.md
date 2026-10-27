---
name: kube-debugging
description: >
  Systematic Kubernetes/OpenShift debugging - CrashLoopBackOff, ImagePullBackOff, OOMKilled, Pending pods, PVC pending,
  Multi-Attach, SCC/PSA rejections, Route 503, RBAC forbidden, webhook denials, Helm failures, evictions, DNS and
  NetworkPolicy issues, and whether an OpenShift error is a reported bug with a fix version. Use when the user pastes
  errors, events, describe output or logs, says something is broken, or asks "is this a known bug?"
---

# Debugging

Diagnose before change. Never lead with a command that executes in a container or changes the cluster. Commands
are for the user to run: give them as copy-paste lines (no shell comments) and do not run them yourself.

1. Ask for read-only evidence: the output of `oc describe pod`, `oc get events --sort-by=.lastTimestamp`,
   `oc logs --previous`, or a redacted bundle (`kube-noob bundle deployment/<name> -n <ns> --cluster-enabled`).
2. Call `kubenoob_diagnose` with the raw text, the platform and, on OpenShift, the cluster version if known (`4.20.8`).
   Present its `readOnlyNextSteps` first.
3. If `knownIssues` is not empty, or the user asks "is this a known bug?", say so plainly: the issue id with its link,
   whether a fix exists and in which version (`status`), and the `workaround`. Call `kubenoob_known_issues` directly
   for a symptom with no playbook. Never claim a bug is reported unless the tool returned it.
4. If `kubenoob_config_status` shows `cluster.enabled: true`, call `kubenoob_cluster_debug_workload` (read-only, never
   reads Secrets, redacts values).
5. Explain the most likely cause with the confirming read-only check, citing `[kn:...]` chunks. When the answer
   depends on versions or recent changes, give `knowledgeAsOf` from the tool result.
6. Only then offer `diagnosticCommands` (rsh, exec, curl) and `proposedChanges`; for each, state the impact and ask for
   approval.
7. If the fix is a manifest change, run `kubenoob_run_protocol` on the corrected YAML before presenting it.
