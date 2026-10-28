---
name: kube-debugging
description: >
  Systematic Kubernetes/OpenShift debugging - CrashLoopBackOff, ImagePullBackOff, OOMKilled, Pending pods, PVC pending,
  Multi-Attach, SCC/PSA rejections, Route 503, RBAC forbidden, webhook denials, Helm failures, evictions, DNS and
  NetworkPolicy issues, and whether an OpenShift error is a reported bug with a fix version. Explains policy denials
  (Kyverno, Gatekeeper, ValidatingAdmissionPolicy, Pod Security, SCC, RHACS, quota, RBAC) and checks whether a
  NetworkPolicy lets one pod reach another. Use when the user pastes errors, events, describe output or logs, says
  something is broken, asks "why was this denied?", "can A reach B?" or "is this a known bug?"
---

# Debugging

Diagnose before change. Never lead with a command that executes in a container or changes the cluster. Commands
are for the user to run: give them as copy-paste lines (no shell comments) and do not run them yourself.

1. Call `kubenoob_incidents` first: if the watch already recorded the problem, its incident has the diagnosis, what
   changed before it started, how often it came back and the fix the team confirmed last time; lead with that.
   Otherwise ask for read-only evidence: the output of `oc describe pod`, `oc get events --sort-by=.lastTimestamp`,
   `oc logs --previous`, or a redacted bundle (`kube-noob bundle deployment/<name> -n <ns> --cluster-enabled`).
2. Call `kubenoob_diagnose` with the raw text, the platform and, on OpenShift, the cluster version if known (`4.20.8`).
   An Alertmanager webhook payload goes in as it is; its `openshift_version` label stands in for the version (see
   `input`). Name the `signals` it found (alert names, reasons), then present `readOnlyNextSteps` first.
   `kubenoob_extract_signals` lists the signals alone, with the alerts the words imply and the playbooks they point at.
3. If `knownIssues` is not empty, or the user asks "is this a known bug?", say so plainly: the issue id with its link,
   what became of it (`status`; for Red Hat Jira tickets also `verdict`: fixed, fix in progress, open, not a bug, won't
   fix, cannot reproduce, obsolete or duplicate), and the `workaround` or `remarks` from the comments. A ticket closed
   as not a bug usually means configuration: lead with the remark that says why. Call `kubenoob_known_issues` directly
   for a symptom with no playbook and `kubenoob_ticket` for a key the user names. Never claim a bug is reported unless
   the tool returned it.
4. If the request was denied by a policy (`policyDenials` in the diagnosis, or a Kyverno, Gatekeeper, Pod Security,
   SCC, RHACS, quota or RBAC message), call `kubenoob_explain_denial` and name each policy and rule, the failing field
   and the fix (its `patch` for Pod Security and RBAC). Exceptions, quota increases and new permissions are the policy
   owner's decision: say so. For "can pod A reach pod B?" call `kubenoob_check_network_policy` with the
   NetworkPolicies and workloads (or `kubenoob_cluster_check_traffic` when cluster access is on); give the verdict, the
   policy and rule that decide each direction, and the proposed allow policy only if the user wants the traffic.
5. If `kubenoob_config_status` shows `cluster.enabled: true`, call `kubenoob_cluster_debug_workload` (read-only, never
   reads Secrets, redacts values).
6. Explain the most likely cause with the confirming read-only check, citing `[kn:...]` chunks. When the answer
   depends on versions or recent changes, give `knowledgeAsOf` from the tool result.
7. Only then offer `diagnosticCommands` (rsh, exec, curl) and `proposedChanges`; for each, state the impact and ask for
   approval.
8. If the fix is a manifest change, run `kubenoob_run_protocol` on the corrected YAML before presenting it.
9. When the user confirms what fixed an incident, offer `kubenoob_incident_confirm` so the next occurrence comes with
   it (summaries only).
