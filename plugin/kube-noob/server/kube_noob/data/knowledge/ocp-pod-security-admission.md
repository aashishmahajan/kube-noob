---
id: ocp-pod-security-admission
title: OpenShift pod security admission label sync
tags: [openshift, security, scc, psa, pod-security, audit]
platforms: [openshift]
updated: 2026-10-28
license: Apache-2.0
requires:
  - [scc, sccs, securitycontextconstraints, security, pod-security, podsecurity, podsecurityviolation, psa, audit-violations]
sources:
  - {title: "OpenShift docs: About pod security admission synchronization", url: "https://github.com/openshift/openshift-docs/blob/164957757519b01359989b533feac5ecab551530/modules/security-context-constraints-psa-synchronization.adoc", license: Apache-2.0}
  - {title: "OpenShift docs: About pod security admission (modes and labels)", url: "https://github.com/openshift/openshift-docs/blob/164957757519b01359989b533feac5ecab551530/modules/security-context-constraints-psa-about.adoc", license: Apache-2.0}
  - {title: "OpenShift docs: Identify pod security violations", url: "https://github.com/openshift/openshift-docs/blob/164957757519b01359989b533feac5ecab551530/modules/security-context-constraints-psa-alert-eval.adoc", license: Apache-2.0}
---
# Pod security admission and SCCs on OpenShift

## Pod security label synchronization: where the warn and audit labels come from

OpenShift keeps the pod security admission `warn` and `audit` labels of your namespaces
(`pod-security.kubernetes.io/warn`, `pod-security.kubernetes.io/audit`) in sync automatically. A controller checks
which security context constraints (SCCs) the ServiceAccounts of each namespace are allowed to use, translates
those SCCs into pod security profiles from their field values, and sets `warn` and `audit` to the most privileged
profile it finds there. That is deliberate: pods created in the namespace then raise no warnings and log no audit
events.

## Label synchronization counts ServiceAccounts, not the user who creates the pod

The labels depend only on what the ServiceAccounts inside the namespace may use. A pod that a user applies
directly may be admitted with that user's SCC privileges, but the user's privileges play no part in the automatic
labeling.

## PodSecurityViolation alert: find the pods that caused it (must-gather audit logs)

The `PodSecurityViolation` alert does not name the workloads. They are in the Kubernetes API server audit logs,
which `must-gather` collects. You need `jq` and the `cluster-admin` role.

```sh
oc adm must-gather -- /usr/bin/gather_audit_logs
zgrep -h pod-security.kubernetes.io/audit-violations must-gather.local.<archive_id>/<image_digest_id>/audit_logs/kube-apiserver/*log.gz \
  | jq -r 'select((.annotations["pod-security.kubernetes.io/audit-violations"] != null) and (.objectRef.resource=="pods")) | .objectRef.namespace + " " + .objectRef.name' \
  | sort | uniq -c
```

Put the real directory names in place of `<archive_id>` and `<image_digest_id>`. Each output line is a count, a
namespace and a pod name, for example `1 test-namespace my-pod`.

Requiring one SCC for a workload (`openshift.io/required-scc`) and reading which SCC admitted a pod are in
[kn:ocp-scc#4].
