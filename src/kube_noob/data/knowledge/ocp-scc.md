---
id: ocp-scc
title: SecurityContextConstraints (SCC) on OpenShift
tags: [openshift, security, scc]
platforms: [openshift, rosa-classic, rosa-hcp]
updated: 2026-10-27
license: Apache-2.0
sources:
  - {title: "Managing security context constraints", url: "https://docs.redhat.com/en/documentation/openshift_container_platform/latest/html/authentication_and_authorization/managing-pod-security-policies", license: CC-BY-SA-3.0}
  - {title: "OpenShift docs: About security context constraints (default SCCs)", url: "https://github.com/openshift/openshift-docs/blob/main/modules/security-context-constraints-about.adoc", license: Apache-2.0}
---
# SecurityContextConstraints

SCCs (`security.openshift.io/v1`) are OpenShift's pod admission policy. When a pod is created, admission tries the
SCCs available to the requesting user and the pod's ServiceAccount, in priority order, and uses the first one the pod
satisfies; if none fits the pod is rejected with `unable to validate against any security context constraint`.

## restricted-v2 (default for authenticated users on new 4.11+ clusters)
- Drops ALL capabilities (NET_BIND_SERVICE may be added explicitly).
- seccomp `runtime/default`.
- `allowPrivilegeEscalation` must be unset or false.
- No privileged containers, host namespaces or hostPath volumes.
- `runAsUser: MustRunAsRange` - the UID comes from the namespace annotation `openshift.io/sa.scc.uid-range`;
  `fsGroup: MustRunAs` - from `openshift.io/sa.scc.supplemental-groups`. Supplemental groups are `RunAsAny` (any
  value allowed). SCCs have no `runAsGroup` strategy. A pod that hard-codes `runAsUser: 1000` is rejected.
Clusters upgraded from 4.10 or earlier keep the legacy `restricted` SCC for existing users. `restricted-v3`
(user namespaces, `hostUsers: false`) is documented from 4.20 onward.

## Practical rules
1. Do not set runAsUser/fsGroup on OpenShift; set `runAsNonRoot: true` and let the SCC assign IDs (runAsGroup is
   not governed by SCCs).
2. Build images that work as an arbitrary UID in group 0 (`chgrp -R 0 /app && chmod -R g=u /app`).
3. If a workload truly needs more, grant the least permissive SCC to its ServiceAccount only:
   `oc adm policy add-scc-to-user nonroot-v2 -z <sa> -n <ns>`. Never grant `privileged` or `anyuid` to app workloads
   casually.
4. `oc get pod <pod> -o jsonpath='{.metadata.annotations.openshift\.io/scc}'` shows which SCC admitted a pod.
5. `oc adm policy scc-subject-review -f manifest.yaml` shows which SCC would admit a manifest.
