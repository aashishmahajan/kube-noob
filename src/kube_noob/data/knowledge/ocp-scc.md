---
id: ocp-scc
title: SecurityContextConstraints (SCC) on OpenShift
tags: [openshift, security, scc, psa, required-scc]
platforms: [openshift, rosa-classic, rosa-hcp]
updated: 2026-10-28
license: Apache-2.0
sources:
  - {title: "Managing security context constraints", url: "https://docs.redhat.com/en/documentation/openshift_container_platform/latest/html/authentication_and_authorization/managing-pod-security-policies", license: CC-BY-SA-3.0}
  - {title: "OpenShift docs: About security context constraints (default SCCs)", url: "https://github.com/openshift/openshift-docs/blob/main/modules/security-context-constraints-about.adoc", license: Apache-2.0}
  - {title: "OpenShift docs: Pod security admission and security context constraints", url: "https://github.com/openshift/openshift-docs/blob/164957757519b01359989b533feac5ecab551530/modules/security-context-constraints-psa-coexistence.adoc", license: Apache-2.0}
  - {title: "OpenShift docs: Configure a workload to require a specific SCC", url: "https://github.com/openshift/openshift-docs/blob/164957757519b01359989b533feac5ecab551530/modules/security-context-constraints-requiring.adoc", license: Apache-2.0}
  - {title: "OpenShift docs: About security context constraints (4.22)", url: "https://github.com/openshift/openshift-docs/blob/164957757519b01359989b533feac5ecab551530/modules/security-context-constraints-about.adoc", license: Apache-2.0}
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
(user namespaces, `hostUsers: false`) is documented from 4.20 onward; those docs call it the most restrictive SCC
of a new installation and say it will be used by default for authenticated users.

## Practical rules
1. Do not set runAsUser/fsGroup on OpenShift; set `runAsNonRoot: true` and let the SCC assign IDs (runAsGroup is
   not governed by SCCs).
2. Build images that work as an arbitrary UID in group 0 (`chgrp -R 0 /app && chmod -R g=u /app`).
3. If a workload truly needs more, grant the least permissive SCC to its ServiceAccount only:
   `oc adm policy add-scc-to-user nonroot-v2 -z <sa> -n <ns>`. Never grant `privileged` or `anyuid` to app workloads
   casually.
4. `oc get pod <pod> -o jsonpath='{.metadata.annotations.openshift\.io/scc}'` shows which SCC admitted a pod.
5. `oc adm policy scc-subject-review -f manifest.yaml` shows which SCC would admit a manifest.

## Pod Security Admission and SCCs: a pod must pass both

On OpenShift, SCC admission and Pod Security Admission are separate checks, and a pod is rejected if it fails either
one. The SCC controller first fills in some securityContext fields from the pod's SCC (for example, an SCC that
requires the `runtime/default` seccomp profile sets `RuntimeDefault` on a pod that set none), then validates the pod
against that SCC. Pod Security Admission then validates the pod against the pod security standard of its namespace.
So `unable to validate against any security context constraint` and `violates PodSecurity` are two different
rejections: a pod that an SCC admits can still break the namespace's `pod-security.kubernetes.io/enforce` level, and
the reverse.

## openshift.io/required-scc: require a specific SCC for a workload

Set the `openshift.io/required-scc` annotation to pin a workload to one SCC, or to stop another SCC in the cluster
from being chosen ahead of it. It goes on the pod template of any resource that has one (Deployment, DaemonSet, ...):

```yaml
apiVersion: apps/v1
kind: Deployment
spec:
# ...
  template:
    metadata:
      annotations:
        openshift.io/required-scc: "my-scc"
# ...
```

Create it with `oc create -f deployment.yaml`. Pod admission fails unless the SCC exists and the user creating the
pod or the pod's ServiceAccount has `use` permission for it in the pod's namespace. Do not edit the annotation on a
running pod (its admission then fails); change it in the pod template, which deletes and re-creates the pods. Check
which SCC admitted a pod with `oc get pod <pod_name> -o jsonpath='{.metadata.annotations.openshift\.io\/scc}{"\n"}'`
(it prints `my-scc` here).

## Privileged workloads: grant an SCC to the ServiceAccount, never edit the default SCCs

- Do not change the default SCCs (`restricted-v2`, `privileged`, `anyuid`, ...): edited defaults can break platform
  pods or upgrades, and some upgrades reset them to their defaults, discarding the change. Create your own SCC when
  none fits. Giving a default SCC a priority above 0 can make the cluster unstable.
- For a workload such as a Deployment or DaemonSet, the pods' SCCs are looked up only through the pod's ServiceAccount
  when the controller creates them; an SCC granted to your own user does not help. Grant it to the ServiceAccount
  with the command in rule 3 above.
- `privileged: true` in the pod spec does not by itself select the `privileged` SCC: admission picks the
  highest-priority SCC with `allowPrivilegedContainer: true` that the requester may use.
- The `privileged` SCC allows privileged pods, host directory volumes, the host IPC and PID namespaces, any user, any
  MCS label, any fsGroup and supplemental group, any seccomp profile and any capability. It is the most relaxed SCC,
  meant for cluster administration only; grant it with caution and never to ordinary application workloads.
