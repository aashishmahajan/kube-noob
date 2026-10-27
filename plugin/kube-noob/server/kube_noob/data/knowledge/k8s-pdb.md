---
id: k8s-pdb
title: PodDisruptionBudgets that protect availability without blocking upgrades
tags: [kubernetes, availability, upgrades]
platforms: [kubernetes, openshift, rosa-classic, rosa-hcp]
updated: 2026-10-27
license: Apache-2.0
sources:
  - {title: "Specifying a Disruption Budget for your Application", url: "https://kubernetes.io/docs/tasks/run-application/configure-pdb/", license: CC-BY-4.0}
---
# PodDisruptionBudgets

A PDB (`policy/v1`; `policy/v1beta1` was removed in 1.25) limits **voluntary** disruptions such as node drains during
upgrades. It does not protect against node crashes.

- Good: `maxUnavailable: 1` with `replicas >= 2`.
- Dangerous: `minAvailable` equal to the replica count, `maxUnavailable: 0` or `minAvailable: 100%` - zero allowed
  disruptions, so `drain` waits forever and OpenShift/ROSA upgrades stall on that node (rule KN-C009).
- A PDB over an unhealthy workload also allows zero disruptions; fix the workload first.
- Check: `oc get pdb -A -o custom-columns=NS:.metadata.namespace,NAME:.metadata.name,ALLOWED:.status.disruptionsAllowed`.
