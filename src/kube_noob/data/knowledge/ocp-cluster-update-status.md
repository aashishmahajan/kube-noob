---
id: ocp-cluster-update-status
title: ClusterOperator conditions and stuck cluster updates
tags: [openshift, clusteroperator, clusterversion, cvo, update, upgrade, degraded, upgradeable]
platforms: [openshift]
updated: 2026-10-28
license: Apache-2.0
requires:
  - [clusteroperator, clusteroperators, co, clusterversion, cvo, degraded, upgradeable, progressing, update, updates, updating, upgrade, upgrades, upgrading, towards]
sources:
  - {title: "OpenShift docs: Understanding cluster Operator condition types", url: "https://github.com/openshift/openshift-docs/blob/164957757519b01359989b533feac5ecab551530/modules/determining-upgrade-viability-conditiontype.adoc", license: Apache-2.0}
  - {title: "OpenShift docs: Diagnosing an update stuck in Working towards state", url: "https://github.com/openshift/openshift-docs/blob/164957757519b01359989b533feac5ecab551530/modules/core-cluster-upgrade-ts-update-stuck.adoc", license: Apache-2.0}
---
# ClusterOperator conditions and stalled cluster updates

## ClusterOperator Available and Progressing conditions (oc get co)

Every cluster Operator reports condition types that describe its health; the Cluster Version Operator (CVO) gathers
them so administrators can read the state of the whole cluster. Some Operators add their own condition types; the
common ones are these four.

- `Available`: the Operator works and is available in the cluster. `False` means at least one part of its operand
  is not working, and an administrator has to step in.
- `Progressing`: the Operator is rolling out new code, spreading a configuration change, or otherwise moving from
  one steady state to the next. It is not `True` while the Operator merely reconciles a state it already knew; it
  becomes `True` when the observed cluster state changed and the Operator is reacting to that.

## ClusterOperator Degraded=True: what it means and what it does not

`Degraded` means the Operator's current state has not matched its required state for some time. How long depends
on the component, but it always reflects a lasting observation, so an Operator does not flip in and out of
`Degraded`; a short-lived mismatch may show up as a different condition type instead.

An Operator does not report `Degraded` during a normal update. It may report it for a lasting infrastructure
failure that will eventually need an administrator.

`Degraded` only says something may need a look and an adjustment. While the Operator is still `Available`, a
`Degraded` condition does not make user workloads fail or cause application downtime.

## ClusterOperator Upgradeable=False blocks minor updates

`Upgradeable` tells whether updating the Operator is safe in the current cluster state; its message explains, in
plain words, what the administrator must do so the update can succeed. The CVO allows updates when the condition is
`True`, `Unknown` or absent.

With `Upgradeable=False`, only minor updates are affected: the CVO refuses those updates unless they are forced.

## Cluster update stuck in "Working towards": oc get clusterversion, oc get co, .status.history

A cluster update normally finishes in 90 to 180 minutes. If `ClusterVersion` keeps showing a "Working towards"
message for much longer, find the Operators that hold it up (needs cluster-admin):

1. `oc get clusterversion -o yaml`: read the `status.conditions` section for the resources that block the update.
2. `oc get co | grep "True"`: an Operator with `PROGRESSING=True` is still updating.
3. `oc get clusterversion -o jsonpath='{.status.history}'`: if the history entry for the update is missing or no
   longer moves, the update has timed out.

Then read the conditions of the Operators that are still progressing (see the sections above for what each
condition means).
