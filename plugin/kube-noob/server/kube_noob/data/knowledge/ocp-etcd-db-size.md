---
id: ocp-etcd-db-size
title: etcd database size on OpenShift
tags: [openshift, etcd, backendquotagib, quota, database]
platforms: [openshift]
updated: 2026-10-28
license: Apache-2.0
requires:
  - [etcd, backendquotagib, etcd_quota_backend_bytes]
sources:
  - {title: "OpenShift docs: Troubleshooting etcd database size increases", url: "https://github.com/openshift/openshift-docs/blob/164957757519b01359989b533feac5ecab551530/modules/etcd-increase-db-troubleshooting.adoc", license: Apache-2.0}
  - {title: "OpenShift docs: Increase the database size for etcd", url: "https://github.com/openshift/openshift-docs/blob/164957757519b01359989b533feac5ecab551530/modules/etcd-increase-db.adoc", license: Apache-2.0}
---
# etcd database size (backendQuotaGiB)

## Raise the etcd disk quota: oc patch etcd/cluster backendQuotaGiB (Technology Preview)

The disk quota of each etcd instance is set in GiB with `spec.backendQuotaGiB` on `etcd/cluster`. It accepts an
integer from 8 to 32, defaults to 8, and can only be increased. Increasing the etcd database size is a Technology
Preview feature: it is not covered by Red Hat production SLAs and Red Hat does not recommend it for production.

When to raise it:
- A `low space` alert: the cluster no longer fits in etcd even with automatic compaction and defragmentation. Raise
  the quota right away, because writes fail once etcd is out of space.
- An `excessive database growth` alert: the database may grow too large within the next four hours; raising the
  quota early avoids reaching `low space`.

The space is not reserved up front; etcd may grow up to the quota when it needs to. Run etcd on a dedicated disk
that is bigger than the quota. A large database also needs more memory and storage on the control plane nodes:
because of the API server cache, plan at least three times the configured database size in memory.

```sh
oc describe etcd/cluster | grep "Backend Quota"
oc patch etcd/cluster --type=merge -p '{"spec": {"backendQuotaGiB": <value>}}'
```

The patch prints `etcd.operator.openshift.io/cluster patched`.

## Verify the new etcd quota (ETCD_QUOTA_BACKEND_BYTES)

The etcd Operator rolls the etcd instances out with the new value on its own. Check:

- `oc describe etcd/cluster | grep "Backend Quota"` shows the value you set.
- `oc get pods -n openshift-etcd`: the etcd pods are `Running` again.
- `oc describe -n openshift-etcd pod/<etcd_podname> | grep "ETCD_QUOTA_BACKEND_BYTES"` shows the quota inside the
  etcd pod, converted to bytes (the default 8 GiB is `8589934592`).

## spec.backendQuotaGiB in body should be greater than or equal to 8 (or less than or equal to 32)

The API rejects values outside the 8 to 32 range:

- Below 8, for example `oc patch etcd/cluster --type=merge -p '{"spec": {"backendQuotaGiB": 5}}'`, fails with
  `spec.backendQuotaGiB in body should be greater than or equal to 8` (the same error lists
  `etcd backendQuotaGiB may not be decreased` too).
- Above 32, for example `oc patch etcd/cluster --type=merge -p '{"spec": {"backendQuotaGiB": 64}}'`, fails with
  `spec.backendQuotaGiB in body should be less than or equal to 32`.

Use an integer from 8 to 32.

## etcd backendQuotaGiB may not be decreased

Once the quota holds a valid value, it cannot be lowered; a smaller value fails with
`spec.backendQuotaGiB: Invalid value: "integer": etcd backendQuotaGiB may not be decreased`. Read the current value
first with `oc describe etcd/cluster | grep "Backend Quota"` (for example `Backend Quota Gi B: 10`) and pick a
larger one: with 10 set, `oc patch etcd/cluster --type=merge -p '{"spec": {"backendQuotaGiB": 8}}'` fails, and the
fix is an integer greater than 10.
