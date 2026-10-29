---
id: k8s-etcd-backup
title: Back up and restore etcd (Kubernetes and OpenShift)
tags: [kubernetes, openshift, etcd, backup, restore, disaster-recovery, control-plane]
platforms: [kubernetes, openshift]
updated: 2026-10-28
license: Apache-2.0
requires:
  - [backup, restore, snapshot, disaster, recover, recovery, etcdctl, etcdutl]
sources:
  - {title: "Kubernetes: Operating etcd clusters for Kubernetes", url: "https://kubernetes.io/docs/tasks/administer-cluster/configure-upgrade-etcd/", license: CC-BY-4.0}
  - {title: "OpenShift 4.22: Backing up and restoring etcd data", url: "https://docs.redhat.com/en/documentation/openshift_container_platform/4.22/html/etcd/backing-up-and-restoring-etcd-data", license: CC-BY-SA-3.0}
---
# Back up and restore etcd

etcd holds every Kubernetes object, so its snapshot is the control plane's backup: `etcdctl snapshot save` takes
one, `etcdutl snapshot status` checks it, and `etcdutl snapshot restore` restores it with every API server
stopped. On OpenShift, `cluster-backup.sh` on one control plane node does the backup. Take snapshots on a schedule,
copy them off the node, and test a restore before you need one. A restore takes the whole cluster back in time.

## Kubernetes: take and check a snapshot

```sh
ETCDCTL_API=3 etcdctl --endpoints=https://127.0.0.1:2379 \
  --cacert=<trusted-ca-file> --cert=<cert-file> --key=<key-file> \
  snapshot save snapshot.db
etcdutl --write-out=table snapshot status snapshot.db
```

The CA, certificate and key paths are in the etcd pod's command line (`kubectl describe pod -n kube-system
etcd-<node>` on a kubeadm cluster). `etcdctl snapshot status` is deprecated since etcd 3.5; use `etcdutl`.

## Kubernetes: restore

Never restore under a running API server. Stop all API server instances, restore every etcd member, then start the
API servers again (and restart kube-scheduler, kube-controller-manager and the kubelets so none keeps stale
state):

```sh
etcdutl --data-dir <new-data-dir> snapshot restore snapshot.db
```

`<new-data-dir>` is created by the restore; point etcd at it. A snapshot restores into the same etcd major.minor
version it came from (a different patch version is fine).

## OpenShift: back up with cluster-backup.sh

Back up from one control plane node only, as a `cluster-admin`:

```sh
oc debug --as-root node/<control-plane-node>
chroot /host
/usr/local/bin/cluster-backup.sh /home/core/assets/backup
```

If a cluster-wide proxy is set (`oc get proxy cluster -o yaml`), export `HTTP_PROXY`, `HTTPS_PROXY` and `NO_PROXY`
first. The script wraps `etcdctl snapshot save` and writes two files: `snapshot_<timestamp>.db` and
`static_kuberesources_<timestamp>.tar.gz` (the static pod resources and, with etcd encryption on, the encryption
keys: store it apart from the snapshot, but you need both to restore). Copy them off the node.

## OpenShift: restoring is a last resort

Restoring an etcd backup on OpenShift is destructive: it takes the cluster back in time, operators can get stuck
when files on disk no longer match etcd, and in extreme cases the cluster loses track of persistent volumes. Use
it only when the control plane lost quorum or something critical was deleted; if the API server still answers,
etcd is available and you should not restore. Follow the disaster-recovery procedure for your exact version.
