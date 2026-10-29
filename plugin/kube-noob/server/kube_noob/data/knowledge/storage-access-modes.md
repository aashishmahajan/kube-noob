---
id: storage-access-modes
title: Storage access modes and what each StorageClass can actually provide
tags: [storage, pvc, rwx, rwo]
platforms: [kubernetes, openshift, rosa-classic, rosa-hcp]
updated: 2026-10-27
license: Apache-2.0
# A question has to be about this document's subject: generic words (container, volume, exit) are not enough.
requires:
  - [pvc, pvcs, persistentvolumeclaim, persistentvolumeclaims, pv, pvs, persistentvolume, persistentvolumes, storageclass, storageclasses, accessmodes, readwriteonce, readwritemany, readonlymany, readwriteoncepod, rwo, rwx, multi-attach, csi, volumeattachment]
sources:
  - {title: "OpenShift docs: Resolve multi-attach errors", url: "https://github.com/openshift/openshift-docs/blob/1400f2c8ebe0f2ec66005ecef2bd720cf4c97cad/modules/storage-multi-attach-error.adoc", license: Apache-2.0}
  - {title: "Kubernetes Persistent Volumes - access modes", url: "https://kubernetes.io/docs/concepts/storage/persistent-volumes/#access-modes", license: CC-BY-4.0}
  - {title: "OpenShift - understanding persistent storage", url: "https://docs.redhat.com/en/documentation/openshift_container_platform/", license: CC-BY-SA-3.0}
---
# Storage access modes

| Mode | Meaning |
|---|---|
| ReadWriteOnce (RWO) | read-write by pods on a **single node** |
| ReadOnlyMany (ROX) | read-only by many nodes |
| ReadWriteMany (RWX) | read-write by many nodes |
| ReadWriteOncePod (RWOP) | read-write by a single pod |

The access mode is a **request**; the provisioner behind the StorageClass decides whether it can be met.

| StorageClass (typical) | Provisioner | RWO | RWX |
|---|---|---|---|
| gp3-csi, gp2-csi (AWS, OpenShift/ROSA default) | ebs.csi.aws.com | yes | **no** |
| efs-sc (you create it) | efs.csi.aws.com | yes | yes |
| ocs-storagecluster-ceph-rbd (ODF) | openshift-storage.rbd.csi.ceph.com | yes | only `volumeMode: Block` |
| ocs-storagecluster-cephfs (ODF) | openshift-storage.cephfs.csi.ceph.com | yes | yes |
| thin-csi (vSphere) | csi.vsphere.vmware.com | yes | needs vSAN File Services |
| managed-csi (Azure Disk) | disk.csi.azure.com | yes | no |
| azurefile-csi | file.csi.azure.com | yes | yes |
| lvms-vg1 (LVM Storage) | topolvm.io | yes (node-local) | no |

## Common traps
- RWX PVC on gp3-csi: stays Pending (`ProvisioningFailed`). kube-noob rule KN-ST001.
- A Deployment with several replicas (or a RollingUpdate surge pod) sharing one RWO claim: pods on other nodes hang in
  ContainerCreating with `Multi-Attach error`. Use a StatefulSet with `volumeClaimTemplates`, or `strategy: Recreate`
  with one replica. Rule KN-ST002.
- `Multi-Attach error ... Volume is already used by pod(s)` after a node crashed or shut down abruptly: the dead node
  cannot unmount its ReadWriteOnce volume. Use ReadWriteMany where the storage supports it; with RWO, once the node
  is confirmed down, force delete the old pod: `oc delete pod <old_pod> --force=true --grace-period=0`. The volume
  stuck on that node is released after six minutes.
- Zonal block storage with `volumeBindingMode: Immediate` can create the volume in a zone where the pod cannot run.
  Use `WaitForFirstConsumer`. Rule KN-ST003.
- `storageClassName` is immutable on a PVC: fixing it means creating a new claim and migrating data.
