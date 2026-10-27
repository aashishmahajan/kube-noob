---
id: rosa-efs
title: ReadWriteMany on ROSA with the AWS EFS CSI driver
tags: [rosa, storage, efs, rwx]
platforms: [rosa-classic, rosa-hcp]
updated: 2026-10-27
license: Apache-2.0
sources:
  - {title: "AWS EFS CSI driver", url: "https://github.com/kubernetes-sigs/aws-efs-csi-driver", license: Apache-2.0}
  - {title: "ROSA storage documentation", url: "https://docs.redhat.com/en/documentation/red_hat_openshift_service_on_aws/", license: CC-BY-SA-3.0}
---
# ReadWriteMany on ROSA (EFS)

`gp3-csi` / `gp2-csi` are EBS block volumes: one node, one AZ, ReadWriteOnce. A PVC asking for ReadWriteMany from them
stays Pending with ProvisioningFailed. For shared storage on ROSA (Classic or HCP) use Amazon EFS:

1. Install the **AWS EFS CSI Driver Operator** from OperatorHub. On STS clusters create the IAM role it needs first
   and pass its ARN.
2. Create the `ClusterCSIDriver` named `efs.csi.aws.com` so the operator deploys the driver.
3. Create an EFS file system in the cluster VPC with **a mount target in every worker subnet** and a security group
   that allows NFS (TCP 2049) from the worker nodes.
4. Create a StorageClass (none exists by default) with `provisioner: efs.csi.aws.com`, `provisioningMode: efs-ap`,
   `fileSystemId: fs-...`; dynamic provisioning creates one EFS access point per PVC.

## Red team notes
- RWX solves "many pods can mount"; it does not solve concurrent writers. Embedded databases (SQLite, BoltDB, Lucene
  indexes) on NFS/EFS can corrupt; use per-replica RWO volumes or a real database.
- EFS is regional and multi-AZ, so it survives a zone failure that would strand a zonal EBS volume.
- Throughput and latency differ from EBS; benchmark I/O-heavy workloads.
