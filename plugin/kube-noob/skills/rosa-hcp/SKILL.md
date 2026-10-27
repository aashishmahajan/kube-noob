---
name: rosa-hcp
description: >
  Red Hat OpenShift Service on AWS - ROSA Classic vs ROSA with Hosted Control Planes (HyperShift): architecture,
  PrivateLink, machine pools, upgrade sequencing, networking CIDRs, EBS vs EFS storage, Terraform rhcs modules. Use when
  the user mentions ROSA, HCP, hosted control planes, HyperShift, machine pools or rosa CLI.
---

# ROSA (Classic and HCP)

- HCP: control plane runs as pods in a Red Hat-owned AWS account; workers in the customer VPC reach it over AWS
  PrivateLink; control plane is multi-AZ; each machine pool is single-AZ; upgrade the control plane first, machine pools
  separately (within two minors).
- Node configuration on HCP: `rosa create kubeletconfig` and machine pools - not MachineConfig objects (rule KN-V017).
- Storage: default `gp3-csi` is EBS (RWO, zonal). RWX requires the AWS EFS CSI Driver Operator, an EFS file system with
  mount targets in every worker subnet (NFS 2049/tcp allowed) and a StorageClass you create (`provisioningMode: efs-ap`).
- Generate with `kubenoob_generate_manifests` using `platform: rosa-hcp`; audit with the same platform.
- Search `kubenoob_search_knowledge` with source filters such as `rosa-experts`, `hypershift-docs` or `tf-rosa-hcp` when
  the corpus is installed.
