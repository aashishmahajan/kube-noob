---
id: rosa-hcp
title: ROSA - Classic vs Hosted Control Planes (HCP)
tags: [rosa, hcp, hypershift, aws]
platforms: [rosa-classic, rosa-hcp]
updated: 2026-10-27
license: Apache-2.0
sources:
  - {title: "Red Hat OpenShift Service on AWS documentation", url: "https://docs.redhat.com/en/documentation/red_hat_openshift_service_on_aws/", license: CC-BY-SA-3.0}
  - {title: "openshift/hypershift", url: "https://github.com/openshift/hypershift", license: Apache-2.0}
  - {title: "Red Hat Cloud Experts - ROSA", url: "https://cloud.redhat.com/experts/rosa/", license: Apache-2.0}
---
# ROSA: Classic vs Hosted Control Planes

## ROSA Classic
Control plane and infrastructure nodes run in the customer's AWS account alongside the workers (higher EC2 footprint:
dedicated control plane and infra nodes).

## ROSA with Hosted Control Planes (HCP)
- Built on **HyperShift**: the control plane (API server, etcd, controllers) runs as pods in a **Red Hat-owned AWS
  account**; only worker nodes (plus platform components such as ingress, registry and monitoring) run in the
  customer's VPC.
- Workers reach the hosted control plane over **AWS PrivateLink**, whether the API endpoint is public or private;
  private clusters' API is reachable only from inside the VPC.
- The hosted control plane is always multi-AZ (3 AZs). Each **machine pool** is deployed in a single AZ / subnet;
  a cluster needs at least 2 worker EC2 instances.
- **Upgrades are decoupled**: upgrade the control plane first, then each machine pool separately. Machine pools cannot
  run a newer version than the control plane and must stay within two minor versions of it.
- Networking: machine CIDR at least /25 for single-AZ and /24 for multi-AZ (default 10.0.0.0/16, immutable after
  install); VPC must have DNS hostnames and DNS resolution enabled; public clusters need a public subnet with a NAT
  gateway, private clusters do not. Default cluster network 10.132.0.0/14 and service network 172.31.0.0/16.
- Node configuration: use the managed interfaces - `rosa create kubeletconfig` for kubelet tuning and machine pools
  (`rosa create|edit machinepool`) for instance type, labels, taints and autoscaling. The Machine Config Operator does
  not run in the hosted cluster (HyperShift applies node config from the management side via NodePool), so
  customer-owned MachineConfig objects are not a supported lever.

## Storage on ROSA
- Default StorageClass `gp3-csi` (AWS EBS, `ebs.csi.aws.com`): block storage, **ReadWriteOnce**, bound to one AZ,
  `WaitForFirstConsumer`.
- **ReadWriteMany** needs AWS EFS: install the AWS EFS CSI Driver Operator (on STS clusters create the IAM role first),
  create an EFS file system with mount targets in each worker subnet (security groups allowing NFS 2049/tcp from the
  workers), then create a StorageClass yourself - the operator does not create one:

```yaml
apiVersion: storage.k8s.io/v1
kind: StorageClass
metadata:
  name: efs-sc
provisioner: efs.csi.aws.com
parameters:
  provisioningMode: efs-ap
  fileSystemId: fs-0123456789abcdef0
  directoryPerms: "700"
```

## Useful commands
`rosa describe cluster -c <name>`, `rosa list machinepools -c <name>`, `rosa upgrade cluster -c <name> --control-plane`,
`rosa upgrade machinepool -c <name> <pool>`, `rosa create kubeletconfig -c <name> --pod-pids-limit <n>`.
