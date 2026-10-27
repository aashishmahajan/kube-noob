---
id: rosa-egress-zero
title: ROSA HCP egress zero (no public egress)
tags: [rosa, rosa-hcp, networking, egress, disconnected, ecr]
platforms: [rosa-hcp]
updated: 2026-10-27
license: Apache-2.0
sources:
  - {title: "Creating ROSA clusters with egress zero", url: "https://docs.redhat.com/en/documentation/red_hat_openshift_service_on_aws/4/html/install_clusters/rosa-hcp-egress-zero-install", license: CC-BY-SA-3.0}
---
# ROSA HCP egress zero

Egress zero lets a ROSA with HCP cluster run without public internet egress: the cluster pulls Red Hat images from
an Amazon ECR in its own region (trying Quay first, then the regional ECR) over VPC endpoints.

## Create one

- ROSA CLI 1.2.45 or later (`rosa create network` needs 1.2.48 or later).
- A VPC with private subnets tagged `kubernetes.io/role/internal-elb` and VPC endpoints for ECR (API and DKR),
  S3, STS and KMS; `rosa create network` builds such a stack.
- Create the cluster with `--hosted-cp --private` and `--properties zero_egress:true`, then follow
  `rosa logs install -c <cluster> --watch`.

## What you give up

- Features that need public access are unavailable, for example Telemetry and Red Hat Lightspeed.
- Only the default channel of Red Hat Operators is mirrored in the software catalog.
- Workloads that pull from public registries (quay.io, docker.io) fail unless you mirror their images.

kube-noob fits this model: run it with the offline lock (`offline: true`) and import a prepared corpus with
`kube-noob corpus import` instead of downloading one.
