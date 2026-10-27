---
id: openshift
title: OpenShift Container Platform - what it adds on top of Kubernetes
tags: [openshift, ocp, architecture]
platforms: [openshift, rosa-classic, rosa-hcp]
updated: 2026-10-27
license: Apache-2.0
sources:
  - {title: "OpenShift Container Platform documentation", url: "https://docs.redhat.com/en/documentation/openshift_container_platform/", license: CC-BY-SA-3.0}
  - {title: "openshift/openshift-docs (source)", url: "https://github.com/openshift/openshift-docs", license: Apache-2.0}
---
# OpenShift Container Platform (OCP)

OpenShift is a Kubernetes distribution from Red Hat that adds an opinionated, operator-managed platform: Red Hat
Enterprise Linux CoreOS (RHCOS) nodes managed by the Machine Config Operator (MCO), the Operator Lifecycle Manager
(OLM), the HAProxy-based ingress router with the `Route` API, OVN-Kubernetes networking, an integrated image registry,
built-in monitoring, and stricter security defaults through SecurityContextConstraints (SCCs).

## Version map (OpenShift -> Kubernetes)
4.12 -> 1.25, 4.13 -> 1.26, 4.14 -> 1.27, 4.15 -> 1.28, 4.16 -> 1.29, 4.17 -> 1.30, 4.18 -> 1.31, 4.19 -> 1.32,
4.20 -> 1.33, 4.21 -> 1.34, 4.22 -> 1.35. OCP 4.22 is the current release (October 2026). Verified from the
release notes in each `enterprise-4.x` branch of openshift/openshift-docs.

## Install models
- **IPI** (installer-provisioned infrastructure): the installer creates the infrastructure (cloud, vSphere, bare metal).
- **UPI** (user-provisioned infrastructure): you provide network, load balancers, DNS and machines.
- **Assisted Installer** (console.redhat.com): guided installs for bare metal / vSphere.
- Managed offerings: ROSA (on AWS, Classic or Hosted Control Planes), ARO (Azure), OpenShift Dedicated.

## OpenShift-specific APIs (do not use on vanilla Kubernetes)
- `route.openshift.io/v1` **Route** - exposes Services through the router with edge, reencrypt or passthrough TLS.
- `security.openshift.io/v1` **SecurityContextConstraints** - admission control for pod security.
- `apps.openshift.io/v1` **DeploymentConfig** - deprecated since OCP 4.14 ("only security-related and critical issues
  will be fixed"); use `apps/v1` Deployment.
- `build.openshift.io`, `image.openshift.io` (BuildConfig, ImageStream), `project.openshift.io` (Project).
- `k8s.ovn.org/v1` **EgressFirewall** (OVN-Kubernetes) - egress control per project.

## Security defaults
New 4.11+ clusters grant the `restricted-v2` SCC to all authenticated users: all capabilities dropped (NET_BIND_SERVICE
may be added back), RuntimeDefault seccomp, no privilege escalation, no privileged containers or hostPath, and the UID
is taken from the namespace's pre-allocated range (annotation `openshift.io/sa.scc.uid-range`). Clusters upgraded from
4.10 or earlier may still use the legacy `restricted` SCC. A newer `restricted-v3` (user namespaces) is documented from
4.20 onward. Images must run as an arbitrary UID in group 0.

## Storage
OpenShift Data Foundation (ODF, Ceph) provides `ocs-storagecluster-ceph-rbd` (block, RWO for filesystem volumes) and
`ocs-storagecluster-cephfs` (shared filesystem, RWX). On AWS the default class is `gp3-csi` (EBS, RWO,
WaitForFirstConsumer).
