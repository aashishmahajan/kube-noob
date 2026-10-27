---
id: stackrox
title: Red Hat Advanced Cluster Security (RHACS) / StackRox
tags: [stackrox, rhacs, security]
platforms: [kubernetes, openshift, rosa-classic, rosa-hcp]
updated: 2026-10-27
license: Apache-2.0
sources:
  - {title: "stackrox/stackrox", url: "https://github.com/stackrox/stackrox", license: Apache-2.0}
  - {title: "StackRox default policies", url: "https://github.com/stackrox/stackrox/tree/master/pkg/defaults/policies/files", license: Apache-2.0}
---
# RHACS / StackRox

RHACS (upstream: StackRox) is Red Hat's Kubernetes-native security platform: vulnerability management, configuration
policy, network segmentation, runtime detection and compliance.

## Architecture
- **Central** (`platform.stackrox.io/v1alpha1` Central): UI, API, policy engine, database. Installed once (or consumed
  as the RHACS Cloud Service).
- **Secured cluster** (`platform.stackrox.io/v1alpha1` SecuredCluster) on every protected cluster: **Sensor**
  (watches the Kubernetes API), **Admission Controller** (validating webhooks `policyeval.stackrox.io` and
  `k8sevents.stackrox.io`), **Collector** (DaemonSet capturing process and network activity), and scanner components.
- `roxctl` CLI: `roxctl image check`, `roxctl deployment check --file manifest.yaml`, `roxctl image scan` in CI.

## Policy lifecycle stages
BUILD (image contents in CI), DEPLOY (manifests and admission), RUNTIME (process/network events, Kubernetes API
actions such as `Kubernetes Actions: Exec into Pod`).

## Default policies worth knowing (deploy-time)
Privileged Container (medium), Container with privilege escalation allowed (medium), Latest tag (low),
No CPU request or memory limit specified (medium; fires when CPU request and memory limit are both unset),
Environment Variable Contains Secret (high), Pod Service Account Token Automatically Mounted (medium),
CAP_SYS_ADMIN capability added (medium), Mount Container Runtime Socket (medium), Mounting Sensitive Host Directories
(medium), Docker CIS 5.9/5.15/5.16 host network/PID/IPC namespace sharing (medium), Docker CIS 4.1 (image has a
non-root USER; low). Several are **disabled by default** - Drop All Capabilities, Container using read-write root
filesystem, Docker CIS 5.21 seccomp, Secret Mounted as Environment Variable, Deployments with externally exposed
endpoints, and the ingress/egress NetworkPolicy checks - and default deploy policies are **inform-only** (no
enforcement) until you enable enforcement per policy.

kube-noob maps its audit rules to these policy names so a clean `kube-noob audit` predicts a clean RHACS evaluation.

## Release history
4.7.0 2025-03-13, 4.8.0 2025-07-07, 4.9.0 2025-10-30, 4.10.0 2026-03-03, 4.11.0 2026-06-12 (latest patch 4.11.6,
2026-10-20). The next release is **5.0** (there is no 4.12: the 4.12.x branch was renamed 5.0.x in August 2026);
5.0.0 was at release-candidate stage in October 2026 and is planned in Jira for 2026-11-04. 5.0 removes the legacy
StackRox Scanner (v2) and adds a `central-worker` deployment. In the Helm/operator configuration, 4.9 introduced
`admissionControl.enforce`, replacing the deprecated `enforceOnCreates` / `enforceOnUpdates` settings.
