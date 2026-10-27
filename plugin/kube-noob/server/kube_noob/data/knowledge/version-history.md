---
id: version-history
title: Release history - Kubernetes, OpenShift, Helm, RHACS (verified 2026-10-27)
tags: [versions, history, lifecycle]
platforms: [kubernetes, openshift, rosa-classic, rosa-hcp]
updated: 2026-10-27
license: Apache-2.0
sources:
  - {title: "kubernetes/kubernetes tags", url: "https://github.com/kubernetes/kubernetes/tags", license: Apache-2.0}
  - {title: "openshift/openshift-docs release notes (enterprise-4.x branches)", url: "https://github.com/openshift/openshift-docs", license: Apache-2.0}
  - {title: "helm/helm tags", url: "https://github.com/helm/helm/tags", license: Apache-2.0}
  - {title: "stackrox/stackrox tags and CHANGELOG", url: "https://github.com/stackrox/stackrox", license: Apache-2.0}
---
# Release history

## Kubernetes (first x.y.0 release)
1.25 2022-08-23 | 1.26 2022-12-08 | 1.27 2023-04-11 | 1.28 2023-08-15 | 1.29 2023-12-13 | 1.30 2024-04-17 |
1.31 2024-08-13 | 1.32 2024-12-11 | 1.33 2025-04-23 | 1.34 2025-08-27 | 1.35 2025-12-17 | 1.36 2026-04-22 |
1.37 2026-08-26 (newest; 1.38 in alpha).

## OpenShift -> Kubernetes
4.12 1.25 | 4.13 1.26 | 4.14 1.27 | 4.15 1.28 | 4.16 1.29 | 4.17 1.30 | 4.18 1.31 | 4.19 1.32 | 4.20 1.33 |
4.21 1.34 | 4.22 1.35 (current). Notable: DeploymentConfig deprecated in 4.14; restricted-v2 SCC default for new
installs from 4.11; restricted-v3 documented from 4.20.

## Helm
3.0.0 2019-11-13 ... 3.19.0 2025-09-11; **4.0.0 2025-11-12**; afterwards 4.x and 3.x minors ship together:
4.1.0/3.20.0 2026-01-21, 4.2.0/3.21.0 2026-05-13, 4.3.0/3.22.0 2026-09-09, 4.3.1 2026-10-14, 3.22.1 2026-10-15.

## RHACS / StackRox
4.0.0 2023-04-24 | 4.1.0 2023-06-29 | 4.2.0 2023-09-15 | 4.3.0 2023-11-15 | 4.4.0 2024-03-28 | 4.5.0 2024-07-23 |
4.6.0 2024-11-26 | 4.7.0 2025-03-13 | 4.8.0 2025-07-07 | 4.9.0 2025-10-30 | 4.10.0 2026-03-03 |
4.11.0 2026-06-12 (4.11.6 on 2026-10-20). Next: 5.0 (no 4.12; release candidate in October 2026, planned
2026-11-04 in Jira), then 5.1 (planned 2027-02-15) and 5.2 (planned 2027-06-14).

## Kubernetes API removals
The official deprecation guide lists removals in 1.16, 1.22, 1.25, 1.26, 1.27, 1.29 and 1.32 and **none after 1.32**
(as of 1.37). See the k8s-deprecations lesson.
