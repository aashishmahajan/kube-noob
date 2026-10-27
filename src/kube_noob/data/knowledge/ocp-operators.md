---
id: ocp-operators
title: ClusterOperators, OLM and platform health
tags: [openshift, operators, olm, upgrades]
platforms: [openshift, rosa-classic, rosa-hcp]
updated: 2026-10-27
license: Apache-2.0
sources:
  - {title: "OpenShift documentation - operators", url: "https://docs.redhat.com/en/documentation/openshift_container_platform/", license: CC-BY-SA-3.0}
---
# Operators on OpenShift

- **ClusterOperators** (`oc get clusteroperators`) run the platform itself (ingress, authentication, image-registry,
  monitoring, network, storage, ...). Each reports Available / Progressing / Degraded. Upgrades
  (`oc get clusterversion`) wait for every ClusterOperator to settle.
- **OLM** installs add-on operators from catalogs (OperatorHub): Subscription -> InstallPlan -> ClusterServiceVersion
  (CSV). Use `installPlanApproval: Manual` for controlled upgrades of critical operators.
- Debug a degraded operator: `oc describe clusteroperator <name>` (conditions explain why), then the operator's
  namespace (`openshift-<name>` or `openshift-<name>-operator`) pods and events.
- On ROSA, platform operators and `openshift-*` namespaces are managed by Red Hat SRE; open a support case instead of
  editing them. Customer-installed OLM operators are yours to manage.
