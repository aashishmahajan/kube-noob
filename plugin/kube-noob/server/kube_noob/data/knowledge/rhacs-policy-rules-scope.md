---
id: rhacs-policy-rules-scope
title: RHACS custom policy logic and scope
tags: [rhacs, stackrox, policy, criteria, scope, exclusion, regex, re2]
platforms: [kubernetes, openshift, rosa-classic, rosa-hcp]
updated: 2026-10-28
license: Apache-2.0
requires:
  - [rhacs, stackrox, roxctl, acs, central, sensor, collector, scanner, securedcluster]
sources:
  - {title: "RHACS docs: RHACS policy structure", url: "https://github.com/openshift/openshift-docs/blob/801ccd0dfd1f73aed72188c8c960de5c5bc85cd6/modules/policy-structure.adoc", license: Apache-2.0}
  - {title: "RHACS docs: Configuring policy resources", url: "https://github.com/openshift/openshift-docs/blob/801ccd0dfd1f73aed72188c8c960de5c5bc85cd6/modules/configure-policy-scope.adoc", license: Apache-2.0}
---
# RHACS custom policies: logic and scope

A RHACS policy has a **definition** (policy details, lifecycle stage, rules) and a **behavior** (which resources it
covers, and the action: enabled or disabled, enforced or not, which notifiers get the alerts).

## Policy rules are ORed, policy criteria inside a rule are ANDed

- A policy triggers when **any** of its rules matches: rule 1 OR rule 2.
- Inside one rule, the policy criteria (the building blocks you pick in the policy editor) must **all** match:
  criterion A AND criterion B.
- So: to alert only when two conditions hold together, put both criteria in the same rule; to alert when either
  holds, make two rules.
- Many criteria also have a `NOT` form. Most describe the condition that should trigger; a few describe the expected,
  compliant state, and a workload that does not meet it triggers:
  - `Container Registry name is <gcr.io>` triggers when gcr.io is used, while
    `Container Registry name is NOT <quay.io>` triggers for any registry other than quay.io (an allow-list).
  - `Liveness probe is <Not Defined>` triggers when the probe is missing; `Liveness probe is <Defined>` matches the
    compliant workloads, useful with a notifier as a positive report.
  - `Drop capabilities, Capabilities that MUST be dropped: <SYS_ADMIN>` states the expected behavior: a workload
    that does not drop `SYS_ADMIN` violates the policy.

## Policy scope: Included resources by cluster, namespace or deployment label

- With no resource rules, a policy is global: every secured cluster, namespace and deployment. That is the default.
- **Add inclusion** narrows it. Pick one option per item:
  - Cluster: by name, or by label `key=value` such as `environment=production` (cluster labels come from the
    `SecuredCluster` CR for Operator installs, or from Helm values for Helm installs).
  - Namespace: by name (RE2 regular expressions allowed), or by label such as `compliance=pci`.
  - Deployment label: a label or `key=value` pair.
- Inside one resource rule, cluster, namespace and deployment label criteria are combined with AND. Several resource
  rules are combined with OR (a resource matching any rule is covered). Example: one rule with cluster label
  `environment=production` and namespace label `compliance=pci` limits the policy to PCI namespaces on production
  clusters.
- Label-based rules pick up new clusters, namespaces and deployments with matching labels without editing the
  policy.

## Excluded resources: skip namespaces or deployments with an RE2 regex such as test-.*

**Add exclusion** removes resources from the policy:

- Cluster: by name only (cluster labels cannot be used to exclude).
- Namespace: by name; RE2 regular expressions allowed. To leave out every test namespace, exclude the namespace name
  pattern `test-.*`.
- Deployment: by name; RE2 regular expressions allowed.
- Deployment label: a label or `key=value` pair.

Excluded resources do not support cluster label or namespace label targeting. To apply a policy everywhere except
one development cluster, leave **Included resources** empty and add an **Excluded resources** rule with that
cluster's name.

## Exclude images and other scope limits (build-time policies ignore cluster and namespace scope)

- **Exclude images** only matters for images checked in CI under the **Build** lifecycle stage (`roxctl image
  check`). It has no effect on Deploy-stage checks of running deployments or on Runtime activity.
- Cluster and namespace targeting, by name or by label, works for deploy-time and runtime policies only. A
  build-time policy ignores any cluster or namespace scope you give it.
- The node event source supports no resource scoping. Audit log event source policies can be scoped to clusters and
  namespaces, not to deployments.
- Cluster-scoped resources such as ClusterRoles ignore namespace-level matchers.

## Label-based policy scope needs RHACS 4.11 or later and a Helm or Operator install

- Cluster labels and namespace labels in resource rules need both Central and the secured clusters on RHACS 4.11 or
  later, with the secured clusters installed by Helm or the Operator.
- Secured clusters on older versions, or installed with manifests or `roxctl`, ignore the cluster label and
  namespace label fields.
- Label matching is an exact `key=value` match and works for included resources only.
