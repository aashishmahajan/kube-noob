---
id: stackrox-admission
title: RHACS admission control - why a deployment was blocked and how to fix it
tags: [stackrox, rhacs, admission, debugging]
platforms: [kubernetes, openshift, rosa-classic, rosa-hcp]
updated: 2026-10-27
license: Apache-2.0
# A question needs a word of this document's subject (and of Kubernetes, where generic words would pass).
requires:
  - [rhacs, stackrox, acs, roxctl, central, sensor, collector, scanner, securedcluster, admission-control]
sources:
  - {title: "stackrox secured-cluster Helm templates (admission-controller.yaml)", url: "https://github.com/stackrox/stackrox/tree/master/image/templates/helm/stackrox-secured-cluster/templates", license: Apache-2.0}
  - {title: "stackrox CHANGELOG 4.9.0 (ROX-30278, ROX-30279) and SecuredCluster API", url: "https://github.com/stackrox/stackrox/blob/master/CHANGELOG.md", license: Apache-2.0}
---
# RHACS admission control

The secured cluster registers a ValidatingWebhookConfiguration (named `stackrox`) with the webhooks
`policyeval.stackrox.io` (evaluates deploy-time policies on workload create/update) and `k8sevents.stackrox.io`
(feeds Kubernetes events such as exec/port-forward into runtime policies). Its `failurePolicy` comes from
`admissionControl.failurePolicy`; the webhook timeout is derived from the admission controller's dynamic timeout.

## Reading a denial
```
admission webhook "policyeval.stackrox.io" denied the request:
The attempted operation violated 1 enforced policy, described below:
Policy: Latest tag
```
Only policies that have deploy-time **enforcement** enabled block admission; others only raise violations in Central.

## Fixing
1. Run `kube-noob audit -f manifest.yaml` - findings list the matching RHACS policy name.
2. Fix the manifest (pin the image, add requests/limits, drop privileges...).
3. Reproduce the evaluation without applying: `roxctl deployment check --file manifest.yaml -e <central>:443`.
4. For a justified exception, scope a policy exclusion (deployment/namespace) in Central; do not disable enforcement
   cluster-wide or delete the webhook.

## Enforcement settings
From RHACS 4.9 enforcement is one switch, spelled differently per install method:
- Helm (secured-cluster-services): `admissionControl.enforce` (enabled by default); the older
  `admissionControl.dynamic.enforceOn*` values are deprecated and ignored.
- Operator (SecuredCluster CR): `spec.admissionControl.enforcement: Enabled | Disabled` (defaults to Enabled for new
  installations); `listenOn*`, `contactImageScanners` and `timeoutSeconds` are deprecated.
