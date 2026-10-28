---
id: rhacs-enforcement
title: RHACS policy enforcement
tags: [rhacs, stackrox, enforcement, admission-controller, break-glass, failurepolicy, roxctl]
platforms: [kubernetes, openshift, rosa-classic, rosa-hcp]
updated: 2026-10-28
license: Apache-2.0
requires:
  - [rhacs, stackrox, roxctl, acs, central, sensor, collector, scanner, securedcluster]
sources:
  - {title: "RHACS docs: About policy enforcement", url: "https://github.com/openshift/openshift-docs/blob/801ccd0dfd1f73aed72188c8c960de5c5bc85cd6/modules/policy-enforcement-about.adoc", license: Apache-2.0}
  - {title: "RHACS docs: Hard enforcement", url: "https://github.com/openshift/openshift-docs/blob/801ccd0dfd1f73aed72188c8c960de5c5bc85cd6/modules/policy-enforcement-hard.adoc", license: Apache-2.0}
  - {title: "RHACS docs: Understanding admission controller enforcement", url: "https://github.com/openshift/openshift-docs/blob/801ccd0dfd1f73aed72188c8c960de5c5bc85cd6/modules/understand-admission-controller-enforcement.adoc", license: Apache-2.0}
  - {title: "RHACS docs: Viewing and enabling admission controller enforcement on an existing cluster", url: "https://github.com/openshift/openshift-docs/blob/801ccd0dfd1f73aed72188c8c960de5c5bc85cd6/modules/enable-admission-controller-enforcement-existing-cluster.adoc", license: Apache-2.0}
  - {title: "RHACS docs: Disabling admission controller enforcement on a cluster", url: "https://github.com/openshift/openshift-docs/blob/801ccd0dfd1f73aed72188c8c960de5c5bc85cd6/modules/disable-admission-controller-enforcement.adoc", license: Apache-2.0}
  - {title: "RHACS docs: Bypassing admission controller enforcement", url: "https://github.com/openshift/openshift-docs/blob/801ccd0dfd1f73aed72188c8c960de5c5bc85cd6/modules/bypass-admission-controller-enforcement.adoc", license: Apache-2.0}
  - {title: "RHACS docs: Configuring the admission controller failure policy on an existing cluster", url: "https://github.com/openshift/openshift-docs/blob/801ccd0dfd1f73aed72188c8c960de5c5bc85cd6/modules/admission-controller-failure-policy-changing.adoc", license: Apache-2.0}
  - {title: "RHACS docs: Admission controller settings (SecuredCluster)", url: "https://github.com/openshift/openshift-docs/blob/801ccd0dfd1f73aed72188c8c960de5c5bc85cd6/modules/admission-controller-settings.adoc", license: Apache-2.0}
  - {title: "RHACS docs: roxctl sensor generate options", url: "https://github.com/openshift/openshift-docs/blob/801ccd0dfd1f73aed72188c8c960de5c5bc85cd6/modules/roxctl-sensor-generate-options.adoc", license: Apache-2.0}
  - {title: "RHACS docs: Generating Sensor files for OpenShift", url: "https://github.com/openshift/openshift-docs/blob/801ccd0dfd1f73aed72188c8c960de5c5bc85cd6/modules/generating-sensor-openshift.adoc", license: Apache-2.0}
  - {title: "RHACS docs: Generating Sensor files for Kubernetes", url: "https://github.com/openshift/openshift-docs/blob/801ccd0dfd1f73aed72188c8c960de5c5bc85cd6/modules/generating-sensor-k8s.adoc", license: Apache-2.0}
  - {title: "StackRox default policy: Emergency Deployment Annotation", url: "https://github.com/stackrox/stackrox/blob/69fc953f424bf243362dfaab47c4a1bad55fd83b/pkg/defaults/policies/files/admission_controller_annotation.json", license: Apache-2.0}
---
# RHACS policy enforcement

A RHACS policy either only informs (a violation shows up in Central) or also enforces. Enforcement exists for
all three lifecycle stages (build, deploy, runtime), and at deploy time it is carried out by two different
components. The `stackrox-admission` document explains how to read a denial; this one explains which switch does
what.

## Soft enforcement (Sensor scales pods down) versus hard enforcement (admission controller)

- **Soft enforcement** (Sensor enforcement): Sensor examines a workload, finds that it violates an enforced policy,
  and scales its pods down through the Kubernetes API (to zero replicas). The workload object was already accepted.
- **Hard enforcement** (admission controller enforcement): the API server sends the create or update request to
  the RHACS validating webhooks as an `AdmissionReview`; the webhooks ask the admission controller through its
  service endpoint, and it answers allow or block. A request that violates an enforced policy is rejected, so the
  object is never stored.
- The two work together. When the admission controller does not reject a noncompliant deployment (a webhook
  timeout, for example), RHACS still applies the other deploy-stage enforcement, such as scaling to zero replicas.

## Make a RHACS policy block deployments: Inform and enforce plus cluster enforcement

A violation blocks a deployment only when both settings are on:

1. **On the policy**: choose **Inform and enforce** for the policy (deploy-time enforcement). A policy left on
   inform only raises violations.
2. **On the secured cluster**: admission controller enforcement must be enabled. In the portal, under
   Platform Configuration -> Clusters -> Static configuration, the field **Admission controller enforcement
   behavior** must show **Enforce policies**. With the Operator, the SecuredCluster CR field is
   `spec.admissionControl.enforcement: Enabled`. **No enforcement** lets violating workloads in even when a policy
   is set to enforce.

Admission controller enforcement is static configuration. On clusters installed with manifests or `roxctl`,
change it in the portal, select **Download YAML File and Keys**, and run the `sensor` script from the new bundle
to redeploy. Operator- and Helm-managed clusters cannot be changed from the portal. Turning enforcement on raises
the admission controller memory limit to 1 GiB per replica (for image scan data caching) unless you set your own
limit. The `ValidatingWebhookConfiguration` and the admission controller logs show the active enforcement settings.

## What hard enforcement blocks: CREATE, UPDATE and SCALE, not kubectl patch

- Deploy-time enforcement blocks pod create, update and scale requests that match the policy. Policies with
  runtime enforcement also block user-initiated `pod exec` and `port forward` commands.
- The RHACS admission controller handles only `CREATE`, `UPDATE` and `SCALE`. `kubectl patch`, `kubectl set` and
  `kubectl scale` reach the API server as `PATCH` requests, which RHACS cannot enforce on; SCALE operations
  themselves are enforced.
- It can evaluate pod `securityContext` options, deployment configuration, image components and vulnerabilities,
  and exec / port-forward commands.
- Every evaluated request adds API latency. Client libraries with short default API timeouts (fabric8 is the
  example the docs give) can time out; allow for that in your automation, and see the failure policy below.

## Emergency bypass: the admission.stackrox.io/break-glass annotation

To push an urgent deployment past the admission controller, annotate the deployment and use a change or ticket
reference as the value, so others can see why:

```yaml
metadata:
  annotations:
    "admission.stackrox.io/break-glass": "jira-3423"
```

- The bypass is recorded: it raises a violation of the "StackRox Emergency Deployment Annotation" policy (the
  default policy file names it `Emergency Deployment Annotation`, severity high), with the deployment details. Its
  remediation is to redeploy without the annotation once the emergency is over.
- The cluster must allow the bypass. Operator: `admissionControl.bypass: BreakGlassAnnotation` (the default;
  `Disabled` turns bypass off). Helm: `admissionControl.dynamic.disableBypass: false`. Portal: Platform
  Configuration -> Clusters -> **Admission controller bypass annotation** set to **Enabled**. Bundles made with
  `roxctl sensor generate --admission-controller-disable-bypass` have bypass turned off (the flag defaults to
  `false`).

## Admission controller failure policy: fail open (Ignore) or fail closed (Fail)

The failure policy decides what happens to the API request when the RHACS webhook evaluation errors or times out:
`Ignore` lets the request through (fail open), `Fail` rejects it (fail closed). The SecuredCluster default is
`Ignore`. The webhook timeout itself cannot be tuned: `admissionControl.timeoutSeconds` and
`--admission-controller-timeout` are deprecated and ignored, and RHACS uses a preset value.

Change it on an existing cluster:

- Operator: in the `SecuredCluster` CR set `spec.admissionControl.failurePolicy` to `Ignore` or `Fail`.
- Helm: set `admissionControl.failurePolicy` in `values-public.yaml`, then run:

```sh
helm upgrade -n stackrox \
  stackrox-secured-cluster-services rhacs/secured-cluster-services \
  --reuse-values \
  -f /config/yaml/values-public.yaml \
  -f /config/yaml/values-private.yaml
```

- Other install methods: in the portal, Platform Configuration -> Clusters -> **Secure a cluster** -> **Legacy
  installation method**, then in **Static configuration (requires deployment)** set **Admission controller failure
  policy** to **Fail open** or **Fail closed**, select **Next** and **Finish**, and redeploy the cluster.

Choose fail closed when RHACS runs inside a CD tool and that tool should own the enforcement; remember that with
fail closed a slow or failing admission controller blocks every matching request.

## roxctl sensor generate --admission-controller-enforcement=false and the other admission flags

`roxctl sensor generate` writes the deployment bundle for a secured cluster installed with `roxctl`. To generate
one without admission controller enforcement, add the flag to the usual command:

```sh
roxctl sensor generate openshift --openshift-version <ocp_version> --name <cluster_name> --central "$ROX_ENDPOINT" --admission-controller-enforcement=false
```

(On Kubernetes: `roxctl sensor generate k8s --name <cluster_name> --central "$ROX_ENDPOINT"` plus the flag.)

| Flag | Meaning |
|---|---|
| `--admission-controller-enforcement` | `true` (default): reject create or update attempts that violate an enabled policy; `false`: no enforcement |
| `--admission-controller-fail-on-error` | `false` (default) allows the request when the webhook errors or times out (fail open); `true` blocks it |
| `--admission-controller-disable-bypass` | disables the break-glass annotation; default `false` |
| `--admission-controller-enforce-on-creates`, `--admission-controller-enforce-on-updates`, `--admission-controller-timeout` | deprecated, no effect |
| `--admission-controller-listen-on-creates`, `--admission-controller-listen-on-updates`, `--admission-controller-scan-inline` | deprecated; the command acts as if they were set |
| `--central` | Central endpoint for Sensor; default `central.stackrox:443` |
