---
id: gatekeeper-enforcement
title: OPA Gatekeeper enforcement and exemptions
tags: [gatekeeper, opa, admission, enforcementaction, webhook]
platforms: [kubernetes, openshift, rosa-classic, rosa-hcp]
updated: 2026-10-28
license: Apache-2.0
requires:
  - [gatekeeper, constrainttemplate, constrainttemplates, opa, enforcementaction, excludednamespaces]
sources:
  - {title: "Gatekeeper: Handling Constraint Violations", url: "https://open-policy-agent.github.io/gatekeeper/website/docs/violations", license: Apache-2.0}
  - {title: "Gatekeeper: Exempting Namespaces", url: "https://open-policy-agent.github.io/gatekeeper/website/docs/exempt-namespaces", license: Apache-2.0}
  - {title: "Gatekeeper: Failing Closed", url: "https://open-policy-agent.github.io/gatekeeper/website/docs/failing-closed", license: Apache-2.0}
---
# OPA Gatekeeper: rolling out constraints, exemptions and the webhook's failure policy

Gatekeeper checks requests in its validating webhook (`validation.gatekeeper.sh`, in the
`gatekeeper-validating-webhook-configuration`), and its audit lists objects already in the cluster that break a
constraint.

## enforcementAction: dryrun or warn instead of deny

A constraint's `spec.enforcementAction` is `deny` unless set, so any violation rejects the request. To try a new
constraint on a running cluster without blocking anything, set `dryrun`: nothing is rejected, and the objects that
would fail appear under `status.violations` of the constraint.

```yaml
apiVersion: constraints.gatekeeper.sh/v1beta1
kind: K8sRequiredLabels
metadata:
  name: ns-must-have-gk
spec:
  enforcementAction: dryrun
  match:
    kinds:
      - apiGroups: [""]
        kinds: ["Namespace"]
  parameters:
    labels: ["gatekeeper"]
```

`warn` (Gatekeeper 3.4 and later, Kubernetes 1.19 and later) also blocks nothing, and in addition tells the person
applying the object right away which constraint it breaks:

```
Warning: [allowed-repos] container <app> has an invalid image repo <docker.io/app>, allowed repos are ["registry.example.com"]
deployment.apps/web created
```

Constraints support `deny`, `dryrun` and `warn`; Gatekeeper validates the value against that list unless it runs
with `--disable-enforcementaction-validation=true`. Setting the field back to `deny` (or removing it) blocks again.

## --log-denies: log every deny, dryrun and warn result

Start Gatekeeper with the `--log-denies` flag to write each deny, dryrun and warn failure to its log. That shows what
is being refused, or would be, without turning on sync or reading the status of every constraint.

## Exempt namespaces for all constraints: the Config resource

The `Config` resource (alpha) excludes namespaces from chosen Gatekeeper processes for every constraint in the
cluster. Gatekeeper only reads it when it is named `config`; `*` works as a wildcard (`kube-*`).

```yaml
apiVersion: config.gatekeeper.sh/v1alpha1
kind: Config
metadata:
  name: config
  namespace: "gatekeeper-system"
spec:
  match:
    - excludedNamespaces: ["kube-*", "my-namespace"]
      processes: ["*"]
    - excludedNamespaces: ["audit-excluded-ns"]
      processes: ["audit"]
```

Processes: `audit` (left out of audit results), `webhook` (left out of the admission webhook), `sync` (not synced into
OPA), `mutation-webhook` (left out of the mutation webhook) and `*` (all of them, including future ones). To exempt a
namespace from one constraint only, use `excludedNamespaces` in that constraint.

## --exempt-namespace and the admission.gatekeeper.sh/ignore label

To keep a namespace (for example `kube-system`) away from the admission webhook altogether:

1. The `validation.gatekeeper.sh` webhook in `gatekeeper-validating-webhook-configuration` needs a
   `namespaceSelector` with key `admission.gatekeeper.sh/ignore` and operator `DoesNotExist` (the default manifest
   has it).
2. Start Gatekeeper with `--exempt-namespace=<NAMESPACE NAME>` (Helm: list it in `controllerManager.exemptNamespaces`).
   Without this the label below is refused, so the right to edit a namespace is not enough to exempt it.
3. Put the `admission.gatekeeper.sh/ignore` label on the namespace; its value is not read, so it can record why.

`--exempt-namespace-prefix` and `--exempt-namespace-suffix` allow the label on every namespace with that prefix or
suffix. This only skips the admission webhook: the namespace is still audited (use the Config resource or the
constraints to leave it out of audit). With the label the API server never calls Gatekeeper for that namespace, so
Gatekeeper being down does not affect it; with the Config resource Gatekeeper is still called and decides itself,
which allows finer rules but leaves the namespace exposed to webhook downtime.

## failurePolicy: Ignore by default (fail open) or Fail (fail closed)

Gatekeeper installs its webhook with `failurePolicy: Ignore`: while the webhook is down or unreachable, constraints are
not enforced, and audit is expected to point out what got in meanwhile. To fail closed after a manifest install, set
`failurePolicy: Fail` on the webhooks in `gatekeeper-validating-webhook-configuration` (for a Helm or operator
install, follow that method's documentation). Before doing so, weigh:

- Deadlock: if every node is deleted, the Gatekeeper pods are gone, and creating a new Node needs the webhook that
  cannot run without a Node. Deleting the ValidatingWebhookConfiguration breaks the loop, and that is always allowed
  because webhook configurations are not sent to webhooks; an operator that recreates the configuration can get in
  the way.
- Availability: by default the webhook sees every request, so the API server is only as available as Gatekeeper.
  Exempting namespaces or kinds narrows that, but critical dependencies are easy to miss (cluster-scoped Nodes,
  namespaces like `istio-system`, ConfigMaps used as leader-election locks).
- More webhook pods add capacity and uptime but can delay a new constraint reaching every pod, and they only help if
  they do not share a failure domain (node, physical host, switch, power supply, rack).
