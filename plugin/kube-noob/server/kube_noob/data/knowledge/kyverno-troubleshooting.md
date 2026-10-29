---
id: kyverno-troubleshooting
title: Kyverno exceptions, webhook timeouts and CI
tags: [kyverno, admission, policyexception, webhook, ci]
platforms: [kubernetes, openshift, rosa-classic, rosa-hcp]
updated: 2026-10-28
license: Apache-2.0
requires:
  - [kyverno, policyexception, policyexceptions, clusterpolicy, validatingpolicy]
sources:
  - {title: "Kyverno: Policy Exceptions", url: "https://kyverno.io/docs/guides/exceptions/", license: Apache-2.0}
  - {title: "Kyverno: Troubleshooting (Kyverno fails on GKE)", url: "https://kyverno.io/docs/guides/troubleshooting/#kyverno-fails-on-gke", license: Apache-2.0}
  - {title: "Kyverno: Testing Policies (Continuous Integration)", url: "https://kyverno.io/docs/guides/testing-policies/#continuous-integration", license: Apache-2.0}
---
# Kyverno: exceptions, unreachable webhooks and testing in CI

Kyverno registers validating and mutating webhooks with the API server, so it only works when the API server can
reach the Kyverno service; its results for each resource are kept in PolicyReports.

## PolicyException: exempt one workload without editing the policy

PolicyExceptions are switched off by default. Kyverno has to run with the `enablePolicyException` flag set to `true`,
and the `exceptionNamespace` flag must say in which namespaces exceptions may be used. A PolicyException is a
namespaced resource in the `policies.kyverno.io` API group (from Kyverno 1.14) for the CEL-based policy types such as
`ValidatingPolicy`, `ImageValidatingPolicy` and `GeneratingPolicy`. It suits a cluster where the team that writes
policies is not the team that deploys, or a one-time exception whose risk is known and accepted.

```yaml
apiVersion: policies.kyverno.io/v1
kind: PolicyException
metadata:
  name: exclude-skipped-deployment
  namespace: default
spec:
  policyRefs:
    - name: require-prod-label
      kind: ValidatingPolicy
  matchConditions:
    - name: skip-by-name
      expression: "object.metadata.name == 'skipped-deployment'"
```

`policyRefs` gives the name and kind of the policy to skip; when a `matchConditions` CEL expression is true for a
resource, that policy is not applied to it, in admission and in background scans. The PolicyReport then shows
`result: skip` with `properties.exceptions` naming the exception and `process: admission review` (or
`background scan`); `reportResult: pass` in the exception reports `pass` instead. An exception can also list
compensating controls under `spec.validations` (for `ValidatingPolicy` and `NamespacedValidatingPolicy` only): the
exception is granted only when all of them are true, otherwise the policy runs as if the exception did not exist and
a denial carries the failing control's message.

## failed calling webhook "validate.kyverno.svc-fail": context deadline exceeded (GKE, EKS)

The API server cannot reach Kyverno's webhook on the worker nodes, so requests time out.

- Private GKE cluster: some traffic from the control plane to the workers is not allowed. Add a firewall rule that
  lets the control plane reach the worker nodes on the Kyverno TCP port, 9443 by default.
- EKS with a custom CNI (Calico, for example): the control plane nodes cannot use that CNI, so install Kyverno with
  the Helm `hostNetwork` option set to `true`.
- EKS with the VPC CNI: an outdated VPC CNI plug-in can cause this error; upgrade it to a version that supports the
  cluster's Kubernetes version.
- EKS with your own security group: add an inbound rule to the worker nodes' security group that allows port 9443 from
  the EKS cluster security group.

Check that the pods are `Running` with `kubectl -n kyverno get po`, and that Kyverno's webhook configurations exist
with `kubectl get validatingwebhookconfigurations,mutatingwebhookconfigurations`; their age should match the age of
the Kyverno pods (an age of a few seconds points to Kyverno failing to register).

## API server timing out because every Kyverno pod is down

If all Kyverno pods are gone (an outage, node groups removed) while policies that match Pods fail closed, the API
server times out on those requests and the cluster looks broken. Kyverno's documented recovery is to delete its two
resource webhook configurations; Kyverno recreates them from the installed policies once it is back:

```sh
kubectl delete validatingwebhookconfiguration kyverno-resource-validating-webhook-cfg
kubectl delete mutatingwebhookconfiguration kyverno-resource-mutating-webhook-cfg
```

Its other webhook configurations are internal and normally stay. Afterwards review the namespace exclusions and run
the admission controller with 3 replicas. A restart is rarely needed:
`kubectl scale deploy kyverno-admission-controller -n kyverno --replicas 0`, then
`kubectl scale deploy kyverno-admission-controller -n kyverno --replicas 3`.

## kyverno apply and kyverno test in CI

The Kyverno CLI covers two CI jobs. First, check manifests that are not in the cluster yet (for example the ones in a
pull request) against known policies; a validate rule failing there means the resource would fail at admission, and
the pipeline fails early. Second, pin the expected results of a set of policies and resources, so a policy change or
a newer Kyverno release that changes an outcome fails the run. A GitHub Actions job (the release can be changed to try
an upgrade first):

```yaml
      - name: Install Kyverno CLI
        uses: kyverno/action-install-cli@v0.2.0
        with:
          release: 'v1.19.0'
      - name: Check install
        run: kyverno version
      - name: Test new resources against existing policies
        run: kyverno apply policies/ -r resources/
      - name: Test pre-defined cases
        run: kyverno test tests/
```

`kyverno apply policies/ -r resources/` applies the policies in `policies/` to the manifests in `resources/`.
`kyverno test tests/` runs the test cases under `tests/`, one folder per case holding a `kyverno-test.yaml`, the
policy and the resource. A failure in either step fails the whole run.
