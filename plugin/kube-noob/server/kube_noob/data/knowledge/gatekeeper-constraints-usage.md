---
id: gatekeeper-constraints-usage
title: Gatekeeper Rego in ConstraintTemplates, audit results, match scope and install
tags: [gatekeeper, opa, rego, constrainttemplate, constraint, audit, helm]
platforms: [kubernetes, openshift, rosa-classic, rosa-hcp]
updated: 2026-10-29
license: Apache-2.0
requires:
  - [gatekeeper, constrainttemplate, constrainttemplates, constraint, rego, opa, expansiontemplate, syncset]
sources:
  - {title: "Gatekeeper: How to use Gatekeeper", url: "https://open-policy-agent.github.io/gatekeeper/website/docs/howto", license: Apache-2.0}
  - {title: "Gatekeeper: Constraint Templates", url: "https://open-policy-agent.github.io/gatekeeper/website/docs/constrainttemplates", license: Apache-2.0}
  - {title: "Gatekeeper: Admission Review Input", url: "https://open-policy-agent.github.io/gatekeeper/website/docs/input", license: Apache-2.0}
  - {title: "Gatekeeper: Debugging", url: "https://open-policy-agent.github.io/gatekeeper/website/docs/debug", license: Apache-2.0}
  - {title: "Gatekeeper: Audit", url: "https://open-policy-agent.github.io/gatekeeper/website/docs/audit", license: Apache-2.0}
  - {title: "Gatekeeper: Replicating Data", url: "https://open-policy-agent.github.io/gatekeeper/website/docs/sync", license: Apache-2.0}
  - {title: "Gatekeeper: Operations", url: "https://open-policy-agent.github.io/gatekeeper/website/docs/operations", license: Apache-2.0}
  - {title: "Gatekeeper: Performance Tuning", url: "https://open-policy-agent.github.io/gatekeeper/website/docs/performance-tuning", license: Apache-2.0}
  - {title: "Gatekeeper: API Reference", url: "https://open-policy-agent.github.io/gatekeeper/website/docs/api", license: Apache-2.0}
  - {title: "Gatekeeper: Enforcement points", url: "https://open-policy-agent.github.io/gatekeeper/website/docs/enforcement-points", license: Apache-2.0}
  - {title: "Gatekeeper: Customizing Admission Behavior", url: "https://open-policy-agent.github.io/gatekeeper/website/docs/customize-admission", license: Apache-2.0}
  - {title: "Gatekeeper: Customizing Startup Behavior", url: "https://open-policy-agent.github.io/gatekeeper/website/docs/customize-startup", license: Apache-2.0}
  - {title: "Gatekeeper: Failing Closed", url: "https://open-policy-agent.github.io/gatekeeper/website/docs/failing-closed", license: Apache-2.0}
  - {title: "Gatekeeper: Exempting Namespaces", url: "https://open-policy-agent.github.io/gatekeeper/website/docs/exempt-namespaces", license: Apache-2.0}
  - {title: "Gatekeeper: Cloud and Vendor Specific Fixes", url: "https://open-policy-agent.github.io/gatekeeper/website/docs/vendor-specific", license: Apache-2.0}
  - {title: "Gatekeeper: Installation", url: "https://open-policy-agent.github.io/gatekeeper/website/docs/install", license: Apache-2.0}
  - {title: "Gatekeeper: Working with Workload Resources", url: "https://open-policy-agent.github.io/gatekeeper/website/docs/workload-resources", license: Apache-2.0}
  - {title: "Gatekeeper: Validating Workload Resources using ExpansionTemplate", url: "https://open-policy-agent.github.io/gatekeeper/website/docs/expansion", license: Apache-2.0}
  - {title: "Gatekeeper: Introduction", url: "https://open-policy-agent.github.io/gatekeeper/website/docs/", license: Apache-2.0}
  - {title: "OPA: Introduction", url: "https://www.openpolicyagent.org/docs/", license: Apache-2.0}
  - {title: "OPA: Policy Language", url: "https://www.openpolicyagent.org/docs/policy-language", license: Apache-2.0}
  - {title: "OPA: Object Built-ins (object.get)", url: "https://www.openpolicyagent.org/docs/policy-reference/builtins/object", license: Apache-2.0}
  - {title: "OPA: Array Built-ins (array.concat)", url: "https://www.openpolicyagent.org/docs/policy-reference/builtins/array", license: Apache-2.0}
  - {title: "OPA: Upgrading to v1.0 (future.keywords)", url: "https://www.openpolicyagent.org/docs/v0-upgrade", license: Apache-2.0}
  - {title: "OPA: v0 Backwards Compatibility", url: "https://www.openpolicyagent.org/docs/v0-compatibility", license: Apache-2.0}
  - {title: "OPA: OPA for Kubernetes Admission Control", url: "https://www.openpolicyagent.org/docs/kubernetes", license: Apache-2.0}
---
# OPA Gatekeeper: Rego in ConstraintTemplates, audit results, match scope and install

A ConstraintTemplate holds the policy code (Rego or CEL) and the schema of its parameters; each Constraint of the kind
it defines sets `match`, `parameters` and `enforcementAction`. In Rego the request under review is `input.review`
(`input.review.object` is the object) and the constraint's parameters are `input.parameters`; the template's
`violation` rule produces one entry per problem. Templates use Rego v0 syntax unless they opt into v1 (Gatekeeper 3.19
and later).

## Rego: list the required annotations an object is missing

Collect what the object has and what the constraint requires as sets, then subtract one from the other. This is the
documented `k8srequiredlabels` template logic with annotations in place of labels:

```rego
package k8srequiredannotations

violation[{"msg": msg, "details": {"missing_annotations": missing}}] {
  provided := {a | input.review.object.metadata.annotations[a]}
  required := {a | a := input.parameters.annotations[_]}
  missing := required - provided
  count(missing) > 0
  msg := sprintf("you must provide annotations: %v", [missing])
}
```

`{a | ...}` is a set comprehension. `annotations[a]` iterates the keys of the annotations object; `[_]` iterates the
parameter array, and each `_` is a new iterator. Declare the parameter in the template's
`spec.crd.spec.validation.openAPIV3Schema` with `type: object` at the top and
`annotations: {type: array, items: {type: string}}` under `properties`: a `v1` ConstraintTemplate rejects a schema
without `type`, and the API server then rejects a Constraint whose `parameters` have the wrong shape
(`spec.parameters in body must be of type object: "array"`).

## Rego: allow only values from a list (sets, the in keyword, and the != loop mistake)

Turn the parameter array into a set and look the value up; `not allowed[env]` is true when the value is not in the
set:

```rego
package k8sallowedenv

violation[{"msg": msg}] {
  env := input.review.object.metadata.labels.env
  allowed := {v | v := input.parameters.allowed[_]}
  not allowed[env]
  msg := sprintf("env label %v is not one of %v", [env, allowed])
}
```

`not env in input.parameters.allowed` says the same with the `in` operator, but `in`, `every`, `if` and `contains`
are keywords that Rego v0, the default in ConstraintTemplates, accepts only after a `future.keywords` import such as
`import future.keywords.in`. A template written as Rego v1 (`code: - engine: Rego` with `source.version: "v1"`,
Gatekeeper 3.19 and later) needs no import. Do not express "every item is allowed" as `x := list[_]; x != "bad"`:
Rego variables mean "some", so that body is true as soon as one item differs. Write a rule for "some item is bad" and
negate it, or count a comprehension of bad items and compare with 0.

## Rego: append to an array or reassign a variable (array.concat, comprehensions)

Rego variables are immutable, and a variable assigned with `:=` cannot be assigned again in the same rule (`x := 1`
followed by `x := 2` does not compile). Build a new value instead: `array.concat` returns a new array with the
elements of the second appended to the first, and a comprehension collects values into an array or set. Inside a
rule body:

```rego
repos := array.concat(input.parameters.repos, ["registry.example.com"])
images := [c.image | c := input.review.object.spec.containers[_]]
```

In Gatekeeper a ConstraintTemplate with a Rego error is in some cases still created by `kubectl apply`; the failure
shows when you apply a Constraint of its kind:

```
error: unable to recognize "constraint.yaml": no matches for kind "K8sRequiredLabels" in version "constraints.gatekeeper.sh/v1beta1"
```

Run `kubectl get -f <template-file>.yaml -o yaml` on the template and read the build errors in its `status` field.
To see exactly what the Rego receives, use a template whose `violation` rule only sets
`msg := sprintf("REVIEW OBJECT: %v", [input.review])`: it denies every request its constraint matches and prints the
request in the denial message.

## Rego: no violation when the object has no metadata.annotations (undefined, object.get)

A reference to a field that does not exist is undefined, and an expression that uses an undefined value is undefined
too, comparisons such as `!=` included. A rule body with an undefined expression produces nothing, so a check like
`input.review.object.metadata.annotations.owner == ""` never fires for an object without annotations. Read optional
fields with `object.get(object, key_or_path, default)`; with a path array it still returns the default when a field
on the way, such as `annotations`, is missing:

```rego
package k8srequiredowner

violation[{"msg": msg}] {
  owner := object.get(input.review.object, ["metadata", "annotations", "owner"], "")
  owner == ""
  msg := "the owner annotation is required"
}
```

`not input.review.object.metadata.annotations.owner` also tests for a missing key. Keys with characters other than
letters, digits and `_` need brackets: `annotations["example.com/owner"]`. Audit cannot fill `userInfo`,
`operation`, `uid` and `dryRun`, so a template that reads them must handle them being empty, or audit reports every
matching object.

## Audit lists violations but the object is still created

Audit evaluates objects already in the cluster; requests are blocked at admission by the `validation.gatekeeper.sh`
webhook (or, for CEL templates, by a generated ValidatingAdmissionPolicy, enforcement point `vap.k8s.io`). When audit
shows a violation but `kubectl apply` succeeds, check:

1. Enforcement: the constraint must deny at the webhook. With `enforcementAction: scoped`, enforcement points not
   listed are skipped, so this constraint only audits:

   ```yaml
   spec:
     enforcementAction: scoped
     scopedEnforcementActions:
     - action: deny
       enforcementPoints:
       - name: "audit.gatekeeper.sh"
   ```

2. Reachability: the webhook fails open, so constraints are not enforced while the API server cannot reach
   `gatekeeper-webhook-service`. On private GKE nodes the control plane may reach nodes only on ports 443 and 10250,
   but it calls the Gatekeeper pod directly on 8443: open 8443 from the control plane to the nodes, or run the
   webhook with `--port=443`, `containerPort: 443` and the `NET_BIND_SERVICE` capability.
3. Startup: the webhook serves nothing until the initial templates, constraints and synced objects are loaded.
4. Scope: a namespace exempted from the webhook (`admission.gatekeeper.sh/ignore` label, or Config `webhook` process)
   is still audited. `status.byPod[].enforced` on the constraint shows which Gatekeeper pods enforce it.

## Constraint status shows no violations, or fewer than expected

`status.violations` holds only the most recent audit run, capped at `--constraint-violations-limit` entries (default
20; the docs suggest at most 500); `status.totalViolations` counts all of them and `status.auditTimestamp` shows the
last run. An empty list can also mean:

- Audit has not run yet: it runs every `--audit-interval` seconds (default 60). Overlapping runs can pre-empt each
  other's status writes; the audit pod's stdout log (`event_type: violation_audited`) is not affected.
- The `status` operation is not running; without it the constraint `status` stays blank.
- `--audit-from-cache=true` is set: audit then reads only objects replicated into its cache, so list every audited
  kind in a SyncSet (or the Config's `spec.sync.syncOnly`):

```yaml
apiVersion: syncset.gatekeeper.sh/v1alpha1
kind: SyncSet
metadata:
  name: syncset-1
spec:
  gvks:
    - group: ""
      version: "v1"
      kind: "Pod"
```

- `enforcementAction: dryrun` results reach `status.violations` through audit; with `scoped`, a constraint without
  `audit.gatekeeper.sh` among its enforcement points is not audited at all.
- The template reads `input.review.userInfo`, which audit cannot fill.

## Install or upgrade Gatekeeper with Helm (repo, CRDs, OpenShift, audit pod)

Install with cluster-admin rights from the Gatekeeper chart repository:

```sh
helm repo add gatekeeper https://open-policy-agent.github.io/gatekeeper/charts
helm install gatekeeper/gatekeeper --name-template=gatekeeper --namespace gatekeeper-system --create-namespace
```

If the repo was added from the older location and Helm is v3.3.2 or later, add it again with `--force-update`.
Warnings about the `crd-install` hook are expected with Helm v3 and do not affect the deployment.
`helm delete gatekeeper --namespace gatekeeper-system` leaves the CRDs behind; `kubectl delete crd -l
gatekeeper.sh/system=yes` removes them together with every ConstraintTemplate, Constraint and config change. On
OpenShift 4.x, add `use` of the `anyuid` SecurityContextConstraints (`security.openshift.io`) to the
`gatekeeper-manager-role` Role. With the Cluster Autoscaler, the audit pod's `emptyDir` (`tmp-volume`) blocks node
scale-down until the pod carries `cluster-autoscaler.kubernetes.io/safe-to-evict-local-volumes=tmp-volume` (Helm
`auditPodAnnotations`). If the audit pod runs out of memory, lower `--audit-chunk-size` or
`--constraint-violations-limit`, set `--audit-match-kind-only=true`, and make `--audit-interval` long enough that
runs do not overlap.

## Constraint applies to every namespace, or to cluster-scoped objects too (spec.match)

An empty or missing `match` selects everything, and every top-level matcher you add must also match. Within `kinds`,
one `{apiGroups, kinds}` entry is enough. `namespaces` keeps only the listed namespaces, `excludedNamespaces` drops
some (both accept prefix globs such as `kube-*`), and `namespaceSelector` selects by the namespace's labels. None of
the three excludes cluster-scoped objects; add `scope: Namespaced` for that:

```yaml
apiVersion: constraints.gatekeeper.sh/v1beta1
kind: K8sRequiredLabels
metadata:
  name: team-label-in-apps
spec:
  match:
    scope: Namespaced
    namespaces: ["team-a", "team-b"]
    kinds:
      - apiGroups: [""]
        kinds: ["Pod"]
  parameters:
    labels: ["team"]
```

To match all kinds, leave `kinds` out; with `--audit-match-kind-only=true`, one such constraint makes audit scan
every kind again. For a cluster-scoped kind such as PriorityClass, list its API group and kind under `kinds` and keep
`scope` at `Cluster` or the default `*`. `labelSelector` filters on the object's own labels and `name` on its name
(prefix globs allowed).

## A Pod constraint from the library does not block Deployments (ExpansionTemplate)

Most library templates read `spec.containers`, while workloads keep their containers under
`spec.template.spec.containers`, so adding `Deployment` to `kinds` does not help. By default the Deployment is created, its Pods are denied, and the
message appears in the ReplicaSet's and then the Deployment's status conditions
(`kubectl get replicaset <name> -o jsonpath='{ .status.conditions[].message }'`). To reject the workload itself
(Gatekeeper 3.10+, beta since 3.13 and enabled by default), add an ExpansionTemplate; constraints on Pods are then
also checked against Pods built from `spec.template`:

```yaml
apiVersion: expansion.gatekeeper.sh/v1alpha1
kind: ExpansionTemplate
metadata:
  name: expand-deployments
spec:
  applyTo:
    - groups: ["apps"]
      kinds: ["DaemonSet", "Deployment", "ReplicaSet", "StatefulSet"]
      versions: ["v1"]
  templateSource: "spec.template"
  generatedGVK:
    kind: "Pod"
    group: ""
    version: "v1"
```

An `enforcementAction` set in the ExpansionTemplate overrides the constraint's for expanded Pods. Fields that other
webhooks inject, such as a sidecar, are missing unless mutators with `source: Generated` add them, and checks based on
the requesting user cannot be enforced accurately this way.

## Block DELETE or kubectl exec with Gatekeeper; reads cannot be blocked

The default `validation.gatekeeper.sh` webhook only receives `CREATE` and `UPDATE`. Add `DELETE`, or `CONNECT` for
`kubectl exec`, to its `operations` in the `gatekeeper-validating-webhook-configuration` ValidatingWebhookConfiguration:

```yaml
    operations:
    - CREATE
    - UPDATE
    - DELETE
```

A template can then test the operation, here with a constraint whose `match.kinds` is `apiGroups: [""]`,
`kinds: ["Namespace"]`:

```rego
package k8sblockdelete

violation[{"msg": msg}] {
  input.review.operation == "DELETE"
  msg := sprintf("deleting %v is not allowed", [input.review.name])
}
```

In CEL templates `variables.anyObject` holds the object, or `oldObject` on DELETE requests. Deletes cannot be
audited, and with the default fail-open webhook a delete can get through while Gatekeeper is unreachable; failing
closed narrows that gap. Admission webhooks are called when objects are created, updated or deleted (and on CONNECT
once enabled), so Gatekeeper is never asked about `get`, `list` or `describe` and cannot restrict reads. Requests to
change webhook configurations are not sent to admission webhooks either.
