---
id: k8s-validating-admission-policy
title: ValidatingAdmissionPolicy
tags: [kubernetes, admission, validatingadmissionpolicy, cel, policy]
platforms: [kubernetes, openshift, rosa-classic, rosa-hcp]
updated: 2026-10-28
license: Apache-2.0
requires:
  - [validatingadmissionpolicy, validatingadmissionpolicies, validatingadmissionpolicybinding, vap, validationactions, messageexpression, typechecking, expressionwarnings]
sources:
  - {title: "Kubernetes: Validating Admission Policy (Message expression)", url: "https://kubernetes.io/docs/reference/access-authn-authz/validating-admission-policy/#message-expression", license: CC-BY-4.0}
  - {title: "Kubernetes: Validating Admission Policy (Validation actions)", url: "https://kubernetes.io/docs/reference/access-authn-authz/validating-admission-policy/#validation-actions", license: CC-BY-4.0}
  - {title: "Kubernetes: Validating Admission Policy (Type checking)", url: "https://kubernetes.io/docs/reference/access-authn-authz/validating-admission-policy/#type-checking", license: CC-BY-4.0}
---
# ValidatingAdmissionPolicy (VAP)

A ValidatingAdmissionPolicy (stable since Kubernetes 1.30) checks requests inside the API server with CEL
expressions, with no webhook to run. The policy has no effect until a `ValidatingAdmissionPolicyBinding` names it in
`policyName`; the binding chooses which resources it covers and what a failed check does. A policy can also take a
parameter resource (a ConfigMap or a custom resource named in `spec.paramKind`), read in CEL as `params`, for values
such as a replica limit.

## ValidatingAdmissionPolicy '...' with binding '...' denied request: failed expression

```
ValidatingAdmissionPolicy 'max-replicas.example.com' with binding 'max-replicas-test' denied request: failed expression: object.spec.replicas <= 5
```

One of the policy's `spec.validations` expressions returned false for your object, and the binding named in the
message has `validationActions: [Deny]`. `failed expression:` followed by the CEL text is what the denial shows for a
validation without a `message` or `messageExpression`, as in the documented example policy whose only check is
`object.spec.replicas <= 5`. Fix the object so the expression holds (here: `spec.replicas` of 5 or less). If the
object should not be covered at all, the binding is what to change: in the documented example its
`matchResources.namespaceSelector` selects namespaces labelled `environment: test`. When several bindings, or several
parameter resources of one binding, match a request, the policy is evaluated once per combination and the request is
admitted only if every evaluation passes.

## message and messageExpression: a denial that says what to change

Each validation can carry a fixed `message` or a `messageExpression`: CEL that has to return a string and can read
`object`, `oldObject`, `request`, `params` and `namespaceObject`.

```yaml
validations:
- expression: "object.spec.replicas <= params.maxReplicas"
  messageExpression: "'object.spec.replicas must be no greater than ' + string(params.maxReplicas)"
  reason: Invalid
```

With a parameter of `maxReplicas: 3`, a Deployment asking for 5 replicas is then refused with
`... denied request: object.spec.replicas must be no greater than 3` instead of the bare expression. When both are
set, `messageExpression` is used; the fixed `message` is the fallback when the expression fails to evaluate or
returns several lines. `reason` sets the machine-readable reason and HTTP status code of the denial (`Unauthorized`,
`Forbidden`, `Invalid` or `RequestEntityTooLarge`); without it the response uses `Invalid`.

## Roll out a policy as warnings first: validationActions [Warn, Audit], then [Deny] to block

Every binding lists one or more `validationActions`:

- `Deny`: a failed validation rejects the request.
- `Warn`: the failure goes back to the client as a warning and the request goes on.
- `Audit`: the failure is written into the audit event of the request.

A binding with `[Warn, Audit]` lets requests through while telling both the client and the audit log what fails;
changing the same binding to `[Deny]` turns those failures into rejections. `Deny` and `Warn` cannot be set together
(the failure would be repeated in the response and in the warning headers).

```yaml
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionPolicyBinding
metadata:
  name: "demo-binding-test.example.com"
spec:
  policyName: "demo-policy.example.com"
  validationActions: [Warn, Audit]
  matchResources:
    namespaceSelector:
      matchLabels:
        environment: test
```

A validation that returns false always follows these actions. Errors handled by `failurePolicy` follow them only when
`failurePolicy` is `Fail` or unset; with `Ignore` such errors are dropped.

## status.typeChecking expressionWarnings: undefined field 'replicas'

The API server parses every expression when the policy is created or updated and refuses a policy with a syntax
error. It then type-checks the fields the expressions use against the types the policy matches in
`spec.matchConstraints` and writes the result to `status.typeChecking`; an empty `status.typeChecking` means no
problems were found.

```yaml
status:
  typeChecking:
    expressionWarnings:
    - fieldRef: spec.validations[0].expression
      warning: |-
        apps/v1, Kind=Deployment: ERROR: <input>:1:7: undefined field 'replicas'
         | object.replicas > 1
         | ......^
```

The Deployment replica count lives at `object.spec.replicas`, so the expression should be `object.spec.replicas > 1`.
These warnings are advice only: type checking never changes what the policy does, the policy keeps being evaluated,
and an expression that errors at request time is handled by `failurePolicy`. Type checking skips resources matched
through `"*"` wildcards, stops after 10 matched types, and does not check CRDs or the `paramKind` type.

## failurePolicy (Fail or Ignore) and parameterNotFoundAction

`failurePolicy` sits on the ValidatingAdmissionPolicy and decides what happens when the policy is misconfigured or a
CEL expression errors: `Fail` rejects the request, `Ignore` lets it continue. If a `matchConditions` expression
errors and none returned false, `Fail` rejects the request without running the policy and `Ignore` skips the policy.
A binding that uses parameters sets `paramRef` with either `name` or `selector` (not both) and the required
`parameterNotFoundAction`: `Allow` treats a missing parameter as a pass, `Deny` hands it to `failurePolicy` (so
`Fail` rejects the request). Without a bound parameter `params` is null; a first validation
`params != null` with a message such as "params missing but required to bind to this policy" makes that case explicit.
Policies created through the API cannot block changes to ValidatingAdmissionPolicies, their bindings, or the mutating
equivalents.
