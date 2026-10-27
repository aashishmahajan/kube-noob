---
id: k8s-ingress
title: Ingress, IngressClass and why an Ingress returns 404
tags: [kubernetes, openshift, networking, ingress]
platforms: [kubernetes, openshift, rosa-classic, rosa-hcp]
updated: 2026-10-27
license: Apache-2.0
sources:
  - {title: "Kubernetes: Ingress", url: "https://kubernetes.io/docs/concepts/services-networking/ingress/", license: CC-BY-4.0}
  - {title: "OpenShift 4.22: Routes (including routes created from Ingress objects)", url: "https://docs.redhat.com/en/documentation/openshift_container_platform/4.22/html/ingress_and_load_balancing/routes", license: CC-BY-SA-3.0}
  - {title: "Red Hat KCS: Route not generated from Ingress object when ingressClassName value set", url: "https://access.redhat.com/node/6995806", license: proprietary-link-only}
---
# Ingress and IngressClass

An Ingress is only a rule; an ingress controller implements it. `spec.ingressClassName` names the controller (an
`IngressClass`). If it is unset, the cluster's default IngressClass (annotation
`ingressclass.kubernetes.io/is-default-class: "true"`) is used; with no default, controllers ignore the Ingress.

## Why an Ingress returns 404

1. Wrong or missing `ingressClassName`: no controller picked it up, and the 404 comes from a controller's default
   backend. Check `kubectl get ingressclass` and the controller's logs.
2. Host or path mismatch: the request `Host` header must match `spec.rules[].host`; `pathType: Prefix` matches path
   elements (`/api` matches `/api/v1`, not `/apiv1`), `Exact` matches one path only.
3. The backend Service has no endpoints (selector mismatch or pods not Ready): see [kn:k8s-services#0]. Some
   controllers answer 503 rather than 404 in this case.
4. TLS: `spec.tls[].secretName` must exist in the Ingress namespace.

## On OpenShift and ROSA

OpenShift automatically creates a Route for an Ingress that its router handles: no `ingressClassName`, or the
`openshift-default` IngressClass. An Ingress that names another class (for example a separately installed NGINX
controller) gets no Route. Check the generated object with `oc get route -n <ns>`; its failures are Route failures
([kn:ocp-routes#2]), and an annotation on the Ingress picks the TLS mode ([kn:ocp-routes#1]).
