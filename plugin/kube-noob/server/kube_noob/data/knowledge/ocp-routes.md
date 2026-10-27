---
id: ocp-routes
title: OpenShift Routes and TLS termination
tags: [openshift, routes, tls, ingress]
platforms: [openshift, rosa-classic, rosa-hcp]
updated: 2026-10-27
license: Apache-2.0
sources:
  - {title: "OpenShift - Route configuration", url: "https://docs.redhat.com/en/documentation/openshift_container_platform/latest/html/networking/configuring-routes", license: CC-BY-SA-3.0}
  - {title: "openshift/api Route CRD", url: "https://github.com/openshift/api/tree/master/route/v1", license: Apache-2.0}
---
# Routes

`route.openshift.io/v1` Route exposes a Service through the HAProxy-based ingress router.

## TLS termination
| termination | Who decrypts | Backend protocol | Notes |
|---|---|---|---|
| edge | router | HTTP | default cert is the cluster wildcard `*.apps.<cluster-domain>` |
| reencrypt | router, then re-encrypts | HTTPS | omit `destinationCACertificate` to trust the service-serving CA (annotate the Service with `service.beta.openshift.io/serving-cert-secret-name`) |
| passthrough | backend pod | HTTPS (SNI) | no certificates on the Route; `insecureEdgeTerminationPolicy` only None or Redirect |

Always set `insecureEdgeTerminationPolicy: Redirect` (or None); `Allow` also serves plain HTTP.

```yaml
apiVersion: route.openshift.io/v1
kind: Route
metadata: {name: orders-api}
spec:
  to: {kind: Service, name: orders-api}
  port: {targetPort: http}
  tls: {termination: edge, insecureEdgeTerminationPolicy: Redirect}
```

## Common failures
- 503 "Application is not available": Service has no ready endpoints, wrong `port.targetPort`, termination mismatch
  with the backend protocol, or a NetworkPolicy that does not allow the router namespace
  (`policy-group.network.openshift.io/ingress: ""`).
- Route not admitted with `HostAlreadyClaimed`: another namespace owns the host.
- Ingress objects are converted into Routes; use annotations `route.openshift.io/termination` to choose termination.
