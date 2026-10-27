---
id: k8s-probes
title: Readiness, liveness and startup probes
tags: [kubernetes, reliability, probes]
platforms: [kubernetes, openshift, rosa-classic, rosa-hcp]
updated: 2026-10-27
license: Apache-2.0
sources:
  - {title: "Configure Liveness, Readiness and Startup Probes", url: "https://kubernetes.io/docs/tasks/configure-pod-container/configure-liveness-readiness-startup-probes/", license: CC-BY-4.0}
---
# Probes

- **readinessProbe**: may this pod receive traffic now? Failing removes the pod from Service endpoints (no restart).
  Can check dependencies.
- **livenessProbe**: is the process wedged? Failing restarts the container. Check only the process itself - never a
  database or downstream API, or one slow dependency restarts every replica at once.
- **startupProbe**: disables liveness/readiness until the app has started; size it as
  `failureThreshold x periodSeconds >= worst-case startup time`.

## Safe defaults
```yaml
readinessProbe: {httpGet: {path: /readyz, port: http}, periodSeconds: 5, timeoutSeconds: 2, failureThreshold: 3}
livenessProbe:  {httpGet: {path: /healthz, port: http}, periodSeconds: 10, timeoutSeconds: 3, failureThreshold: 3}
```
Apps must listen on 0.0.0.0 (not 127.0.0.1) so the kubelet can reach them. Keep `timeoutSeconds` below
`periodSeconds` as a convention so probes do not overlap (Kubernetes does not enforce it).
