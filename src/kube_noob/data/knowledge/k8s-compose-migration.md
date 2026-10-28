---
id: k8s-compose-migration
title: Moving a Docker Compose app to Kubernetes or OpenShift
tags: [kubernetes, openshift, docker, compose, kompose, migration, beginner]
platforms: [kubernetes, openshift, rosa-classic, rosa-hcp]
updated: 2026-10-28
license: Apache-2.0
requires:
  - [compose, kompose]
  - [kubernetes, k8s, openshift, ocp, rosa, kubectl, kompose, pod, deployment, cluster, helm]
sources:
  - {title: "Kubernetes: Translate a Docker Compose File to Kubernetes Resources", url: "https://kubernetes.io/docs/tasks/configure-pod-container/translate-compose-kubernetes/", license: CC-BY-4.0}
  - {title: "openshift-docs: OpenShift-specific guidelines for creating images (modules/images-create-guide-openshift.adoc)", url: "https://github.com/openshift/openshift-docs/blob/enterprise-4.22/modules/images-create-guide-openshift.adoc", license: Apache-2.0}
---
# From Docker Compose to Kubernetes

Kompose converts a Compose file into Kubernetes objects: `kompose convert` writes a Deployment and a Service per
Compose service (and a PersistentVolumeClaim per volume), then `kubectl apply -f <files>`. Treat the output as a
first draft to read and edit, not a finished deployment.

## What does not carry over

- **`build:`** is ignored for Kubernetes (`WARN Unsupported key build`): build and push each image to a registry
  first and reference it by tag or digest.
- **Services without `ports`** get no Kubernetes Service (`Service cannot be created because of missing port`):
  other pods cannot reach them by name until you add one.
- **Volumes** become PersistentVolumeClaims, and kompose switches that Deployment to the `Recreate` strategy so two
  pods never share the volume during a rollout.
- **Exposure**: the label `kompose.service.type` (`nodeport`, `clusterip`, `loadbalancer`) picks the Service type,
  and `kompose.service.expose: "true"` (or a host name) creates an Ingress (a Route for OpenShift).
- Service names replace container links: pods reach each other at `<service>:<port>`, never by pod IP.

## On OpenShift

`kompose --provider openshift convert` emits DeploymentConfigs, ImageStreams and BuildConfigs. DeploymentConfig is
deprecated ([kn:ocp-deploymentconfig#0]), so prefer the default Kubernetes output (Deployments) and add Routes.
Images also have to run as an arbitrary non-root UID with GID 0 and must not listen on ports below 1024: an image
that works under Docker as root often fails with `Permission denied` or `listen EACCES` until it is fixed
([kn:ocp-arbitrary-uid#1]).
