---
id: ocp-arbitrary-uid
title: Building images that run as an arbitrary UID (OpenShift)
tags: [openshift, images, security]
platforms: [openshift, rosa-classic, rosa-hcp]
updated: 2026-10-28
license: Apache-2.0
requires:
  - [permission, denied, eacces, uid, user, root, nonroot, non-root, runasuser, runasnonroot, chown, chmod, chgrp, writable, mkdir, dockerfile, containerfile, scc, arbitrary]
sources:
  - {title: "OpenShift - creating images (support arbitrary user ids)", url: "https://docs.redhat.com/en/documentation/openshift_container_platform/", license: CC-BY-SA-3.0}
  - {title: "openshift-docs: OpenShift-specific guidelines for creating images (modules/images-create-guide-openshift.adoc)", url: "https://github.com/openshift/openshift-docs/blob/enterprise-4.22/modules/images-create-guide-openshift.adoc", license: Apache-2.0}
---
# Arbitrary UIDs

Under restricted-v2 every container runs with a UID from the namespace range (for example 1000680000) and GID 0. The
UID has no entry in `/etc/passwd` and owns nothing in the image.

## Dockerfile pattern
```dockerfile
FROM registry.access.redhat.com/ubi9/ubi-minimal
COPY app /opt/app
RUN chgrp -R 0 /opt/app && chmod -R g=u /opt/app
USER 1001
```
- Make every directory the app writes **group-owned by 0 and group-writable**; never `chown` at runtime.
- Use a numeric `USER` so `runAsNonRoot: true` can be verified by the kubelet.
- Write state to mounted volumes or emptyDir, not the image filesystem; that also enables `readOnlyRootFilesystem`.
- Listen on a port above 1024 (8080, 8443): the process is not privileged, so it cannot bind ports below 1024. The
  Service (and the Route) map port 80 or 443 to it.

## Symptoms when an image is not ready
`Permission denied` / `EACCES` on startup, `mkdir: cannot create directory`, `listen EACCES` on port 80 or 443,
CrashLoopBackOff only on OpenShift.
