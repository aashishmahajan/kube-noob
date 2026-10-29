---
id: k8s-invalid-utf8
title: "string field contains invalid UTF-8: CreateContainerError and the RHACS Collector"
tags: [kubernetes, openshift, troubleshooting, secrets, containerd, grpc]
platforms: [kubernetes, openshift, rosa-classic, rosa-hcp]
updated: 2026-10-28
license: Apache-2.0
# Only for this error: its words (secret, data, nodes) are everywhere else.
requires:
  - [utf-8, utf8]
sources:
  - {title: "Kubernetes: Secrets (data is base64, stringData is plain text)", url: "https://github.com/kubernetes/website/blob/a4c4bc29d562421ed29abebd7ef9835c24c27e71/content/en/docs/concepts/configuration/secret.md", license: CC-BY-4.0}
  - {title: "Kubernetes: ConfigMaps (data is UTF-8, binaryData for binary)", url: "https://github.com/kubernetes/website/blob/a4c4bc29d562421ed29abebd7ef9835c24c27e71/content/en/docs/concepts/configuration/configmap.md", license: CC-BY-4.0}
  - {title: "Report: CreateContainerError, string field contains invalid UTF-8 (aws/containers-roadmap #2791)", url: "https://github.com/aws/containers-roadmap/issues/2791", license: proprietary-link-only}
  - {title: "Report: pods fail to start, string field contains invalid UTF-8 (ministryofjustice/cloud-platform #8186)", url: "https://github.com/ministryofjustice/cloud-platform/issues/8186", license: proprietary-link-only}
  - {title: "Report: Secret values base64-encoded twice reach the pod undecodable (giantswarm platform-manager #280)", url: "https://github.com/giantswarm/giantswarm-platform-manager/issues/280", license: proprietary-link-only}
  - {title: "Red Hat KCS: RHACS collector CrashLoopBackOff, libprotobuf invalid UTF-8 data", url: "https://access.redhat.com/node/7086811", license: proprietary-link-only}
---
# string field contains invalid UTF-8

## CreateContainerError: grpc: error unmarshalling request: string field contains invalid UTF-8

The container runtime refused a request because a text field held bytes that are not UTF-8. The usual field is an
environment variable that comes from a Secret (`env.valueFrom.secretKeyRef` or `envFrom`):

- Values under a Secret's `data` are base64; Kubernetes decodes them once. A value that was base64-encoded twice
  decodes to random bytes. Put plain text under `stringData`, or encode it exactly once under `data`.
- Binary data (keys, keystores) is not text: mount the key as a file from a Secret volume, or base64-encode it once
  more and decode it in the application. For ConfigMaps, `data` holds UTF-8 strings and `binaryData` holds binary.
- Users reported the error appearing after their nodes moved to containerd 2.2, on Secrets that nodes running
  containerd 2.1 had accepted: check `oc get nodes -o wide` (CONTAINER-RUNTIME) when only new nodes fail.

On RHACS, Collector in CrashLoopBackOff with `String field 'storage.ProcessSignal.args' contains invalid UTF-8 data
when serializing a protocol buffer` is a known issue (RHACS 4.5, ROX-26025) with no published workaround.
