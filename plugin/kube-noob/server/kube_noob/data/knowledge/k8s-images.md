---
id: k8s-images
title: Images - tags, digests, pulls and architectures
tags: [kubernetes, images, supply-chain]
platforms: [kubernetes, openshift, rosa-classic, rosa-hcp]
updated: 2026-10-27
license: Apache-2.0
sources:
  - {title: "Images", url: "https://kubernetes.io/docs/concepts/containers/images/", license: CC-BY-4.0}
---
# Images

- Pin images by **digest** (`repo@sha256:...`) or at least an immutable version tag. `:latest` (or no tag) changes
  underneath you and breaks rollbacks (rule KN-S012; RHACS policy "Latest tag").
- `imagePullPolicy` defaults to `Always` for `:latest`/untagged images and `IfNotPresent` otherwise.
- Private registries need an image pull secret linked to the pod's ServiceAccount
  (`oc secrets link <sa> <secret> --for=pull`).
- `ImagePullBackOff` causes: wrong name/tag, missing credentials, registry rate limits (`toomanyrequests` on Docker
  Hub), untrusted registry TLS, no network path from nodes to the registry.
- `exec format error`: the image architecture does not match the node (arm64 vs amd64); build multi-arch images.
- Sign and verify images (Sigstore/cosign) and scan them (RHACS `roxctl image check`) in CI.
