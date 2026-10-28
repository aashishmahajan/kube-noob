---
id: k8s-images
title: Images - tags, digests, pulls and architectures
tags: [kubernetes, images, supply-chain]
platforms: [kubernetes, openshift, rosa-classic, rosa-hcp]
updated: 2026-10-28
license: Apache-2.0
# A question needs a word of this document's subject (and of Kubernetes, where generic words would pass).
requires:
  - [image, images, imagepullbackoff, errimagepull, registry, registries, imagepullsecrets, imagepullsecret, digest, digests, pull]
  - [pod, pods, kubectl, oc, kubernetes, k8s, openshift, ocp, rosa, kubelet, kubeadm, deployment, deployments, statefulset, statefulsets, daemonset, daemonsets, replicaset, replicasets, namespace, namespaces, crashloopbackoff, configmap, configmaps, pvc, persistentvolumeclaim, helm, imagepullbackoff, errimagepull, imagepullsecrets, imagepullsecret]
sources:
  - {title: "Images", url: "https://kubernetes.io/docs/concepts/containers/images/", license: CC-BY-4.0}
  - {title: "Using image pull secrets (OpenShift)", url: "https://docs.redhat.com/en/documentation/openshift_container_platform/4.21/html/images/using-image-pull-secrets", license: CC-BY-SA-3.0}
  - {title: "kubelet getPullSecretsForPod", url: "https://github.com/kubernetes/kubernetes/blob/master/pkg/kubelet/kubelet_pods.go", license: Apache-2.0}
---
# Images

- Pin images by **digest** (`repo@sha256:...`) or at least an immutable version tag. `:latest` (or no tag) changes
  underneath you and breaks rollbacks (rule KN-S012; RHACS policy "Latest tag").
- `imagePullPolicy` defaults to `Always` for `:latest`/untagged images and `IfNotPresent` otherwise.
- Private registries need an image pull secret linked to the pod's ServiceAccount
  (`oc secrets link <sa> <secret> --for=pull`).
- A pull secret only works in its own namespace: `imagePullSecrets` (on the pod or its ServiceAccount) name Secrets
  in the pod's namespace, so a Secret in another namespace is never used. kubelet then reports
  `FailedToRetrieveImagePullSecret` ("Unable to retrieve some image pull secrets (<name>)") next to
  `ErrImagePull` / `ImagePullBackOff`. Fix: create (or sync, for example with the External Secrets Operator) the
  Secret in the pod's namespace and link it. On OpenShift a registry every project uses goes in the global pull
  secret (`openshift-config/pull-secret`; on hosted control planes `kube-system/additional-pull-secret`), and an
  image in another project's internal registry needs `system:image-puller` for the pod's ServiceAccount in that
  project instead of a pull secret (rule KN-C013).
- `ImagePullBackOff` causes: wrong name/tag, missing credentials, registry rate limits (`toomanyrequests` on Docker
  Hub), untrusted registry TLS, no network path from nodes to the registry.
- `exec format error`: the image architecture does not match the node (arm64 vs amd64); build multi-arch images.
- Sign and verify images (Sigstore/cosign) and scan them (RHACS `roxctl image check`) in CI.
