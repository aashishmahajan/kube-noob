---
id: k8s-common-errors
title: Everyday Kubernetes errors and what they mean
tags: [kubernetes, openshift, troubleshooting, deployments, configmap, finalizers, storage]
platforms: [kubernetes, openshift, rosa-classic, rosa-hcp]
updated: 2026-10-27
license: Apache-2.0
sources:
  - {title: "Kubernetes: Deployments", url: "https://kubernetes.io/docs/concepts/workloads/controllers/deployment/", license: CC-BY-4.0}
  - {title: "Kubernetes: ConfigMaps", url: "https://kubernetes.io/docs/concepts/configuration/configmap/", license: CC-BY-4.0}
  - {title: "Kubernetes: Finalizers", url: "https://kubernetes.io/docs/concepts/overview/working-with-objects/finalizers/", license: CC-BY-4.0}
  - {title: "Kubernetes: Storage Classes (volume binding mode)", url: "https://kubernetes.io/docs/concepts/storage/storage-classes/", license: CC-BY-4.0}
  - {title: "Kubernetes: Force delete StatefulSet pods", url: "https://kubernetes.io/docs/tasks/run-application/force-delete-stateful-set-pod/", license: CC-BY-4.0}
---
# Everyday Kubernetes errors

## "spec.selector: Invalid value ... field is immutable"

In `apps/v1` a Deployment's (and StatefulSet's, DaemonSet's) label selector cannot change after creation. Either
keep the old selector and only add pod labels, or create the workload under a new name, move traffic, then delete
the old one. Deleting and recreating under the same name causes downtime.

## A ConfigMap change does not show up in the pod

- Values used as environment variables (`env`, `envFrom`) are read only at container start: restart the pods.
- Files from a mounted ConfigMap volume are updated eventually (kubelet sync period plus cache delay, often a
  minute), and the application must re-read them.
- Files mounted with `subPath` never receive updates.
- A ConfigMap with `immutable: true` cannot be changed; create a new one and point the pods at it.
- To roll pods after a config change, run `kubectl rollout restart deployment/<name>`, or in Helm put a checksum
  of the ConfigMap in a pod template annotation so every change rolls the pods.

## Restart a Deployment without changing its YAML

`kubectl rollout restart deployment/<name> -n <ns>` sets the `kubectl.kubernetes.io/restartedAt` annotation on the
pod template, which triggers a normal rolling update that respects `maxUnavailable` and PodDisruptionBudgets.
Follow it with `kubectl rollout status deployment/<name> -n <ns>`.

## A pod is stuck in Terminating

1. `kubectl get pod <pod> -o jsonpath='{.metadata.finalizers}'`: a finalizer whose controller is gone blocks
   deletion.
2. `kubectl get node <node>`: if the node is NotReady or gone, the kubelet cannot confirm the container stopped.
3. Force deletion (`--grace-period=0 --force`) only removes the API object; the process may still run. Never force
   delete StatefulSet pods unless the node is confirmed down: two pods with the same identity can corrupt data.

## A namespace is stuck in Terminating

1. `kubectl get namespace <ns> -o yaml`: the status conditions say why. `NamespaceContentRemaining` and
   `NamespaceFinalizersRemaining` name the leftover objects; `NamespaceDeletionDiscoveryFailure` means an aggregated
   API is unavailable.
2. `kubectl get apiservice | grep False`: an unavailable APIService (for example a removed metrics adapter)
   blocks namespace deletion everywhere. Fix or delete that APIService.
3. List what is left: `kubectl api-resources --verbs=list --namespaced -o name | xargs -n 1 kubectl get
   --show-kind --ignore-not-found -n <ns>`, then fix the controller that owns the finalizers. Removing finalizers by
   hand skips that controller's cleanup (cloud load balancers, volumes) and leaks resources.

## A PVC is Pending with "waiting for first consumer"

That is expected with `volumeBindingMode: WaitForFirstConsumer`: the volume is provisioned only when a pod that
uses the claim is scheduled, so it lands in that pod's zone. If the pod is also Pending, debug the pod's scheduling
first (`kubectl describe pod`); see [kn:storage-access-modes#0] for access modes per StorageClass.
