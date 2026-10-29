---
id: k8s-kubectl-selectors
title: Find a workload's pods with labels and selectors
tags: [kubernetes, openshift, kubectl, labels, selectors, deployments, beginner]
platforms: [kubernetes, openshift, rosa-classic, rosa-hcp]
updated: 2026-10-28
license: Apache-2.0
# A question needs a word of this document's subject (and of Kubernetes, where generic words would pass).
requires:
  - [label, labels, selector, selectors, matchlabels, belong, belongs, owner, owned, ownerreferences]
  - [pod, pods, kubectl, oc, kubernetes, k8s, openshift, ocp, rosa, kubelet, kubeadm, deployment, deployments, statefulset, statefulsets, daemonset, daemonsets, replicaset, replicasets, namespace, namespaces, crashloopbackoff, configmap, configmaps, pvc, persistentvolumeclaim, helm]
sources:
  - {title: "Kubernetes: Labels and Selectors", url: "https://kubernetes.io/docs/concepts/overview/working-with-objects/labels/", license: CC-BY-4.0}
  - {title: "Kubernetes: kubectl Quick Reference", url: "https://kubernetes.io/docs/reference/kubectl/quick-reference/", license: CC-BY-4.0}
  - {title: "Kubernetes: Deployments", url: "https://kubernetes.io/docs/concepts/workloads/controllers/deployment/", license: CC-BY-4.0}
---
# Labels and selectors

A label selector is how Kubernetes groups objects: a Deployment, ReplicaSet or Service finds its pods by their
labels, never by their names. So to list "the pods of a deployment", ask for the pods that match the Deployment's
selector instead of piping `kubectl get pods` through `grep`.

## List the pods of one Deployment

1. Read the selector: `kubectl describe deployment <name> -n <ns>` prints a `Selector:` line (for example
   `app=hello`), or `kubectl get deployment <name> -n <ns> -o jsonpath='{.spec.selector.matchLabels}'`.
2. List the matching pods: `kubectl get pods -n <ns> -l app=hello` (same as `--selector=app=hello`). Add `-o wide`
   for the node and pod IP, or `--show-labels` to see every pod's labels.
3. Logs from all of them: `kubectl logs -n <ns> -l app=hello --all-containers`.

Each ReplicaSet a Deployment creates adds a `pod-template-hash` label to its pods, so
`-l app=hello,pod-template-hash=<hash>` narrows the list to one rollout's pods. Use `oc` the same way on OpenShift.

## Selector syntax

- Equality-based: `-l environment=production,tier=frontend` (comma means AND), `-l tier!=frontend`.
- Set-based: `-l 'environment in (production, qa)'`, `-l 'tier notin (frontend)'`, `-l 'environment'` (the key
  exists), `-l '!canary'` (the key does not exist). Quote set-based selectors for the shell.
- Show a label as a column: `kubectl get pods -l app=nginx -L tier`.
- Field selectors filter on fields, not labels: `kubectl get pods --field-selector=status.phase=Running`.

## Print only what you need

- `-o jsonpath='{.items[*].metadata.name}'` prints the names of everything a selector matched.
- `-o custom-columns='NAME:.metadata.name,IMAGE:.spec.containers[*].image'` prints a table of chosen fields.
- `kubectl get pods --selector=app=cassandra -o jsonpath='{.items[*].metadata.labels.version}'` reads one label
  across pods.
