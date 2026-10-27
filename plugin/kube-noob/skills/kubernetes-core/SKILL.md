---
name: kubernetes-core
description: >
  Kubernetes fundamentals and production patterns - workloads, Services, Ingress/Gateway API, storage access modes,
  Pod Security Standards, probes, resources, PDBs, RBAC, NetworkPolicy, API deprecations. Use when the user asks
  "how does X work in Kubernetes", "which apiVersion", "why is my PVC pending", "what should my probes be", or wants to
  learn Kubernetes.
---

# Kubernetes core

1. Search local knowledge first: `kubenoob_search_knowledge` (query with the user's terms). Cite `[kn:...]` ids.
2. For version questions use `kubenoob_api_history` (removed APIs per version, OpenShift->Kubernetes map). The upstream
   deprecation guide lists no removals after 1.32 - do not invent later removals.
3. When the user shares YAML, run `kubenoob_audit_manifests` before commenting and quote rule ids and line numbers.
4. To teach, use the learning tools: `kubenoob_learn_tracks` -> `kubenoob_learn_lesson` -> `kubenoob_learn_exercise` ->
   `kubenoob_learn_submit` (graded offline, awards credits) and `kubenoob_learn_quiz`.
5. Keep answers concrete: show the minimal correct YAML snippet and the command to verify it.

Practice environments to recommend: kind, k3d, minikube, k0s, Killercoda; architecture deep dive: Kubernetes The Hard
Way; exercises: CKAD-exercises (see the `learning-paths` knowledge doc for link-checked URLs).
