---
id: kubernetes
title: Kubernetes core - objects, networking, storage and how they fit together
tags: [kubernetes, fundamentals]
platforms: [kubernetes, openshift, rosa-classic, rosa-hcp]
updated: 2026-10-27
license: Apache-2.0
sources:
  - {title: "Kubernetes Concepts", url: "https://kubernetes.io/docs/concepts/", license: CC-BY-4.0}
---
# Kubernetes core

## Workloads
- **Pod**: one or more containers sharing a network namespace and volumes; the unit of scheduling. Pods are disposable.
- **Deployment** (`apps/v1`): stateless replicas managed through ReplicaSets; rolling updates and rollbacks.
- **StatefulSet** (`apps/v1`): stable identities (`name-0`, `name-1`), ordered rollout, one PersistentVolumeClaim per
  replica via `volumeClaimTemplates`; needs a headless Service.
- **DaemonSet**: one pod per (selected) node - log shippers, CNI and CSI node agents.
- **Job / CronJob** (`batch/v1`): run-to-completion work; `backoffLimit` and `activeDeadlineSeconds` bound retries.

## Networking and discovery
- **Service**: stable virtual IP and DNS name (`<svc>.<ns>.svc.cluster.local`) in front of pods selected by labels.
  Types: ClusterIP (default), NodePort, LoadBalancer, ExternalName; headless (`clusterIP: None`) for StatefulSets.
- **Ingress** (`networking.k8s.io/v1`) and the newer **Gateway API** (`gateway.networking.k8s.io/v1` Gateway and
  HTTPRoute) route external HTTP(S) traffic to Services. On OpenShift, Ingress objects are converted to Routes.
- **NetworkPolicy**: pod-level firewall; once any policy selects a pod for a direction, only explicitly allowed traffic
  is permitted in that direction.

## Configuration and storage
- **ConfigMap / Secret**: configuration injected as env vars or files. Secrets are base64-encoded, not encrypted -
  enable encryption at rest and prefer external secret stores.
- **PersistentVolumeClaim / PersistentVolume / StorageClass**: a PVC requests storage with an access mode; a
  StorageClass's provisioner creates the PV. Access mode support depends on the provisioner (see the storage access
  modes lesson): block volumes such as AWS EBS are ReadWriteOnce only.

## Security building blocks
Pod Security Standards (privileged / baseline / restricted) enforced by Pod Security Admission namespace labels;
securityContext (runAsNonRoot, allowPrivilegeEscalation, capabilities, seccompProfile, readOnlyRootFilesystem);
RBAC (Role/ClusterRole + bindings); ServiceAccounts and their tokens.

## Reliability building blocks
Requests/limits (scheduling and QoS), readiness/liveness/startup probes, PodDisruptionBudgets, topology spread
constraints, HorizontalPodAutoscaler (`autoscaling/v2`).

## Where to practice
Local clusters: kind (Kubernetes in Docker), k3d/k3s, minikube, k0s. Browser labs: Killercoda. See the
learning-paths lesson for the curated, link-checked list.
