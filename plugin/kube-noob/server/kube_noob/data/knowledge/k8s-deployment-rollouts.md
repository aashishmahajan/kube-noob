---
id: k8s-deployment-rollouts
title: Deployment rollouts - status, progress deadline, history and rollback
tags: [kubernetes, deployment, rollout, rollback, revision, progress-deadline]
platforms: [kubernetes, openshift, rosa-classic, rosa-hcp]
updated: 2026-10-28
license: Apache-2.0
requires:
  - [rollout, rollback, revision, revisions, undo, progressdeadlineexceeded, progressdeadlineseconds, deadline]
sources:
  - {title: "Kubernetes: Deployments", url: "https://kubernetes.io/docs/concepts/workloads/controllers/deployment/", license: CC-BY-4.0}
---
# Deployment rollouts

A change to a Deployment's pod template (a new image, an env var) starts a rollout: a new ReplicaSet scales up
while the old one scales down. `kubectl rollout status deployment/<name>` waits for it and exits non-zero when it
fails.

## "exceeded its progress deadline" (ProgressDeadlineExceeded)

When the new pods do not become available within `.spec.progressDeadlineSeconds` (600 by default), the Deployment
gets the condition `Progressing=False` with reason `ProgressDeadlineExceeded`, and `kubectl rollout status` ends
with `error: deployment "<name>" exceeded its progress deadline` (exit status 1). Kubernetes only reports this: it
does not roll back on its own, and the controller keeps retrying. Usual causes: not enough quota, failing readiness
probes, image pull errors, missing permissions, limit ranges, or bad application configuration. Find the cause in
`kubectl describe deployment <name>` (Conditions) and in the new pods' events, fix it, or roll back. A paused
rollout is not checked against the deadline.

## History and rollback

```sh
kubectl rollout history deployment/<name>                  # revisions and their CHANGE-CAUSE
kubectl rollout history deployment/<name> --revision=2     # what revision 2 ran
kubectl rollout undo deployment/<name>                     # back to the previous revision
kubectl rollout undo deployment/<name> --to-revision=2     # back to a specific revision
```

CHANGE-CAUSE comes from the `kubernetes.io/change-cause` annotation
(`kubectl annotate deployment/<name> kubernetes.io/change-cause="image 1.16.1"`); the old `--record` flag is
deprecated. Only changes to the pod template make a revision: scaling does not. `.spec.revisionHistoryLimit` (10 by
default) is how many old ReplicaSets are kept to roll back to; with 0 you cannot roll back.
