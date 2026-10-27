---
id: k8s-debug-pods
title: Debugging pods - a systematic path
tags: [kubernetes, openshift, debugging]
platforms: [kubernetes, openshift, rosa-classic, rosa-hcp]
updated: 2026-10-27
license: Apache-2.0
sources:
  - {title: "Debug Pods", url: "https://kubernetes.io/docs/tasks/debug/debug-application/debug-pods/", license: CC-BY-4.0}
---
# Debugging pods

1. **Status and phase**: `oc get pods -n <ns> -o wide` - Pending (scheduling/storage), ContainerCreating
   (volumes, image, CNI), CrashLoopBackOff/Error (process exits), Running but not Ready (readiness).
2. **Events**: `oc describe pod <pod>` and `oc get events -n <ns> --sort-by=.lastTimestamp` - FailedScheduling,
   FailedMount, Multi-Attach, BackOff, Unhealthy (probe failures), FailedCreate on the ReplicaSet (admission/SCC/PSA).
3. **Logs**: `oc logs <pod> -c <container>`; for crash loops `--previous` shows the failed attempt.
4. **Exit codes**: 0 completed (but restartPolicy Always restarts it), 1 app error, 126 not executable, 127 command
   not found, 137 SIGKILL/OOMKilled, 139 segfault, 143 SIGTERM (often a liveness kill).
5. **Inside the pod**: `oc rsh <pod>` / `kubectl exec -it`, or `oc debug pod/<pod>` / `kubectl debug` to start a copy
   with a shell when the image has none.
6. **Owner**: for workloads, `oc describe deploy/<name>` (conditions such as ProgressDeadlineExceeded) and the
   ReplicaSet events (admission rejections appear there, not on a pod that never existed).

`kube-noob diagnose` matches pasted output against these patterns offline; with `cluster.enabled: true`,
`kube-noob debug deployment/<name> -n <ns>` collects the evidence read-only and diagnoses it.
