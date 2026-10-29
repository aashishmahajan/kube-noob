---
id: k8s-debug-pods
title: Debugging pods - a systematic path
tags: [kubernetes, openshift, debugging]
platforms: [kubernetes, openshift, rosa-classic, rosa-hcp]
updated: 2026-10-27
license: Apache-2.0
# A question has to be about this document's subject: generic words (container, volume, exit) are not enough.
requires:
  - [pod, pods, kubectl, oc, kubernetes, k8s, openshift, kubelet, crashloopbackoff, deployment, deployments, statefulset, daemonset, initcontainer, initcontainers]
sources:
  - {title: "Debug Pods", url: "https://kubernetes.io/docs/tasks/debug/debug-application/debug-pods/", license: CC-BY-4.0}
  - {title: "Determine the Reason for Pod Failure", url: "https://github.com/kubernetes/website/blob/a4c4bc29d562421ed29abebd7ef9835c24c27e71/content/en/docs/tasks/debug/debug-application/determine-reason-pod-failure.md", license: CC-BY-4.0}
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

## Why a container exited: the termination message and FallbackToLogsOnError

A container can write why it stopped to its termination message file, `/dev/termination-log` by default
(`terminationMessagePath`; it cannot be changed after the pod starts). Kubernetes copies that file into the
container's status, on success and on failure. The kubelet truncates a message over 4096 bytes, and all containers
of a pod share 12 KiB.

When the application writes no message, set `terminationMessagePolicy: FallbackToLogsOnError` on the container. The
default, `File`, reads only the file; with `FallbackToLogsOnError`, an empty file and an exit with an error make Kubernetes use
the last chunk of the container's log (at most 2048 bytes or 80 lines, whichever is smaller).

Read it in `kubectl get pod <pod> -o yaml` under `lastState.terminated.message`, or only the messages:

```sh
kubectl get pod <pod> -o go-template='{{range .status.containerStatuses}}{{printf "%s:\n%s\n\n" .name .lastState.terminated.message}}{{end}}'
```
