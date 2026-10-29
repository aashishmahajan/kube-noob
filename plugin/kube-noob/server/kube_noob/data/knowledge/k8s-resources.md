---
id: k8s-resources
title: Requests, limits, QoS and right-sizing
tags: [kubernetes, resources, reliability]
platforms: [kubernetes, openshift, rosa-classic, rosa-hcp]
updated: 2026-10-27
license: Apache-2.0
# A question has to be about this document's subject: generic words (container, volume, exit) are not enough.
requires:
  - [limit, limits, request, requests, resources, cpu, memory, oomkilled, qos, limitrange, resourcequota, throttling, throttled, millicores]
sources:
  - {title: "Resource Management for Pods and Containers", url: "https://kubernetes.io/docs/concepts/configuration/manage-resources-containers/", license: CC-BY-4.0}
  - {title: "Resource Management for Pods and Containers (limit enforcement)", url: "https://github.com/kubernetes/website/blob/a4c4bc29d562421ed29abebd7ef9835c24c27e71/content/en/docs/concepts/configuration/manage-resources-containers.md", license: CC-BY-4.0}
---
# Requests and limits

- **Requests** are what the scheduler reserves; a pod only fits on a node with enough unrequested allocatable capacity.
- **Limits** cap usage: exceeding the memory limit OOM-kills the container (exit code 137); exceeding the CPU limit
  throttles it.
- **QoS classes**: Guaranteed (requests == limits for every container), Burstable, BestEffort (no requests/limits;
  evicted first under node pressure).
- A request larger than its limit is rejected by the API server.
- Utilization-based HPA divides usage by the **request**; without CPU requests the HPA shows `<unknown>`.

## Sizing recipe
1. Observe real usage (`oc adm top pods --containers`, Prometheus `container_memory_working_set_bytes`).
2. Memory request ~ steady-state working set; memory limit = request x 1.25-2 depending on burstiness.
3. CPU request ~ p50-p90 usage; a CPU limit is optional (it trades latency for isolation).
4. Runtime heaps must respect the container limit (JVM `-XX:MaxRAMPercentage=75`, Node `--max-old-space-size`).
5. Add a namespace LimitRange (defaults) and ResourceQuota (ceilings).

## CPU limits throttle; memory limits are enforced reactively by OOM kills

The kubelet applies both limits and the Linux kernel enforces them, differently:

- A `cpu` limit is a hard limit enforced by throttling: as the container approaches it, the kernel restricts its
  CPU time. The container gets slower; it is not killed for using CPU.
- A `memory` limit is enforced by the kernel with out of memory (OOM) kills, and only when the kernel detects
  memory pressure. A container can therefore go over its memory limit for a while without being killed, and may be
  killed later (`OOMKilled`, exit code 137). Memory limits are enforced reactively, not the moment they are crossed.
