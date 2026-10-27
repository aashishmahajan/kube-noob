---
id: k8s-resources
title: Requests, limits, QoS and right-sizing
tags: [kubernetes, resources, reliability]
platforms: [kubernetes, openshift, rosa-classic, rosa-hcp]
updated: 2026-10-27
license: Apache-2.0
sources:
  - {title: "Resource Management for Pods and Containers", url: "https://kubernetes.io/docs/concepts/configuration/manage-resources-containers/", license: CC-BY-4.0}
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
