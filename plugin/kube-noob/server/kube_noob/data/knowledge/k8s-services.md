---
id: k8s-services
title: Services, endpoints and why traffic does not arrive
tags: [kubernetes, networking, services, debugging]
platforms: [kubernetes, openshift, rosa-classic, rosa-hcp]
updated: 2026-10-27
license: Apache-2.0
# A question needs a word of this document's subject (and of Kubernetes, where generic words would pass).
requires:
  - [service, services, endpoints, endpointslice, endpointslices, clusterip, nodeport, targetport, loadbalancer]
  - [pod, pods, kubectl, oc, kubernetes, k8s, openshift, ocp, rosa, kubelet, kubeadm, deployment, deployments, statefulset, statefulsets, daemonset, daemonsets, replicaset, replicasets, namespace, namespaces, crashloopbackoff, configmap, configmaps, pvc, persistentvolumeclaim, helm]
sources:
  - {title: "Service", url: "https://kubernetes.io/docs/concepts/services-networking/service/", license: CC-BY-4.0}
---
# Services and endpoints

A Service selects pods by label and publishes the **ready** ones as EndpointSlices. Traffic fails when:
1. `spec.selector` does not match pod template labels (rule KN-V011) - `kubectl get endpointslices
   -l kubernetes.io/service-name=<svc>` is empty.
2. Pods are not Ready (readiness probe failing) - they are excluded from endpoints.
3. `targetPort` names a port the container does not declare (rule KN-V012), or the numeric port is wrong.
4. The app listens on 127.0.0.1 inside the container.
5. A NetworkPolicy blocks the caller.

Types: ClusterIP (internal), NodePort (port on every node - avoid), LoadBalancer (cloud LB; restrict with
`loadBalancerSourceRanges` or make it internal, e.g. `service.beta.kubernetes.io/aws-load-balancer-internal: "true"`
on AWS/ROSA), headless (`clusterIP: None`) for StatefulSet peer discovery.
