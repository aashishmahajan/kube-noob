---
id: k8s-dns
title: DNS inside pods (CoreDNS and OpenShift DNS)
tags: [kubernetes, openshift, networking, dns, troubleshooting]
platforms: [kubernetes, openshift, rosa-classic, rosa-hcp]
updated: 2026-10-27
license: Apache-2.0
# A question needs a word of this document's subject (and of Kubernetes, where generic words would pass).
requires:
  - [dns, coredns, nslookup, resolv.conf, dig, cluster.local, svc.cluster.local]
  - [pod, pods, kubectl, oc, kubernetes, k8s, openshift, ocp, rosa, kubelet, kubeadm, deployment, deployments, statefulset, statefulsets, daemonset, daemonsets, replicaset, replicasets, namespace, namespaces, crashloopbackoff, configmap, configmaps, pvc, persistentvolumeclaim, helm, coredns, cluster.local, svc.cluster.local]
sources:
  - {title: "Kubernetes: Debugging DNS Resolution", url: "https://kubernetes.io/docs/tasks/administer-cluster/dns-debugging-resolution/", license: CC-BY-4.0}
  - {title: "Kubernetes: DNS for Services and Pods", url: "https://kubernetes.io/docs/concepts/services-networking/dns-pod-service/", license: CC-BY-4.0}
  - {title: "OpenShift: DNS Operator", url: "https://docs.redhat.com/en/documentation/openshift_container_platform/4.22/html/networking_operators/dns-operator", license: CC-BY-SA-3.0}
---
# DNS inside pods

Pods resolve names through the cluster DNS Service (CoreDNS). A Service is `<svc>.<ns>.svc.cluster.local`; the pod's
`/etc/resolv.conf` has search domains and `ndots:5`, so a name with fewer than five dots is tried with every search
suffix first.

## Debug in this order

1. `kubectl exec -it <pod> -- cat /etc/resolv.conf`: the nameserver should be the cluster DNS Service IP.
2. Resolve from a debug pod: `kubectl run dnsutils --rm -it --restart=Never --image=<dnsutils image> --
   nslookup kubernetes.default`. If this works but your app's lookups fail, check the name and namespace.
3. DNS pods: `kubectl get pods -n kube-system -l k8s-app=kube-dns` (OpenShift: `oc get pods -n openshift-dns`) and
   their logs.
4. NetworkPolicy: a default-deny egress policy must allow DNS. On Kubernetes allow UDP and TCP 53 to the DNS pods;
   on OpenShift the `dns-default` pods listen on port 5353, so allow UDP and TCP 5353 to namespace `openshift-dns`
   (see [kn:k8s-networkpolicy#3]).
5. External names timing out: ndots:5 makes `api.example.com` try cluster suffixes first. Use a fully qualified
   name with a trailing dot, or lower `ndots` through `spec.dnsConfig.options`.

On OpenShift the DNS Operator manages CoreDNS (`oc get dns.operator/default -o yaml`); forward zones for corporate
DNS are configured there with `spec.servers`, not by editing CoreDNS directly.
