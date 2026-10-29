---
id: k8s-networkpolicy
title: NetworkPolicy patterns (Kubernetes and OpenShift)
tags: [kubernetes, openshift, network, security]
platforms: [kubernetes, openshift, rosa-classic, rosa-hcp]
updated: 2026-10-27
license: Apache-2.0
# A question needs a word of this document's subject (and of Kubernetes, where generic words would pass).
requires:
  - [networkpolicy, networkpolicies, podselector, namespaceselector, policytypes]
sources:
  - {title: "Network Policies", url: "https://kubernetes.io/docs/concepts/services-networking/network-policies/", license: CC-BY-4.0}
  - {title: "openshift-docs nw-networkpolicy-multitenant-isolation (main @10a3557)", url: "https://github.com/openshift/openshift-docs/blob/main/modules/nw-networkpolicy-multitenant-isolation.adoc", license: Apache-2.0}
---
# NetworkPolicy patterns

Once any NetworkPolicy selects a pod for Ingress (or Egress), all traffic in that direction not explicitly allowed is
dropped. Policies are additive (union of allows).

## Default deny + explicit allows
```yaml
kind: NetworkPolicy
apiVersion: networking.k8s.io/v1
metadata: {name: default-deny}
spec: {podSelector: {}, policyTypes: [Ingress]}
```

## Allow the OpenShift router (ingress controller) and monitoring
```yaml
ingress:
- from:
  - namespaceSelector:
      matchLabels:
        policy-group.network.openshift.io/ingress: ""      # router namespace (OVN-Kubernetes)
  - namespaceSelector:
      matchLabels:
        network.openshift.io/policy-group: monitoring      # openshift-monitoring
```
On vanilla Kubernetes select the ingress controller's namespace instead, e.g.
`kubernetes.io/metadata.name: ingress-nginx`.

## Egress and DNS
If you restrict egress, allow DNS first. OpenShift DNS pods listen on **5353** (TCP/UDP) in namespace `openshift-dns`;
CoreDNS on vanilla Kubernetes listens on 53 in `kube-system`. For external destinations by DNS name on OpenShift use
an EgressFirewall.
