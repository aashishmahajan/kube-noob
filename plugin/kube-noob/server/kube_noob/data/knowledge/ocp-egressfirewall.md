---
id: ocp-egressfirewall
title: EgressFirewall (OVN-Kubernetes)
tags: [openshift, network, egress, security]
platforms: [openshift, rosa-classic, rosa-hcp]
updated: 2026-10-27
license: Apache-2.0
sources:
  - {title: "OpenShift - egress firewall", url: "https://docs.redhat.com/en/documentation/openshift_container_platform/latest/html/network_security/egress-firewall", license: CC-BY-SA-3.0}
  - {title: "cluster-network-operator OVN-K CRDs", url: "https://github.com/openshift/cluster-network-operator/blob/a1b26444418f0f14c7d35a1242c2bbd705932bdb/bindata/network/ovn-kubernetes/common/001-crd.yaml", license: Apache-2.0}
---
# EgressFirewall

`k8s.ovn.org/v1` EgressFirewall controls which external hosts pods in a project may reach.

- The object **must be named `default`** and there can be **at most one per project** (up to 8,000 rules). Violating
  this breaks the egress firewall and drops all external traffic for the project.
- Rules are evaluated **in order; the first match wins**. Put specific `Allow` rules first and a catch-all
  `Deny 0.0.0.0/0` last - a leading catch-all Deny makes every later Allow dead code (rule KN-N006).
- Destinations: `cidrSelector`, `dnsName` (resolved and refreshed by OVN-K), `nodeSelector`; optional `ports`.
- Cannot be created in kube-node-lease, kube-public, kube-system, openshift or openshift-* namespaces.

```yaml
apiVersion: k8s.ovn.org/v1
kind: EgressFirewall
metadata: {name: default, namespace: payments}
spec:
  egress:
  - {type: Allow, to: {dnsName: api.stripe.com}}
  - {type: Allow, to: {cidrSelector: 10.0.0.0/16}}
  - {type: Deny,  to: {cidrSelector: 0.0.0.0/0}}
```
