---
id: ocp-egressip
title: Egress IPs on OpenShift and ROSA (OVN-Kubernetes)
tags: [openshift, rosa, rosa-hcp, networking, egress, egressip, ovn-kubernetes]
platforms: [openshift, rosa-classic, rosa-hcp]
updated: 2026-10-27
license: Apache-2.0
sources:
  - {title: "ROSA: Configuring an egress IP address (OVN-Kubernetes)", url: "https://docs.redhat.com/en/documentation/red_hat_openshift_service_on_aws_classic_architecture/4/html/ovn-kubernetes_network_plugin/configuring-egress-ips-ovn", license: CC-BY-SA-3.0}
  - {title: "ROSA tutorial: Assign a consistent egress IP for external traffic", url: "https://docs.openshift.com/rosa/cloud_experts_tutorials/cloud-experts-consistent-egress-ip.html", license: CC-BY-SA-3.0}
---
# Egress IPs on OpenShift and ROSA

An `EgressIP` (`k8s.ovn.org/v1`, cluster-scoped) gives traffic leaving selected namespaces or pods a fixed source
IP, so an external firewall or database allowlist can trust it. It needs the OVN-Kubernetes network plugin, the
default on current OpenShift and ROSA.

## Set it up on ROSA (classic or HCP)

1. Label the worker nodes that may host egress IPs. On ROSA you label the machine pool, not the nodes:
   `rosa edit machinepool -c <cluster> <pool> --labels "k8s.ovn.org/egress-assignable="`. This replaces the
   pool's existing labels, so repeat any labels you need. Label nodes before creating EgressIP objects, or every
   egress IP may land on the first labelled node.
2. Pick free IPs inside the subnets of those worker nodes (optionally reserve them in AWS so DHCP never hands them
   out).
3. Create the EgressIP:

```yaml
apiVersion: k8s.ovn.org/v1
kind: EgressIP
metadata:
  name: payments-egress
spec:
  egressIPs: [10.0.128.15, 10.0.160.15]
  namespaceSelector:
    matchLabels:
      kubernetes.io/metadata.name: payments
  podSelector:             # optional: narrow to some pods
    matchLabels: {app: api}
```

4. Verify: `oc get egressip` shows the assigned node for each IP (empty until a labelled node can host it).

## Limits and caveats

- AWS limits how many IPs a node can hold by instance type. Each node publishes its capacity in the
  `cloud.network.openshift.io/egress-ipconfig` annotation (`capacity.ipv4`); spread egress IPs across zones and
  nodes.
- Egress IPs are never assigned to control plane nodes. On ROSA HCP there are no control plane nodes in your
  account at all: only labelled worker machine pools can host them.
- ROSA HCP: application pods and ingress router pods run on the same worker nodes, so traffic from an application
  project to a Route of the same cluster does not use the egress IP.
- The egress IP only changes the source address of traffic leaving the cluster. Use NetworkPolicy and an
  `EgressFirewall` (see [kn:ocp-egressfirewall#0]) to restrict where traffic may go.

## Troubleshooting

- `oc get egressip` with no assigned node: no node carries `k8s.ovn.org/egress-assignable`, the IP is outside the
  node subnets, or node IP capacity is used up.
- `oc get nodes -l k8s.ovn.org/egress-assignable` lists eligible nodes; `oc describe egressip <name>` shows status.
