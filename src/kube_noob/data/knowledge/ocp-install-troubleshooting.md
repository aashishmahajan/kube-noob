---
id: ocp-install-troubleshooting
title: OpenShift installation troubleshooting
tags: [openshift, install, bootstrap, ignition, bootkube, csr, upi]
platforms: [openshift]
updated: 2026-10-28
license: Apache-2.0
requires:
  - [bootstrap, bootkube, bootkube.service, ignition, bootstrap.ign, installer, openshift-install, upi, csr, csrs, certificatesigningrequest, certificatesigningrequests, kubelet-serving, node-bootstrapper, machine-approver, join, joining]
sources:
  - {title: "OpenShift docs: Determining where installation issues occur", url: "https://github.com/openshift/openshift-docs/blob/164957757519b01359989b533feac5ecab551530/modules/determining-where-installation-issues-occur.adoc", license: Apache-2.0}
  - {title: "OpenShift docs: Gathering bootstrap node diagnostic data", url: "https://github.com/openshift/openshift-docs/blob/164957757519b01359989b533feac5ecab551530/modules/gathering-bootstrap-diagnostic-data.adoc", license: Apache-2.0}
  - {title: "OpenShift docs: Approve the certificate signing requests for your machines", url: "https://github.com/openshift/openshift-docs/blob/164957757519b01359989b533feac5ecab551530/modules/installation-approve-csrs.adoc", license: Apache-2.0}
---
# OpenShift installation: bootstrap, Ignition and CSRs

## Installation stages: what the bootstrap machine does and when the installer shuts it down

An install goes through fixed stages; watch the installation logs to see which stage failed, then collect the
diagnostic data for that stage. In order:

1. The Ignition config files are created.
2. The bootstrap machine boots and serves the remote resources the control plane machines need in order to boot.
3. The control plane machines fetch those resources from the bootstrap machine and finish booting.
4. The control plane machines form an etcd cluster, with help from the bootstrap machine.
5. On that new etcd cluster, the bootstrap machine runs a temporary Kubernetes control plane.
6. The temporary control plane schedules the production control plane onto the control plane machines.
7. The temporary control plane stops and hands over to the production control plane.
8. The bootstrap machine adds the OpenShift components to the production control plane.
9. The installation program shuts the bootstrap machine down.
10. The control plane sets up the worker nodes.
11. The control plane installs more services as a set of Operators.
12. The cluster fetches and configures the rest of what daily operation needs, including creating worker machines
    where the environment supports it.

So the bootstrap machine is temporary: it feeds the control plane machines, hosts the first (temporary) control
plane, and is shut down before the workers are set up.

## Bootstrap stuck: check that the Ignition file is served (curl -I bootstrap.ign)

If you can see the bootstrap node's console, watch it until the node reaches its login prompt. Then check the
Ignition file:

- Ignition files served by your own HTTP server: request the headers of the bootstrap file. A `200 OK` status means
  the file is there; `404 file not found` means it is not.
  `curl -I http://<http_server_fqdn>:<port>/bootstrap.ign`
- To see whether the bootstrap node actually fetched it, search the web server's log on the serving host. With
  Apache: `grep -is 'bootstrap.ign' /var/log/httpd/access_log`. An `HTTP GET` line with `200 OK` means the request
  succeeded.
- Not fetched: on the serving host, confirm the Ignition files exist and that file and web server permissions let
  the server hand them out.
- Ignition injected by a cloud provider mechanism at first boot: read the bootstrap node's console to see whether
  the mechanism delivers the bootstrap Ignition file correctly.

Also confirm that the bootstrap node's assigned storage device is available and that DHCP gave it an IP address.

## bootkube.service logs and container logs on the bootstrap node

You need SSH access to the bootstrap node and its fully qualified domain name. Follow the `bootkube.service` journal:

`ssh core@<bootstrap_fqdn> journalctl -b -f -u bootkube.service`

etcd `connection refused` errors in this log mean the bootstrap server cannot reach etcd on the control plane
nodes yet; they should stop once etcd runs on every control plane node and those nodes have joined the cluster.

Logs of every container on the bootstrap node, collected with podman:

`ssh core@<bootstrap_fqdn> 'for pod in $(sudo podman ps -a -q); do sudo podman logs $pod; done'`

## Bootstrap fails: api.<cluster_name>.<base_domain> DNS and the load balancer on port 6443

When the bootstrap process fails, check two things from the network side:

- The installation host can resolve `api.<cluster_name>.<base_domain>`.
- The load balancer forwards port 6443 connections to the bootstrap node and to the control plane nodes, and its
  proxy configuration meets the OpenShift installation requirements.

## New machines missing from oc get nodes: approve the client CSRs, then the kubelet-serving CSRs

A machine you added may not show up as a node until its certificate signing requests (CSRs) are approved, by the
cluster or by you. Approve the client requests first, then the server requests.

1. `oc get nodes`: compute nodes may be absent until some CSRs are approved.
2. `oc get csr`: each new machine should have a client request from
   `system:serviceaccount:openshift-machine-config-operator:node-bootstrapper` in `Pending` (or `Approved`).
3. Approve the pending client CSRs, one at a time with `oc adm certificate approve <csr_name>`, or all at once:
   `oc get csr -o go-template='{{range .items}}{{if not .status}}{{.metadata.name}}{{"\n"}}{{end}}{{end}}' | xargs --no-run-if-empty oc adm certificate approve`
   Every node submits two CSRs and some Operators might not become available until CSRs are approved, so you may
   have to run it several times.
4. After a client CSR is approved, the kubelet files a second CSR for its serving certificate. `oc get csr` now
   shows requests from `system:node:<node_name>` in `Pending`; approve them individually as above, or all with
   `oc get csr -o go-template='{{range .items}}{{if not .status}}{{.metadata.name}}{{"\n"}}{{end}}{{end}}' | xargs oc adm certificate approve`
5. Once both kinds are approved the machines turn `Ready` in `oc get nodes`, which can take a few minutes.

Approve within an hour of adding the machines. After that the certificates rotate and each node has more than two
certificates waiting, all of which must be approved. Later serving certificate renewals are approved by the
`machine-approver` automatically when the kubelet asks with the same parameters.

## oc logs, oc exec and oc rsh fail on bare metal and UPI: kubelet serving CSRs not approved

The API server needs the kubelet's serving certificate to connect to the kubelet. While a kubelet serving CSR is
not approved, `oc exec`, `oc rsh` and `oc logs` (and anything else that calls the kubelet endpoint) cannot succeed.

On platforms without the machine API, such as bare metal and other user-provisioned infrastructure, you must set up
your own automatic approval of kubelet serving CSRs. It has to watch for new CSRs, check that the request came from
the `node-bootstrapper` service account in the `system:node` or `system:admin` groups, and confirm the node's
identity.
