---
id: k8s-node-kubelet
title: The kubelet will not start or a node is NotReady
tags: [kubernetes, openshift, kubelet, nodes, kubeadm, swap, cgroups, certificates, troubleshooting]
platforms: [kubernetes, openshift]
updated: 2026-10-28
license: Apache-2.0
sources:
  - {title: "Kubernetes: Installing kubeadm (swap configuration)", url: "https://kubernetes.io/docs/setup/production-environment/tools/kubeadm/install-kubeadm/", license: CC-BY-4.0}
  - {title: "Kubernetes: Swap memory management", url: "https://kubernetes.io/docs/concepts/cluster-administration/swap-memory-management/", license: CC-BY-4.0}
  - {title: "Kubernetes: Configuring each kubelet in your cluster using kubeadm", url: "https://kubernetes.io/docs/setup/production-environment/tools/kubeadm/kubelet-integration/", license: CC-BY-4.0}
  - {title: "Kubernetes: Troubleshooting kubeadm", url: "https://kubernetes.io/docs/setup/production-environment/tools/kubeadm/troubleshooting-kubeadm/", license: CC-BY-4.0}
  - {title: "Kubernetes: Troubleshooting Clusters", url: "https://kubernetes.io/docs/tasks/debug/debug-cluster/", license: CC-BY-4.0}
  - {title: "Kubernetes: Certificate Management with kubeadm", url: "https://kubernetes.io/docs/tasks/administer-cluster/kubeadm/kubeadm-certs/", license: CC-BY-4.0}
  - {title: "Kubernetes: Communication between Nodes and the Control Plane", url: "https://kubernetes.io/docs/concepts/architecture/control-plane-node-communication/", license: CC-BY-4.0}
  - {title: "Kubernetes: kube-apiserver flags", url: "https://kubernetes.io/docs/reference/command-line-tools-reference/kube-apiserver/", license: CC-BY-4.0}
---
# The kubelet will not start

The kubelet is a systemd service on each node, so its own log says why it stopped. On the node:
`systemctl status kubelet`, then `journalctl -u kubelet --no-pager | tail -n 50`. From the cluster,
`kubectl describe node <node>` shows the node's conditions and recent events. On OpenShift, open a shell on the
node with `oc debug --as-root node/<node>`, run `chroot /host`, then read the same journal.

## Common causes in the kubelet's log

1. **Swap is on.** By default the kubelet fails to start on a Linux node with swap enabled. Either turn swap off
   (`sudo swapoff -a`, and remove it from `/etc/fstab` or the systemd swap unit so it stays off after a reboot) or
   tolerate it with `failSwapOn: false` in the kubelet configuration (workloads still get no swap unless
   `swapBehavior` is set). Restart the kubelet after changing swap.
2. **The cgroup driver does not match the container runtime's.** The kubelet's `cgroupDriver` (`systemd` or
   `cgroupfs`) must be the one the container runtime uses; the kubelet's own default is `cgroupfs`.
3. **The container runtime is not reachable.** The kubelet talks to the runtime through
   `--container-runtime-endpoint` (a socket); check that the runtime service (containerd or CRI-O) is running.
4. **An expired client certificate.** With kubeadm the kubelet rotates its client certificate through
   `/var/lib/kubelet/pki/kubelet-client-current.pem`; when rotation failed, the API server logs
   `x509: certificate has expired or is not yet valid`. The kubeadm troubleshooting guide regenerates
   `kubelet.conf` from a control-plane node and restarts the kubelet.
5. **Before `kubeadm init` or `kubeadm join`** the kubelet restarts every few seconds by design: it waits in a
   crash loop for kubeadm to tell it what to do. That is not a fault.

## The API server cannot verify the kubelets (CIS `--kubelet-certificate-authority`)

The API server connects to each kubelet to fetch pod logs, attach to pods and port-forward, and by default it does
not verify the kubelet's serving certificate. `--kubelet-certificate-authority` gives it a CA bundle to verify
with. With kubeadm the kubelets' serving certificates are self-signed by default, so a kubelet whose certificate
that CA did not sign fails those calls once the flag is set. First have the kubelets request signed serving
certificates (`serverTLSBootstrap: true` in the kubelet configuration), approve their CSRs (`kubectl get csr`, then
`kubectl certificate approve <name>`; the built-in signer does not approve `kubernetes.io/kubelet-serving` CSRs
automatically, and rotation creates new ones to approve), then point the flag at the cluster CA.
