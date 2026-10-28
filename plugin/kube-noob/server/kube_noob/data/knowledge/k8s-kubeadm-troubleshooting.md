---
id: k8s-kubeadm-troubleshooting
title: kubeadm first-day problems
tags: [kubernetes, kubeadm, coredns, cni, kubeconfig, x509, control-plane]
platforms: [kubernetes]
updated: 2026-10-28
license: Apache-2.0
requires:
  - [kubeadm, coredns, admin.conf, kube-dns]
sources:
  - {title: "Kubernetes: Troubleshooting kubeadm", url: "https://kubernetes.io/docs/setup/production-environment/tools/kubeadm/troubleshooting-kubeadm/", license: CC-BY-4.0}
  - {title: "Kubernetes: Installing Addons (Pod network add-ons)", url: "https://kubernetes.io/docs/concepts/cluster-administration/addons/", license: CC-BY-4.0}
---
# kubeadm clusters: the first problems after kubeadm init

kubeadm installs the control plane and leaves the Pod network to you. Most first-day surprises come from that, from
a kubeconfig that belongs to a cluster you have since reset, or from flags that take `key=value` pairs.

## CoreDNS stays Pending after kubeadm init

This is expected. kubeadm does not choose a network provider, so CoreDNS (or kube-dns) cannot be scheduled until
you install a Pod network add-on (a CNI plugin such as Calico, Cilium or Flannel). Install one, then watch
`kubectl get pods -n kube-system`: CoreDNS starts once the nodes report Ready. Right after `kubeadm init`, no pod
should be in `RunContainerError`, `CrashLoopBackOff` or `Error`; if CoreDNS crashes only after the network add-on is
installed, the add-on is the likely problem (it may need more RBAC or a newer version). CoreDNS also crash-loops when
it detects a DNS forwarding loop (its `loop` plugin documents the workarounds), or on SELinux nodes with an old
Docker.

## x509: certificate signed by unknown authority after kubeadm reset and init

`kubeadm reset` and a new `kubeadm init` create a new cluster CA, but `$HOME/.kube/config` still holds the old
cluster's certificates, so kubectl fails with `x509: certificate signed by unknown authority` (often with
`crypto/rsa: verification error` naming the CA "kubernetes"). Use the new admin kubeconfig:

```sh
unset KUBECONFIG                                  # or: export KUBECONFIG=/etc/kubernetes/admin.conf
mv $HOME/.kube $HOME/.kube.bak && mkdir $HOME/.kube
sudo cp -i /etc/kubernetes/admin.conf $HOME/.kube/config
sudo chown $(id -u):$(id -g) $HOME/.kube/config
```

The certificates in a kubeconfig are base64; `base64 --decode` and `openssl x509 -text -noout` show which CA they
are from.

## flag: malformed pair, expect string=string

`--apiserver-extra-args` (and the other `*-extra-args` flags) take `key=value` pairs, so a value with commas, such
as `enable-admission-plugins=LimitRanger,NamespaceExists`, makes `NamespaceExists` look like a key without a value.
Repeating the key keeps only the last value. Put the setting in a kubeadm configuration file and run
`kubeadm init --config <file>`.
