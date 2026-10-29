---
id: k8s-tls-x509
title: x509 and TLS errors (oc, kubectl, registries, Routes)
tags: [kubernetes, openshift, tls, x509, certificates, troubleshooting]
platforms: [kubernetes, openshift, rosa-classic, rosa-hcp]
updated: 2026-10-27
license: Apache-2.0
# A question needs a word of this document's subject (and of Kubernetes, where generic words would pass).
requires:
  - [x509, tls, certificate, certificates, cert, certs, ssl, ca]
  - [pod, pods, kubectl, oc, kubernetes, k8s, openshift, ocp, rosa, kubelet, kubeadm, deployment, deployments, statefulset, statefulsets, daemonset, daemonsets, replicaset, replicasets, namespace, namespaces, crashloopbackoff, configmap, configmaps, pvc, persistentvolumeclaim, helm, route, routes, registry]
sources:
  - {title: "Kubernetes: Configure Access to Multiple Clusters", url: "https://kubernetes.io/docs/tasks/access-application-cluster/configure-access-multiple-clusters/", license: CC-BY-4.0}
  - {title: "Kubernetes: Certificates", url: "https://kubernetes.io/docs/tasks/administer-cluster/certificates/", license: CC-BY-4.0}
  - {title: "OpenShift 4.22: Configuring a custom PKI", url: "https://docs.redhat.com/en/documentation/openshift_container_platform/4.22/html/configuring_network_settings/configuring-a-custom-pki", license: CC-BY-SA-3.0}
  - {title: "OpenShift 4.22: Certificate types and descriptions", url: "https://docs.redhat.com/en/documentation/openshift_container_platform/4.22/html/security_and_compliance/certificate-types-and-descriptions", license: CC-BY-SA-3.0}
---
# x509 and TLS errors

`x509: certificate signed by unknown authority` means the client does not trust the CA that signed the server's
certificate. `x509: certificate has expired or is not yet valid` means the date is outside the certificate's validity,
or the client's clock is wrong. `x509: certificate is valid for A, not B` means the name you called is not in the
certificate's subject alternative names.

## When oc or kubectl cannot reach the API server

`Unable to connect to the server: x509: ...` comes from your own machine, before any request reaches the cluster, so
`oc get` and `oc describe` cannot help. Check locally instead:

1. Which server the kubeconfig calls: `oc config view --minify` (the `server` field).
2. Which CA signed it: `openssl s_client -connect <api-host>:6443 -servername <api-host>` piped to
   `openssl x509 -noout -issuer -subject -dates`.
3. The clock: `date -u`. A skewed clock makes valid certificates look expired or not yet valid.

Then log in again with the right CA (`oc login <api-url> --certificate-authority=<ca.crt>`), or fix the
`certificate-authority-data` in the kubeconfig. Behind a TLS-inspecting corporate proxy, the proxy re-signs traffic
with its own CA: add that CA to the system trust store. `--insecure-skip-tls-verify` turns off the check entirely; keep
it for throwaway clusters.

## Inside the cluster

- **Image pulls**: the node must trust the registry's CA. On OpenShift add it to `image.config.openshift.io/cluster`
  (`additionalTrustedCA`); on Kubernetes add it to the container runtime's trust configuration on every node.
- **Pods calling other services**: mount the CA bundle. On OpenShift, a ConfigMap labelled
  `config.openshift.io/inject-trusted-cabundle=true` receives the cluster-wide trusted bundle, including a custom
  proxy CA set in `proxy/cluster` `trustedCA`.
- **Routes and Ingress**: check the certificate the router serves for the host (edge, reencrypt and passthrough
  terminate in different places) and that the host is in its subject alternative names.
- **Expiry**: OpenShift rotates its internal certificates automatically; certificates you supplied (custom ingress,
  API server named certificates) are yours to renew.
