---
name: openshift-platform
description: >
  Red Hat OpenShift (OCP on-prem IPI/UPI) specifics - SecurityContextConstraints and arbitrary UIDs, Routes and TLS
  termination, OVN-Kubernetes EgressFirewall, ODF storage, operators/OLM, DeploymentConfig deprecation, OCP to
  Kubernetes version map. Use when the user mentions OpenShift, OCP, oc, SCC, Route, restricted-v2, ODF or EgressFirewall.
---

# OpenShift platform

- Version map: OCP 4.12->K8s 1.25 ... 4.20->1.33, 4.21->1.34, 4.22->1.35 (current). Confirm with `kubenoob_api_history`.
- Admission: new 4.11+ clusters use the `restricted-v2` SCC (drop ALL caps, RuntimeDefault seccomp, no privilege
  escalation, UID from the namespace range). Pods with fixed runAsUser are rejected; images must run as an arbitrary UID
  in group 0. Grant a more permissive SCC only to a dedicated ServiceAccount and only the least permissive one that works.
- Routes: edge / reencrypt (omit destinationCACertificate to trust the service-serving CA) / passthrough; always
  `insecureEdgeTerminationPolicy: Redirect`. 503 "Application is not available" = no ready endpoints, port mismatch,
  termination mismatch, or a NetworkPolicy missing `policy-group.network.openshift.io/ingress: ""`.
- EgressFirewall: name must be `default`, one per project, first match wins (specific Allow first, Deny 0.0.0.0/0 last).
- Use `kubenoob_audit_manifests` with `platform: openshift` and a `version`, and `kubenoob_diagnose` for errors.
- To enforce the audit rules in the cluster, `kubenoob_policy_generate` writes ValidatingAdmissionPolicy or Kyverno
  ValidatingPolicy YAML; suggest `mode: audit` first and switch a rule to enforce once its warnings are gone.
- For "what could an attacker reach?", `kubenoob_posture_scan` ranks paths from a Route, Ingress or exposed
  Service to node access or the pod's ServiceAccount rights; lead with rank 1, its evidence and its fix.
- With an RHACS policy export, `kubenoob_rhacs_compare` says which policies kube-noob's rules also check, which
  differ (image, runtime or API-event data) and what kube-noob has no rule for; name the gaps and disagreements first.
- For a failed build (GitHub Actions, Jenkins, Tekton, `oc logs build/...`), `kubenoob_build_diagnose` names the
  failing step, the cause class and the fix; `kubenoob_containerfile_audit` checks the Containerfile.
- For scanner output (Trivy or Grype JSON, a CycloneDX or SPDX SBOM, an RHACS image scan), `kubenoob_vuln_report`
  applies Red Hat VEX (citing each statement it used to drop a finding), marks CISA KEV entries and, with the
  manifests, ranks findings by exposure and privileges; lead with rank 1 and its attack path, then the fix version.
- For "what could go wrong with this application?", `kubenoob_threat_model` gives a STRIDE table per element with
  the rules and policies that mitigate each threat and ATT&CK ids; name the open threats first.
