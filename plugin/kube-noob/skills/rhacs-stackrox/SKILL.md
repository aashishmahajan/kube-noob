---
name: rhacs-stackrox
description: >
  Red Hat Advanced Cluster Security (RHACS) / StackRox - Central, Sensor, Admission Controller, Collector, default
  policies, admission denials (policyeval.stackrox.io), roxctl in CI, release history (4.10, 4.11, 5.0) and public ROX
  Jira insights. Use when the user mentions RHACS, ACS, StackRox, roxctl, Central, SecuredCluster or a policy violation.
---

# RHACS / StackRox

- Deploy-time policies are evaluated by the `policyeval.stackrox.io` webhook; only policies with enforcement enabled
  block admission. Default deploy policies are inform-only and several are disabled by default.
- kube-noob audit findings list the matching RHACS policy name (`stackroxPolicies`), so a clean audit predicts a clean
  RHACS evaluation. Reproduce RHACS checks with `roxctl deployment check --file manifest.yaml`.
- Versions: 4.10.0 (2026-03-03), 4.11.0 (2026-06-12); next is 5.0 (there is no 4.12). From 4.9 use
  `admissionControl.enforce` instead of `enforceOnCreates`/`enforceOnUpdates`.
- For known issues search the local corpus with source `jira:ROX` (public ROX issues 4.10+, ingested by
  `kube-noob corpus jira`) and the `jira-insights:ROX` aggregate; cite issue keys and URLs.
- Validate Central / SecuredCluster CRs with `kubenoob_validate_manifests` (bundled operator CRD schemas).
