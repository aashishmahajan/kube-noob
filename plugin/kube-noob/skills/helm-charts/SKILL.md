---
name: helm-charts
description: >
  Helm 3 and Helm 4 charts - structure, values.schema.json, templating, releases, rollback and common failures
  ("another operation is in progress", ownership metadata, no matches for kind). Use when the user asks to create, review,
  debug or upgrade a Helm chart or release.
---

# Helm

- Helm 4.0.0 shipped 2025-11-12; Helm 3 and 4 minors now release together. `apiVersion: v2` charts work with both.
- Create charts with `kubenoob_generate_helm_chart` (audited manifests -> templates, values.yaml, values.schema.json).
- Review a chart: ask the user to render it (`helm template .`) and paste the output, then run
  `kubenoob_audit_manifests` on it. In CI they can pipe it: `helm template . | kube-noob audit -f - --platform <p>`.
- Release failures: run `kubenoob_diagnose` on the error text; typical fixes are `helm history` + `helm rollback`, adopting
  objects with `meta.helm.sh/*` annotations, or migrating removed APIs.
- In CI recommend `helm lint --strict`, `helm upgrade --install --atomic --wait --timeout`.
