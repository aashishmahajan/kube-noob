---
id: helm
title: Helm 3 and Helm 4 - charts, values, releases
tags: [helm, packaging]
platforms: [kubernetes, openshift, rosa-classic, rosa-hcp]
updated: 2026-10-27
license: Apache-2.0
# A question needs a word of this document's subject (and of Kubernetes, where generic words would pass).
requires:
  - [helm, chart, charts, values.yaml, chart.yaml]
sources:
  - {title: "Helm documentation", url: "https://helm.sh/docs/", license: MIT}
  - {title: "helm/helm releases", url: "https://github.com/helm/helm/tags", license: Apache-2.0}
---
# Helm

Helm packages Kubernetes manifests as **charts** and installs them as **releases**.

## Versions
Helm 4.0.0 shipped on 2025-11-12. Since then Helm 4 and Helm 3 minors are released on the same day (v4.3.0 and
v3.22.0 on 2026-09-09; v4.3.1 on 2026-10-14, v3.22.1 on 2026-10-15). helm.sh/docs now documents Helm 4 by default,
with Helm 3 docs under /docs/v3/. Charts with `apiVersion: v2` work with Helm 3 and Helm 4.

## Chart layout
```
mychart/
  Chart.yaml           # apiVersion: v2, name, version (SemVer 2), appVersion (quoted string), kubeVersion
  values.yaml          # defaults
  values.schema.json   # JSON schema validated on install/upgrade/lint/template
  templates/           # Go templates + Sprig functions; _helpers.tpl for named templates
  templates/NOTES.txt  # printed after install
  charts/              # dependencies (helm dependency update)
```

## Best practices
- Pin image tags (or digests) in values, never `latest`.
- Ship `values.schema.json` so bad values fail before rendering.
- Use `{{- toYaml .Values.resources | nindent 12 }}` for nested blocks; `quote` user strings.
- Label everything with `app.kubernetes.io/*` and let Helm add `app.kubernetes.io/managed-by: Helm`.
- In CI use `helm lint`, `helm template | kube-noob audit -f -`, and `helm upgrade --install --atomic --wait --timeout`.
- Keep secrets out of values files committed to Git; use external secret operators.

## Release mechanics
- Release state is stored as Secrets (`sh.helm.release.v1.<name>.v<revision>`) in the release namespace.
- `helm history`, `helm rollback <release> <revision>`, `helm uninstall`.
- Objects not created by the release are refused unless they carry `meta.helm.sh/release-name`,
  `meta.helm.sh/release-namespace` annotations and the `app.kubernetes.io/managed-by: Helm` label.
