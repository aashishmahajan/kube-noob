---
id: helm-troubleshooting
title: Helm troubleshooting
tags: [helm, debugging]
platforms: [kubernetes, openshift, rosa-classic, rosa-hcp]
updated: 2026-10-27
license: Apache-2.0
sources:
  - {title: "Helm documentation", url: "https://helm.sh/docs/", license: MIT}
---
# Helm troubleshooting

## "another operation (install/upgrade/rollback) is in progress"
A previous operation was interrupted and the release is stuck in `pending-install`, `pending-upgrade` or
`pending-rollback`. Check `helm history <release> -n <ns>`. If a good revision exists, `helm rollback <release> <rev>`;
if the very first install failed, `helm uninstall` and reinstall. Prevent with `--atomic --wait --timeout 10m` in CI.

## "rendered manifests contain a resource that already exists" / "invalid ownership metadata"
The object exists but was not created by this release. Either delete/rename it, or adopt it deliberately by adding the
`app.kubernetes.io/managed-by=Helm` label and the `meta.helm.sh/release-name` / `meta.helm.sh/release-namespace`
annotations.

## "no matches for kind ... in version ..."
The chart uses an API that the cluster does not serve: a removed API (e.g. `policy/v1beta1` PodDisruptionBudget on
1.25+) or a CRD that is not installed. Render and audit: `helm template . | kube-noob audit -f - --platform openshift
--version 4.22`.

## Values not applied
`helm get values <release> -n <ns> --all` shows the merged values; check indentation and key names against
`values.schema.json`; `--set` uses dot paths and needs escaping for keys containing dots.

## Debugging templates
`helm template . --debug`, `helm lint --strict`, and `helm install --dry-run=server` (validates against the API server).
