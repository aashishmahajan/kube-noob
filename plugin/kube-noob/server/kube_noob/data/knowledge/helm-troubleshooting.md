---
id: helm-troubleshooting
title: Helm troubleshooting
tags: [helm, debugging]
platforms: [kubernetes, openshift, rosa-classic, rosa-hcp]
updated: 2026-10-27
license: Apache-2.0
sources:
  - {title: "Helm 3: Advanced techniques (--take-ownership)", url: "https://github.com/helm/helm-www/blob/e5a4c621283c8551426adce8cb27a2cc3f402ea8/versioned_docs/version-3/topics/advanced.md", license: MIT}
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
annotations. Helm can also adopt it for you: `helm install <release> ./chart --take-ownership` (or `helm upgrade
... --take-ownership`) skips the ownership check, and later upgrades and uninstalls treat the object as part of the
release. Review `--dry-run` output first so Helm does not take objects it should not manage; fields the chart never
set stay on the object.

## "no matches for kind ... in version ..."
The chart uses an API that the cluster does not serve: a removed API (e.g. `policy/v1beta1` PodDisruptionBudget on
1.25+) or a CRD that is not installed. Render and audit: `helm template . | kube-noob audit -f - --platform openshift
--version 4.22`.

## Values not applied
`helm get values <release> -n <ns> --all` shows the merged values; check indentation and key names against
`values.schema.json`; `--set` uses dot paths and needs escaping for keys containing dots.

## Debugging templates
`helm template . --debug`, `helm lint --strict`, and `helm install --dry-run=server` (validates against the API server).
