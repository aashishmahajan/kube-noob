---
id: helm-cli-operations
title: Helm 3 CLI - --set syntax, OCI registries, repositories, removed APIs, rollback and where Helm keeps files
tags: [helm, set, oci, registry, repository, rollback, mapkubeapis, xdg]
platforms: [kubernetes, openshift, rosa-classic, rosa-hcp]
updated: 2026-10-28
license: Apache-2.0
requires:
  - [helm, chart, charts, values.yaml, chart.yaml]
sources:
  - {title: "Helm 3: Using Helm (The Format and Limitations of --set)", url: "https://helm.sh/docs/v3/intro/using_helm/", license: MIT}
  - {title: "Helm 3: helm install (--set-string, --set-file, --set-json)", url: "https://helm.sh/docs/v3/helm/helm_install/", license: MIT}
  - {title: "Helm 3: Use OCI-based registries", url: "https://helm.sh/docs/v3/topics/registries/", license: MIT}
  - {title: "Helm 3: Troubleshooting", url: "https://helm.sh/docs/v3/faq/troubleshooting/", license: MIT}
  - {title: "Helm 3: Deprecated Kubernetes APIs", url: "https://helm.sh/docs/v3/topics/kubernetes_apis/", license: MIT}
  - {title: "Helm 3: helm (environment variables and paths)", url: "https://helm.sh/docs/v3/helm/helm/", license: MIT}
  - {title: "Helm 3: Changes since Helm 2 (three-way strategic merge patch)", url: "https://helm.sh/docs/v3/faq/changes_since_helm2/", license: MIT}
---
# Helm 3 on the command line

## --set syntax: commas, dots, lists and strings

`--set a=b,c=d` sets two keys; `--set outer.inner=value` sets a nested key; `--set name={a,b,c}` sets a list;
`--set servers[0].port=80` sets a list item; `--set name=[]` and `--set a=null` set an empty list and null.
Escape a comma or a dot that belongs to the key or value with a backslash:
`--set name=value1\,value2` gives the string `value1,value2`, and
`--set nodeSelector."kubernetes\.io/role"=master` gives the key `kubernetes.io/role` (quote the whole argument in
your shell). `--set-string` keeps a value a string (a long number, `true`), `--set-file key=path` reads the value
from a file, and `--set-json` sets JSON values. Deeply nested values are easier in a `-f` values file.

## OCI registries: package, log in, push, install

```sh
helm package ./mychart                                 # makes mychart-0.1.0.tgz
helm registry login -u <user> registry.example.com
helm push mychart-0.1.0.tgz oci://registry.example.com/helm-charts
helm install myrelease oci://registry.example.com/helm-charts/mychart --version 0.1.0
```

`helm push` takes only a packaged `.tgz`, and its reference must start with `oci://` and must not include the
chart name or tag: Helm takes the name from the chart and the tag from its version. Some registries need the
repository or namespace created first. `helm pull`, `helm show`, `helm template`, `helm install` and `helm upgrade`
take `oci://` references too.

## helm repo add: "repository name (...) already exists"

Since Helm 3.3.2, adding a repository name that is already configured is an error. Use
`helm repo add <name> <url> --force-update` to overwrite it (the old `--no-update` flag is ignored), so a CI step
stays repeatable.

## UPGRADE FAILED: current release manifest contains removed kubernetes api(s)

Helm diffs the last deployed manifest against the new one; when that stored manifest uses an API version the
cluster no longer serves (`apps/v1beta1`, say), Helm cannot parse it and cannot upgrade the release, even if the new
chart is fixed. Rewrite the stored release to supported APIs with the
[helm-mapkubeapis](https://github.com/helm/helm-mapkubeapis) plugin, or edit the release Secret by hand as the
Helm page describes. Update charts to supported APIs before upgrading Kubernetes to avoid it.

## helm rollback: Error: no ConfigMap with the name "..." found

This happens when revision 2 removed a resource, the upgrade failed halfway and left the resource in the cluster,
and you roll back to revision 1. Older Helm 3 clients fail there; newer Helm 3 releases use the live cluster state
as the baseline, so upgrade the Helm client and retry.

## Upgrades and rollbacks see the live state

Helm 3 uses a three-way strategic merge patch: it compares the old manifest, the live state in the cluster and the
new manifest. A change made with `kubectl edit` (replicas scaled to 0, a sidecar injected) is therefore reverted
by a rollback, and fields added by others are kept on upgrade. Helm 2 compared only the two manifests.

## Where Helm keeps its cache, configuration and data

Helm uses `$HELM_CACHE_HOME`, `$HELM_CONFIG_HOME` and `$HELM_DATA_HOME` when set, otherwise the XDG variables
(`XDG_CACHE_HOME`, `XDG_CONFIG_HOME`, `XDG_DATA_HOME`), otherwise the OS default (on Linux `~/.cache/helm`,
`~/.config/helm` and `~/.local/share/helm`). Point them at a writable directory on a read-only home. The
repositories file (`repositories.yaml`) is in the configuration directory, so add your repositories again in the
new place, or point `$HELM_REPOSITORY_CONFIG` and `$HELM_REPOSITORY_CACHE` at them.
