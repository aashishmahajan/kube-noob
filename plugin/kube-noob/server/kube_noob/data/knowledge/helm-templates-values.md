---
id: helm-templates-values
title: Helm values and templates
tags: [helm, templates, values, go-template, upgrade, uninstall, debugging]
platforms: [kubernetes, openshift, rosa-classic, rosa-hcp]
updated: 2026-10-28
license: Apache-2.0
requires:
  - [helm, chart, charts, values.yaml, chart.yaml, tpl, sprig]
sources:
  - {title: "Helm: Values Files", url: "https://helm.sh/docs/v3/chart_template_guide/values_files/", license: MIT}
  - {title: "Helm: Flow Control (scope with range and with)", url: "https://helm.sh/docs/v3/chart_template_guide/control_structures/", license: MIT}
  - {title: "Helm: Variables ($ is the root context)", url: "https://helm.sh/docs/v3/chart_template_guide/variables/", license: MIT}
  - {title: "Helm: Values best practices (keys with dashes)", url: "https://helm.sh/docs/v3/chart_best_practices/values/", license: MIT}
  - {title: "Helm: Chart Development Tips and Tricks", url: "https://helm.sh/docs/v3/howto/charts_tips_and_tricks/", license: MIT}
  - {title: "Helm: Debugging Templates", url: "https://helm.sh/docs/v3/chart_template_guide/debugging/", license: MIT}
  - {title: "Helm: helm upgrade", url: "https://helm.sh/docs/v3/helm/helm_upgrade/", license: MIT}
  - {title: "Helm: helm template", url: "https://helm.sh/docs/v3/helm/helm_template/", license: MIT}
  - {title: "Helm 3: Changes since Helm 2 (helm/helm-www versioned_docs/version-3/faq/changes_since_helm2.md)", url: "https://github.com/helm/helm-www/blob/e5a4c621283c8551426adce8cb27a2cc3f402ea8/versioned_docs/version-3/faq/changes_since_helm2.md", license: MIT}
  - {title: "Helm 3: Named Templates (setting the scope of a template)", url: "https://github.com/helm/helm-www/blob/e5a4c621283c8551426adce8cb27a2cc3f402ea8/versioned_docs/version-3/chart_template_guide/named_templates.md", license: MIT}
  - {title: "Helm 3: Migrating Helm v2 to v3 (2to3 plugin)", url: "https://github.com/helm/helm-www/blob/e5a4c621283c8551426adce8cb27a2cc3f402ea8/versioned_docs/version-3/topics/v2_v3_migration.md", license: MIT}
---
# Helm values and templates

Values reach a template in this order, the later one winning: the chart's `values.yaml`, each `-f` file from left
to right, then each `--set` from left to right. `values.yaml` itself is plain YAML: templates in it are not
rendered unless the chart passes that value through `tpl`.

## Values on install and upgrade

- Several values files: `helm install -f base.yaml -f prod.yaml ...`; the right-most file wins a key both set.
- Remove a default: set the key to `null` (`--set livenessProbe.httpGet=null`) and Helm drops it from the merged
  values; commenting it out in your file only leaves the chart's default in place.
- `helm upgrade` without values flags does not keep what you passed last time. `--reuse-values` reuses the last
  release's values and merges new `--set`/`-f` over them; `--reset-then-reuse-values` starts from the chart's
  (possibly new) defaults, applies the last release's values, then the new overrides; `--reset-values` uses only
  the chart's defaults.
- Quote strings, never integers: `name: {{ .Values.name | quote }}` but `port: {{ .Values.port }}`. Environment
  variable values are strings, so quote them even when they hold a number (an unquoted number there makes the API
  reject the manifest).

## Template scope: `.`, `$`, `range` and `with`

`.` is the current scope, not the chart: inside `range` or `with` it is the list item or the object you switched
to, so `.Values` and `.Release.Name` stop working there ("nil pointer evaluating interface {}"). Use `$`, which
always points at the root context: `{{ $.Release.Name }}`, `{{ $.Values.image }}`. A named template sees only the
scope you pass: `{{ include "mychart.labels" . }}` or `{{ template "mychart.labels" . }}`, not
`{{ template "mychart.labels" }}`. Without the dot, `.Chart.Name` and `.Chart.Version` inside the template are
empty, and the install fails with `unknown object type "nil" in ConfigMap.metadata.labels.chart`.

## Keys with dashes, includes and required values

- A key with a dash (`gitlab-runner`) cannot be read with dot notation (the dash parses as subtraction); use
  `{{ index .Values "gitlab-runner" "checkInterval" }}`, and prefer camelCase keys in your own charts.
- `include` can be piped and indented, which the `template` action cannot: `{{- include "mytpl" . | nindent 4 }}`.
- `{{ required "A valid .Values.who entry required!" .Values.who }}` fails the render with your message when a
  value is missing.
- Restart pods when a ConfigMap changes: put a checksum of the rendered ConfigMap in the pod template's
  annotations (`checksum/config: {{ include (print $.Template.BasePath "/configmap.yaml") . | sha256sum }}`), so
  every change to it rolls the Deployment.

## Debugging a chart

`helm template --debug ./chart` renders locally; `helm template -s templates/deployment.yaml ./chart` renders one
template; `helm install --dry-run --debug` renders with your values; `helm get manifest <release>` shows what is
installed; `helm get values <release>` shows the values a release was installed with.

## Helm 3 commands that changed

- A release name (or `--generate-name`) is required: `helm install myrelease ./chart`; the Helm 2 `--name` flag is
  gone, hence "unknown flag: --name".
- `helm delete` is an alias of `helm uninstall`, which removes the release history by default (Helm 2's
  `--purge`); keep it with `--keep-history`.
- `--create-namespace` creates a missing namespace on install.
- `helm search repo <name> --versions` lists every version of a chart in the repositories you added.

## `helm list` is empty or shows few releases: releases live in a namespace

Helm 2 kept every release in Tiller's namespace. Helm 3 stores each release in the namespace of the release itself,
and `helm list` shows only the releases in your current namespace (the one `kubectl config view --minify` shows).
After moving from Helm 2 (the 2to3 plugin migrates releases), or when you switch context, the other releases are
still there: `helm list -n <ns>` for one namespace, `helm list -A` (`--all-namespaces`) for all. Other release
commands are namespaced too: `helm uninstall <release> -n <ns>`, `helm upgrade ... -n <ns>`; without `-n`, Helm
looks in the current namespace and reports the release as not found.
