---
id: helm-chart-authoring
title: Writing Helm 3 charts
tags: [helm, chart, crds, hooks, library, templates, whitespace]
platforms: [kubernetes, openshift, rosa-classic, rosa-hcp]
updated: 2026-10-28
license: Apache-2.0
requires:
  - [helm, chart, charts, values.yaml, chart.yaml]
sources:
  - {title: "Helm 3: Custom Resource Definitions (best practices)", url: "https://helm.sh/docs/v3/chart_best_practices/custom_resource_definitions/", license: MIT}
  - {title: "Helm 3: Chart Hooks", url: "https://helm.sh/docs/v3/topics/charts_hooks/", license: MIT}
  - {title: "Helm 3: Library Charts", url: "https://helm.sh/docs/v3/topics/library_charts/", license: MIT}
  - {title: "Helm 3: Flow Control (Controlling Whitespace)", url: "https://helm.sh/docs/v3/chart_template_guide/control_structures/", license: MIT}
  - {title: "Helm 3: Templates (YAML comments vs template comments)", url: "https://helm.sh/docs/v3/chart_best_practices/templates/", license: MIT}
---
# Writing Helm 3 charts

## CRDs in the chart's crds/ directory

Put CustomResourceDefinitions in `crds/`, not `templates/`. Helm installs them on `helm install` before the rest
of the chart; they are plain YAML (not templated), an existing CRD is skipped with a warning, and `--skip-crds`
skips them. Helm never upgrades or deletes CRDs from `crds/` (a deliberate choice against accidental data loss),
so a new CRD version must be applied separately (`kubectl apply -f crds/`), or the CRDs moved to a chart of their
own. `--dry-run` does not work for charts that install CRDs; use `helm template`.

## Hooks: pre-install, post-install and friends

A hook is a normal manifest with the `helm.sh/hook` annotation (`pre-install`, `post-install`, `pre-upgrade`,
`post-upgrade`, `pre-delete`, `post-delete`, `pre-rollback`, `post-rollback`, `test`). For a Job or Pod hook Helm
waits until it completes, and a failed hook fails the release. `helm.sh/hook-weight` (a string, such as `"-5"`)
orders hooks, lowest first. Hook resources are not part of the release: `helm uninstall` does not delete them.
`helm.sh/hook-delete-policy` decides when Helm deletes them: `before-hook-creation` (the default: delete the old one
before running the hook again), `hook-succeeded`, `hook-failed`; a Job can also use `ttlSecondsAfterFinished`.

## Library charts

A chart with `type: library` in `Chart.yaml` only provides named templates for other charts: it renders no
manifests, and `helm install` fails with `Error: library charts are not installable`. Add it as a dependency of an
application chart and call its templates with `include`.

## Whitespace: {{- and -}}

`{{- ` removes the whitespace (including the newline) before the action, ` -}}` the whitespace after it. Chomping
on the wrong side joins two lines or shifts indentation, and the render fails with
`error converting YAML to JSON: yaml: line N: did not find expected key`. Put `{{- if }}` and `{{- end }}` on lines
of their own, pipe `include` through `nindent`, and read the reported line in `helm template --debug` output.

## Template comments, not YAML comments, around template code

A `#` YAML comment does not stop the template engine: actions inside it still run, so a `required` in a commented-out
line still fails the render. Use a template comment, which renders nothing:
`{{- /* memory: {{ required "maxMem must be set" .Values.maxMem }} */ -}}`. YAML comments stay in the output and show
in `helm install --debug`; template comments do not.
