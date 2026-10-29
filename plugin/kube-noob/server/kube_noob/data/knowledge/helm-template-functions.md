---
id: helm-template-functions
title: Helm 3 template functions, loops and chart files
tags: [helm, templates, range, toyaml, tpl, files, merge, subcharts]
platforms: [kubernetes, openshift, rosa-classic, rosa-hcp]
updated: 2026-10-29
license: Apache-2.0
requires:
  - [helm, chart, charts, values.yaml, chart.yaml, tpl, toyaml, tojson, nindent, sprig, mergeoverwrite, uuidv4, subchart, subcharts]
  - [template, templates, templating, tpl, toyaml, tojson, nindent, indent, include, range, loop, loops, sprig, default, required, merge, mergeoverwrite, uuidv4, randalphanum, files, glob, subchart, subcharts, global, globals, function, functions, pipeline]
sources:
  - {title: "Helm 3: Flow Control", url: "https://helm.sh/docs/v3/chart_template_guide/control_structures/", license: MIT}
  - {title: "Helm 3: Variables", url: "https://helm.sh/docs/v3/chart_template_guide/variables/", license: MIT}
  - {title: "Helm 3: Template Functions and Pipelines (default, lookup)", url: "https://helm.sh/docs/v3/chart_template_guide/functions_and_pipelines/", license: MIT}
  - {title: "Helm 3: Template Function List", url: "https://helm.sh/docs/v3/chart_template_guide/function_list/", license: MIT}
  - {title: "Helm 3: Named Templates (the include function)", url: "https://helm.sh/docs/v3/chart_template_guide/named_templates/", license: MIT}
  - {title: "Helm 3: Accessing Files Inside Templates", url: "https://helm.sh/docs/v3/chart_template_guide/accessing_files/", license: MIT}
  - {title: "Helm 3: Built-in Objects", url: "https://helm.sh/docs/v3/chart_template_guide/builtin_objects/", license: MIT}
  - {title: "Helm 3: Appendix: YAML Techniques", url: "https://helm.sh/docs/v3/chart_template_guide/yaml_techniques/", license: MIT}
  - {title: "Helm 3: Appendix: Go Data Types and Templates", url: "https://helm.sh/docs/v3/chart_template_guide/data_types/", license: MIT}
  - {title: "Helm 3: Subcharts and Global Values", url: "https://helm.sh/docs/v3/chart_template_guide/subcharts_and_globals/", license: MIT}
  - {title: "Helm 3: Values Files", url: "https://helm.sh/docs/v3/chart_template_guide/values_files/", license: MIT}
  - {title: "Helm 3: Debugging Templates", url: "https://helm.sh/docs/v3/chart_template_guide/debugging/", license: MIT}
  - {title: "Helm 3: Chart Development Tips and Tricks", url: "https://helm.sh/docs/v3/howto/charts_tips_and_tricks/", license: MIT}
  - {title: "Helm 3: Values (best practices)", url: "https://helm.sh/docs/v3/chart_best_practices/values/", license: MIT}
  - {title: "Helm 3: Templates (best practices)", url: "https://helm.sh/docs/v3/chart_best_practices/templates/", license: MIT}
  - {title: "Helm 3: Charts (dependencies, alias, global values)", url: "https://helm.sh/docs/v3/topics/charts/", license: MIT}
  - {title: "Helm 3: Library Charts", url: "https://helm.sh/docs/v3/topics/library_charts/", license: MIT}
  - {title: "Helm 3: Using Helm", url: "https://helm.sh/docs/v3/intro/using_helm/", license: MIT}
---
# Helm 3 template functions, loops and chart files

Helm 3 templates are Go templates with the Sprig functions (all except `env` and `expandenv`), plus `include`,
`required`, `tpl`, `lookup` and the `.Files` object. Check each fix below with `helm template --debug ./chart`.

## Generate one Deployment per item of a list in values.yaml (range, nested range)

`range` sets `.` to each list item in turn, so `.name` reads that item's field. Start the loop body with `---`:
a template file may hold several YAML documents, and Helm splits them before sending them to Kubernetes. When the
body has an inner `range`, name the outer loop's item (`range $app := ...`). Inside the inner loop `.` is the
inner item, but `$app` still works, because a variable stays in scope for the whole block it was declared in.
`range $i, $c := ...` gives the index (from 0) and the item; on a map, `range $key, $val := ...`.

```yaml
{{- range $app := .Values.apps }}
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: {{ $.Release.Name }}-{{ $app.name }}
spec:
  template:
    spec:
      containers:
        {{- range $i, $c := $app.containers }}
        - name: {{ $app.name }}-{{ $i }}
          image: {{ $c.image }}
        {{- end }}
{{- end }}
```

Selector and labels are left out above. Helm's guide recommends several documents in one file only when
necessary, because such files are harder to debug.

## Leave out args, annotations or volumes when the value is empty (if, with)

`if` and `with` skip their block when the value is false, 0, an empty string, missing or null, or an empty list
or map. `with` also sets `.` to the value, so the block can print it with `toYaml .`. Put `{{-` on the `with` and
`end` lines so a skipped block leaves no blank line. A helper that may render nothing works the same way:
`include` puts the helper's output into the pipeline, so `with include ...` drops the key when that output is
empty.

```yaml
metadata:
  name: {{ .Release.Name }}-web
  {{- with include "mychart.annotations" . }}
  annotations:
    {{- . | nindent 4 }}
  {{- end }}
spec:
  template:
    spec:
      containers:
        - name: web
          image: {{ .Values.image }}
          {{- with .Values.args }}
          args:
            {{- toYaml . | nindent 12 }}
          {{- end }}
```

Because 0 and false count as empty, `{{ if .Values.replicas }}` also skips `replicas: 0`.

## Insert an affinity, tolerations or resources block from values: toYaml and nindent

`toYaml` turns a map or list from values into YAML text aligned to the left. Pipe it through `nindent N`: it
adds a newline and indents every line by N spaces, while `{{-` removes the whitespace and newline before the
action. N is the indentation of the key's children: the parent key's spaces plus two (`labels:` at 2 takes
`nindent 4`). With the wrong indentation, the YAML parse fails with
`error converting YAML to JSON: yaml: line N: did not find expected key`.

```yaml
    spec:
      {{- with .Values.affinity }}
      affinity:
        {{- toYaml . | nindent 8 }}
      {{- end }}
      {{- with .Values.tolerations }}
      tolerations:
        {{- toYaml . | nindent 8 }}
      {{- end }}
```

`indent` is `nindent` without the leading newline. `toYamlPretty` works like `toYaml` but indents list items by
two more spaces.

## A list from values shows up as [a b c] in a ConfigMap: use toYaml or toJson

ConfigMap `data` holds string keys and string values. A list printed straight into the template comes out in
Go's notation (`[a b c]`, the form the function list uses), not as YAML. Encode it first: `toYaml` for YAML,
`toJson` or `toPrettyJson` for JSON, `toToml` for TOML. Put the result in a `|-` block string (multi-line,
no trailing newline) and indent it with `nindent`.

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: {{ .Release.Name }}-hosts
data:
  hosts.yaml: |-
    {{- toYaml .Values.hosts | nindent 4 }}
  hosts.json: |-
    {{- toPrettyJson .Values.hosts | nindent 4 }}
```

`toJson` returns an empty string when the item cannot be converted; `mustToJson` returns an error instead.

## default replaces false and 0, and a nested default fails when the parent key is missing

`default X .Values.y` returns X whenever the value is empty: 0, "", an empty list or map, false or null. So
`default true .Values.enabled` can never be false, and `default 3 .Values.replicas` turns 0 into 3. Keep static
defaults in values.yaml and `default` for computed values, as Helm's guide advises, and use `hasKey $dict "key"`
to tell "set to false" from "not set". A nested value such as `.Values.server.name` must be checked at every level,
or flattened to `serverName`. Or replace a missing map with an empty dict and read it with `get` (returns "" for
a missing key) or `dig` (walks several keys, returns its default if any is missing).

```yaml
{{- $server := .Values.server | default (dict) }}
name: {{ get $server "name" | default "none" }}
{{- $ingress := .Values.ingress | default (dict) }}
secretName: {{ dig "tls" "secretName" "default-tls" $ingress }}
```

## required: put the missing key's name in the error message

`required "message" value` stops rendering and prints your message when the value is empty or not defined. It
uses the same emptiness rules as `default`, so 0, false and "" fail too. The error shows the template position
and your text (`Error: execution error at (templates/test.yaml:2:13): maxMem must be set`), so write the key path
in the message. In a loop, build the message with `printf` so it names the item. For a rule that depends on
several values, test it with `if` and stop with `fail`.

```yaml
{{- range $i, $s := .Values.servers }}
- name: {{ $s.name }}
  port: {{ required (printf "servers[%d].port is required" $i) $s.port }}
{{- end }}
{{- if and .Values.tls.enabled (not .Values.tls.secretName) }}
{{- fail "tls.secretName must be set when tls.enabled is true" }}
{{- end }}
```

## Add numbers in a template and keep a running total in a range loop

The math functions `add` (two or more numbers), `add1`, `sub`, `mul`, `div` (integer division), `mod`, `max` and
`min` work on int64 values; `addf`, `subf`, `mulf` and `divf` work on float64. Convert a string with `int` first.
Store a result with `$x := add ...`. A variable declared inside `range` exists only inside that block, so carry a
total across iterations in a dict: dicts can be changed, and `set` updates a key and returns the dict (assign it
to `$_` so nothing is printed).

```yaml
{{- $metricsPort := add (int .Values.port) 1 }}
{{- $sum := dict "replicas" 0 }}
{{- range .Values.workers }}
{{- $_ := set $sum "replicas" (add (get $sum "replicas") .replicas) }}
{{- end }}
data:
  metricsPort: {{ $metricsPort | toString | quote }}
  totalReplicas: {{ get $sum "replicas" | toString | quote }}
```

## merge or mergeOverwrite: which side wins, and merging a base YAML file with values

`merge $a $b $c` gives precedence to the earlier (left) dicts. `mergeOverwrite $dest $src1 $src2` gives it to the
later (right) ones and overwrites values in `$dest`. Both are deep merges but not deep copies: nested maps end up
shared, so `deepCopy` the source first. To merge a YAML file shipped in the chart with overrides from values,
parse it with `fromYaml`, merge, and print it with `toYaml`. To fold a list of maps into one, merge each item into
one dict inside `range`. `mustMerge` and `mustMergeOverwrite` return an error when the merge fails.

```yaml
{{- $base := .Files.Get "config/base.yaml" | fromYaml }}
{{- $cfg := deepCopy .Values.config | mergeOverwrite $base }}
{{- range .Values.extraConfigs }}
{{- $_ := mergeOverwrite $cfg (deepCopy .) }}
{{- end }}
data:
  config.yaml: |-
    {{- toYaml $cfg | nindent 4 }}
```

## Fill placeholders from values into a config file (appsettings.json) with tpl

`.Files.Get` inserts a file without sending it through the template engine, so `{{ .Values.x }}` placeholders in
it stay as text. `tpl TEMPLATE_STRING VALUES` renders a string as a template: `tpl (.Files.Get "...") .` fills
the placeholders. Keep the file outside `templates/`, because `.Files` cannot read files there or files excluded
by `.helmignore`. The same works for a template string held in values: `{{ tpl .Values.hostTemplate . }}`. Files
from outside the chart cannot be passed at install time; users supply data with `-f` or `--set`. With the chart
file `files/appsettings.json` holding `{"Db": "Host={{ .Values.db.host }};Port={{ .Values.db.port }}"}`:

```yaml
data:
  appsettings.json: |-
    {{- tpl (.Files.Get "files/appsettings.json") . | nindent 4 }}
```

## One ConfigMap per file in a chart folder: .Files.Glob, AsConfig, AsSecrets

`.Files.Glob "configs/*"` returns the matching chart files. `range $path, $_ := ...` loops over their paths, and
`$.Files.Get $path` reads each file (inside `range`, reach `.Files` through `$`). `base`, `dir` and `ext` work on
the path. For one object holding all files, `(.Files.Glob "certs/*").AsSecrets` returns the bodies Base64-encoded
for a Secret's `data`, and `.AsConfig` returns them as a YAML map for a ConfigMap. `.Files` cannot read
`templates/` or files in `.helmignore`, and the chart must stay smaller than 1M.

```yaml
{{- range $path, $_ := .Files.Glob "configs/*" }}
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: {{ $.Release.Name }}-{{ base $path | trimSuffix (ext $path) }}
data:
  {{ base $path }}: |-
    {{- $.Files.Get $path | nindent 4 }}
{{- end }}
---
apiVersion: v1
kind: Secret
metadata:
  name: {{ .Release.Name }}-certs
type: Opaque
data:
  {{- (.Files.Glob "certs/*").AsSecrets | nindent 2 }}
```

## uuidv4 or randAlphaNum gives a new value on every helm upgrade

Helm runs the templates again on every upgrade, and `uuidv4`, `randAlphaNum` and the other random functions
return a new value on each call. The rendered resource differs, so Helm updates it each time and a generated
password or token changes. To keep the first value, read the existing object with `lookup`, which returns an
empty value when nothing is found. `lookup` always returns empty with `helm template`, and a client `--dry-run`
does not contact the cluster; test it with `--dry-run=server`. A failed API call (no RBAC permission, for
example) fails the render. Used on purpose, a `rollme: {{ randAlphaNum 5 | quote }}` pod annotation rolls the
Deployment on every upgrade.

```yaml
{{- $old := lookup "v1" "Secret" .Release.Namespace (printf "%s-auth" .Release.Name) }}
apiVersion: v1
kind: Secret
metadata:
  name: {{ .Release.Name }}-auth
type: Opaque
data:
  {{- if $old }}
  token: {{ $old.data.token }}
  {{- else }}
  token: {{ uuidv4 | b64enc }}
  {{- end }}
```

## Set a subchart's values from the parent chart: subchart key, alias and global

In the parent's values.yaml, the values under a key named after the subchart are sent to that subchart and
override its own values.yaml. The subchart's templates read them without the prefix (`.Values.dessert`, not
`.Values.mysubchart.dessert`), and a subchart cannot read the parent's other values. An `alias` on a dependency
in Chart.yaml makes the alias the dependency's name, so its values go under the alias key; the same chart can be
added twice under two aliases. Values under `global:` reach every chart as `.Values.global.<name>`. Parent
globals take precedence over a subchart's, and a subchart's globals pass down to its own subcharts, never up.

```yaml
dependencies:                # parent Chart.yaml
  - name: mysubchart
    version: 0.1.0
    repository: https://example.com/charts
    alias: cache

cache:                       # parent values.yaml
  dessert: ice cream         # mysubchart reads .Values.dessert
global:
  salad: caesar              # every chart reads .Values.global.salad
```
