{{- define "kube-noob.fullname" -}}
{{- if contains .Chart.Name .Release.Name -}}{{ .Release.Name | trunc 63 | trimSuffix "-" }}{{- else -}}{{ printf "%s-%s" .Release.Name .Chart.Name | trunc 63 | trimSuffix "-" }}{{- end -}}
{{- end -}}

{{- define "kube-noob.selectorLabels" -}}
app.kubernetes.io/name: {{ .Chart.Name }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "kube-noob.labels" -}}
{{ include "kube-noob.selectorLabels" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | quote }}
{{- end -}}

{{- define "kube-noob.image" -}}
{{- if .Values.image.digest -}}{{ .Values.image.repository }}@{{ .Values.image.digest }}{{- else -}}{{ .Values.image.repository }}:{{ .Values.image.tag | default .Chart.AppVersion }}{{- end -}}
{{- end -}}

{{- /* Secret holding the bearer token: yours (auth.existingSecret) or one the chart generates. Empty when unauthenticated. */ -}}
{{- define "kube-noob.tokenSecret" -}}
{{- if .Values.auth.existingSecret -}}{{ .Values.auth.existingSecret }}{{- else if not .Values.auth.allowUnauthenticated -}}{{ include "kube-noob.fullname" . }}-token{{- end -}}
{{- end -}}

{{- /* Team memory (memory.source): where the repository is mounted, and how the git source is reached. */ -}}
{{- define "kube-noob.memorySource" -}}
{{- (.Values.memory | default dict).source | default "none" -}}
{{- end -}}

{{- define "kube-noob.memoryGitHost" -}}
{{- first (splitList ":" (urlParse .Values.memory.git.url).host) -}}
{{- end -}}

{{- define "kube-noob.memoryGitInCluster" -}}
{{- $host := include "kube-noob.memoryGitHost" . -}}
{{- if or (hasSuffix ".svc" $host) (hasSuffix ".svc.cluster.local" $host) -}}true{{- end -}}
{{- end -}}

{{- define "kube-noob.memoryGitPort" -}}
{{- $g := .Values.memory.git -}}
{{- $u := urlParse $g.url -}}
{{- if $g.port -}}{{ $g.port }}{{- else if contains ":" $u.host -}}{{ last (splitList ":" $u.host) }}{{- else if eq $u.scheme "ssh" -}}22{{- else -}}443{{- end -}}
{{- end -}}

{{- define "kube-noob.memoryGitImage" -}}
{{- $i := .Values.memory.git.image -}}
{{- if $i.digest -}}{{ $i.repository }}@{{ $i.digest }}{{- else -}}{{ $i.repository }}:{{ $i.tag }}{{- end -}}
{{- end -}}

{{- define "kube-noob.seedSource" -}}
{{- ((.Values.jira | default dict).seed | default dict).source | default "none" -}}
{{- end -}}

{{- define "kube-noob.seedImage" -}}
{{- $i := .Values.jira.seed.image -}}
{{- if $i.digest -}}{{ $i.repository }}@{{ $i.digest }}{{- else -}}{{ $i.repository }}:{{ $i.tag }}{{- end -}}
{{- end -}}
