{{/*
The name of the chart. Kept as a helper so a generator emits it and so the
release name is the one place a reader looks.
*/}}
{{- define "gateway.name" -}}
{{- .Chart.Name | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
The release name, which is also the name of every resource this chart
creates: the Argo Application is named `gateway`, so the Helm release is
`gateway`, so the Service is `gateway` and `IDENTITY_URL`'s default
(`http://identity:8080`) resolves the same way for identity's chart.
*/}}
{{- define "gateway.fullname" -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
The labels every resource carries. The `app.kubernetes.io` set is the
convention tooling selects on; `app.kubernetes.io/version` moves with
appVersion so a rollout is visible in the same labels that identify it.
*/}}
{{- define "gateway.labels" -}}
app.kubernetes.io/name: {{ include "gateway.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}
