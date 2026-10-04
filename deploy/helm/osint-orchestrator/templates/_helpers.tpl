{{/*
Expand the name of the chart.
*/}}
{{- define "osint-orchestrator.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name (release-name + chart-name, unless
the release already contains the chart name).
*/}}
{{- define "osint-orchestrator.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{- define "osint-orchestrator.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "osint-orchestrator.labels" -}}
helm.sh/chart: {{ include "osint-orchestrator.chart" . }}
{{ include "osint-orchestrator.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{- define "osint-orchestrator.selectorLabels" -}}
app.kubernetes.io/name: {{ include "osint-orchestrator.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{- define "osint-orchestrator.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "osint-orchestrator.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Name of the Secret the Deployment reads credentials from.
*/}}
{{- define "osint-orchestrator.secretName" -}}
{{- if .Values.secrets.existingSecret }}
{{- .Values.secrets.existingSecret }}
{{- else }}
{{- include "osint-orchestrator.fullname" . }}
{{- end }}
{{- end }}

{{/*
Name of the ConfigMap that carries targets.yaml.
*/}}
{{- define "osint-orchestrator.targetsConfigMapName" -}}
{{- if .Values.targets.existingConfigMap }}
{{- .Values.targets.existingConfigMap }}
{{- else }}
{{- printf "%s-targets" (include "osint-orchestrator.fullname" .) }}
{{- end }}
{{- end }}

{{/*
Name of the PVC mounted at /app/data and /app/daily_reports.
*/}}
{{- define "osint-orchestrator.pvcName" -}}
{{- if .Values.persistence.existingClaim }}
{{- .Values.persistence.existingClaim }}
{{- else }}
{{- include "osint-orchestrator.fullname" . }}
{{- end }}
{{- end }}

{{- define "osint-orchestrator.imageTag" -}}
{{- default .Chart.AppVersion .Values.image.tag }}
{{- end }}
