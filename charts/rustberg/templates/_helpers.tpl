{{/*
Expand the name of the chart.
*/}}
{{- define "rustberg.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
*/}}
{{- define "rustberg.fullname" -}}
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

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "rustberg.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "rustberg.labels" -}}
helm.sh/chart: {{ include "rustberg.chart" . }}
{{ include "rustberg.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "rustberg.selectorLabels" -}}
app.kubernetes.io/name: {{ include "rustberg.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Create the name of the service account to use
*/}}
{{- define "rustberg.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "rustberg.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Return the image name
*/}}
{{- define "rustberg.image" -}}
{{- $tag := default .Chart.AppVersion .Values.image.tag -}}
{{- printf "%s:%s" .Values.image.repository $tag -}}
{{- end }}

{{/*
Generate storage environment variables
*/}}
{{- define "rustberg.storageEnv" -}}
{{- if eq .Values.rustberg.storage.type "s3" }}
- name: AWS_REGION
  value: {{ .Values.rustberg.storage.s3.region | quote }}
{{- if .Values.rustberg.storage.s3.endpoint }}
- name: AWS_ENDPOINT_URL
  value: {{ .Values.rustberg.storage.s3.endpoint | quote }}
{{- end }}
{{- if .Values.rustberg.storage.s3.existingSecret }}
- name: AWS_ACCESS_KEY_ID
  valueFrom:
    secretKeyRef:
      name: {{ .Values.rustberg.storage.s3.existingSecret }}
      key: {{ .Values.rustberg.storage.s3.existingSecretAccessKeyIdKey }}
- name: AWS_SECRET_ACCESS_KEY
  valueFrom:
    secretKeyRef:
      name: {{ .Values.rustberg.storage.s3.existingSecret }}
      key: {{ .Values.rustberg.storage.s3.existingSecretSecretAccessKeyKey }}
{{- else if .Values.rustberg.storage.s3.accessKeyId }}
- name: AWS_ACCESS_KEY_ID
  value: {{ .Values.rustberg.storage.s3.accessKeyId | quote }}
- name: AWS_SECRET_ACCESS_KEY
  value: {{ .Values.rustberg.storage.s3.secretAccessKey | quote }}
{{- end }}
{{- end }}
{{- if eq .Values.rustberg.storage.type "gcs" }}
{{- if .Values.rustberg.storage.gcs.existingSecret }}
- name: GOOGLE_APPLICATION_CREDENTIALS
  value: /gcp/credentials.json
{{- end }}
{{- end }}
{{- if eq .Values.rustberg.storage.type "azure" }}
{{- if .Values.rustberg.storage.azure.existingSecret }}
- name: AZURE_STORAGE_ACCOUNT_KEY
  valueFrom:
    secretKeyRef:
      name: {{ .Values.rustberg.storage.azure.existingSecret }}
      key: {{ .Values.rustberg.storage.azure.existingSecretKey }}
{{- else if .Values.rustberg.storage.azure.accountKey }}
- name: AZURE_STORAGE_ACCOUNT_KEY
  value: {{ .Values.rustberg.storage.azure.accountKey | quote }}
{{- end }}
{{- if .Values.rustberg.storage.azure.accountName }}
- name: AZURE_STORAGE_ACCOUNT_NAME
  value: {{ .Values.rustberg.storage.azure.accountName | quote }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Generate warehouse location based on storage type
*/}}
{{- define "rustberg.warehouseLocation" -}}
{{- if .Values.rustberg.warehouse.location }}
{{- .Values.rustberg.warehouse.location }}
{{- else if eq .Values.rustberg.storage.type "s3" }}
s3://{{ .Values.rustberg.storage.s3.bucket }}/warehouse
{{- else if eq .Values.rustberg.storage.type "gcs" }}
gs://{{ .Values.rustberg.storage.gcs.bucket }}/warehouse
{{- else if eq .Values.rustberg.storage.type "azure" }}
az://{{ .Values.rustberg.storage.azure.container }}/warehouse
{{- else }}
file:///data/warehouse
{{- end }}
{{- end }}
