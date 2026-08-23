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

{{/*
The DSN Secret the pod reads the catalog URL from.

Precedence: an operator-supplied Secret, then the bundled subchart's Secret,
then a Secret this chart renders from an inline DSN. A plaintext DSN in values
is fine for evaluation and wrong for production, which is why it is last.
*/}}
{{- define "rustberg.postgresSecretName" -}}
{{- if .Values.rustberg.catalog.postgres.existingSecret -}}
{{- .Values.rustberg.catalog.postgres.existingSecret -}}
{{- else -}}
{{- include "rustberg.fullname" . }}-catalog-dsn
{{- end -}}
{{- end -}}

{{- define "rustberg.postgresSecretKey" -}}
{{- if .Values.rustberg.catalog.postgres.existingSecret -}}
{{- .Values.rustberg.catalog.postgres.existingSecretKey -}}
{{- else -}}
dsn
{{- end -}}
{{- end -}}

{{/*
Fail early on configurations that cannot work, rather than letting the pod
crash-loop with an error only visible in its logs.
*/}}
{{- define "rustberg.validateCatalog" -}}
{{- $backend := .Values.rustberg.catalog.backend -}}
{{- if not (has $backend (list "postgres" "redb")) -}}
{{- fail (printf "rustberg.catalog.backend must be \"postgres\" or \"redb\", got %q" $backend) -}}
{{- end -}}
{{- if eq $backend "redb" -}}
{{- if gt (int .Values.replicaCount) 1 -}}
{{- fail "The redb catalog is a single file with an exclusive lock: a second replica cannot start. Set replicaCount to 1, or use rustberg.catalog.backend=postgres." -}}
{{- end -}}
{{- if not .Values.persistence.enabled -}}
{{- fail "The redb catalog needs persistence.enabled=true, or the catalog is lost on every pod restart." -}}
{{- end -}}
{{- if .Values.autoscaling.enabled -}}
{{- fail "Autoscaling adds replicas, which the redb catalog cannot support. Use rustberg.catalog.backend=postgres." -}}
{{- end -}}
{{- end -}}
{{- if eq $backend "postgres" -}}
{{- if and (not .Values.rustberg.catalog.postgres.existingSecret) (not .Values.rustberg.catalog.postgres.dsn) -}}
{{- fail "catalog.backend=postgres needs a database. Set rustberg.catalog.postgres.existingSecret to a Secret holding the DSN (recommended), or .dsn for evaluation. Use a managed Postgres or an operator such as CloudNativePG." -}}
{{- end -}}
{{- end -}}
{{- end -}}
