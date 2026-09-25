{{/*
Chart name and release-scoped full name, the standard way.
*/}}
{{- define "yellowjack.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "yellowjack.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- $name := default .Chart.Name .Values.nameOverride -}}
{{- if contains $name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{/*
Common labels. app.kubernetes.io/component is added per resource.
*/}}
{{- define "yellowjack.labels" -}}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
app.kubernetes.io/name: {{ include "yellowjack.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{- define "yellowjack.selectorLabels" -}}
app.kubernetes.io/name: {{ include "yellowjack.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{/*
Image reference: [registry/]repository[:tag][@digest].

Takes a dict with .global and .image. The registry PREFIX is the zero-egress hook: an
air-gapped cluster mirrors every image once and sets global.imageRegistry, and nothing in
any template hardcodes a public path around it. Tag and digest are both emitted when both
are set, so a reviewer can see which version a digest moved from (the same rule
scripts/pinned-images.sh enforces on compose files).
*/}}
{{- define "yellowjack.image" -}}
{{- $reg := .global.imageRegistry -}}
{{- $i := .image -}}
{{- $ref := $i.repository -}}
{{- if $reg -}}{{- $ref = printf "%s/%s" (trimSuffix "/" $reg) $i.repository -}}{{- end -}}
{{- if $i.tag -}}{{- $ref = printf "%s:%s" $ref ($i.tag | toString) -}}{{- end -}}
{{- if $i.digest -}}{{- $ref = printf "%s@%s" $ref $i.digest -}}{{- end -}}
{{- $ref -}}
{{- end -}}

{{/*
Resource names for the services other templates need to address.
*/}}
{{- define "yellowjack.approval.name" -}}
{{- printf "%s-approval" (include "yellowjack.fullname" .) -}}
{{- end -}}

{{- define "yellowjack.postgres.name" -}}
{{- printf "%s-postgres" (include "yellowjack.fullname" .) -}}
{{- end -}}

{{- define "yellowjack.console.name" -}}
{{- printf "%s-console" (include "yellowjack.fullname" .) -}}
{{- end -}}

{{- define "yellowjack.gate.name" -}}
{{- printf "%s-gate-%s" (include "yellowjack.fullname" .root) .gate.name -}}
{{- end -}}

{{/*
The approval service URL as seen from inside the cluster, or "" when approval is off.
Gates and the console both read it, so it is defined once.
*/}}
{{- define "yellowjack.approval.url" -}}
{{- if .Values.approval.enabled -}}
{{- printf "http://%s:%d" (include "yellowjack.approval.name" .) (int .Values.approval.service.port) -}}
{{- end -}}
{{- end -}}

{{/*
Whether the bundled postgres is actually in use: enabled AND no external database given.
An external DSN or secret wins over the bundle, so a production values file that sets
approval.database.url cannot accidentally also run the evaluation database.
*/}}
{{- define "yellowjack.postgres.inUse" -}}
{{- if and .Values.postgres.enabled (not .Values.approval.database.url) (not .Values.approval.database.existingSecret) -}}true{{- end -}}
{{- end -}}

{{/*
Validation that fails the render rather than the deployment. A chart that installs a
half-configured stack and lets the operator discover it from a crash loop is the shape
this whole repository refuses (#58's "fail closed and say so").
*/}}
{{- define "yellowjack.validate" -}}
{{- if and .Values.approval.enabled (not (include "yellowjack.postgres.inUse" .)) (not .Values.approval.database.url) (not .Values.approval.database.existingSecret) -}}
{{- fail "approval.enabled is true but there is no database: set approval.database.url or approval.database.existingSecret, or enable the bundled postgres" -}}
{{- end -}}
{{- if not .Values.gates -}}
{{- fail "gates is empty: a Yellow Jack install with no gate is a console and an approval queue with nothing to decide. Define at least one gate (see values.yaml)" -}}
{{- end -}}
{{- range .Values.gates -}}
{{- $g := default "<unnamed>" .name -}}
{{- if not .name -}}
{{- fail "a gate has no name: gates[].name is required (it becomes the Deployment and Service name)" -}}
{{- end -}}
{{- if not (has (default "" .ecosystem) (list "npm" "pypi" "maven" "oci")) -}}
{{- fail (printf "gate %q: ecosystem %q is not one of npm, pypi, maven, oci" $g (default "" .ecosystem)) -}}
{{- end -}}
{{- if not .upstream -}}
{{- fail (printf "gate %q: upstream is required -- the address of YOUR registry" $g) -}}
{{- end -}}
{{- end -}}
{{- end -}}
