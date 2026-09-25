#!/bin/sh
# chart_check.sh — the Helm chart's own gate (#83, D210).
#
# WHAT IT ASSERTS, and why each half is here:
#
#   1. `helm lint` is clean.
#   2. The DEFAULT values render, and render the stack they claim: one gate, approval,
#      console, the bundled postgres, the generated secret, the network policy.
#   3. A PRODUCTION-SHAPED override renders the OTHER branches: two gates (npm + oci),
#      an external database via existingSecret, console auth via existingSecret, a
#      mirror registry prefix on EVERY image, the bundle and the policy off. The
#      two-gate render is load-bearing on its own: a single-gate render never showed
#      the `{{- end }}` that glued the second gate's `---` onto the first Service.
#   4. Five half-configured inputs are REFUSED at render time, each with the message
#      an operator can act on. A chart that installs a stack with no gate, or approval
#      with no database, and lets the operator find out from a crash loop is the shape
#      this repository refuses everywhere else (#58: fail closed and say so).
#
# helm is NOT on the dev host by default, and this check must not degrade into a
# silent pass when it is missing -- the exact failure scripts/pinned-images.sh
# documents for a file walk that finds no files. Missing helm is a FAILURE here,
# with the install line; `dev.sh chart` is the entry point, deliberately separate
# from `dev.sh vet` so the vet gate stays runnable on a host with no helm.
#
# Run:  sh scripts/chart_check.sh        (or: sh scripts/dev.sh chart)
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CHART="$ROOT/deploy/helm/yellowjack"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
PASS=0; FAIL=0
ok()  { PASS=$((PASS + 1)); printf 'ok   %s\n' "$*"; }
bad() { FAIL=$((FAIL + 1)); printf 'FAIL %s\n' "$*"; }

HELM="${HELM:-helm}"
if ! command -v "$HELM" >/dev/null 2>&1; then
  printf 'chart-check: helm is not installed (looked for %s).\n' "$HELM" >&2
  printf '    This check cannot run without it, and it will not pretend to. Install helm 3\n' >&2
  printf '    (https://helm.sh/docs/intro/install/) or set HELM=/path/to/helm.\n' >&2
  exit 2
fi

render() { # render OUTFILE [helm template args...]
  out="$1"; shift
  "$HELM" template yj "$CHART" "$@" > "$out" 2> "$out.err"
}
kinds() { grep -E '^kind:' "$1" | sort | uniq -c | sed 's/^ *//' | tr '\n' ';'; }
count_kind() { grep -cE "^kind: $2\$" "$1"; }

# ── 1. lint ──────────────────────────────────────────────────────────────────
if "$HELM" lint "$CHART" > "$TMP/lint" 2>&1; then ok "helm lint is clean"; else bad "helm lint: $(tail -3 "$TMP/lint")"; fi

# ── 2. the default render is the evaluation stack it claims to be ────────────
if render "$TMP/default.yaml"; then
  d="$TMP/default.yaml"
  [ "$(count_kind "$d" Deployment)" = 3 ]  && ok "default: 3 Deployments (one gate, approval, console)" || bad "default: Deployments = $(count_kind "$d" Deployment), want 3 [$(kinds "$d")]"
  [ "$(count_kind "$d" StatefulSet)" = 1 ] && ok "default: the bundled postgres StatefulSet" || bad "default: no bundled postgres"
  [ "$(count_kind "$d" Secret)" = 1 ]      && ok "default: one generated postgres Secret" || bad "default: Secrets = $(count_kind "$d" Secret), want 1"
  [ "$(count_kind "$d" NetworkPolicy)" = 1 ] && ok "default: approval fenced by a NetworkPolicy" || bad "default: no NetworkPolicy"
  grep -q 'postgres://postgres:\$(POSTGRES_PASSWORD)@' "$d" && ok "default: the DSN is assembled from the Secret via \$(VAR), the credential lives in one place" || bad "default: DSN is not built from the Secret"
  grep -q 'readOnlyRootFilesystem: true' "$d" && grep -q 'runAsNonRoot: true' "$d" && ok "default: read-only rootfs, non-root" || bad "default: hardening context missing"
  grep -qE 'image: "postgres:17@sha256:[0-9a-f]{64}"' "$d" && ok "default: the external image is pinned by digest" || bad "default: postgres image not digest-pinned in the render"
  # D165: readiness is NOT liveness. The gate's readiness probe must be /readyz (503 while
  # the policy in force is not the file on the mount) and its liveness /healthz (local
  # process health only, D163). Counted per gate so a second gate cannot fall back to
  # /healthz unnoticed; the override below renders two.
  [ "$(grep -A2 'readinessProbe:' "$d" | grep -c 'path: /readyz')" = 1 ] && grep -A2 'livenessProbe:' "$d" | grep -q 'path: /healthz' && ok "default: the gate's readiness probe is /readyz and its liveness /healthz (D165)" || bad "default: gate probes are not /readyz (readiness) + /healthz (liveness): $(grep -A2 -E '(readiness|liveness)Probe:' "$d" | grep 'path:' | sort | uniq -c | tr -s ' ' | tr '\n' ';')"
else
  bad "default values do not render: $(tail -3 "$TMP/default.yaml.err")"
fi

# ── 3. the production-shaped override exercises the other branches ───────────
cat > "$TMP/prod.yaml" <<'YAML'
global: { imageRegistry: registry.internal:5000/mirror }
images:
  firewall: { repository: yellowjack/firewall, tag: "1.0.0", digest: "sha256:1111111111111111111111111111111111111111111111111111111111111111" }
gates:
  - { name: npm, ecosystem: npm, upstream: http://nexus.internal/repository/npm, publicURL: https://npm.example.com, replicas: 3, lists: { allow: "", deny: "left-pad\n" }, env: { FW_SCORECARD_MODE: stub }, service: { port: 8080 } }
  - { name: oci, ecosystem: oci, upstream: http://harbor.internal, replicas: 2, lists: { allow: "", deny: "library/busybox\n" }, env: { FW_SCORECARD_MODE: stub }, service: { port: 8080 } }
postgres: { enabled: false }
approval: { database: { existingSecret: my-db-secret } }
console: { auth: { existingSecret: my-console-secret } }
networkPolicy: { enabled: false }
YAML
if render "$TMP/prod.yaml.out" -f "$TMP/prod.yaml"; then
  p="$TMP/prod.yaml.out"
  [ "$(count_kind "$p" Deployment)" = 4 ]   && ok "override: 4 Deployments (npm gate, oci gate, approval, console)" || bad "override: Deployments = $(count_kind "$p" Deployment), want 4"
  [ "$(count_kind "$p" StatefulSet)" = 0 ]  && ok "override: no bundled postgres when an external database is given" || bad "override: bundled postgres rendered alongside an external database"
  [ "$(count_kind "$p" NetworkPolicy)" = 0 ] && ok "override: network policy off when disabled" || bad "override: NetworkPolicy rendered while disabled"
  unprefixed=$(grep -E '^\s+image: ' "$p" | grep -vc 'image: "registry.internal:5000/mirror/')
  [ "$unprefixed" = 0 ] && ok "override: every image carries the mirror prefix (zero-egress: no hardcoded public path)" || bad "override: $unprefixed image(s) escaped the mirror prefix: $(grep -E '^\s+image: ' "$p" | grep -v 'registry.internal' | sed 's/^ *//' | tr '\n' ' ')"
  grep -q 'yellowjack/firewall:1.0.0@sha256:1111' "$p" && ok "override: tag AND digest both rendered, so a reviewer can see which version a digest moved from" || bad "override: tag@digest form not rendered"
  grep -q 'value: "oci"' "$p" && ok "override: the second gate speaks oci" || bad "override: no oci gate rendered"
  [ "$(grep -A2 'readinessProbe:' "$p" | grep -c 'path: /readyz')" = 2 ] && ok "override: BOTH gates probe readiness on /readyz (D165)" || bad "override: /readyz readiness probes = $(grep -A2 'readinessProbe:' "$p" | grep -c 'path: /readyz'), want 2 (one per gate)"
  grep -q 'name: my-db-secret' "$p" && grep -q 'name: my-console-secret' "$p" && ok "override: existing secrets referenced, not copied" || bad "override: existingSecret references missing"
else
  bad "the production override does not render: $(tail -3 "$TMP/prod.yaml.out.err")"
fi

# ── 3b. a MINIMAL gate renders: name, ecosystem, upstream and nothing else ─────
# service, lists, env, replicas and resources are all optional. The first values file
# e2e/helm_list_drill.sh wrote omitted `service`, and the chart died on a nil pointer
# with no hint which key was missing -- a render error is the operator's first contact
# with the chart, so it must be a sentence or a success, never a stack trace.
printf 'gates:
  - name: m
    ecosystem: npm
    upstream: http://u
approval: { enabled: false }
postgres: { enabled: false }
console: { enabled: false }
' > "$TMP/min.yaml"
if render "$TMP/min.yaml.out" -f "$TMP/min.yaml"; then
  m="$TMP/min.yaml.out"
  [ "$(count_kind "$m" Deployment)" = 1 ] && [ "$(count_kind "$m" Service)" = 1 ] && [ "$(count_kind "$m" ConfigMap)" = 1 ]     && ok "minimal gate: renders one Deployment, one Service, one ConfigMap with no optional block set"     || bad "minimal gate: rendered [$(kinds "$m")], want 1 Deployment + 1 Service + 1 ConfigMap"
  grep -qE '^\s+port: 8080$' "$m" && grep -qE '^\s+type: ClusterIP$' "$m" && ok "minimal gate: service defaults to ClusterIP on 8080" || bad "minimal gate: service defaults missing"
else
  bad "a minimal gate (no service/lists block) does not render: $(grep -o 'Error: .*' "$TMP/min.yaml.out.err" | cut -c1-160)"
fi

# ── 4. half-configured inputs are refused, each with an actionable message ───
refuse() { # refuse LABEL VALUES-FILE MESSAGE-FRAGMENT
  if render "$TMP/neg.out" -f "$2"; then
    bad "$1 RENDERED -- the validation is not firing"
  elif grep -q "$3" "$TMP/neg.out.err"; then
    ok "$1 is refused, and the message says what to do"
  else
    bad "$1 is refused with the WRONG message: $(grep -o 'Error: .*' "$TMP/neg.out.err" | cut -c1-120)"
  fi
}
printf 'gates: []\n' > "$TMP/n1.yaml";                                          refuse "no gates" "$TMP/n1.yaml" "gates is empty"
printf 'gates:\n  - name: x\n    ecosystem: cargo\n    upstream: http://u\n' > "$TMP/n2.yaml"; refuse "an unknown ecosystem" "$TMP/n2.yaml" 'ecosystem "cargo" is not one of'
printf 'gates:\n  - name: x\n    ecosystem: npm\n    upstream: ""\n' > "$TMP/n3.yaml";   refuse "a gate with no upstream" "$TMP/n3.yaml" "upstream is required"
printf 'gates:\n  - ecosystem: npm\n    upstream: http://u\n' > "$TMP/n4.yaml";           refuse "a gate with no name" "$TMP/n4.yaml" "gates\[\].name is required"
printf 'approval: { enabled: true }\npostgres: { enabled: false }\n' > "$TMP/n5.yaml";   refuse "approval with no database" "$TMP/n5.yaml" "there is no database"

# ── anti-vacuity: the refusal helper must be able to see a render SUCCEED ────
# Every refuse() above passes when helm exits non-zero. A helm that failed for an
# unrelated reason (bad chart path, broken install) would make all five "pass".
if render "$TMP/ctl.out"; then ok "control: the same helm renders the default chart, so the refusals above are the chart's, not helm's" ; else bad "control: helm cannot render the default chart, so the five refusals above prove nothing"; fi

printf '\n%s passed, %s failed\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
