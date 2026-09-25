#!/usr/bin/env bash
# e2e/helm_list_drill.sh -- a list edit reaching every gate POD on Kubernetes (#131, Helm half)
#
# ── WHY THIS EXISTS ──────────────────────────────────────────────────────────
#
# e2e/ha_drill.sh leg 9 measures a list edit reaching N gates that share a bind-mounted
# DIRECTORY: the compose shape, one host, 4.4-4.7s. On Kubernetes the list is a ConfigMap
# (deploy/helm/yellowjack/templates/gates.yaml) and `helm upgrade` is the edit; each
# NODE's kubelet projects the change into its pods on its own schedule, and only then
# does the gate's 5s lookup-triggered reload see it. So the window has a term the compose
# drill cannot have, it differs pod by pod, and the chart's comment ("reaches the running
# gate inside its 5-second reload") was a claim about the second term only.
#
# This drill runs it on a real cluster: kind with THREE worker nodes and one gate pod per
# node (podAntiAffinity), so the per-node kubelet timing is visible rather than collapsed
# onto one kubelet.
#
# ── WHAT IT PROVES AND DOES NOT ─────────────────────────────────────────────
#
# PROVES:
#   * After one `helm upgrade` that adds a deny-list entry and changes nothing else (no
#     rollout: the pod template hashes env, not lists), EVERY gate pod enforces it within
#     BOUND, measured per pod against the client pod's own clock, and the spread between
#     the first and last pod is reported -- that spread is the window in which two
#     replicas of one deployment answer the same request differently.
#   * A pod created AFTER the edit (one gate pod deleted; the Deployment replaces it)
#     comes up on the new list: a fresh mount, a fresh load.
#   * The documented trap is real and the instrument can see it: a pod that mounts the
#     SAME ConfigMap through `subPath` never receives the update (Kubernetes says so) and
#     never flips, and the drill reports it rather than averaging it away.
#   * Offline, like every leg of ha_drill.sh: the package is an unscorable one served by
#     an in-cluster nginx stand-in, so the pre-edit verdict is a policy 403 (unscorable)
#     and the post-edit one an operator-denied 403 with the deny-list rule on the wire.
#     The flip is in KIND and RULE, not status.
#
# DOES NOT prove:
#   * Anything about a managed cluster's kubelet settings. kind uses the defaults
#     (syncFrequency 1m, ConfigMap change detection by watch); a cluster with a longer
#     sync period has a longer window. The number here is a measurement of the mechanism
#     on defaults, and the report says which settings it ran on.
#   * Console-driven edits: this chart wires no CONSOLE_LIST_REPO, so there are none.
#
# NOT IN CI. kind inside docker:dind is a cluster inside a container inside a runner, and
# the #83 chart proof was run the same way, by hand on a laptop. Run it locally:
#     sh scripts/dev.sh helmdrill        (needs docker, kind, kubectl, helm)
# YJ_KEEP=1 keeps the cluster afterwards for a look.
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
FAIL=0
say()  { printf '\n=== %s ===\n' "$*"; }
pass() { printf 'PASS: %s\n' "$*"; }
bad()  { printf 'FAIL: %s\n' "$*"; FAIL=1; }

CLUSTER="${YJ_KIND_CLUSTER:-yj-listdrill}"
RELEASE="yj"
KIND="${KIND:-kind}"; HELM="${HELM:-helm}"; KUBECTL="${KUBECTL:-kubectl}"
# The bound is dominated by the kubelet: sync period 1m on defaults, plus the gate's 5s.
BOUND="${YJ_HELM_LIST_EDIT_BOUND:-120}"
IMAGE="yellowjack/firewall:dev"
# Pinned, the same image the compose drill uses for a container that HAS a shell and curl.
CLIENT_IMAGE='nginx:1.27-alpine@sha256:65645c7bb6a0661892a8b03b89d0743208a18dd2f3f17a54ef4b76fb8e2f2a10'
UNSC="yj-helm-unscorable"
WORK="$ROOT/.helmdrill"
# Git Bash rewrites arguments that look like Unix paths (see ha_drill.sh); kubectl exec
# arguments such as /proc/uptime are exactly that shape.
NOPATHCONV="env MSYS_NO_PATHCONV=1"

for tool in docker "$KIND" "$KUBECTL" "$HELM"; do
  command -v "$tool" >/dev/null 2>&1 || { echo "helm-list-drill: $tool is not installed; this drill cannot run without it and will not pretend to."; exit 2; }
done

cleanup() {
  if [ "${YJ_KEEP:-0}" = 1 ]; then echo "(YJ_KEEP=1: cluster $CLUSTER kept)"; return; fi
  "$KIND" delete cluster --name "$CLUSTER" >/dev/null 2>&1
  rm -rf "$WORK"
}
trap cleanup EXIT
"$KIND" delete cluster --name "$CLUSTER" >/dev/null 2>&1
rm -rf "$WORK"; mkdir -p "$WORK"

kexec() { # kexec POD CMD... -- run inside a pod, path conversion off
  $NOPATHCONV "$KUBECTL" exec "$@"
}
clock() { kexec yj-client -- cut -d' ' -f1 /proc/uptime 2>/dev/null | tr -d '\r'; }
# verdict_at IP -> "code|kind|rule|source", read from inside the client pod
verdict_at() {
  kexec yj-client -- sh -c "
    curl -s -o /dev/null -m 5 -D /tmp/h 'http://$1:8080/$UNSC' -w '%{http_code}' 2>/dev/null; printf '|'
    for h in Kind Rule Source; do grep -i \"^X-Yellowjack-\$h:\" /tmp/h | tr -d '\r' | cut -d' ' -f2- | tr -d '\n'; printf '|'; done
  " 2>/dev/null | tr -d '\r'
}

say "0) a three-worker kind cluster, and the gate image built from this tree"
cat > "$WORK/kind.yaml" <<'KIND'
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
  - role: control-plane
  - role: worker
  - role: worker
  - role: worker
KIND
if ! "$KIND" create cluster --name "$CLUSTER" --config "$WORK/kind.yaml" --wait 180s >"$WORK/kind-create.log" 2>&1; then
  bad "kind could not create the cluster:"; tail -5 "$WORK/kind-create.log"; exit 1
fi
docker build -q -t "$IMAGE" -f Dockerfile . >/dev/null 2>&1 || { bad "could not build $IMAGE"; exit 1; }
"$KIND" load docker-image "$IMAGE" --name "$CLUSTER" >/dev/null 2>&1 || { bad "could not load $IMAGE into kind"; exit 1; }
docker pull -q "$CLIENT_IMAGE" >/dev/null 2>&1
"$KIND" load docker-image "$CLIENT_IMAGE" --name "$CLUSTER" >/dev/null 2>&1
workers=$("$KUBECTL" get nodes --no-headers 2>/dev/null | grep -c -v control-plane)
[ "$workers" = 3 ] && pass "cluster up: 3 worker nodes, $IMAGE loaded" || { bad "expected 3 workers, got $workers"; exit 1; }

say "1) an in-cluster registry stand-in serving one UNSCORABLE package, and a client pod"
# The same stand-in ha_drill.sh leg 7 uses: nginx serving a packument with no repository,
# so the gate can score nothing and refuses on policy -- offline, and ours.
cat > "$WORK/upstream.yaml" <<YAML
apiVersion: v1
kind: ConfigMap
metadata: { name: yj-upstream-data }
data:
  index.json: '{"name":"$UNSC","dist-tags":{"latest":"1.0.0"},"versions":{"1.0.0":{"name":"$UNSC","version":"1.0.0"}}}'
  default.conf: |
    server {
        listen 80;
        root /srv;
        default_type application/json;
        location = /$UNSC { try_files /index.json =404; }
        location / { }
    }
---
apiVersion: v1
kind: Pod
metadata: { name: yj-upstream, labels: { app: yj-upstream } }
spec:
  containers:
    - name: nginx
      image: $CLIENT_IMAGE
      volumeMounts:
        - { name: data, mountPath: /srv/index.json, subPath: index.json }
        - { name: data, mountPath: /etc/nginx/conf.d/default.conf, subPath: default.conf }
  volumes:
    - name: data
      configMap: { name: yj-upstream-data }
---
apiVersion: v1
kind: Service
metadata: { name: yj-upstream }
spec:
  selector: { app: yj-upstream }
  ports: [ { port: 80, targetPort: 80 } ]
---
apiVersion: v1
kind: Pod
metadata: { name: yj-client }
spec:
  containers:
    - name: sh
      image: $CLIENT_IMAGE
      command: ["sleep", "3600"]
YAML
"$KUBECTL" apply -f "$WORK/upstream.yaml" >/dev/null 2>&1
"$KUBECTL" wait --for=condition=Ready pod/yj-upstream pod/yj-client --timeout=120s >/dev/null 2>&1 \
  || { bad "stand-in or client pod never became Ready"; "$KUBECTL" get pods; exit 1; }
# Ready is not routable: the fourth run of this drill got curl's 000 here in the instant
# after both pods went Ready, before kube-proxy had programmed the Service. Retried,
# bounded, and the wait is reported so a slow cluster is visible rather than flaky.
up=000; tries=0
while [ "$tries" -lt 40 ]; do
  up=$(kexec yj-client -- curl -s -o /dev/null -w '%{http_code}' -m 5 "http://yj-upstream/$UNSC" 2>/dev/null)
  [ "$up" = 200 ] && break
  tries=$((tries + 1)); sleep 0.5
done
[ "$up" = 200 ] && pass "stand-in serves /$UNSC (200) to the client pod (routable after $tries retries)" || { bad "stand-in answered $up for /$UNSC after $tries retries"; exit 1; }

say "2) helm install: one gate, 3 replicas, one per worker node, an EMPTY deny list"
values() { # values DENY-ENTRY -> a values file; the entry is the only difference between v1 and v2
  cat <<YAML
approval: { enabled: false }
postgres: { enabled: false }
console: { enabled: false }
networkPolicy: { enabled: false }
gates:
  - name: npm
    ecosystem: npm
    upstream: http://yj-upstream
    replicas: 3
    lists:
      deny: |
        # helm list drill: edited by helm upgrade
        $1
    env:
      FW_SCORECARD_MODE: stub
affinity:
  podAntiAffinity:
    requiredDuringSchedulingIgnoredDuringExecution:
      - labelSelector:
          matchLabels: { app.kubernetes.io/component: gate }
        topologyKey: kubernetes.io/hostname
YAML
}
values "" > "$WORK/v1.yaml"
values "$UNSC" > "$WORK/v2.yaml"
if ! "$HELM" install "$RELEASE" deploy/helm/yellowjack -f "$WORK/v1.yaml" --wait --timeout 180s >"$WORK/helm-install.log" 2>&1; then
  bad "helm install failed:"; tail -8 "$WORK/helm-install.log"; "$KUBECTL" get pods -o wide; exit 1
fi
CM=$("$KUBECTL" get configmap -l yellowjack.io/gate=npm -o jsonpath='{.items[0].metadata.name}' 2>/dev/null)
pods=$("$KUBECTL" get pods -l yellowjack.io/gate=npm -o jsonpath='{range .items[*]}{.metadata.name} {.status.podIP} {.spec.nodeName}{"\n"}{end}' 2>/dev/null)
n=$(printf '%s\n' "$pods" | grep -c .)
nodes=$(printf '%s\n' "$pods" | awk '{print $3}' | sort -u | wc -l | tr -d ' ')
if [ "$n" = 3 ] && [ "$nodes" = 3 ]; then
  pass "3 gate pods Ready on 3 distinct nodes (ConfigMap $CM):"; printf '%s\n' "$pods" | sed 's/^/      /'
else
  bad "want 3 pods on 3 nodes, got $n pods on $nodes nodes:"; printf '%s\n' "$pods"; exit 1
fi

say "3) the CONTROL: a pod mounting the SAME ConfigMap through subPath (the documented trap)"
# Kubernetes: "A container using a ConfigMap as a subPath volume mount will not receive
# ConfigMap updates." The chart mounts the directory, deliberately. This pod does what
# a reader tidying the chart would do, and must NEVER see the edit.
cat > "$WORK/control.yaml" <<YAML
apiVersion: v1
kind: Pod
metadata: { name: yj-ctrl-subpath, labels: { app: yj-ctrl-subpath } }
spec:
  containers:
    - name: gate
      image: $IMAGE
      imagePullPolicy: IfNotPresent
      env:
        - { name: FW_LISTEN_ADDR, value: ":8080" }
        - { name: FW_ECOSYSTEM, value: "npm" }
        - { name: FW_UPSTREAM, value: "http://yj-upstream" }
        - { name: FW_SCORECARD_MODE, value: "stub" }
        - { name: FW_DENY_LIST, value: "/lists/deny.txt" }
      volumeMounts:
        - { name: lists, mountPath: /lists/deny.txt, subPath: deny.txt, readOnly: true }
  volumes:
    - name: lists
      configMap: { name: $CM }
YAML
"$KUBECTL" apply -f "$WORK/control.yaml" >/dev/null 2>&1
"$KUBECTL" wait --for=condition=Ready pod/yj-ctrl-subpath --timeout=120s >/dev/null 2>&1 \
  || { bad "the subPath control pod never became Ready"; "$KUBECTL" logs yj-ctrl-subpath 2>&1 | tail -5; exit 1; }
CTRL_IP=$("$KUBECTL" get pod yj-ctrl-subpath -o jsonpath='{.status.podIP}')
pass "control pod Ready at $CTRL_IP (subPath mount of $CM)"

say "4) BASELINE: identical across pods, a 403 on policy, NOT the deny list"
targets="ctrl=$CTRL_IP"
while read -r name ip node; do targets="$targets $name=$ip"; done <<< "$pods"
# The three chart pods must answer IDENTICALLY (same image, same policy, same list). The
# control is held to less: a 403 that is not the deny list. Its Source carries the policy
# fingerprint, and its env is not the chart's (no approval URL), so its fingerprint
# differs -- the first run of this drill failed here on exactly that, comparing the
# control against the gates as though it were one of them.
base_ok=1; base0=""
for t in $targets; do
  v=$(verdict_at "${t#*=}")
  case "$v" in
    *operator-denied*) bad "${t%=*} refuses $UNSC by the DENY LIST before the edit"; base_ok=0 ;;
    403\|*) ;;
    *) bad "${t%=*} baseline is '$v' (want a 403 that is not operator-denied)"; base_ok=0 ;;
  esac
  case "$t" in ctrl=*) ctrl_base="$v"; continue ;; esac
  [ -n "$base0" ] || base0="$v"
  [ "$v" = "$base0" ] || { bad "${t%=*} baseline '$v' differs from the first gate pod's '$base0'"; base_ok=0; }
done
[ "$base_ok" = 1 ] && pass "baseline: 3 gate pods identical '$base0'; control '$ctrl_base'"

say "5) THE EDIT: helm upgrade adds one deny entry; every pod polled from the client pod"
# One TTL of quiet, then touch every pod so its last list check is fresh (the worst case
# for an edit is the lookup just before it; a touch only re-stamps the check when the
# previous one is older than the TTL -- ha_drill.sh leg 9 learned both the hard way).
sleep 6
kexec yj-client -- sh -c "for ip in $(for t in $targets; do printf '%s ' "${t#*=}"; done); do curl -s -o /dev/null -m 5 http://\$ip:8080/$UNSC; done" >/dev/null 2>&1
cat > "$WORK/poll.sh" <<'POLL'
#!/bin/sh
# poll.sh PKG BOUND NAME=IP... -- inside the client pod. Prints "NAME UPTIME" the first
# time a pod answers with the deny-list rule, "end UPTIME" when done: when every non-ctrl
# pod has flipped and 10s more have passed (the control must get its chance), or at BOUND.
pkg="$1"; bound="$2"; shift 2
start=$(cut -d' ' -f1 /proc/uptime); s0=${start%.*}
done_=" "; pending=0; last=0
for t in "$@"; do case "$t" in ctrl=*) ;; *) pending=$((pending+1));; esac; done
while :; do
  now=$(cut -d' ' -f1 /proc/uptime); el=$(( ${now%.*} - s0 ))
  for t in "$@"; do
    name=${t%%=*}; ip=${t#*=}
    case "$done_" in *" $name "*) continue;; esac
    rule=$(curl -s -o /dev/null -m 3 -D - "http://$ip:8080/$pkg" 2>/dev/null | grep -i '^X-Yellowjack-Rule:' | tr -d '\r' | cut -d' ' -f2-)
    if [ "$rule" = "deny-list:$pkg" ]; then
      echo "$name $now"; done_="$done_$name "; last=$el
      case "$name" in ctrl) ;; *) pending=$((pending-1));; esac
    fi
  done
  if [ "$pending" -eq 0 ] && [ $((el - last)) -ge 10 ]; then break; fi
  [ "$el" -ge "$bound" ] && break
  sleep 0.25
done
echo "end $(cut -d' ' -f1 /proc/uptime)"
POLL
t0=$(clock)
"$HELM" upgrade "$RELEASE" deploy/helm/yellowjack -f "$WORK/v2.yaml" >"$WORK/helm-upgrade.log" 2>&1 \
  || { bad "helm upgrade failed:"; tail -5 "$WORK/helm-upgrade.log"; exit 1; }
t_applied=$(clock)
# shellcheck disable=SC2086
flips=$($NOPATHCONV "$KUBECTL" exec -i yj-client -- sh -s -- "$UNSC" "$BOUND" $targets < "$WORK/poll.sh" 2>/dev/null | tr -d '\r')
rollout=$("$KUBECTL" get pods -l yellowjack.io/gate=npm -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}' | sort | tr '\n' ' ')
before=$(printf '%s\n' "$pods" | awk '{print $1}' | sort | tr '\n' ' ')
report=$(printf '%s\n' "$flips" | awk -v t0="$t0" -v ta="$t_applied" -v pods="$pods" '
  BEGIN { n = split(pods, L, "\n"); for (i = 1; i <= n; i++) { split(L[i], f, " "); if (f[1] != "") { name[f[1]] = 1; node[f[1]] = f[3]; order[++cnt] = f[1] } } }
  /^end/ { end = $2 - t0; next }
  /^ctrl / { ctrl = $2 - t0; next }
  { d[$1] = $2 - t0 }
  END {
    miss = ""; maxd = 0; mind = 1e9
    for (i = 1; i <= cnt; i++) { k = order[i]; if (!(k in d)) miss = miss (miss == "" ? "" : ",") k; else { if (d[k] > maxd) maxd = d[k]; if (d[k] < mind) mind = d[k] } }
    if (miss == "") miss = "none"
    printf "miss=%s max=%.2f spread=%.2f applied=%.2f end=%.2f ctrl=%s", miss, maxd, (mind < 1e9 ? maxd - mind : -1), ta - t0, end, (ctrl == "" ? "never" : sprintf("%.2f", ctrl))
    for (i = 1; i <= cnt; i++) { k = order[i]; if (k in d) printf " %s@%s=%.2f", k, node[k], d[k] }
  }')
for kv in $report; do case "$kv" in
  miss=*) miss="${kv#miss=}" ;; max=*) maxd="${kv#max=}" ;; spread=*) spread="${kv#spread=}" ;;
  applied=*) applied="${kv#applied=}" ;; end=*) endt="${kv#end=}" ;; ctrl=*) ctrl="${kv#ctrl=}" ;;
esac; done
times=$(printf '%s' "$report" | sed 's/^.*ctrl=[0-9.never]*//')
if [ "$rollout" != "$before" ]; then
  bad "helm upgrade ROLLED the gate pods (before: $before; after: $rollout) -- a list edit must not restart gates, or the window measured here is a rollout, not propagation"
fi
if [ "$miss" = "none" ] && awk "BEGIN{exit !($maxd <= $BOUND)}"; then
  pass "every gate pod enforced the edit within ${BOUND}s (helm upgrade applied in ${applied}s):${times}s"
  pass "pods on different nodes DISAGREED for ${spread}s -- the window in which one replica refuses and another still allows"
elif [ "$miss" = "none" ]; then
  bad "every pod flipped, but the slowest took ${maxd}s against a ${BOUND}s bound:${times}"
else
  bad "pod(s) $miss never enforced the edit in ${endt}s:${times}"
  for p in $(printf '%s' "$miss" | tr ',' ' '); do echo "--- $p log:"; "$KUBECTL" logs "$p" 2>&1 | tail -4; done
fi
if [ "$ctrl" = "never" ]; then
  pass "CONTROL: the subPath-mounted pod never saw the edit in ${endt}s -- the trap is real and the instrument can see a pod that misses an edit"
else
  bad "CONTROL flipped at ${ctrl}s: a subPath mount received a ConfigMap update, which Kubernetes documents as impossible -- the instrument is not measuring what it says"
fi

say "6) a pod created AFTER the edit comes up on the new list"
victim=$(printf '%s\n' "$pods" | awk 'NR==1{print $1}')
t1=$(clock)
"$KUBECTL" delete pod "$victim" --wait=false >/dev/null 2>&1
newpod=""
for _ in $(seq 1 60); do
  newpod=$("$KUBECTL" get pods -l yellowjack.io/gate=npm --field-selector=status.phase=Running -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}' 2>/dev/null | grep -v -F -x -f <(printf '%s\n' "$pods" | awk '{print $1}') | head -1)
  [ -n "$newpod" ] && "$KUBECTL" wait --for=condition=Ready "pod/$newpod" --timeout=1s >/dev/null 2>&1 && break
  sleep 1
done
if [ -z "$newpod" ]; then bad "no replacement pod became Ready within 60s"; else
  newip=$("$KUBECTL" get pod "$newpod" -o jsonpath='{.status.podIP}')
  v=$(verdict_at "$newip"); t2=$(clock)
  case "$v" in
    403\|operator-denied\|deny-list:$UNSC\|*) pass "replacement pod $newpod Ready and refusing by rule deny-list:$UNSC $(awk "BEGIN{printf \"%.1f\", $t2 - $t1}")s after the delete -- fresh mount, fresh load" ;;
    *) bad "replacement pod $newpod answers '$v' (want operator-denied by deny-list:$UNSC)" ;;
  esac
  # Captured, then a shell pattern: `logs | grep -q` under pipefail reads a present line as
  # absent when grep quits before the writer finishes (SIGPIPE) -- see ha_drill.sh leg 9.
  np_log=$("$KUBECTL" logs "$newpod" 2>&1)
  case "$np_log" in
    *"1 package(s) blocked outright"*) pass "its log shows a fresh load of 1 entry, not a reload" ;;
    *) bad "its log has no fresh-load line for 1 entry"; printf '%s
' "$np_log" | grep -i "deny-list" | tail -3 ;;
  esac
fi

say "7) no flip back, one TTL later"
sleep 6; stuck=0
for ip in $("$KUBECTL" get pods -l yellowjack.io/gate=npm -o jsonpath='{range .items[*]}{.status.podIP}{" "}{end}'); do
  v=$(verdict_at "$ip")
  case "$v" in 403\|operator-denied\|deny-list:$UNSC\|"operator deny list"\|*) ;; *) bad "$ip one TTL later: '$v'"; stuck=1 ;; esac
done
[ "$stuck" = 0 ] && pass "all gate pods still refuse by rule deny-list:$UNSC, source 'operator deny list'"

say "RESULT"
kv=$("$KUBECTL" version -o json 2>/dev/null | python -c "import sys,json; print(json.load(sys.stdin)['serverVersion']['gitVersion'])" 2>/dev/null || echo "?")
if [ "$FAIL" -eq 0 ]; then
  echo "ALL PASS: kind $("$KIND" version 2>/dev/null | awk '{print $2}') / kubernetes $kv, 3 workers, kubelet defaults;"
  echo "          a helm-upgrade list edit is enforced by every gate pod within ${BOUND}s (#131),"
  echo "          pods disagree for ${spread:-?}s, a subPath mount never sees it, a new pod starts on it."
else
  echo "FAILED"
fi
exit "$FAIL"
