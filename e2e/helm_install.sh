#!/usr/bin/env bash
# e2e/helm_install.sh -- the Helm chart INSTALLED on a real cluster, not just rendered (#163, D348, D358)
#
# ── WHY THIS EXISTS ──────────────────────────────────────────────────────────
#
# D348 sets the bar at "stable, battle tested, and fits into the rest of my ecosystem" --
# which is Kubernetes. CI's `chart` job lints and renders the chart and refuses half-set
# values, but a chart that renders can still fail to install: the first real `helm install`
# found approval restarting five times because it started before postgres resolved. This is
# the install, run nightly beside the real-client e2e (D336), from the tree.
#
# ── WHAT IT PROVES ──────────────────────────────────────────────────────────
#
#   1. `helm install --wait` of the chart with its DEFAULTS (approval, postgres, console,
#      2 gate replicas, the disruption budget, network policy) succeeds, and NO pod restarts.
#      Install time and restarts are reported: a green install with restarting pods is not
#      "battle tested". Two values differ from the defaults, both forced by running offline
#      and deterministically: the gate's upstream is an in-cluster stand-in, and its deny
#      list has one entry.
#   2. From a client pod, through the gate's Service: an unlisted package is SERVED (200),
#      and the deny-listed one is REFUSED with `X-Yellowjack-Rule: deny-list:<name>` -- the
#      rule on the wire, not merely a 403.
#   3. HA (D358): the two gate replicas land on different nodes (soft spread, so reported as
#      expected rather than guaranteed), and draining the node that holds one of them while a
#      client pulls in a loop drops NO request.
#
# ── ITS CONTROLS: A LEG THAT CANNOT GO RED PROVES NOTHING ────────────────────
#
#   * Drain control: the SAME drain with the disruption budget OFF and both replicas pinned
#     to the drained node MUST drop requests. Otherwise the leg cannot tell the budget from
#     luck.
#   * Refusal control: the same release with the deny entry REMOVED must fail the refusal
#     assertion (the package is then served). Otherwise the assertion could pass on anything.
#
# ── WHERE IT RUNS ───────────────────────────────────────────────────────────
#
# CI: the e2e-helm-install job (docker:27-cli + the docker:27-dind service). kind's nodes then
# live in the dind daemon, so the API server is reached at the service host, not localhost:
# set YJ_KIND_API_HOST=docker and the cluster is created with that name in its certificate
# and in the kubeconfig. Locally, run it in the same image against your Docker:
#
#   docker run --rm -v //var/run/docker.sock:/var/run/docker.sock -v "$PWD":/src -w /src \
#     -e YJ_KIND_API_HOST=host.docker.internal docker:27-cli \
#     sh -c 'apk add --no-cache bash curl git >/dev/null && sh e2e/kind_tools.sh && bash e2e/helm_install.sh'
#
# Tools (e2e/kind_tools.sh installs pinned, checksum-verified copies): docker, kind, kubectl, helm.

set -u -o pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

CLUSTER="${YJ_KIND_CLUSTER:-yj-helminstall}"
RELEASE="yj"
KIND="${KIND:-kind}"; HELM="${HELM:-helm}"; KUBECTL="${KUBECTL:-kubectl}"
API_HOST="${YJ_KIND_API_HOST:-}"
API_PORT="${YJ_KIND_API_PORT:-16443}"
NODE_IMAGE='kindest/node:v1.34.0@sha256:7416a61b42b1662ca6ca89f02028ac133a309a2a30ba309614e8ec94d976dc5a'
# The same pinned image the list drill uses for a container that has a shell and curl.
CLIENT_IMAGE='nginx:1.27-alpine@sha256:65645c7bb6a0661892a8b03b89d0743208a18dd2f3f17a54ef4b76fb8e2f2a10'
LOCAL_NGINX='yj-e2e-nginx:1.27'
SERVED="yj-served"; DENIED="yj-denied"
WORK="$ROOT/.helminstall"
NOPATHCONV="env MSYS_NO_PATHCONV=1"
FAIL=0
T0=$(date +%s)

say()  { printf '\n=== %s ===\n' "$*"; }
pass() { printf 'PASS: %s\n' "$*"; }
bad()  { printf 'FAIL: %s\n' "$*"; FAIL=1; }

for tool in docker "$KIND" "$KUBECTL" "$HELM"; do
  command -v "$tool" >/dev/null 2>&1 || { echo "helm-install: $tool is not installed; run e2e/kind_tools.sh first."; exit 2; }
done
mkdir -p "$WORK"

cleanup() {
  if [ "${YJ_KEEP:-0}" = 1 ]; then echo "(YJ_KEEP=1: cluster $CLUSTER kept)"; return; fi
  "$KIND" delete cluster --name "$CLUSTER" >/dev/null 2>&1
}
trap cleanup EXIT

kexec() { $NOPATHCONV "$KUBECTL" exec "$@"; }

# pull PKG -> "code|rule" as the client pod sees it through the gate Service
pull() {
  kexec yj-client -- sh -c "
    code=\$(curl -s -o /dev/null -m 12 -D /tmp/h 'http://$SVC:8080/$1' -w '%{http_code}' 2>/dev/null)
    printf '%s|' \"\$code\"; grep -i '^X-Yellowjack-Rule:' /tmp/h 2>/dev/null | tr -d '\r' | cut -d' ' -f2- | tr -d '\n'
  " 2>/dev/null | tr -d '\r'
}

gate_pods() { "$KUBECTL" get pods -l yellowjack.io/gate=npm --field-selector=status.phase=Running \
  -o jsonpath='{range .items[*]}{.metadata.name} {.spec.nodeName}{"\n"}{end}' 2>/dev/null; }

ready_gates() { "$KUBECTL" get deploy -l yellowjack.io/gate=npm -o jsonpath='{.items[0].status.readyReplicas}' 2>/dev/null; }

wait_ready_gates() { # wait_ready_gates N SECONDS
  local i=0
  while [ "$i" -lt "$2" ]; do [ "$(ready_gates)" = "$1" ] && return 0; sleep 2; i=$((i + 2)); done
  return 1
}

# drain_under_load NODE -> the number of pulls that were NOT served while NODE was drained
drain_under_load() {
  # nohup: the loop must outlive the exec session that starts it.
  kexec yj-client -- sh -c "rm -f /tmp/stop /tmp/loop.log; nohup sh -c 'while [ ! -f /tmp/stop ]; do
      curl -s -o /dev/null -m 12 -w \"%{http_code}\n\" http://$SVC:8080/$SERVED >> /tmp/loop.log 2>/dev/null; sleep 0.2
    done' >/dev/null 2>&1 &" >/dev/null 2>&1
  sleep 3
  $NOPATHCONV "$KUBECTL" drain "$1" --ignore-daemonsets --delete-emptydir-data --timeout=240s >"$WORK/drain.log" 2>&1
  local drained=$?
  sleep 8   # let replacements start answering, so the tail of the window is counted too
  kexec yj-client -- sh -c 'touch /tmp/stop' >/dev/null 2>&1
  sleep 1
  local total fails
  total=$(kexec yj-client -- sh -c 'wc -l < /tmp/loop.log' 2>/dev/null | tr -d ' \r')
  fails=$(kexec yj-client -- sh -c 'grep -vc "^200$" /tmp/loop.log' 2>/dev/null | tr -d ' \r')
  echo "drain=$drained total=${total:-0} fails=${fails:-0}"
}

# ────────────────────────────────────────────────────────────────────────────
say "0) a kind cluster (control plane + 3 workers) and the three images built from this tree"
{
  echo "kind: Cluster"
  echo "apiVersion: kind.x-k8s.io/v1alpha4"
  if [ -n "$API_HOST" ]; then
    # The API server is published on the Docker host, which the job reaches by name.
    echo "networking: { apiServerAddress: \"0.0.0.0\", apiServerPort: $API_PORT }"
    echo "kubeadmConfigPatches:"
    echo "  - |"
    echo "    kind: ClusterConfiguration"
    echo "    apiServer:"
    echo "      certSANs: [\"$API_HOST\", \"localhost\", \"127.0.0.1\"]"
  fi
  echo "nodes:"
  echo "  - role: control-plane"
  echo "  - role: worker"
  echo "  - role: worker"
  echo "  - role: worker"
} > "$WORK/kind.yaml"
"$KIND" delete cluster --name "$CLUSTER" >/dev/null 2>&1
if ! "$KIND" create cluster --name "$CLUSTER" --image "$NODE_IMAGE" --config "$WORK/kind.yaml" --wait 240s >"$WORK/kind-create.log" 2>&1; then
  bad "kind could not create the cluster:"; tail -8 "$WORK/kind-create.log"; exit 1
fi
if [ -n "$API_HOST" ]; then
  "$KIND" get kubeconfig --name "$CLUSTER" | sed -E "s#(server: https://)[^:/]+:#\1$API_HOST:#" > "$WORK/kubeconfig"
  export KUBECONFIG="$WORK/kubeconfig"
fi
"$KUBECTL" get nodes >/dev/null 2>&1 || { bad "kubectl cannot reach the cluster (API host '${API_HOST:-default}')"; exit 1; }

for spec in "yellowjack/firewall:dev Dockerfile" "yellowjack/approval:dev approval/Dockerfile" "yellowjack/console:dev console/Dockerfile"; do
  set -- $spec
  docker build -q -t "$1" -f "$2" . >"$WORK/build.log" 2>&1 || { bad "could not build $1:"; tail -8 "$WORK/build.log"; exit 1; }
  "$KIND" load docker-image "$1" --name "$CLUSTER" >/dev/null 2>&1 || { bad "could not load $1 into kind"; exit 1; }
done
# Loaded under a plain local TAG, like the three images above, and never pulled: the first
# CI run loaded it by digest reference and both pods failed with CreateContainerError inside
# dind, while the same load worked on Docker Desktop.
docker pull -q "$CLIENT_IMAGE" >/dev/null 2>&1 && docker tag "$CLIENT_IMAGE" "$LOCAL_NGINX"   || { bad "could not pull $CLIENT_IMAGE"; exit 1; }
"$KIND" load docker-image "$LOCAL_NGINX" --name "$CLUSTER" >/dev/null 2>&1 || { bad "could not load $LOCAL_NGINX into kind"; exit 1; }
pass "cluster up ($("$KUBECTL" get nodes --no-headers | grep -vc control-plane) workers), three images built and loaded ($(( $(date +%s) - T0 ))s so far)"

say "1) an in-cluster registry stand-in (two packages, published 2020) and a client pod"
# Offline and deterministic. Published long ago so the default 14-day cooldown serves them.
pkt() { printf '{"name":"%s","dist-tags":{"latest":"1.0.0"},"versions":{"1.0.0":{"name":"%s","version":"1.0.0"}},"time":{"created":"2020-01-01T00:00:00.000Z","modified":"2020-01-01T00:00:00.000Z","1.0.0":"2020-01-01T00:00:00.000Z"}}' "$1" "$1"; }
cat > "$WORK/upstream.yaml" <<YAML
apiVersion: v1
kind: ConfigMap
metadata: { name: yj-upstream-data }
data:
  served.json: '$(pkt "$SERVED")'
  denied.json: '$(pkt "$DENIED")'
  default.conf: |
    server {
        listen 80;
        root /srv;
        default_type application/json;
        location = /$SERVED { try_files /served.json =404; }
        location = /$DENIED { try_files /denied.json =404; }
        location / { }
    }
---
apiVersion: v1
kind: Pod
metadata: { name: yj-upstream, labels: { app: yj-upstream } }
spec:
  # On the control plane, which is never drained: a drain must not take the instrument
  # down with the thing it measures.
  nodeSelector: { node-role.kubernetes.io/control-plane: "" }
  tolerations: [ { key: node-role.kubernetes.io/control-plane, operator: Exists, effect: NoSchedule } ]
  containers:
    - name: nginx
      image: $LOCAL_NGINX
      imagePullPolicy: Never
      volumeMounts:
        - { name: data, mountPath: /srv }
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
  nodeSelector: { node-role.kubernetes.io/control-plane: "" }
  tolerations: [ { key: node-role.kubernetes.io/control-plane, operator: Exists, effect: NoSchedule } ]
  containers:
    - name: sh
      image: $LOCAL_NGINX
      imagePullPolicy: Never
      command: ["sleep", "7200"]
YAML
"$KUBECTL" apply -f "$WORK/upstream.yaml" >/dev/null 2>&1
"$KUBECTL" wait --for=condition=Ready pod/yj-upstream pod/yj-client --timeout=180s >/dev/null 2>&1 \
  || { bad "stand-in or client pod never became Ready"; "$KUBECTL" get pods -o wide
       for p in yj-upstream yj-client; do "$KUBECTL" describe pod "$p" | sed -n '/^Events:/,$p' | tail -8; done; exit 1; }
pass "stand-in and client pod Ready"

say "2) helm install --wait: the chart's defaults, plus the offline upstream and one deny entry"
values() { # values DENY-ENTRY [extra yaml]
  cat <<YAML
gates:
  - name: npm
    ecosystem: npm
    upstream: http://yj-upstream
    replicas: 2
    lists:
      allow: |
      deny: |
        $1
$2
YAML
}
values "$DENIED" "" > "$WORK/v-default.yaml"
t1=$(date +%s)
if ! "$HELM" install "$RELEASE" deploy/helm/yellowjack -f "$WORK/v-default.yaml" --wait --timeout 420s >"$WORK/helm-install.log" 2>&1; then
  bad "helm install failed:"; tail -10 "$WORK/helm-install.log"; "$KUBECTL" get pods -o wide; exit 1
fi
INSTALL_S=$(( $(date +%s) - t1 ))
restarts=$("$KUBECTL" get pods -l app.kubernetes.io/instance="$RELEASE" -o jsonpath='{range .items[*]}{range .status.containerStatuses[*]}{.restartCount}{"\n"}{end}{end}' | awk '{s+=$1} END {print s+0}')
"$KUBECTL" get pods -l app.kubernetes.io/instance="$RELEASE" -o wide --no-headers | sed 's/^/      /'
if [ "$restarts" = 0 ]; then pass "helm install --wait succeeded in ${INSTALL_S}s with 0 pod restarts"
else bad "helm install succeeded in ${INSTALL_S}s but pods restarted $restarts time(s): not battle tested"; fi
SVC=$("$KUBECTL" get svc -l yellowjack.io/gate=npm -o jsonpath='{.items[0].metadata.name}' 2>/dev/null)
[ -n "$SVC" ] || { bad "no Service found for the npm gate"; exit 1; }

say "3) through the gate Service ($SVC): served and refused, with the rule on the wire"
got=""; for _ in $(seq 1 30); do got=$(pull "$SERVED"); [ "${got%%|*}" = 200 ] && break; sleep 2; done
[ "${got%%|*}" = 200 ] && pass "$SERVED served: 200" || bad "$SERVED: got '$got', want 200"
got=$(pull "$DENIED")
case "$got" in
  "403|deny-list:$DENIED") pass "$DENIED refused: 403, X-Yellowjack-Rule: deny-list:$DENIED" ;;
  *) bad "$DENIED: got '$got', want '403|deny-list:$DENIED'" ;;
esac

say "4) HA (D358): spread, then a drain under load with the disruption budget ON"
placement=$(gate_pods); printf '%s\n' "$placement" | sed 's/^/      /'
nodes=$(printf '%s\n' "$placement" | awk 'NF{print $2}' | sort -u | grep -c .)
[ "$nodes" = 2 ] && pass "the 2 gate replicas are on 2 different nodes (soft spread)" \
  || echo "NOTE: the 2 gate replicas share a node ($nodes distinct); the spread is soft (ScheduleAnyway), so this is reported, not failed"
# Drain a gate node that does NOT hold approval or postgres, when one exists, so a request
# failure is the GATE's availability and not the control plane's.
held=$("$KUBECTL" get pods -l app.kubernetes.io/instance="$RELEASE" -o jsonpath='{range .items[*]}{.metadata.labels.app\.kubernetes\.io/component} {.spec.nodeName}{"\n"}{end}' | awk '$1=="approval"||$1=="postgres"{print $2}' | sort -u)
target=""
for n in $(printf '%s\n' "$placement" | awk 'NF{print $2}' | sort -u); do
  printf '%s\n' "$held" | grep -qx "$n" || { target=$n; break; }
done
[ -n "$target" ] || target=$(printf '%s\n' "$placement" | awk 'NF{print $2; exit}')
res=$(drain_under_load "$target"); echo "      drain $target: $res"
case "$res" in
  drain=0\ *fails=0) wait_ready_gates 2 120 && pass "drained $target under load: 0 requests dropped, 2 gate replicas Ready again" \
                       || bad "drained $target with 0 dropped, but 2 gate replicas never came back Ready" ;;
  drain=0\ *) bad "drained $target with the disruption budget ON and requests were dropped: $res" ;;
  *) bad "kubectl drain $target failed:"; tail -5 "$WORK/drain.log" ;;
esac
"$KUBECTL" uncordon "$target" >/dev/null 2>&1

say "5) the drain CONTROL: budget OFF, both replicas pinned to one node, drain that node"
pin=$(printf '%s\n' "$(gate_pods)" | awk 'NF{print $2; exit}')
values "$DENIED" "gateAvailability: { podDisruptionBudget: false }
nodeSelector: { kubernetes.io/hostname: $pin }" > "$WORK/v-control.yaml"
if "$HELM" upgrade "$RELEASE" deploy/helm/yellowjack -f "$WORK/v-control.yaml" --wait --timeout 300s >"$WORK/helm-control.log" 2>&1 \
   && wait_ready_gates 2 120; then
  res=$(drain_under_load "$pin"); echo "      drain $pin (control): $res"
  # The control asserts the STATE the budget prevents, not a loop count. Counting loop
  # failures was timing-dependent: once no endpoint is left a request hangs to curl's
  # timeout rather than failing fast, so the first CI run counted 1 failure of 40, a margin
  # one unlucky run turns into a false red. Instead: after a drain with no budget, no gate
  # replica is Ready, and every pull fails.
  left=$(ready_gates); left=${left:-0}
  failed=0
  for _ in 1 2 3; do
    c=$(kexec yj-client -- sh -c "curl -s -o /dev/null -m 5 -w '%{http_code}' http://$SVC:8080/$SERVED" 2>/dev/null | tr -d '\r')
    [ "$c" != 200 ] && failed=$((failed + 1))
  done
  if [ "$left" = 0 ] && [ "$failed" = 3 ]; then
    pass "CONTROL: without the budget, the drain left 0 gate replicas Ready and 3 of 3 pulls failed -- the leg can go red"
  else
    bad "CONTROL: without the budget the drain left $left replica(s) Ready and $failed of 3 pulls failed -- the leg cannot tell the budget from luck"
  fi
  "$KUBECTL" uncordon "$pin" >/dev/null 2>&1
else
  bad "CONTROL: could not set up the pinned, budget-less release:"; tail -5 "$WORK/helm-control.log"
fi

say "6) the refusal CONTROL: the same release with the deny entry removed"
values "" "" > "$WORK/v-nodeny.yaml"
if "$HELM" upgrade "$RELEASE" deploy/helm/yellowjack -f "$WORK/v-nodeny.yaml" --wait --timeout 300s >"$WORK/helm-nodeny.log" 2>&1; then
  got=""; for _ in $(seq 1 75); do got=$(pull "$DENIED"); [ "${got%%|*}" = 200 ] && break; sleep 2; done
  case "$got" in
    "403|deny-list:$DENIED") bad "CONTROL: with no deny entry, $DENIED is STILL refused by deny-list -- the refusal assertion could not go red" ;;
    200*) pass "CONTROL: with the deny entry removed, $DENIED is served (200) -- the refusal assertion can go red" ;;
    *) bad "CONTROL: $DENIED answered '$got' with no deny entry (want 200)" ;;
  esac
else
  bad "CONTROL: helm upgrade without the deny entry failed:"; tail -5 "$WORK/helm-nodeny.log"
fi

say "RESULT"
echo "install ${INSTALL_S:-?}s, pod restarts ${restarts:-?}, whole run $(( $(date +%s) - T0 ))s"
if [ "$FAIL" = 0 ]; then echo "HELM INSTALL: PASS"; exit 0; fi
echo "HELM INSTALL: FAIL"; exit 1
