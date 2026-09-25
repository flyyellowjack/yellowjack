#!/usr/bin/env bash
# REMOTE-DAEMON LAUNCHER DRILL (#80) — the socket-free scan path, run rather than argued.
#
# ── WHY THIS EXISTS ──────────────────────────────────────────────────────────
#
# #80 is our own architecture's worst-sounding fact: the scheduler drives the Docker
# socket to start each run-once scanner, and access to that socket is effectively host
# root. D133 re-scoped the issue from "engineer it away" to "state the risk and name the
# hardened option", and !241 did that in docs/SETUP.md. One box stayed unticked, on
# purpose, and its reason was written down:
#
#   "...and is marked the RECOMMENDED PRODUCTION option."
#   Left unticked because "Yellow Jack's own e2e does not exercise a remote-daemon
#   deployment. Stamping something 'recommended production' that we have never run end
#   to end is the kind of claim this issue's own source material punishes."
#
# So the doc told the truth and paid for it: option 1 (point the launcher at another
# daemon, mount no socket) rests on two verified FACTS -- the launcher does not override
# the child environment, and the docker CLI dials DOCKER_HOST when set -- but nobody had
# ever watched a scan actually happen that way. This drill is that missing run. It does
# not tick the box: naming a recommended deployment is a product call. It removes the
# reason the box could not be ticked.
#
# ── WHAT IT PROVES ───────────────────────────────────────────────────────────
#
#   * A scheduler container with NO docker socket mounted, given only DOCKER_HOST +
#     DOCKER_TLS_VERIFY + DOCKER_CERT_PATH, completes a scan end to end: it launches the
#     run-once container, the container reports back through the capability-token sink,
#     and /scan answers with the score. Exactly the compose block docs/SETUP.md prints.
#   * The container ran on the OTHER daemon. Not inferred from the scan succeeding --
#     read from that daemon's own event stream, and the local daemon's event stream is
#     checked to be empty of it, so "it worked" cannot be satisfied by a scan that
#     quietly ran here.
#   * The absence is structural: the scheduler's mounts are inspected and must contain no
#     docker socket, so the drill cannot pass because a socket was left in by accident.
#
# ── THE TWO CONTROLS, AND WHY EACH ONE ───────────────────────────────────────
#
#   A. SAME container, DOCKER_HOST REMOVED. Must FAIL. Without this the pass above is
#      equally explained by a socket we failed to notice, or by a launcher that never ran
#      a container at all. This is the leg that makes the measurement attributable.
#   B. The docker-api launcher pointed at the SAME tcp:// address. Must FAIL. !241 removed
#      a comment from e2e/hardening.sh offering that as a mitigation, because
#      newAPILauncher's transport dials ("unix", socket) unconditionally and reads a
#      tcp:// value as a FILENAME. An operator who reaches for the wrong launcher must hit
#      a wall, not a silent fallback -- and if that ever changes, this control tells us by
#      going green when it should be red.
#
# ── WHAT IT DOES NOT PROVE, stated rather than implied ───────────────────────
#
#   * A second HOST. The "remote" daemon is a privileged docker-in-docker container on
#     this machine. What that exercises is the whole client path -- TCP, mutual TLS, a
#     daemon that is not ours, an image store that is not ours -- and what it does not
#     exercise is the network between two machines, which is the deployer's (D133).
#   * Certificate ROTATION, or what happens when the remote daemon is unreachable
#     mid-scan. The first is an operator procedure; the second is the scheduler's timeout
#     path, which async_local.sh already drives.
#   * That this deployment is RECOMMENDED. That is the product call #80's last box is
#     waiting on. This drill says only that it works.
#
# Run: sh scripts/dev.sh remotedaemon      (needs docker; not in CI -- see the note at the
# end of this header)
#
# NOT A CI JOB, deliberately and for a stated reason: it needs a PRIVILEGED container, and
# CI's own runner is already docker:dind, so this would be a privileged daemon inside a
# privileged daemon inside a runner. Same call as e2e/helm_list_drill.sh, same reason. The
# CI-side counterweight is scheduler/launcher_env_test.go, which pins the two source facts
# this whole path rests on (the launcher never sets cmd.Env; the api launcher dials unix)
# so they cannot change without a test going red.

set -uo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT" || exit 1

FAIL=0
say()  { printf '\n=== %s ===\n' "$*"; }
pass() { printf 'PASS: %s\n' "$*"; }
bad()  { printf 'FAIL: %s\n' "$*"; FAIL=1; }

# MSYS_NO_PATHCONV: Git Bash on the Windows dev host rewrites arguments that look like
# absolute paths, so `-v yj-rd-certs:/certs` becomes a Windows path and the mount is
# wrong. Harmless on Linux.
NOPATHCONV="env MSYS_NO_PATHCONV=1"

NET="yj-rd-net"
# A fixed subnet so the scheduler's address is known BEFORE it starts. It has to be: the
# run-once container is launched on the other daemon and reaches the result sink by IP,
# because docker DNS names on this network do not resolve inside that daemon.
SUBNET="${YJ_RD_SUBNET:-10.77.66.0/24}"
SCHED_IP="${YJ_RD_SCHED_IP:-10.77.66.10}"
SCHED_PORT="${YJ_RD_PORT:-18796}"

DAEMON="yj-rd-daemon"      # the "other machine" (container name)
# The name we DIAL it by. dind generates its server certificate for exactly three
# names -- the container id, "docker" and localhost -- so a remote daemon reached by
# any other name fails verification. That is the first wall an operator following
# docs/SETUP.md hits, and this drill hit it: x509 "certificate is valid for <id>,
# docker, localhost, not yj-rd-daemon". Dialling it as "docker" is also exactly how
# GitLab CI addresses its own dind service, so it is the configuration in widest use.
DAEMON_DNS="docker"
SCHED="yj-rd-scheduler"
CERTS="yj-rd-certs"        # named volume: dind writes its CA + server + client certs here
SCHED_IMAGE="yellowjack-scheduler:rd"
FAKE_IMAGE="yellowjack-scanner-fake:e2e"
# Pinned by digest for the same reason every other rig pins: a drill that measures a
# security posture must not measure different bytes on different days.
DIND_IMAGE='docker:27-dind@sha256:aa3df78ecf320f5fafdce71c659f1629e96e9de0968305fe1de670e0ca9176ce'
# The repo the fake scanner scores. Any name works EXCEPT one containing the fixture's
# unscorable substring (expressjs/), which the fixture answers with "could not score".
SCAN_REPO="github.com/lodash/lodash"
FAKE_SCORE_INT=9           # e2e/fakescanner/Dockerfile's ARG FAKE_SCORE default

cleanup() {
  docker rm -f "$SCHED" "$DAEMON" >/dev/null 2>&1
  docker network rm "$NET" >/dev/null 2>&1
  docker volume rm "$CERTS" >/dev/null 2>&1
}
trap cleanup EXIT
cleanup

# ── 0. images ────────────────────────────────────────────────────────────────
say "0) build the scheduler and the DETERMINISTIC scanner"

# mirror-bases for the scanner, exactly as async_local.sh does (#106: the scanner's bases
# come from our own registry when one is configured).
sh scripts/mirror-bases.sh build scanner/Dockerfile -t yellowjack-scanner:dev . >/dev/null 2>&1 \
  || { bad "could not build yellowjack-scanner:dev"; exit 1; }
docker build -q -f e2e/fakescanner/Dockerfile -t "$FAKE_IMAGE" . >/dev/null 2>&1 \
  || { bad "could not build $FAKE_IMAGE"; exit 1; }
docker build -q -f scheduler/Dockerfile -t "$SCHED_IMAGE" . >/dev/null 2>&1 \
  || { bad "could not build $SCHED_IMAGE"; exit 1; }
pass "scheduler + run-once scanner built (the scanner binary is REAL; only scorecard is the fixture)"

# ── 1. the other machine ─────────────────────────────────────────────────────
say "1) start a daemon that is NOT ours, with mutual TLS"

docker network create --subnet "$SUBNET" "$NET" >/dev/null 2>&1 \
  || { bad "could not create $NET on $SUBNET (in use? set YJ_RD_SUBNET)"; exit 1; }

# DOCKER_TLS_CERTDIR makes dind generate a CA, a server cert and a CLIENT cert -- which is
# what lets this drill exercise the DOCKER_TLS_VERIFY/DOCKER_CERT_PATH pair the doc shows,
# rather than a plaintext shortcut no operator should copy.
$NOPATHCONV docker run -d --name "$DAEMON" --network "$NET" --network-alias "$DAEMON_DNS" --privileged \
  -e DOCKER_TLS_CERTDIR=/certs -v "$CERTS:/certs" "$DIND_IMAGE" >/dev/null 2>&1 \
  || { bad "could not start the remote daemon"; exit 1; }

ready=0
for _ in $(seq 1 60); do
  if $NOPATHCONV docker exec "$DAEMON" docker version >/dev/null 2>&1; then ready=1; break; fi
  sleep 1
done
[ "$ready" = "1" ] || { bad "the remote daemon never came up"; docker logs "$DAEMON" 2>&1 | tail -15; exit 1; }
pass "remote daemon up on tcp://$DAEMON_DNS:2376 over mutual TLS (its cert covers $DAEMON_DNS, NOT the container name)"

# Its image store is its own -- the scanner image has to be put there, which is itself the
# point: the scheduler is not handing this daemon anything from our filesystem.
docker save "$FAKE_IMAGE" | $NOPATHCONV docker exec -i "$DAEMON" docker load >/dev/null 2>&1 \
  || { bad "could not load $FAKE_IMAGE into the remote daemon"; exit 1; }
pass "the run-once image is present on the REMOTE daemon's own image store"

# ── 2. the scheduler, with no socket at all ──────────────────────────────────
say "2) start the scheduler with NO docker socket -- only DOCKER_HOST + client certs"

start_scheduler() { # start_scheduler [extra docker run args...]
  docker rm -f "$SCHED" >/dev/null 2>&1
  $NOPATHCONV docker run -d --name "$SCHED" --network "$NET" --ip "$SCHED_IP" \
    -p "$SCHED_PORT:8096" \
    -v "$CERTS:/certs:ro" \
    -e SCHEDULER_SELF_URL="http://$SCHED_IP:8096" \
    -e SCHEDULER_SCANNER_IMAGE="$FAKE_IMAGE" \
    -e SCHEDULER_SCAN_TIMEOUT_SECS=90 \
    "$@" "$SCHED_IMAGE" >/dev/null 2>&1
}

start_scheduler \
  -e DOCKER_HOST="tcp://$DAEMON_DNS:2376" \
  -e DOCKER_TLS_VERIFY=1 \
  -e DOCKER_CERT_PATH=/certs/client \
  || { bad "could not start the scheduler"; exit 1; }

up=0
for _ in $(seq 1 30); do
  if curl -fsS -m 2 "http://localhost:$SCHED_PORT/healthz" >/dev/null 2>&1; then up=1; break; fi
  sleep 1
done
[ "$up" = "1" ] || { bad "the scheduler never served"; docker logs "$SCHED" 2>&1 | tail -15; exit 1; }

# STRUCTURAL, not hopeful: read the mounts back off the running container. A drill that
# only checked "a scan worked" would pass just as happily with a socket mounted by
# mistake, and would then be measuring the ordinary deployment under a new name.
mounts=$(docker inspect "$SCHED" --format '{{json .Mounts}}{{json .HostConfig.Binds}}' 2>/dev/null)
case "$mounts" in
  *docker.sock*) bad "the scheduler HAS a docker socket mounted -- this drill would prove nothing: $mounts" ;;
  *) pass "the scheduler has NO docker socket: $(docker inspect "$SCHED" --format '{{range .Mounts}}{{.Source}}->{{.Destination}} {{end}}')" ;;
esac

# ── 3. the scan ──────────────────────────────────────────────────────────────
say "3) a scan, launched across TCP onto the other daemon"

since=$(date +%s)
body=$(curl -s -m 120 -X POST -H 'Content-Type: application/json' \
  -d "{\"repo\":\"$SCAN_REPO\"}" "http://localhost:$SCHED_PORT/scan" 2>&1)
code=$(curl -s -o /dev/null -m 5 -w '%{http_code}' -X POST -H 'Content-Type: application/json' \
  -d "{\"repo\":\"$SCAN_REPO\"}" "http://localhost:$SCHED_PORT/scan" 2>&1)
until_now=$(date +%s)

case "$body" in
  *'"score"'*) pass "the scheduler answered with a score: $body" ;;
  *) bad "no score came back from /scan: ${body:-<empty>}"; docker logs "$SCHED" 2>&1 | tail -20 ;;
esac
case "$body" in
  *"\"score\":$FAKE_SCORE_INT"*) pass "and it is the FIXTURE's score ($FAKE_SCORE_INT) -- the run-once container really produced it" ;;
  *) bad "the score is not the fixture's $FAKE_SCORE_INT, so something other than our scanner answered: $body" ;;
esac
[ "$code" = "200" ] && pass "/scan is a 200 (repeated, so the path is not a one-off)" \
  || bad "/scan returned $code on the second call"

# WHERE it ran, read from the daemons themselves rather than inferred from success.
# `docker run --rm` removes the container on exit, so `ps -a` is racy by construction --
# the event stream is the record that survives it.
remote_ev=$($NOPATHCONV docker exec "$DAEMON" docker events --since "$since" --until "$until_now" \
  --filter event=create --format '{{.Actor.Attributes.image}}' 2>/dev/null | tr -d '\r')
local_ev=$(docker events --since "$since" --until "$until_now" \
  --filter event=create --format '{{.Actor.Attributes.image}}' 2>/dev/null | tr -d '\r')

case "$remote_ev" in
  *"$FAKE_IMAGE"*) pass "the REMOTE daemon created the run-once container: $(printf '%s' "$remote_ev" | tr '\n' ' ')" ;;
  *) bad "the remote daemon created no run-once container (events: ${remote_ev:-<none>})" ;;
esac
case "$local_ev" in
  *"$FAKE_IMAGE"*) bad "the LOCAL daemon also created one -- the scan did not go where the drill claims" ;;
  *) pass "CONTROL: the local daemon created none, so the launch left this machine" ;;
esac

# ── 4. control A: the same container, without DOCKER_HOST ────────────────────
say "4) CONTROL A -- remove DOCKER_HOST and nothing else; the scan MUST fail"

start_scheduler || { bad "could not restart the scheduler for control A"; exit 1; }
up=0
for _ in $(seq 1 30); do
  if curl -fsS -m 2 "http://localhost:$SCHED_PORT/healthz" >/dev/null 2>&1; then up=1; break; fi
  sleep 1
done
[ "$up" = "1" ] || { bad "the scheduler never served for control A"; exit 1; }

ctl_code=$(curl -s -o /dev/null -m 60 -w '%{http_code}' -X POST -H 'Content-Type: application/json' \
  -d "{\"repo\":\"$SCAN_REPO\"}" "http://localhost:$SCHED_PORT/scan" 2>&1)
ctl_body=$(curl -s -m 60 -X POST -H 'Content-Type: application/json' \
  -d "{\"repo\":\"$SCAN_REPO\"}" "http://localhost:$SCHED_PORT/scan" 2>&1)

case "$ctl_code" in
  2*) bad "without DOCKER_HOST the scan still SUCCEEDED ($ctl_code) -- leg 3 proved nothing, because something other than DOCKER_HOST is reaching a daemon" ;;
  *)  pass "without DOCKER_HOST the scan fails ($ctl_code), so leg 3's success is attributable to it" ;;
esac
# And it fails for the RIGHT reason: no daemon to talk to, not some unrelated crash.
#
# Read from the RESPONSE, never the scheduler's log. The first version of this check
# matched the log, which carries a startup banner reading "launcher: docker-run" on every
# boot -- so it would have passed on ANY failure, including one with nothing to do with
# the launcher. Measured while writing it: the log holds no failure line at all, because
# the launch error is returned to the caller rather than logged. A plausible handle is not
# the one carrying the answer (the same trap !185's leg 23 hit with a 303).
case "$ctl_body" in
  *"failed to launch scanner"*) pass "and the failure is the LAUNCH itself: $(printf '%s' "$ctl_body" | cut -c1-140)" ;;
  *) bad "the refusal is not a launch failure, so this control may be failing for an unrelated reason: ${ctl_body:-<empty>}" ;;
esac
case "$ctl_body" in
  *"Cannot connect to the Docker daemon"*|*"docker.sock"*)
    pass "and it names the daemon it could not reach: with DOCKER_HOST gone the CLI fell back to the default SOCKET, which is exactly what this deployment does not mount" ;;
  *) bad "the launch failure does not name a daemon or socket, so the fallback path is not what failed: ${ctl_body:-<empty>}" ;;
esac

# ── 5. control B: the api launcher cannot do this ────────────────────────────
say "5) CONTROL B -- the docker-api launcher pointed at the same tcp:// address MUST fail"

start_scheduler \
  -e SCHEDULER_LAUNCHER=docker-api \
  -e SCHEDULER_DOCKER_SOCKET="tcp://$DAEMON_DNS:2376" \
  || { bad "could not restart the scheduler for control B"; exit 1; }
up=0
for _ in $(seq 1 30); do
  if curl -fsS -m 2 "http://localhost:$SCHED_PORT/healthz" >/dev/null 2>&1; then up=1; break; fi
  sleep 1
done
[ "$up" = "1" ] || { bad "the scheduler never served for control B"; exit 1; }

api_code=$(curl -s -o /dev/null -m 60 -w '%{http_code}' -X POST -H 'Content-Type: application/json' \
  -d "{\"repo\":\"$SCAN_REPO\"}" "http://localhost:$SCHED_PORT/scan" 2>&1)
case "$api_code" in
  2*) bad "the docker-api launcher ACCEPTED a tcp:// address ($api_code). That contradicts newAPILauncher dialling (\"unix\", socket) unconditionally -- if the launcher gained remote support, docs/SETUP.md option 2 and this control both need rewriting" ;;
  *)  pass "the docker-api launcher fails ($api_code) on a tcp:// address, as !241 documented: it reads the value as a FILENAME" ;;
esac

# ── result ───────────────────────────────────────────────────────────────────
say "RESULT"
if [ "$FAIL" -eq 0 ]; then
  echo "ALL PASS: a scan ran on another daemon over mutual TLS with NO socket mounted here,"
  echo "the container was created there and not here, and both controls failed as required."
  echo
  echo "What this does NOT settle: whether this deployment is RECOMMENDED (#80's last box)"
  echo "is a product call, and the 'other machine' here is a privileged container on this one."
else
  echo "FAILURES above."
  echo "--- scheduler log ---"; docker logs "$SCHED" 2>&1 | tail -25
  echo "--- remote daemon log ---"; docker logs "$DAEMON" 2>&1 | tail -15
fi
exit "$FAIL"
