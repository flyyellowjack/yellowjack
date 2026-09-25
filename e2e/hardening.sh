#!/usr/bin/env bash
# CONTAINER HARDENING (#22 checkbox 1) — non-root, read-only rootfs, arbitrary UID,
# and no writable host directory.
#
# ── WHY THIS IS PRODUCT WORK, NOT TIDYING ────────────────────────────────────
#
# D54: the ICP is the budget-constrained SMB self-hoster who left the closed-source
# incumbents. What their security review checks first is exactly this list, and
# failing it is a lost deal rather than a hardening gap. The incumbent record #22
# collects is not subtle — JFrog's charts were filed against SIX times between 2018
# and 2024 for `Cannot write to router.pid: Permission denied` and "does not deploy
# on OpenShift due to securityContext".
#
# We are a set of static Go binaries on distroless with no durable state, so this
# costs us nothing to hold — and that is the point. It is cheap for US and expensive
# for them, which makes it worth ASSERTING rather than assuming.
#
# ── WHAT "ARBITRARY UID" MEANS AND WHY IT IS THE HARD ONE ────────────────────
#
# OpenShift's restricted SCC assigns each namespace a random high UID and runs the
# container as it with GID 0 — the UID is NOT in the image's /etc/passwd. Code that
# looks up its own username, or writes to a home directory, breaks there and nowhere
# else. So the rig uses 1000670000, a genuinely unmapped UID, rather than a friendly
# one that happens to exist in the image.
#
# ── THE INSTRUMENT IS CHECKED BEFORE THE SUBJECT ─────────────────────────────
#
# Every leg below asserts that something DOESN'T break. That family of test fails
# silently: if `--read-only` were ignored — an old daemon, a rootless quirk, a typo
# in the flag — every leg would pass while testing nothing. So leg 0 proves the
# constraint actually refuses a write on THIS host before anything else runs, and
# leg 2 re-reads ReadonlyRootfs off the containers it actually launched.
#
# ── STANDING NEGATIVE CONTROLS (run these when changing this rig) ────────────
#
#  1. Drop `--read-only` from harden_run. Leg 2's ReadonlyRootfs assertion fails.
#     Without that assertion nothing would fail, which is the whole reason it exists.
#  2. Remove `scheduler` from ROOT_BY_DESIGN. Leg 1 fails and names it — proving the
#     non-root check reads real image config rather than a hardcoded pass.
#  3. Break the feed path in leg 3 (point FW_MALWARE_LIST at a missing file). The
#     firewall refuses to start, and leg 2/3 fail rather than reporting a healthy
#     service that enforces nothing.
#
# Run from the repo root:  bash e2e/hardening.sh      (or: sh scripts/dev.sh harden)
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
E2E_HOST="${E2E_HOST:-localhost}"
FAIL=0
say()  { printf '\n=== %s ===\n' "$*"; }
pass() { printf 'PASS: %s\n' "$*"; }
fail() { printf 'FAIL: %s\n' "$*"; FAIL=1; }
# has TEXT NEEDLE / hasre TEXT ERE -- substring and regex tests that do not lie.
#
# `producer | grep -q X` is WRONG in this rig, because it sets pipefail: grep -q exits
# at the FIRST match and closes the pipe, the producer dies of SIGPIPE, and pipefail
# reports the PIPELINE as failed -- so a string that IS present reads as ABSENT. It is
# size-dependent, so a leg passes for months and then starts failing as the thing it
# reads grows. Measured 2026-09-22: leg 21b reported "the firewall did not report a
# known-malware feed at startup" while the next three assertions in the same leg proved
# the feed was loaded, reloaded and enforced.
#
# `has` uses a shell pattern and no pipe at all. `hasre` keeps grep for the cases that
# need a regex, but with -c, which reads to EOF and so never closes the pipe early.
# Enforced by scripts/pipefail-grep.sh.
has()   { case "$1" in *"$2"*) return 0 ;; esac; return 1; }
hasre() { [ "$(printf '%s\n' "$1" | grep -ciE -- "$2")" -gt 0 ]; }

# An unmapped, OpenShift-shaped UID. GID 0 matches the restricted SCC, which puts
# every process in the root GROUP while denying the root USER.
ARBITRARY_UID="${YJ_ARBITRARY_UID:-1000670000}"

# MSYS_NO_PATHCONV: Git Bash on the Windows dev host rewrites arguments that look
# like Unix paths, so `-v x:/feed/f` reaches Docker as `-v x:C:/Program Files/Git/feed/f`
# and the service reports a nonsense absolute path.
#
# Applied PER COMMAND, not exported. Exporting it globally was tried and broke curl:
# with translation off, `curl -o "$ROOT/file"` receives an MSYS path (/c/Users/...)
# that the Windows curl cannot open, so the file silently never appeared and leg 4
# read an empty body while correctly reporting a 403. Only the commands that pass a
# CONTAINER-side path need it.
NOPATHCONV="env MSYS_NO_PATHCONV=1"

# An image we already pin, chosen because it HAS a shell — distroless does not, so
# our own images cannot be asked to attempt a write directly.
PROBE_IMAGE='nginx:1.27-alpine@sha256:65645c7bb6a0661892a8b03b89d0743208a18dd2f3f17a54ef4b76fb8e2f2a10'

# Images built here, and the port each serves on.
IMAGES="firewall:Dockerfile:8080 approval:approval/Dockerfile:8090 console:console/Dockerfile:8085 cache:cache/Dockerfile:8070 scheduler:scheduler/Dockerfile:8096 scanner:scanner/Dockerfile:0"

# Services that must run as a NON-root user. The scheduler is deliberately absent:
# see ROOT_BY_DESIGN.
#
# ROOT_BY_DESIGN — the scheduler runs as uid 0 because it drives the host's Docker
# daemon through a mounted /var/run/docker.sock, which on a normal host is owned
# root:docker. Making it non-root would mean baking in the host's docker GID, which
# differs per host.
#
# ⚠️ Recorded honestly rather than papered over: a container with the docker socket
# is root-equivalent ON THE HOST whatever user it runs as, so dropping its UID would
# buy appearance rather than safety. The real mitigations are elsewhere and belong to
# the scheduler's design, not to this rig — docs/SETUP.md states them for an operator:
#
#   - docker-run + DOCKER_HOST (with DOCKER_TLS_VERIFY/DOCKER_CERT_PATH) sends launches
#     to a remote daemon and needs no socket mount. No longer only "both facts checked":
#     e2e/remote_daemon_drill.sh RUNS it — a scan onto a second daemon over mutual TLS
#     with no socket mounted, with the launch attributed to DOCKER_HOST by a control.
#   - a filtering socket proxy, mounted in place of the real socket via
#     SCHEDULER_DOCKER_SOCKET, which the docker-api launcher dials by path.
#   - D24's ECS-RunTask / Kubernetes launcher, which is designed but NOT BUILT.
#
# This comment previously offered "the docker-API launcher pointed at a remote
# endpoint" as a fourth option. It is not one: newAPILauncher's DialContext dials
# "unix" unconditionally and ignores the request host, so a tcp:// value in
# SCHEDULER_DOCKER_SOCKET is read as a filename. Corrected under #80 rather than left
# as a mitigation a reader could try and find missing.
ROOT_BY_DESIGN="scheduler"

# TWO RUNS OF THIS RIG CANNOT SHARE A HOST, so refuse rather than interleave.
#
# Every container here has a FIXED name (yjharden-run-firewall, …) and cleanup() removes
# them BY NAME. So a second run starting while a first is alive — or while a killed first
# run's EXIT trap is still pending — deletes the other's containers mid-poll. The rig then
# reports the service as having EXITED, and every downstream leg that needs it fails too.
#
# Measured, because it happened here: killing a run and starting another 70 s later produced
# four FAILs (approval "EXITED" with `No such container` — removal, not exit, from a rig that
# uses no --rm; then the idle-CPU floor; then two event-export legs), and the result looked
# exactly like a product regression. It cost a control run on main plus a re-run to prove the
# code was innocent. A refusal up front would have cost one line of output.
#
# Checked against DOCKER rather than a pidfile: a pidfile goes stale when a run is killed,
# which is precisely the case that bit, and the containers are the thing that actually
# collides.
_live="$(docker ps -a --format '{{.Names}}' 2>/dev/null | grep -c '^yjharden-' || true)"
if [ "${_live:-0}" -gt 0 ]; then
  echo "REFUSING TO START: $_live container(s) named yjharden-* already exist on this host." >&2
  echo "  Another run of this rig is live, or a killed one left containers behind. Both runs" >&2
  echo "  use the SAME container names and cleanup() removes them by name, so continuing would" >&2
  echo "  corrupt whichever run is older and report its services as having crashed." >&2
  echo "  Wait for it to finish, or: docker ps -a --format '{{.Names}}' | grep '^yjharden-' | xargs -r docker rm -f" >&2
  exit 2
fi

CONTAINERS=""
cleanup() {
  for c in $CONTAINERS; do docker rm -f "$c" >/dev/null 2>&1 || true; done
  rm -f "$ROOT/.hardening-feed.ndjson" "$ROOT/.harden-block.json" "$ROOT/.harden-fixture.Dockerfile"
  rm -f "$ROOT/.harden-cpu.raw" "$ROOT/.harden-cpu.agg"
  rm -f "$ROOT/.harden-lat-pairs" "$ROOT/.harden-lat-slow"
  docker network rm yjharden-lat-net >/dev/null 2>&1 || true
  docker rmi yjharden-fixture-control >/dev/null 2>&1 || true
}
trap cleanup EXIT

say "0) INSTRUMENT CHECK — does --read-only actually refuse a write on this host?"
# If this does not fire, every "it still worked" below is meaningless.
if docker run --rm "$PROBE_IMAGE" sh -c 'touch /probe' >/dev/null 2>&1; then
  pass "a writable rootfs accepts a write (the probe can distinguish the two cases)"
else
  fail "the probe image cannot write even WITHOUT --read-only, so it cannot tell the two apart"
  exit 1
fi
if docker run --rm --read-only "$PROBE_IMAGE" sh -c 'touch /probe' >/dev/null 2>&1; then
  fail "--read-only did NOT refuse a write on this host. Every leg below would pass without testing anything."
  exit 1
else
  pass "--read-only refuses a write, so a green result below is a real result"
fi

say "1) build the service images"
for spec in $IMAGES; do
  name="${spec%%:*}"; rest="${spec#*:}"; dockerfile="${rest%%:*}"
  if docker build -q -f "$dockerfile" -t "yjharden-$name" . >/tmp/hb-$name.log 2>&1; then
    pass "built $name"
  else
    fail "could not build $name: $(tail -3 /tmp/hb-$name.log | tr '\n' ' ')"
    exit 1
  fi
done

say "1b) the shipped images contain NO test fixtures (#46)"
# GuardDog shipped live malware samples inside its release tarball for two years
# (DataDog/guarddog#766; #776 — "don't ship test files as part of release tarballs" —
# still open). Our runtime images are distroless plus one static binary, so this holds
# by construction, which is exactly why it is asserted: the day a Dockerfile grows a
# `COPY . .` or a go:embed of testdata, nothing else in the pipeline would notice.
# Judged by PATH, not content: a fixture under any of these names is a fixture wherever
# it was copied to.
FIXTURE_PATHS='(^|/)(e2e|testdata|fakeupstream[^/]*|malicious-corpus)/|_test\.go$'
# image_fixture_hits NAME — print every path in the image filesystem that matches.
# Exit 0 = hits, 1 = clean, 2 = the image could not be read at all.
image_fixture_hits() {
  local c hits
  c=$(docker create "yjharden-$1" 2>/dev/null) || return 2
  hits=$(docker export "$c" 2>/dev/null | tar -tf - 2>/dev/null | grep -E "$FIXTURE_PATHS")
  docker rm -f "$c" >/dev/null 2>&1
  [ -n "$hits" ] && { printf '%s\n' "$hits"; return 0; }
  return 1
}
# image_file_count NAME — how many entries the image filesystem has (0 = unreadable).
image_file_count() {
  local c n
  c=$(docker create "yjharden-$1" 2>/dev/null) || { echo 0; return; }
  n=$(docker export "$c" 2>/dev/null | tar -tf - 2>/dev/null | wc -l | tr -d ' ')
  docker rm -f "$c" >/dev/null 2>&1
  echo "${n:-0}"
}
# THE INSTRUMENT IS CHECKED FIRST: an image that DOES carry a fixture must be caught, or
# every clean result below means nothing. Plant one on top of the real firewall image.
printf 'FROM yjharden-firewall\nCOPY e2e/fakeupstream /opt/fixtures/fakeupstream\n' > "$ROOT/.harden-fixture.Dockerfile"
if docker build -q -f "$ROOT/.harden-fixture.Dockerfile" -t yjharden-fixture-control . >/dev/null 2>&1 \
   && image_fixture_hits fixture-control >/dev/null; then
  pass "instrument: an image with a planted fixture IS detected (control)"
else
  fail "instrument: the fixture-in-image check did not detect a planted fixture — every clean result below would be vacuous"
fi
docker rmi yjharden-fixture-control >/dev/null 2>&1
rm -f "$ROOT/.harden-fixture.Dockerfile"
checked=0
for spec in $IMAGES; do
  name="${spec%%:*}"
  n=$(image_file_count "$name")
  if [ "${n:-0}" -lt 1 ]; then
    fail "$name: could not list the image filesystem (0 entries) — nothing was checked"
    continue
  fi
  hits=$(image_fixture_hits "$name"); rc=$?
  case "$rc" in
    0) fail "$name ships test fixtures ($n files): $(printf '%s' "$hits" | head -3 | tr '\n' ' ')" ;;
    1) pass "$name ships no test fixtures ($n files in the image)"; checked=$((checked + 1)) ;;
    *) fail "$name: the image filesystem could not be read" ;;
  esac
done
# Anti-vacuity: this loop asserts nothing if IMAGES is ever emptied or renamed.
if [ "$checked" -lt 5 ]; then
  fail "only $checked images were checked for fixtures; the check looked at almost nothing"
fi

say "2) every image runs as a non-root user (except the declared exception)"
checked=0
for spec in $IMAGES; do
  name="${spec%%:*}"
  user="$(docker inspect -f '{{.Config.User}}' "yjharden-$name" 2>/dev/null)"
  checked=$((checked + 1))
  declared=0
  for r in $ROOT_BY_DESIGN; do [ "$r" = "$name" ] && declared=1; done
  case "$user" in
    ""|"0"|"root"|"0:0"|"root:root")
      if [ "$declared" = "1" ]; then
        pass "$name runs as root BY DESIGN (docker socket; see ROOT_BY_DESIGN)"
      else
        fail "$name runs as root (User=${user:-<unset>}) and is not a declared exception. " \
             "A self-hoster's security review checks this first."
      fi ;;
    *)
      if [ "$declared" = "1" ]; then
        fail "$name is listed in ROOT_BY_DESIGN but does not run as root (User=$user) — " \
             "the exception is stale and should be removed"
      else
        pass "$name runs as $user"
      fi ;;
  esac
done
# Anti-vacuity: this loop asserts nothing if IMAGES is ever emptied or renamed.
if [ "$checked" -lt 5 ]; then
  fail "only $checked images were examined; the non-root check looked at almost nothing"
fi

# harden_run NAME PORT INTERNAL [extra docker args...] — start a service under the
# full constraint set and wait for /healthz.
harden_run() {
  local name="$1" port="$2" internal="$3"; shift 3
  local cname="yjharden-run-$name"
  CONTAINERS="$CONTAINERS $cname"
  docker rm -f "$cname" >/dev/null 2>&1
  if ! docker run -d --name "$cname" --read-only --user "${ARBITRARY_UID}:0" \
      -p "$port:$internal" "$@" "yjharden-$name" >/dev/null 2>&1; then
    fail "$name would not even start under --read-only --user ${ARBITRARY_UID}:0"
    return 1
  fi
  # The constraints must actually be in force on the container we just made. Without
  # this, deleting the flags above would make every leg pass.
  local ro usr
  ro="$(docker inspect -f '{{.HostConfig.ReadonlyRootfs}}' "$cname" 2>/dev/null)"
  usr="$(docker inspect -f '{{.Config.User}}' "$cname" 2>/dev/null)"
  if [ "$ro" != "true" ]; then
    fail "$name is not actually running with a read-only rootfs (ReadonlyRootfs=$ro)"
    return 1
  fi
  if [ "$usr" != "${ARBITRARY_UID}:0" ]; then
    fail "$name is not actually running as the arbitrary UID (User=$usr)"
    return 1
  fi
  local i
  for i in $(seq 1 25); do
    if curl -fsS -m 2 "http://${E2E_HOST}:$port/healthz" >/dev/null 2>&1; then
      pass "$name starts and serves under read-only rootfs + unmapped uid ${ARBITRARY_UID}"
      return 0
    fi
    if [ -z "$(docker ps -q -f name="$cname")" ]; then
      fail "$name EXITED under the constraints: $(docker logs "$cname" 2>&1 | tail -2 | tr '\n' ' ')"
      return 1
    fi
    sleep 1
  done
  fail "$name never answered /healthz under the constraints: $(docker logs "$cname" 2>&1 | tail -2 | tr '\n' ' ')"
  return 1
}

say "3) every long-running service starts and serves under the full constraint set"
harden_run firewall  18601 8080 -e FW_SCORECARD_MODE=stub -e FW_ECOSYSTEM=npm
harden_run approval  18602 8090
harden_run console   18603 8085 -e CONSOLE_LISTEN_ADDR=:8085
harden_run cache     18604 8070
harden_run scheduler 18605 8096

say "3b) FOOTPRINT REGRESSION GUARD (#21) — image size and resident memory stay in budget"
# WHY HERE rather than in a job of its own: this rig already builds every image and already
# has five services running under the full constraint set, so the guard costs seconds
# instead of a second stack boot. docs/FOOTPRINT.md is the measurement; this is the
# tripwire that stops it silently drifting.
#
# WHAT IS ASSERTED, and what deliberately is NOT.
#
#   * IMAGE SIZE — the strongest cheap signal, and completely deterministic. The
#     regression this catches is the real one: a dependency or a toolchain accidentally
#     landing in a runtime image. No stack, no sampling, no flake.
#   * RESIDENT MEMORY of the running services, against a generous ceiling. Sampled here
#     shortly after boot, NOT after the nine-minute settle docs/FOOTPRINT.md uses, so
#     these numbers are a tripwire rather than the published figure — stated so nobody
#     quotes them as the footprint.
#   * IDLE CPU is asserted in leg 3c. This block used to record a refusal — "idle CPU on
#     a shared runner is dominated by whatever else the host is doing, so the assertion
#     would flake" — and the worry was the right one to have: a gate that cries wolf gets
#     ignored, which this repo has spent real time undoing. The MECHANISM was wrong, and
#     one measurement settles it: `docker stats` CPUPerc is computed from the container's
#     OWN cgroup, so a neighbour cannot spend our budget. Measured 2026-09-15 on the dev
#     host, an idle gate read 0.00% on all ten samples while four containers each burned a
#     full core beside it. See leg 3c for the numbers and the ceiling they justify.
#
# CEILINGS clear the LARGER of two baselines, because this one check runs on both platforms
# and they differ by more than the drift it is looking for. Measured 2026-09-10:
#
#              dev host (Windows)        CI (Linux)
#   firewall   17.2 MB / 4.8 MiB         9.83 MB / 1.42 MiB
#   approval   21.8 MB / 4.8 MiB         13.5 MB / 1.47 MiB
#   console    19.5 MB / 4.9 MiB         11.5 MB / 1.67 MiB
#   cache      15.4 MB / 6.7 MiB         8.51 MB / 1.19 MiB
#   scheduler  78.2 MB / 4.8 MiB         51.6 MB / 1.26 MiB   (docker client, by design)
#
# The same build is ~40% smaller on disk and 3-4x smaller resident on Linux, so a ceiling
# tuned to CI would fail every developer running `sh scripts/dev.sh harden` on Windows.
# Against the dev host these are ~2-3x; against CI, ~5x. Loose is the right side to err on:
# the regression this exists for — a dependency or a toolchain landing in a runtime image —
# is an order-of-magnitude event, while a ceiling that fires on a 20% drift gets re-run
# rather than read. docs/FOOTPRINT.md carries both columns.
#
#   service    image ceiling   RSS ceiling
FOOTPRINT_BUDGET="firewall:48:64 approval:48:64 console:48:64 cache:48:64 scheduler:160:64"

# mb_of SIZESTR — docker's human size ("17MB", "1.2GB", "4.883MiB") as whole DECIMAL
# megabytes, which is the unit docker itself reports. Binary inputs are converted, so a
# ceiling here is MB and is labelled MB; at 2-3x headroom the MB/MiB distinction cannot
# change an outcome, but the label should still say what the number is.
mb_of() {
  awk -v s="$1" 'BEGIN{
    n = s + 0
    if (s ~ /GB/) n = n * 1000; else if (s ~ /GiB/) n = n * 1024
    else if (s ~ /kB/ || s ~ /KB/) n = n / 1000
    else if (s ~ /KiB/) n = n / 1024
    else if (s ~ /MiB/) n = n * 1.048576
    printf "%d", n
  }'
}

# INSTRUMENT CHECK FIRST: a budget comparison that cannot fail would pass this whole leg
# while measuring nothing, which is the shape every other check in this file guards against.
if [ "$(mb_of 200MB)" -gt 48 ] && [ "$(mb_of 17MB)" -le 48 ]; then
  pass "instrument: the budget comparison accepts 17MB and rejects 200MB against a 48 MB ceiling"
else
  fail "instrument: the size comparison cannot tell 17MB from 200MB — every budget check below is vacuous"
fi

# INSTRUMENT CHECK FOR THE MEMORY PATH. The comparison is proven above (17MB vs 200MB),
# but nothing proved the READING: that `docker stats --format {{.MemUsage}}` still emits a
# parseable figure for a container that is genuinely holding memory. A format change, a
# daemon hiccup or a renamed container yields an empty string, and until the refusal added
# below that was indistinguishable from a very lean service.
#
# So: a container told to hold a known ballast must MEASURE above a floor well clear of any
# real idle service. This is the memory twin of leg 3c's spinner, and it exists for the same
# reason -- a sampler that has silently stopped sampling reports the best numbers it has
# ever produced.
# NAMED OUTSIDE THE `yjharden-run-` PREFIX ON PURPOSE. Leg 3c samples idle CPU by grepping
# `^yjharden-run-`, so a ballast under that prefix would be measured as if it were one of
# our services — passing (it sleeps after the dd) but inflating the count of services that
# leg believes it checked. An instrument for one leg must not become a phantom subject of
# another.
BALLAST="yjharden-mem-ballast"
BALLAST_MB="${YJ_BALLAST_MB:-48}"
BALLAST_FLOOR="${YJ_BALLAST_FLOOR:-24}"
docker rm -f "$BALLAST" >/dev/null 2>&1
CONTAINERS="$CONTAINERS $BALLAST"
# /dev/shm is tmpfs and its pages count against the container's own cgroup, so this holds
# real resident memory without needing a language runtime in the image. Default shm is
# 64 MB, hence a 48 MB ballast rather than something larger.
docker run -d --name "$BALLAST" "$PROBE_IMAGE" \
  sh -c "dd if=/dev/zero of=/dev/shm/ballast bs=1M count=$BALLAST_MB >/dev/null 2>&1; sleep 120" >/dev/null 2>&1
sleep 3
ballast_used=$(docker stats --no-stream --format '{{.MemUsage}}' "$BALLAST" 2>/dev/null | cut -d/ -f1)
ballast_rss=$(mb_of "$ballast_used")
if [ -n "$ballast_used" ] && [ -n "$ballast_rss" ] && [ "$ballast_rss" -ge "$BALLAST_FLOOR" ]; then
  pass "instrument: a container holding ${BALLAST_MB}MB measured ${ballast_used} (>= ${BALLAST_FLOOR} MB), so the memory reading works"
else
  fail "instrument: a container holding ${BALLAST_MB}MB measured '${ballast_used:-<nothing>}' (parsed ${ballast_rss:-<nothing>} MB, floor ${BALLAST_FLOOR}) -- the memory READING is broken, so every resident-memory pass in this leg is vacuous and the ceilings were never applied"
fi
# Gone as soon as it has served its purpose: it exists to prove the reading works, not to
# sit in the rig holding 48 MB while later legs measure the host.
docker rm -f "$BALLAST" >/dev/null 2>&1

checked=0
for spec in $FOOTPRINT_BUDGET; do
  name="${spec%%:*}"; rest="${spec#*:}"; img_max="${rest%%:*}"; rss_max="${rest#*:}"
  size=$(docker images --format '{{.Size}}' "yjharden-$name" 2>/dev/null | head -1)
  if [ -z "$size" ]; then fail "$name: no image to measure"; continue; fi
  img=$(mb_of "$size")
  if [ "${img:-0}" -le "$img_max" ]; then
    pass "$name image ${size} (<= ${img_max} MB)"
  else
    fail "$name image has grown to ${size}, over its ${img_max} MB budget. Something large landed in a "          "runtime image — check the Dockerfile's final stage before raising this number (#21)."
  fi
  # RSS only for the services this rig actually started.
  cname="yjharden-run-$name"
  if [ -n "$(docker ps -q -f name="^${cname}$" 2>/dev/null)" ]; then
    used=$(docker stats --no-stream --format '{{.MemUsage}}' "$cname" 2>/dev/null | cut -d/ -f1)
    rss=$(mb_of "$used")
    # A MISSING MEASUREMENT MUST NOT LOOK LIKE A GOOD ONE. `${rss:-0}` used to stand in
    # here, and mb_of("") is 0 -- so a `docker stats` that returned nothing (container
    # gone, daemon busy, --format changed under us) produced "0 MB", sailed under every
    # ceiling, and printed a PASS reading leaner than any real service. The guard was
    # most confident exactly when it had measured nothing.
    #
    # Any live container has non-zero RSS, so 0 is not a small reading, it is the absence
    # of one. Same rule as the instrument checks throughout this file: a default that
    # substitutes for a measurement has to fail loudly rather than resemble a normal
    # outcome.
    # The test is on the READING, not on the rounded megabytes, and that distinction is
    # load-bearing: an idle container really can sit under 1 MB (a probe measured 372KiB
    # on this host), which mb_of floors to 0. Refusing on "rss == 0" would therefore cry
    # wolf at the leanest services — the false-alarm failure this file's own leg 3c notes
    # warn about, and a gate that cries wolf is one people learn to bypass.
    #
    # What cannot be legitimate is a reading that is ABSENT or not a number at all.
    case "${used:-}" in
      [0-9]*) rss_readable=1 ;;
      *) rss_readable=0 ;;
    esac
    if [ "$rss_readable" -eq 0 ]; then
      fail "$name: could not read resident memory (docker stats gave '${used:-<nothing>}'). NOT a pass: that is an unmeasured service, not a lean one, and the ceiling below was never applied (#21)."
    elif [ "$rss" -le "$rss_max" ]; then
      pass "$name resident ${used} (<= ${rss_max} MB; a tripwire, not the published idle figure)"
    else
      fail "$name is resident at ${used}, over its ${rss_max} MB budget (#21)"
    fi
  fi
  checked=$((checked + 1))
done
# Anti-vacuity: the loop asserts nothing if FOOTPRINT_BUDGET is emptied or the names drift.
if [ "$checked" -lt 5 ]; then
  fail "only $checked services were measured against the footprint budget; the guard looked at almost nothing"
fi

say "3c) IDLE-CPU REGRESSION GUARD (#21) — the async model must not become a busy-poll"
# THE REGRESSION THIS EXISTS FOR, named in #21: the async cold-scan model (D18) degrading
# into a busy-poll. That is the shape which silently costs us the admin-first claim —
# nothing breaks, no test goes red, and the product just never goes quiet. Artifactory's
# ~7-15% idle CPU is the finding this table exists to avoid becoming.
#
# WHY THIS IS NOT THE FLAKY ASSERTION IT LOOKS LIKE. `docker stats` reports each
# container's CPU from its OWN cgroup accounting, not from the host's load, so a busy
# neighbour on a shared runner cannot inflate our number — it can only slow the sampling.
# Measured on the dev host 2026-09-15, deliberately under load:
#
#   idle firewall, host quiet ................. 0.00% on 5 of 5 samples
#   idle firewall, 4 containers spinning ...... 0.00% on 10 of 10 samples
#   a spinning container, same samples ........ 98-101%
#
# So the two states are separated by the whole scale, and the ceiling below sits in the
# gap: 10% is more than 10x any idle tick these services make (list reload is every 5s and
# reads a file of a few dozen lines) and 5-10x below what one spinning goroutine costs.
# A ceiling tuned close to 0.00 would be the flaky version; this one cannot fire on jitter.
#
# THE MEAN is asserted, not the peak, because a single sample lands wherever a GC or a
# reload tick happened to be; the peak is printed so an operator reading a failure can
# tell a spike from a sustained burn.
CPU_CEILING="${YJ_CPU_CEILING:-10}"
CPU_SAMPLES="${YJ_CPU_SAMPLES:-5}"
CPU_RAW="$ROOT/.harden-cpu.raw"
CPU_AGG="$ROOT/.harden-cpu.agg"

# THE INSTRUMENT IS CHECKED WITH THE SUBJECT, in the same samples rather than in a
# separate pass: a spinner that must be caught. If the sampling silently stopped working
# — a format change, a name that no longer matches, an empty file — every service would
# read 0.00% and this leg would report five passes while measuring nothing. That is the
# failure mode leg 1b and leg 3b each guard against in their own way; this is its shape
# here. The spinner uses the image the rig already pins (it needs a shell).
SPINNER="yjharden-run-spinner"
CONTAINERS="$CONTAINERS $SPINNER"
docker rm -f "$SPINNER" >/dev/null 2>&1
docker run -d --name "$SPINNER" "$PROBE_IMAGE" sh -c 'while :; do :; done' >/dev/null 2>&1

: > "$CPU_RAW"
sleep 3
cpu_i=0
while [ "$cpu_i" -lt "$CPU_SAMPLES" ]; do
  docker stats --no-stream --format '{{.Name}}|{{.CPUPerc}}' 2>/dev/null     | grep '^yjharden-run-' >> "$CPU_RAW"
  cpu_i=$((cpu_i + 1))
  [ "$cpu_i" -lt "$CPU_SAMPLES" ] && sleep 2
done

awk -F'|' '
{ n = $1; c = $2 + 0; sum[n] += c; if (c > peak[n]) peak[n] = c; cnt[n]++ }
END { for (n in sum) printf "%s %.2f %.2f %d\n", n, sum[n] / cnt[n], peak[n], cnt[n] }
' "$CPU_RAW" > "$CPU_AGG"

cpu_checked=0
spinner_mean=""
while read -r cname cmean cpeak ccnt; do
  [ -n "$cname" ] || continue
  short="${cname#yjharden-run-}"
  if [ "$cname" = "$SPINNER" ]; then spinner_mean="$cmean"; continue; fi
  # Only the long-running services from leg 3; the feed/verdict containers of leg 4 are
  # short-lived and may not have been sampled in every window.
  case " firewall approval console cache scheduler " in
    *" $short "*) ;;
    *) continue ;;
  esac
  cpu_checked=$((cpu_checked + 1))
  if awk -v a="$cmean" -v b="$CPU_CEILING" 'BEGIN { exit !(a <= b) }'; then
    pass "$short idle CPU ${cmean}% mean over $ccnt samples (peak ${cpeak}%, ceiling ${CPU_CEILING}%)"
  else
    fail "$short is burning ${cmean}% CPU at idle (peak ${cpeak}%, ceiling ${CPU_CEILING}%) — a service with no traffic should be indistinguishable from zero. The regression #21 names is the async model (D18) degrading into a busy-poll; check for a ticker or a retry loop with no backoff."
  fi
done < "$CPU_AGG"

if [ -z "$spinner_mean" ]; then
  fail "instrument: the spinner was never sampled, so every 0.00% above may be the sampling failing rather than a quiet service"
elif awk -v a="$spinner_mean" -v b="$CPU_CEILING" 'BEGIN { exit !(a > b) }'; then
  pass "instrument: a deliberately spinning container reads ${spinner_mean}% and is caught by the same ${CPU_CEILING}% ceiling"
else
  fail "instrument: a container spinning on a full core read only ${spinner_mean}%, under the ${CPU_CEILING}% ceiling — this leg cannot tell a busy-poll from an idle service and every pass above is vacuous"
fi
if [ "$cpu_checked" -lt 5 ]; then
  fail "only $cpu_checked service(s) were measured for idle CPU; the guard looked at almost nothing"
fi
docker rm -f "$SPINNER" >/dev/null 2>&1
rm -f "$CPU_RAW" "$CPU_AGG"
say "3d) ADDED-LATENCY GUARD (#21) — being in the way must stay free at p99"
# THE CLAIM THIS DEFENDS, from docs/FOOTPRINT.md §3: a package pulled through the gate
# costs the developer nothing measurable at p99. That is the number an admin weighs when
# deciding whether to put us in the pull path at all, and the regression that would take it
# away is a blocking call landing on the WARM path — a fresh upstream lookup, a scan
# awaited rather than launched, a verdict recomputed instead of read from the cache.
# Nothing breaks when that happens; installs just get slower, which nobody bisects.
#
# HERMETIC ON PURPOSE, and the published number is NOT this one. §3 measures against the
# real registry, which is network-bound and unfair to a CI runner. This measures the SAME
# comparison against a local fixture upstream, so what is left in the difference is our own
# overhead and nothing else. Do not quote it as the added latency; quote §3.
#
# THE TRAP §3 RECORDS, honoured here: `curl` without `--compressed` sends no
# Accept-Encoding, while Go's client does, so an uncompressed direct path moves four times
# the bytes and the proxy looks FASTER. Both sides below pass --compressed. If that flag is
# ever dropped from one side the result inverts, which is why it is stated rather than
# assumed.
#
# WARM-UP IS DISCARDED. The first pull of a package is the cold decision (1.2-2.4 s in §3,
# by design — D18's async model exists so it happens once); it is not what a developer feels
# on the hundredth install, and averaging it in would measure the cache's first miss.
#
# THE TRANSFERS ARE PAIRED, and that is the difference between a guard and a flake. The
# obvious version — time N transfers each way, then subtract the two p99s — differences two
# TAIL statistics drawn from separate sample sets, so a single scheduling stall on either
# side moves the answer by its whole size. Measured here first: direct p99 178.1 ms, gate
# p99 186.9 ms on a quiet dev host, where the quantity being asserted is ~9 ms. A runner
# that stalls once during the gate's samples and not during the direct ones would report a
# regression that is not there.
#
# So each iteration times ONE direct transfer and ONE through the gate back to back, and the
# statistic is a percentile of the PER-PAIR DIFFERENCES: whatever the host was doing during a
# pair is in both halves and cancels. The order alternates, because the second transfer of a
# pair is systematically warmer and a fixed order would bake that bias into the answer.
#
# ⚠️ THE ASSERTION IS ON THE MEDIAN, NOT THE p99, and that is a correction #21's wording
# does not survive. The first version of this leg asserted the paired p99 against 150 ms.
# Then the statistic was run five times on a QUIET dev host, which is the only way to set a
# threshold honestly:
#
#   run        1      2      3      4      5
#   paired p50   3.0    2.1    3.6    0.9    1.8   ms   <- stable
#   paired p99  75.2  122.3  115.4  118.7  135.2   ms   <- 75-135, and run 5 brushed the ceiling
#
# Pairing removes the noise COMMON to a pair; it cannot remove the jitter of one transfer,
# and that jitter is what the tail of the differences is made of. A p99 ceiling tight enough
# to catch anything would fire on a quiet machine one run in five — the crying-wolf gate this
# repo keeps having to undo. The MEDIAN of the same differences is stable to about a
# millisecond, and it is the right statistic for the regression this guards against anyway:
# a blocking call on the warm path is paid by EVERY request, so it moves the median by its
# whole size. The p99 is printed for a human, never asserted, and the reason is this table.
LAT_CEILING_MS="${YJ_LAT_CEILING_MS:-25}"   # ~7x the worst paired median measured over five runs (3.6 ms)
LAT_N="${YJ_LAT_N:-100}"
LAT_WARM=5
LAT_NET="yjharden-lat-net"
FAKEUP="yjharden-run-fakeup"
SLOWUP="yjharden-run-slowup"
LATGATE="yjharden-run-latgate"
# The image the verifyrepo compose already pins for this same fixture tree.
PY_IMAGE='python:3.12-alpine@sha256:b64631e04e4920160c50fbe8d8df828f7f35f06f425cb44aa09bca53e708a35a'
CONTAINERS="$CONTAINERS $FAKEUP $SLOWUP $LATGATE"

docker network create "$LAT_NET" >/dev/null 2>&1
for c in "$FAKEUP" "$SLOWUP" "$LATGATE"; do docker rm -f "$c" >/dev/null 2>&1; done

# The fixture registry: the tree e2e/fakeupstream already carries, served by the module's
# own CLI (ThreadingHTTPServer since 3.7 — a single-threaded stub deadlocks behind a
# keep-alive client, which this repo has paid for once already).
$NOPATHCONV docker run -d --name "$FAKEUP" --network "$LAT_NET" -p 18607:8000 \
  -v "$ROOT/e2e/fakeupstream:/srv:ro" "$PY_IMAGE" \
  python -m http.server 8000 --directory /srv >/dev/null 2>&1

# The instrument's stand-in: identical except that it sleeps 500 ms per request. It is what
# proves the comparison below can SEE added latency; without it, "we add nothing" and "the
# measurement cannot tell" produce the same green.
docker run -d --name "$SLOWUP" --network "$LAT_NET" -p 18609:8000 "$PY_IMAGE" python -c '
import http.server, time
class H(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    def do_GET(self):
        time.sleep(0.5)
        b = b"{}"
        self.send_response(200)
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)
    def log_message(self, *a):
        pass
http.server.ThreadingHTTPServer(("", 8000), H).serve_forever()
' >/dev/null 2>&1

# The gate under measurement, pointed at the fixture. Permissive on every axis that would
# otherwise need the network, so what is measured is the relay and the verdict, not deps.dev.
docker run -d --name "$LATGATE" --network "$LAT_NET" -p 18608:8080 \
  -e FW_LISTEN_ADDR=:8080 -e FW_ECOSYSTEM=npm \
  -e "FW_UPSTREAM=http://$FAKEUP:8000" \
  -e FW_SCORECARD_MODE=stub -e FW_SCORE_THRESHOLD=0 \
  -e FW_UNSCORABLE_POLICY=allow -e FW_UNVERIFIED_POLICY=open-with-visibility \
  -e FW_VERIFY_REPO=false \
  yjharden-firewall >/dev/null 2>&1

lat_ready=0
for i in $(seq 1 30); do
  if curl -fsS -m 2 "http://${E2E_HOST}:18607/left-pad/latest" >/dev/null 2>&1 \
     && curl -fsS -m 2 "http://${E2E_HOST}:18608/healthz" >/dev/null 2>&1 \
     && curl -fsS -m 2 "http://${E2E_HOST}:18609/x" >/dev/null 2>&1; then lat_ready=1; break; fi
  sleep 1
done

# lat_samples URL N -> one curl time_total (seconds) per line.
lat_samples() {
  _u="$1"; _n="$2"; _i=0
  while [ "$_i" -lt "$_n" ]; do
    curl -s -o /dev/null --compressed -m 10 -w '%{time_total}\n' "$_u"
    _i=$((_i + 1))
  done
}
# lat_pct FILE P -> the P-th percentile in MILLISECONDS, from seconds-per-line input.
lat_pct() {
  sort -g "$1" | awk -v p="$2" '{v[NR] = $1} END {
    if (NR == 0) { print "NaN"; exit }
    i = int(p / 100 * NR + 0.999); if (i < 1) i = 1; if (i > NR) i = NR
    printf "%.1f", v[i] * 1000
  }'
}

if [ "$lat_ready" != 1 ]; then
  fail "the latency fixtures never became ready; this leg measured nothing"
else
  PAIR_RAW="$ROOT/.harden-lat-pairs"; SLOW_RAW="$ROOT/.harden-lat-slow"
  # Warm-up, discarded: the first pull is the cold decision by design (D18).
  lat_samples "http://${E2E_HOST}:18608/left-pad/latest" "$LAT_WARM" >/dev/null
  lat_samples "http://${E2E_HOST}:18607/left-pad/latest" "$LAT_WARM" >/dev/null

  # lat_pairs BASE_URL N FILE -> "gate direct" per line, order alternating.
  lat_pairs() {
    _b="$1"; _n="$2"; _f="$3"; _i=0
    : > "$_f"
    while [ "$_i" -lt "$_n" ]; do
      if [ $((_i % 2)) -eq 0 ]; then
        _d=$(curl -s -o /dev/null --compressed -m 10 -w '%{time_total}' "http://${E2E_HOST}:18607/left-pad/latest")
        _g=$(curl -s -o /dev/null --compressed -m 10 -w '%{time_total}' "$_b")
      else
        _g=$(curl -s -o /dev/null --compressed -m 10 -w '%{time_total}' "$_b")
        _d=$(curl -s -o /dev/null --compressed -m 10 -w '%{time_total}' "http://${E2E_HOST}:18607/left-pad/latest")
      fi
      printf '%s %s\n' "$_g" "$_d" >> "$_f"
      _i=$((_i + 1))
    done
  }
  # lat_delta_pct FILE P -> the P-th percentile of (first - second), in MILLISECONDS.
  lat_delta_pct() {
    awk '{ printf "%.9f\n", $1 - $2 }' "$1" | sort -g | awk -v p="$2" '{v[NR] = $1} END {
      if (NR == 0) { print "NaN"; exit }
      i = int(p / 100 * NR + 0.999); if (i < 1) i = 1; if (i > NR) i = NR
      printf "%.1f", v[i] * 1000
    }'
  }
  lat_col_pct() { awk -v c="$2" '{print $c}' "$1" | sort -g | awk -v p="$3" '{v[NR] = $1} END {
      i = int(p / 100 * NR + 0.999); if (i < 1) i = 1; if (i > NR) i = NR; printf "%.1f", v[i] * 1000 }'; }

  lat_pairs "http://${E2E_HOST}:18608/left-pad/latest" "$LAT_N" "$PAIR_RAW"
  add50=$(lat_delta_pct "$PAIR_RAW" 50); add99=$(lat_delta_pct "$PAIR_RAW" 99)
  d50=$(lat_col_pct "$PAIR_RAW" 2 50); d99=$(lat_col_pct "$PAIR_RAW" 2 99)
  g50=$(lat_col_pct "$PAIR_RAW" 1 50); g99=$(lat_col_pct "$PAIR_RAW" 1 99)

  # THE INSTRUMENT, FIRST, and through the SAME statistic: pair the direct transfer against
  # a stand-in that adds a known 500 ms. If the paired p99 cannot see half a second, the
  # few milliseconds below are not evidence of anything.
  lat_pairs "http://${E2E_HOST}:18609/x" 12 "$SLOW_RAW"
  slowadd=$(lat_delta_pct "$SLOW_RAW" 50)
  if awk -v a="$slowadd" 'BEGIN { exit !(a >= 300) }'; then
    pass "instrument: an upstream that sleeps 500 ms is measured ${slowadd} ms slower at the paired median, so this comparison can see added latency"
  else
    fail "instrument: a stand-in that sleeps 500 ms per request measured only ${slowadd} ms slower at the paired median — the timing cannot see half a second, so the added-latency result below is not evidence of anything"
  fi

  # Anti-vacuity: a curl that fails instantly also produces a small number.
  ok_direct=$(curl -s -o /dev/null --compressed -m 10 -w '%{http_code}' "http://${E2E_HOST}:18607/left-pad/latest")
  ok_gate=$(curl -s -o /dev/null --compressed -m 10 -w '%{http_code}' "http://${E2E_HOST}:18608/left-pad/latest")
  if [ "$ok_direct" = "200" ] && [ "$ok_gate" = "200" ]; then
    pass "both paths answer 200, so the timings above are of a served package rather than of a refusal"
  else
    fail "the measured paths did not both serve the package (direct=$ok_direct, gate=$ok_gate) — a fast error is not a fast pull"
  fi
  # AND THE MEASURED TRANSFERS WENT THROUGH THE GATE. Without this the whole leg passes
  # VACUOUSLY if the "through the gate" URL ever points somewhere else: a difference of zero is
  # exactly what a comparison of one upstream against itself reports, and every other check
  # here is satisfied by it.
  #
  # THE COUNT IS COMPARED TO $LAT_N, not to 1, and the difference is not pedantry: the first
  # version asked only for "at least one verdict", and the sabotage that points the measured
  # URL at the fixture STILL PASSED IT — the warm-up transfers and the 200-check go through the
  # gate whatever the measured URL is, so the gate had logged 6 verdicts while all 100 timed
  # pairs bypassed it. A vacuity guard that the vacuity it guards against can satisfy is
  # decoration. One log line per request, so the timed pairs must be in the count.
  gate_verdicts=$(docker logs "$LATGATE" 2>&1 | grep -c 'left-pad -> allowed=true')
  if [ "${gate_verdicts:-0}" -ge "$LAT_N" ]; then
    pass "the gate rendered ${gate_verdicts} verdicts for the measured package (>= ${LAT_N} timed transfers), so the timed pairs really went through it"
  else
    fail "the gate rendered only ${gate_verdicts} verdict(s) for the measured package but ${LAT_N} transfers were timed through it — the timed pairs did not go through the gate, and a difference of zero means nothing"
  fi

  if awk -v a="$add50" -v b="$LAT_CEILING_MS" 'BEGIN { exit !(a <= b) }'; then
    pass "added latency, paired median ${add50} ms (ceiling ${LAT_CEILING_MS} ms, ${LAT_N} pairs, hermetic — §3 is the published figure). Paired p99 ${add99} ms, printed not asserted; raw p50/p99 — direct ${d50}/${d99} ms, gate ${g50}/${g99} ms"
  else
    fail "the gate now adds ${add50} ms to the MEDIAN pull (paired over ${LAT_N} transfers; raw medians — direct ${d50} ms, through the gate ${g50} ms), over the ${LAT_CEILING_MS} ms ceiling. A cost paid on the median is paid by every developer on every install: something blocking has landed on the WARM path — a fresh upstream lookup, a scan awaited rather than launched, or a verdict recomputed instead of read from the cache (#21)."
  fi
  rm -f "$PAIR_RAW" "$SLOW_RAW"
fi
for c in "$FAKEUP" "$SLOWUP" "$LATGATE"; do docker rm -f "$c" >/dev/null 2>&1; done
docker network rm "$LAT_NET" >/dev/null 2>&1

say "4) FUNCTIONAL — the firewall renders a real verdict under the constraints"
# /healthz proves the process is alive, not that it WORKS. Layer 1 is the right
# functional probe: it is the only verdict that needs no network at all, so this leg
# measures the constraints rather than the internet.
printf '{"id":"MAL-HARDEN-1","ecosystem":"npm","name":"yj-harden-blocked"}\n' > "$ROOT/.hardening-feed.ndjson"
CONTAINERS="$CONTAINERS yjharden-run-fwfeed"
docker rm -f yjharden-run-fwfeed >/dev/null 2>&1
$NOPATHCONV docker run -d --name yjharden-run-fwfeed --read-only --user "${ARBITRARY_UID}:0" -p 18606:8080 \
  -v "$ROOT/.hardening-feed.ndjson:/feed/h.ndjson:ro" \
  -e FW_SCORECARD_MODE=stub -e FW_ECOSYSTEM=npm -e FW_MALWARE_LIST=/feed/h.ndjson \
  yjharden-firewall >/dev/null 2>&1 || fail "the firewall would not start with a read-only feed mount"
for i in $(seq 1 25); do curl -fsS -m 2 "http://${E2E_HOST}:18606/healthz" >/dev/null 2>&1 && break; sleep 1; done

# ANTI-VACUITY: a feed whose records were all SKIPPED yields 404, not 403, and a rig
# that only checked "not 200" would read that as a pass. Assert the feed actually
# loaded, and say so in the failure message.
# POLLED, not read once. This assertion failed in CI while passing locally on the
# first run of this rig: on Linux the services answer /healthz in ~0.4s, and
# `docker logs` had not yet surfaced the startup line the grep was looking for. The
# tell was that the failure message — built from a second `docker logs` a few
# milliseconds later — printed the very line it had just reported missing.
#
# It failed SAFE (a healthy service reported as broken), but a log-read race is the
# same defect in either direction, so it now waits like everything else here.
feed_loaded=0
for i in $(seq 1 20); do
  if has "$(docker logs yjharden-run-fwfeed 2>&1)" "1 package-wide advisories enforced"; then
    feed_loaded=1
    break
  fi
  sleep 1
done
if [ "$feed_loaded" = "1" ]; then
  pass "the read-only mounted feed was loaded and is enforced (1 advisory)"
else
  fail "the feed did not load: $(docker logs yjharden-run-fwfeed 2>&1 | grep -i 'malware feed' | tail -1). " \
       "A 403 below would be for the wrong reason, and a 404 would look like a pass."
fi

CODE=$(curl -s -o "$ROOT/.harden-block.json" -w '%{http_code}' -m 20 "http://${E2E_HOST}:18606/yj-harden-blocked" 2>/dev/null)
if [ "$CODE" = "403" ]; then
  pass "a real layer-1 block was rendered under read-only rootfs + unmapped uid (403)"
  if grep -q 'MAL-HARDEN-1' "$ROOT/.harden-block.json" 2>/dev/null; then
    pass "the refusal names the advisory, so the whole response path works, not just the status line"
  else
    fail "the refusal does not name the advisory: $(head -c 200 "$ROOT/.harden-block.json")"
  fi
else
  fail "the blocked package returned $CODE, not 403 — the firewall serves /healthz under the " \
       "constraints but cannot actually render a verdict, which is the thing that matters"
fi

say "4b) the firewall PULLS a signed snapshot, and refuses a tampered one (#157)"
# The same constraints as leg 4 (read-only root, unmapped uid), but no feed is mounted:
# FW_MALWARE_LIST points into an EMPTY writable tmpfs and FW_MALWARE_FEED_URL at a
# fixture server. The gate must seed itself from the pull before it starts, and the
# verdict below must come from bytes it fetched and verified -- nothing on the host.
# The fixture holds a signed snapshot, its signature and the PUBLIC key only.
FEEDNET="yjharden-feed-net"
FEEDSRV="yjharden-run-feedsrv"
FEEDGATE="yjharden-run-fwpull"
FEEDBAD="yjharden-run-fwpull-bad"
CONTAINERS="$CONTAINERS $FEEDSRV $FEEDGATE $FEEDBAD"
for c in $FEEDSRV $FEEDGATE $FEEDBAD; do docker rm -f "$c" >/dev/null 2>&1; done
docker network create "$FEEDNET" >/dev/null 2>&1
rm -rf "$ROOT/.hardening-feedsrv"
cp -r "$ROOT/e2e/feed-fetch-fixture" "$ROOT/.hardening-feedsrv"
FEED_PUB="$(tr -d '\r\n' < "$ROOT/e2e/feed-fetch-fixture/pubkey.txt")"

$NOPATHCONV docker run -d --name "$FEEDSRV" --network "$FEEDNET" \
  -e PYTHONUNBUFFERED=1 -v "$ROOT/.hardening-feedsrv:/srv:ro" "$PY_IMAGE" \
  python -m http.server 8000 --directory /srv >/dev/null 2>&1

run_pull_gate() {
  $NOPATHCONV docker run -d --name "$1" --network "$FEEDNET" --read-only \
    --user "${ARBITRARY_UID}:0" --tmpfs /feed:rw,mode=1777 -p "$2:8080" \
    -e FW_SCORECARD_MODE=stub -e FW_ECOSYSTEM=npm \
    -e FW_MALWARE_LIST=/feed/m.ndjson \
    -e FW_MALWARE_FEED_URL="http://${FEEDSRV}:8000/snapshot.ndjson" \
    -e FW_MALWARE_FEED_KEY="$FEED_PUB" \
    yjharden-firewall >/dev/null 2>&1
}

# The server must be answering before the gate asks it, or a startup refusal below
# would be about a server that was not up yet rather than about the bytes.
for i in $(seq 1 20); do
  srvlog="$(docker logs "$FEEDSRV" 2>&1)"
  has "$srvlog" "Serving HTTP" && break
  sleep 1
done

run_pull_gate "$FEEDGATE" 18610
for i in $(seq 1 25); do curl -fsS -m 2 "http://${E2E_HOST}:18610/healthz" >/dev/null 2>&1 && break; sleep 1; done
pull_log="$(docker logs "$FEEDGATE" 2>&1)"
if has "$pull_log" "so pulled one before starting" && has "$pull_log" "signature VERIFIED"; then
  pass "an empty read-only-root gate seeded itself from the pull and verified it"
else
  fail "the gate did not report a verified seed pull: $(printf '%s\n' "$pull_log" | grep -i 'snapshot\|malware feed' | tail -3)"
fi
# CONTACT: the fixture server must have been asked for the snapshot. Without this, a
# 403 below could come from a feed that reached the gate some other way.
if has "$(docker logs "$FEEDSRV" 2>&1)" "GET /snapshot.ndjson "; then
  pass "the fixture server was asked for the snapshot (contact proven)"
else
  fail "the fixture server was never asked for the snapshot, so nothing below proves a pull"
fi
CODE=$(curl -s -o "$ROOT/.harden-pull.json" -w '%{http_code}' -m 20 "http://${E2E_HOST}:18610/yj-harden-pulled" 2>/dev/null)
if [ "$CODE" = "403" ] && grep -q 'MAL-HARDEN-PULL' "$ROOT/.harden-pull.json" 2>/dev/null; then
  pass "the package named only in the PULLED snapshot is refused, naming its advisory (403)"
else
  fail "the pulled advisory is not enforced: code=$CODE body=$(head -c 200 "$ROOT/.harden-pull.json" 2>/dev/null)"
fi

# TAMPERED: one extra line changes the bytes the signature covers. The gate must refuse
# to start, name the failure, and name the fix, rather than boot enforcing nothing.
printf '{"id":"MAL-EVIL","ecosystem":"npm","name":"attacker-choice"}\n' >> "$ROOT/.hardening-feedsrv/snapshot.ndjson"
run_pull_gate "$FEEDBAD" 18611
for i in $(seq 1 20); do
  [ "$(docker inspect -f '{{.State.Running}}' "$FEEDBAD" 2>/dev/null)" = "false" ] && break
  sleep 1
done
bad_log="$(docker logs "$FEEDBAD" 2>&1)"
if [ "$(docker inspect -f '{{.State.Running}}' "$FEEDBAD" 2>/dev/null)" = "false" ] \
   && has "$bad_log" "does not verify" && has "$bad_log" "Seed that directory"; then
  pass "a tampered snapshot is refused at startup, with the reason and the fix named"
else
  fail "a tampered snapshot was not refused cleanly: $(printf '%s\n' "$bad_log" | tail -3)"
fi
for c in $FEEDSRV $FEEDGATE $FEEDBAD; do docker rm -f "$c" >/dev/null 2>&1; done
docker network rm "$FEEDNET" >/dev/null 2>&1
rm -rf "$ROOT/.hardening-feedsrv" "$ROOT/.harden-pull.json"

say "5) FUNCTIONAL — the approval service accepts a write and exports it"
# The audit log is the one write path in the stack. If a read-only rootfs broke it,
# #28's decision record would be empty on exactly the hardened deployments that care.
CODE=$(curl -s -o /dev/null -w '%{http_code}' -m 20 -X POST -H 'Content-Type: application/json' \
  -d '{"package":"yj-harden-pkg","ecosystem":"npm","action":"block","reason":"hardening rig","policy_digest":"deadbeef"}' \
  "http://${E2E_HOST}:18602/v1/events" 2>/dev/null)
if [ "$CODE" = "201" ]; then
  pass "an audit event was accepted under the constraints (201)"
else
  fail "POST /v1/events returned $CODE under the constraints, not 201"
fi
if has "$(curl -fsS -m 20 "http://${E2E_HOST}:18602/v1/events/export" 2>/dev/null)" 'yj-harden-pkg'; then
  pass "the compliance export returns the event that was just written (#28 path intact)"
else
  fail "the event was accepted but does not come back out of the export"
fi

say "6) no service requires a WRITABLE host directory"
# The JFrog failure mode, and the one #22 opens with: six issues filed over six years
# for "directory is not writable". We hold this by construction — durable state is a
# named VOLUME, never a bind mount — so it is worth an assertion that fails if anyone
# adds one.
#
# The docker socket is the single declared exception (see ROOT_BY_DESIGN).
violations=0
mounts=0
listmounts=0
for f in $(git ls-files 'docker-compose*.yml'); do
  while IFS= read -r line; do
    [ -z "$line" ] && continue
    mounts=$((mounts + 1))
    case "$line" in
      */var/run/docker.sock*) continue ;;
      *:ro) continue ;;
      # THE OPERATOR-LIST REPO (D193 / #58 increment 3b) — the second declared exception,
      # and the only read-write bind mount in the tree.
      #
      # Why it is writable at all: D193 ruled that the console EDITS the operator
      # allow/deny lists, and chose option (c) — the console commits them to git. So this
      # one service genuinely does need durable storage, and saying otherwise would be the
      # lie. That is a real cost of D193 and it is recorded here rather than hidden.
      #
      # Why a BIND MOUNT here rather than the named volume a deployment should use: leg 23
      # asserts on the resulting git history with plain git FROM THE HOST, which is the
      # whole claim being tested — an auditor does not need our console to read the audit
      # trail. A named volume would make that assertion impossible to write.
      #
      # ⚠️ SCOPED TO THE ASYNC OVERRIDE ON PURPOSE. docker-compose.asyncfake.yml is layered
      # by e2e/async_local.sh alone and is never part of a shipped deployment. The same
      # mount appearing in docker-compose.yml would be a real regression of the #22 claim,
      # so the file is part of the condition, not just the path.
      *)
        case "$f:$line" in
          docker-compose.asyncfake.yml:*/srv/lists*|docker-compose.asyncfake.yml:*/srv/lists-remote*)
            listmounts=$((listmounts + 1)); continue ;;
        esac
        printf 'FAIL: %s mounts a host path READ-WRITE: %s\n' "$f" "$(echo "$line" | tr -d ' -')"
        violations=$((violations + 1)) ;;
    esac
  done <<EOF
$(grep -E '^[[:space:]]+- (\.|/|\$)' "$f" 2>/dev/null)
EOF
done
if [ "$mounts" -lt 3 ]; then
  fail "only $mounts host mounts were examined; the bind-mount check parsed almost nothing"
elif [ "$violations" -eq 0 ]; then
  pass "all $mounts host mounts are read-only, the declared docker socket, or the declared operator-list repo ($listmounts)"
else
  FAIL=1
fi

# A pardon that no longer covers anything is a pardon waiting to cover something else --
# the same reasoning configsurface_test.go applies to its file-access allowances. If the
# operator-list mounts move or go away, this must be noticed HERE rather than silently
# widening the exception above to whatever lands on that path next.
if [ "$listmounts" -eq 0 ]; then
  fail "the operator-list mount exception matched nothing. Either those mounts moved (so they are now UNCHECKED) or they are gone and the exception should be deleted."
fi

say "RESULT"
if [ "$FAIL" -eq 0 ]; then
  echo "CONTAINER HARDENING: PASS"
else
  echo "CONTAINER HARDENING: FAIL"
fi
exit "$FAIL"
