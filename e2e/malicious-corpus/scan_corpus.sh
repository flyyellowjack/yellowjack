#!/bin/sh
# Detection floor for the synthetic malicious corpus (issue #31).
# Asserts every fixture against manifest.json. Exits non-zero on ANY mismatch --
# a missed detection AND a clean-control false positive both fail.
# 'known-gap' fixtures are reported but never fail the run: they record a shape the
# current scanner does not detect (see manifest for the measurement behind each).
#
# Scanner is pluggable; GuardDog is the default (D118: adopted as an ADVISORY sidecar,
# so this asserts its detection floor, NOT that we gate on its output).
set -eu

IMAGE="${GUARDDOG_IMAGE:-ghcr.io/datadog/guarddog:latest}"
HERE="$(cd "$(dirname "$0")" && pwd)"
fail=0
checked=0
gaps=0

# ---- per-fixture wall-clock bound (issue #82) --------------------------------------
#
# On pipeline 2736252619 the job ran SEVEN fixtures in 2.5 minutes and then sat on the
# eighth (pypi/setup-exec) for 57 minutes with no output until the job budget killed it.
# It was not slow; it HUNG. With no bound on a single scan, one hung fixture converts
# the entire 60-minute job into a timeout, on a free plan with 400 CI minutes a month.
#
# Two facts measured in the real CI image (docker:27-cli, i.e. BusyBox) shape this:
#   - BusyBox `timeout` exits 143 (SIGTERM) or 137 (-s KILL), NOT GNU's 124, so all
#     three are treated as a timeout below.
#   - killing the `docker run` CLIENT does not stop the CONTAINER: it kept running on
#     the daemon after the client died. So every scan gets a name, and a timed-out one
#     is removed by name -- otherwise each hang leaks a running scanner and the next
#     fixture collides with it.
FIXTURE_TIMEOUT="${CORPUS_FIXTURE_TIMEOUT_SECS:-300}"

# rm_gone NAME -- force-remove NAME and wait until the daemon has actually released it.
# `docker rm -f` returns once the kill is SIGNALLED; the removal itself completes
# asynchronously, and it races the container's own --rm auto-removal (one of the two can
# even error "removal already in progress"). On a loaded shared runner that outlasts a
# fixed one-second grace: the selftest below failed 3/3 on the SaaS runner with the SAME
# code and the SAME docker:27-dind digest that had passed 4/4 an hour earlier, and 0/15
# locally (the host, a Docker 29 dind, and that exact CI image). A load-dependent timing
# flake, not a regression -- so wait for it to be gone, bounded, instead of guessing a
# sleep. Integer sleeps only: BusyBox.
rm_gone() {
  _rn=$1; _ri=0
  while [ "$_ri" -lt 20 ]; do
    docker rm -f "$_rn" >/dev/null 2>&1 || true
    docker inspect "$_rn" >/dev/null 2>&1 || return 0
    _ri=$((_ri + 1)); sleep 1
  done
  return 1
}

# run_bounded NAME CMD... -- run CMD under the wall-clock bound. Stdout passes through.
# Returns CMD's own status normally, or 124 on timeout (normalised across BusyBox/GNU),
# after removing the container NAME and WAITING for it to be gone, so nothing is left
# running and the next fixture cannot collide with it.
run_bounded() {
  _bname=$1; shift
  _brc=0
  timeout -s KILL "$FIXTURE_TIMEOUT" "$@" || _brc=$?
  case $_brc in
    124|137|143)
      # Two races, both measured on the SaaS runner, one cleanup. rm_gone (above) closes
      # the first: removal is asynchronous, so a single `rm -f` can return with the name
      # still held. The second is EARLIER: `timeout` kills the CLIENT, but the daemon
      # finishes creating the container regardless, and on a cold dind that can land
      # after the bound has already fired -- so any removal that runs now, rm_gone
      # included, finds nothing, and the container appears afterwards (`container leak:
      # rc=124, still present=1`, twice on !211's gate). So: poll for the name until a
      # wall-clock window closes, and hand it to rm_gone the moment it is seen. The
      # deadline is wall-clock, not a retry count, so a host with no daemon -- where
      # every docker call stalls ~20s -- pays one stall as before, not ten.
      _deadline=$(( $(date +%s) + ${CLEANUP_WINDOW_SECS:-10} ))
      while :; do
        if docker inspect "$_bname" >/dev/null 2>&1; then
          rm_gone "$_bname" || true
          break
        fi
        [ "$(date +%s)" -lt "$_deadline" ] || break
        sleep 1
      done
      return 124 ;;
  esac
  return $_brc
}

# --selftest: prove the bound bites, prove it does not mangle a normal scan, and prove
# a timed-out container is actually gone. A timeout that was never shown to fire is
# decoration, and #82 is exactly the failure that decoration would not prevent.
if [ "${1:-}" = "--selftest" ]; then
  FIXTURE_TIMEOUT=2
  ok=0; bad=0
  pass() { ok=$((ok + 1)); printf 'ok   %s\n' "$1"; }
  fail() { bad=$((bad + 1)); printf 'FAIL %s\n' "$1"; }

  # 1. a hung command is killed and reported as 124 BEFORE it would have finished on its
  #    own. The threshold is the command's natural duration, not a few seconds past the
  #    bound: measured under BusyBox, the kill itself takes 2s but `docker rm -f` against
  #    an unreachable daemon stalls ~22s, and a tight threshold blamed the bound for that.
  HANG=30
  t0=$(date +%s); _rc=0
  run_bounded corpus-selftest-none sleep "$HANG" >/dev/null 2>&1 || _rc=$?
  el=$(( $(date +%s) - t0 ))
  if [ "$_rc" -eq 124 ] && [ "$el" -lt "$HANG" ]; then pass "a hung scan is killed and reported as a timeout before it would have ended itself (rc=124, ${el}s < ${HANG}s)"
  else fail "hung scan not bounded: rc=$_rc after ${el}s"; fi

  # 2. control: a normal scan's output AND status pass through untouched
  _rc=0; _out=$(run_bounded corpus-selftest-none sh -c 'echo "3 risks detected"') || _rc=$?
  if [ "$_rc" -eq 0 ] && [ "$_out" = "3 risks detected" ]; then pass "a normal scan passes through with its output and status"
  else fail "normal scan mangled: rc=$_rc out=$_out"; fi

  # 3. control: a scanner ERROR keeps its own status -- it must not read as a timeout
  _rc=0; run_bounded corpus-selftest-none sh -c 'exit 3' >/dev/null 2>&1 || _rc=$?
  if [ "$_rc" -eq 3 ]; then pass "a scanner error keeps its own exit status (3), distinct from a timeout"
  else fail "exit status not preserved: rc=$_rc"; fi

  # 4. the container a timed-out scan was running in is GONE afterwards. Needs a daemon
  #    and an image; in CI the scanner image is already present. An abstention is printed
  #    as SKIP, never counted as a pass.
  if docker image inspect "$IMAGE" >/dev/null 2>&1; then
    cname="corpus-selftest-$$"
    docker rm -f "$cname" >/dev/null 2>&1 || true
    _rc=0; run_bounded "$cname" docker run --rm --name "$cname" --entrypoint sleep "$IMAGE" 60 >/dev/null 2>&1 || _rc=$?
    sleep 1
    if [ "$_rc" -eq 124 ] && ! docker ps -a --format '{{.Names}}' | grep -qx "$cname"; then pass "a timed-out scan's container is removed, not left running"
    else fail "container leak: rc=$_rc, still present=$(docker ps -a --format '{{.Names}}' | grep -cx "$cname")"; docker rm -f "$cname" >/dev/null 2>&1 || true; fi
  else
    printf 'SKIP leg 4 (container removal): scanner image %s not present here -- runs in CI\n' "$IMAGE"
  fi

  # 5. the cleanup must also catch a container that appears AFTER the kill -- the shape
  #    that went red twice on !211's gate and that rm_gone alone cannot see (a name that
  #    does not exist yet inspects as gone). Simulated deterministically, outside the
  #    bounded command so no process-group behaviour of `timeout` is involved: a
  #    detached creator makes the container ~2s after the 2s bound has killed the
  #    client. NEGATIVE CONTROL: CLEANUP_WINDOW_SECS=0 restores the one-shot behaviour
  #    and this leg must then FAIL with "late container leaked" -- run it that way once
  #    before trusting a green.
  if docker image inspect "$IMAGE" >/dev/null 2>&1; then
    cname="corpus-selftest-late-$$"
    docker rm -f "$cname" >/dev/null 2>&1 || true
    ( sleep 4; docker run -d --name "$cname" --entrypoint sleep "$IMAGE" 60 >/dev/null 2>&1 ) &
    _late=$!
    _rc=0; run_bounded "$cname" sleep 30 >/dev/null 2>&1 || _rc=$?
    wait "$_late" 2>/dev/null || true
    sleep 1
    if [ "$_rc" -eq 124 ] && ! docker ps -a --format '{{.Names}}' | grep -qx "$cname"; then pass "a container that appears AFTER the kill is still removed"
    else fail "late container leaked: rc=$_rc, still present=$(docker ps -a --format '{{.Names}}' | grep -cx "$cname")"; fi
    docker rm -f "$cname" >/dev/null 2>&1 || true
  else
    printf 'SKIP leg 5 (late container): scanner image %s not present here -- runs in CI\n' "$IMAGE"
  fi

  printf '\nselftest: %s passed, %s failed\n' "$ok" "$bad"
  [ "$bad" -eq 0 ] && [ "$ok" -ge 3 ]
  exit $?
fi

printf '== malicious-corpus detection floor ==\n'
printf 'scanner: %s\n\n' "$IMAGE"

# Preflight: name the real problem rather than emitting a cryptic scan error.
if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
  printf 'PREFLIGHT FAIL: image %s not present locally.\n' "$IMAGE" >&2
  printf '  fix: docker pull %s\n' "$IMAGE" >&2
  exit 2
fi

dirs=$(grep -o '"dir": "[^"]*"' "$HERE/manifest.json" | cut -d'"' -f4)
ecos=$(grep -o '"ecosystem": "[^"]*"' "$HERE/manifest.json" | cut -d'"' -f4)
expects=$(grep -o '"expect": "[^"]*"' "$HERE/manifest.json" | cut -d'"' -f4)

i=1
for d in $dirs; do
  eco=$(echo "$ecos" | sed -n "${i}p")
  expect=$(echo "$expects" | sed -n "${i}p")
  i=$((i + 1))

  # npm fixtures MUST use the TARBALL layout (files under package/). GuardDog resolves
  # package/package.json by convention; a bare-directory npm fixture silently skips every
  # metadata rule (install hooks, manifest mismatch) and reads as CLEAN -- a false green.
  # See README "The layout trap". Proven: 3 of 4 failed before restructuring.
  cname="yj-corpus-$$-$i"
  rc=0
  out=$(MSYS_NO_PATHCONV=1 run_bounded "$cname" docker run --rm --name "$cname" \
          -v "$HERE:/corpus:ro" "$IMAGE" "$eco" scan "/corpus/$d" --no-sandbox 2>/dev/null) || rc=$?
  # A timeout is its OWN class. Falling through would parse an empty $out as n=0 and
  # report a hung positive fixture as MISSED -- the wrong diagnosis, and the one an
  # operator would act on. Status right, reason wrong, is the failure this repo keeps
  # paying for.
  if [ "$rc" -eq 124 ]; then
    checked=$((checked + 1))
    printf 'FAIL  %-28s %-5s TIMEOUT: no verdict after %ss -- the scanner HUNG (not a miss; #82)\n' "$d" "$eco" "$FIXTURE_TIMEOUT"
    fail=$((fail + 1))
    continue
  fi
  n=$(printf '%s' "$out" | grep -oE '[0-9]+ risks? detected' | grep -oE '^[0-9]+' | tail -1)
  [ -n "${n:-}" ] || n=0

  case "$expect" in
    known-gap)
      gaps=$((gaps + 1))
      printf 'GAP   %-28s %-5s not detected (%s risk(s)) - documented, not asserted\n' "$d" "$eco" "$n"
      ;;
    clean)
      checked=$((checked + 1))
      if [ "$n" -eq 0 ]; then
        printf 'PASS  %-28s %-5s clean as required\n' "$d" "$eco"
      else
        printf 'FAIL  %-28s %-5s FALSE POSITIVE: %s risk(s) on the negative control\n' "$d" "$eco" "$n"
        fail=$((fail + 1))
      fi
      ;;
    *)
      checked=$((checked + 1))
      if [ "$n" -ge 1 ]; then
        printf 'PASS  %-28s %-5s detected (%s risk(s))\n' "$d" "$eco" "$n"
      else
        printf 'FAIL  %-28s %-5s MISSED: scanner reported 0 risks\n' "$d" "$eco"
        fail=$((fail + 1))
      fi
      ;;
  esac
done

printf '\nasserted=%s failed=%s documented-gaps=%s\n' "$checked" "$fail" "$gaps"
[ "$fail" -eq 0 ] || { printf 'DETECTION FLOOR BREACHED\n' >&2; exit 1; }
printf 'detection floor holds\n'
