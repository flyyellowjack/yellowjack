#!/usr/bin/env bash
# mirror_blackhole.sh — proves the scanner build SURVIVES ghcr.io and gcr.io being
# unreachable (#106's third acceptance box), on every pipeline, with a control.
#
# A nested docker daemon is started with ghcr.io and gcr.io pointed at 127.0.0.1 in its
# /etc/hosts, so any pull from either registry is refused at connect. Against that daemon:
#
#   CONTROL  a plain `docker build` of scanner/Dockerfile (the upstream defaults) MUST
#            FAIL, and its log must name the refused connection. This is what makes the
#            green build below mean something: a blackhole that lets the plain build
#            through would let the mirrored build through for the same non-reason.
#   TEST     the same Dockerfile built through scripts/mirror-bases.sh MUST SUCCEED,
#            with the wrapper accounting for every base: two from the mirror, the Go
#            toolchain from its declared upstream (docker.io, which is NOT blackholed —
#            it is the declared exception, preflighted by `ensure`, see the script).
#
# The nested daemon is reached through a port published on the outer daemon's host
# ($E2E_HOST: `docker` under GitLab's dind service, `localhost` on a laptop), for the
# same reason the other rigs do it that way: the job container cannot route to the outer
# daemon's bridge network. The outer daemon keeps its TLS settings; `nd` strips them for
# the nested one only.
#
# An availability fix that has only ever been observed working is not evidence (the
# issue's own words). This runs on every MR pipeline, so the property is re-proven
# rather than remembered.
set -uo pipefail
: "${YJ_BASE_MIRROR:?YJ_BASE_MIRROR must name the mirror prefix (CI sets it from CI_REGISTRY_IMAGE)}"
E2E_HOST="${E2E_HOST:-localhost}"
PORT="${BLACKHOLE_PORT:-23750}"
NESTED="yj-blackhole-$$"
FAIL=0
say()  { printf '\n=== %s ===\n' "$*"; }
pass() { printf 'PASS: %s\n' "$*"; }
bad()  { printf 'FAIL: %s\n' "$*"; FAIL=1; }
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
cleanup() { docker rm -f "$NESTED" >/dev/null 2>&1 || true; }
trap cleanup EXIT

# nd CMD.. — run CMD against the NESTED daemon (plain TCP, no TLS). Everything not
# wrapped in nd still talks to the outer daemon.
nd() { env -u DOCKER_TLS_VERIFY -u DOCKER_CERT_PATH DOCKER_HOST="tcp://$E2E_HOST:$PORT" "$@"; }

say "nested daemon with ghcr.io and gcr.io blackholed"
docker run -d --name "$NESTED" --privileged -e DOCKER_TLS_CERTDIR= -p "$PORT:2375" \
  --add-host ghcr.io:127.0.0.1 --add-host gcr.io:127.0.0.1 docker:27-dind >/dev/null \
  || { bad "could not start the nested daemon"; exit 1; }
for _ in $(seq 1 45); do nd docker version >/dev/null 2>&1 && break; sleep 2; done
if nd docker version --format 'nested daemon: {{.Server.Version}}' 2>/dev/null; then
  pass "nested daemon reachable at $E2E_HOST:$PORT"
else
  bad "the nested daemon never answered"; docker logs "$NESTED" 2>&1 | tail -10; exit 1
fi
# (paths live inside `sh -c` so a Git-Bash-on-Windows shell does not rewrite /etc/hosts)
if docker exec "$NESTED" sh -c 'grep -qE "^127\.0\.0\.1[[:space:]]+ghcr\.io" /etc/hosts && grep -qE "^127\.0\.0\.1[[:space:]]+gcr\.io" /etc/hosts'; then
  pass "ghcr.io and gcr.io resolve to 127.0.0.1 inside it"
else
  bad "the blackhole is not in place"; docker exec "$NESTED" sh -c 'cat /etc/hosts'; exit 1
fi

say "CONTROL: a plain build (upstream defaults) must FAIL against it, naming the refused connection"
if nd docker build --progress=plain -f scanner/Dockerfile -t yj-blackhole-control . > /tmp/blackhole-control.log 2>&1; then
  bad "the plain build SUCCEEDED against the blackholed daemon — the blackhole is not real, so nothing below would prove anything"
  tail -20 /tmp/blackhole-control.log
elif hasre "$(grep -E 'ghcr\.io|gcr\.io' /tmp/blackhole-control.log)" 'connection refused|dial tcp 127\.0\.0\.1'; then
  pass "plain build failed on the blackholed registry: $(grep -E 'ghcr\.io|gcr\.io' /tmp/blackhole-control.log | grep -iE 'refused|dial tcp 127' | head -1 | cut -c1-170)"
else
  bad "the plain build failed, but not on ghcr.io/gcr.io being unreachable — a different failure is not the control"
  tail -20 /tmp/blackhole-control.log
fi

say "mirror holds every mirrored base (idempotent; populates on the first run)"
if sh scripts/mirror-bases.sh ensure scanner/Dockerfile; then
  pass "ensure: mirror complete"
else
  bad "ensure failed — the mirror could not be completed, so the test below cannot run"; exit 1
fi

say "TEST: the same build through the mirror must SUCCEED against the blackholed daemon"
if nd sh scripts/mirror-bases.sh build scanner/Dockerfile -t yj-blackhole-proof . > /tmp/blackhole-test.log 2>&1; then
  cat /tmp/blackhole-test.log
  if grep -q 'base pull(s): 2 from' /tmp/blackhole-test.log && grep -q '1 declared upstream' /tmp/blackhole-test.log; then
    pass "mirrored build succeeded with ghcr.io and gcr.io unreachable: 2 bases from the mirror, the Go toolchain from docker.io"
  else
    bad "the mirrored build succeeded, but the wrapper's accounting is not the expected 2 mirrored + 1 declared upstream"
  fi
else
  bad "the mirrored build FAILED against the blackholed daemon"; cat /tmp/blackhole-test.log
fi

say "RESULT"
if [ "$FAIL" -eq 0 ]; then
  echo "ALL PASS: the scanner build survives ghcr.io and gcr.io being unreachable (#106)"
else
  echo "FAILED"
fi
exit "$FAIL"
