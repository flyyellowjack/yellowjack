#!/usr/bin/env bash
# LOCAL-MODE borrow-a-score E2E (D39). Extends D33's api-mode cross-check to the async
# local path, and proves the thing unit tests can only approximate: with the REAL
# scheduler+scanner stack wired up and a REAL client driving it, a package that borrows
# someone else's repo is refused BEFORE a scan is launched.
#
# The rig (see e2e/fakeupstream/README.md): the UPSTREAM REGISTRY is crafted to lie
# about its source repo — the half of the attack a publisher actually controls — while
# deps.dev stays REAL (live api.deps.dev). Names are chosen so deps.dev already holds a
# SOURCE_REPO record to contradict the lie.
#
# Legs (each with a real client: npm / pip / mvn / crane):
#   A. npm   borrow  lodash -> claims expressjs/express  => BLOCK, and NO scan launched
#   B. npm   honest  left-pad                            => 403 pending + scan on the right repo
#   G. npm   unknown yj-unverifiable-d36 -> claims lodash => BLOCK (D36: no deps.dev record
#            at all is a DURABLE negative and now fails closed, where it used to degrade open)
#   C. pypi  borrow  six -> claims pallets/flask         => BLOCK, and NO scan launched
#   D. pypi  honest  certifi                             => 403 pending + scan on the right repo
#   E. maven borrow  guava -> claims junit-team/junit5    => BLOCK, and NO scan launched
#   F. oci   traefik (declares a source label)          => BLOCK as unverified (D48, #33:
#            deps.dev cannot index OCI, so the claim is unverifiable), and NO scan launched
#
# Prereq: the run-once scanner image must exist:
#   docker build -f scanner/Dockerfile -t yellowjack-scanner:dev .
# Run from the repo root:  bash e2e/verify_repo_local.sh
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
# Where the SCRIPT ITSELF reaches the stack's published ports. On a dev laptop that is
# localhost; under GitLab's docker:dind the containers run on the dind daemon and their
# published ports are reachable at the service host `docker`, not at the job container's
# own loopback — so CI sets E2E_HOST=docker. The real CLIENTS below need no such switch:
# they join the compose NETWORK and address services by name, which works identically in
# both environments.
E2E_HOST="${E2E_HOST:-localhost}"
# The control-plane ports are bound to LOOPBACK by default in docker-compose.yml, so an
# operator who deploys the shipped file does not publish an unauthenticated approval
# service to their network (#13 item 2 is still open). THIS RIG NEEDS THEM PUBLISHED:
# under docker:dind the script reaches the stack at E2E_HOST=docker, i.e. from OUTSIDE
# the compose network, so loopback on the daemon host is unreachable and every check
# returns curl code 000. Opting out here keeps the exception in the test harness, where
# it is visible, rather than weakening the file an operator deploys.
export YJ_CONTROL_PLANE_BIND=0.0.0.0
# POSTGRES_PASSWORD is REQUIRED by docker-compose.yml since #22 — the shipped file no
# longer carries a credential. This is a FIXTURE, not a secret: it is invented here, lives
# only in a throwaway stack this rig tears down, and grants nothing outside it. Same
# standing as the console credential docker-compose.e2e.yml already documents. NOTE it is
# also interpolated by compose for every command, including `logs` and `down`, so it is
# exported before the COMPOSE array rather than beside `up`.
export POSTGRES_PASSWORD="yj-e2e-fixture-not-a-secret"
COMPOSE=(docker compose -f docker-compose.yml -f docker-compose.e2e.yml -f docker-compose.verifyrepo.yml)
NET="yellowjack"
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

# fwlog <service> — the service's whole log so far.
fwlog() { "${COMPOSE[@]}" logs "$1" 2>/dev/null; }

# logmatch <service> <literal> — does the service's log contain <literal>?
#
# Deliberately NOT `fwlog svc | grep -q ...`. `grep -q` exits at the FIRST match, so a
# still-writing `docker compose logs` gets SIGPIPE and exits 141 — and under
# `set -o pipefail` the PIPELINE then reports failure even though the pattern WAS found.
# That is a false NEGATIVE on a security assertion, and it is load-bearing here: leg A
# reported "no mismatch log line" in CI while the very line it was looking for appeared
# in the same job output. It hid because it depends on WHERE in the log the match falls
# (an early match leaves more left to write, so SIGPIPE is likelier) — which is why the
# same helper passed on legs C and G, and why the whole rig passed on a laptop.
#
# Reading the log into a variable and matching with `case` removes the pipe entirely.
# All call sites match fixed strings, so no regex is needed.
logmatch() {
  local svc="$1" pat="$2" log
  log="$(fwlog "$svc")"
  case "$log" in *"$pat"*) return 0 ;; *) return 1 ;; esac
}

# logmatch_re <svc> <extended regex> — logmatch against a REGEX instead of a literal.
#
# Required for anything matching a decision line: #76 put an optional bracketed outcome
# token between the method and the package name (`GET [verdict-blocked] pkg -> …`), so
# 'GET <pkg>' is no longer contiguous text. The positive assertions below would fail
# loudly — but the NEGATIVE ones ("the plugin tree must not cross the gate") would start
# passing for the wrong reason, which is the failure this rig exists to prevent. Any
# 'GET <name>' assertion belongs here, not in logmatch.
#
# `grep -Ec` rather than `grep -Eq` for the reason given above: -q exits early and can
# SIGPIPE the producer.
logmatch_re() {
  local svc="$1" pat="$2"
  [ "$(fwlog "$svc" | grep -Ec "$pat")" -gt 0 ]
}

# assert_no_scan <repo> — the scheduler must never have been asked to scan <repo>.
# This is the load-bearing D39 assertion: a mismatch must be refused UPSTREAM of the
# scan launch, so the borrowed repo must appear nowhere in the scheduler's log.
# (`grep -c` is safe in a pipeline here, unlike `grep -q`: it reads its input to the
# end, so the producer is never killed by SIGPIPE. See logmatch above.)
assert_no_scan() {
  local repo="$1" leg="$2"
  local n
  n="$(fwlog scheduler | grep -c "$repo")"
  [ "$n" = "0" ] && pass "$leg: NO scan was launched on the borrowed repo ($repo)" \
                 || bad "$leg: scheduler saw the borrowed repo $repo $n time(s) — a scan WAS launched"
}

# wait_for_scan <repo> — poll the scheduler log until it launches a scan for <repo>.
wait_for_scan() {
  local repo="$1" leg="$2" i
  for i in $(seq 1 40); do
    if logmatch scheduler "scan $repo"; then
      pass "$leg: scan launched on the verified repo ($repo)"
      return 0
    fi
    sleep 3
  done
  bad "$leg: no scan was ever launched for $repo"
}

cleanup() {
  say "logs (tails)"
  "${COMPOSE[@]}" logs --tail=20 firewall firewall-pypi firewall-maven firewall-oci-verify scheduler 2>/dev/null
  say "teardown"
  "${COMPOSE[@]}" down -v >/dev/null 2>&1
}
trap cleanup EXIT

# FIRST, before spending four minutes building images: this rig verifies against the REAL
# api.deps.dev by design, so a 429 on a shared runner IP — or a change in deps.dev's own
# data — fails legs for reasons that are not regressions. The preflight names which one it
# is and exits with a distinct code (3 rate-limited / 4 premise drift / 5 unreachable)
# instead of leaving that to be inferred from a failed assertion.
bash e2e/depsdev_preflight.sh verifyrepo || exit $?

say "prereq: scanner image"
if ! docker image inspect yellowjack-scanner:dev >/dev/null 2>&1; then
  echo "building yellowjack-scanner:dev ..."
  # Through the mirror wrapper (#106): CI builds from our own registry, a laptop from upstream.
  sh scripts/mirror-bases.sh build scanner/Dockerfile -t yellowjack-scanner:dev . || { bad "scanner image build"; exit 1; }
fi

# Preflight: a port already held by something unrelated (e.g. a local
# Artifactory rig on 8081-8082) makes `compose up` fail with an error that reads like a
# docker problem. Name it up front instead.
say "preflight: required host ports are free"
for p in 8000 8080 8090 8182 8183 8184; do
  if has "$(docker ps --format '{{.Ports}}')" ":$p->"; then
    bad "host port $p is already published by another container — stop it or re-map this rig"
    docker ps --format '  {{.Names}}\t{{.Ports}}' | grep ":$p->"
    exit 1
  fi
done
pass "ports free"

say "bring up the local-mode stack (fake upstream + npm/pypi/maven/oci firewalls)"
"${COMPOSE[@]}" up -d --build \
  fakeupstream fakeupstream-maven postgres approval scheduler firewall firewall-pypi firewall-maven firewall-oci-verify \
  || { bad "compose up"; exit 1; }

say "wait for health"
for i in $(seq 1 40); do
  curl -fsS http://${E2E_HOST}:8080/healthz >/dev/null 2>&1 && \
  curl -fsS http://${E2E_HOST}:8182/healthz >/dev/null 2>&1 && \
  curl -fsS http://${E2E_HOST}:8183/healthz >/dev/null 2>&1 && \
  curl -fsS http://${E2E_HOST}:8184/healthz >/dev/null 2>&1 && \
  curl -fsS http://${E2E_HOST}:8090/healthz >/dev/null 2>&1 && break
  sleep 2
done

# Sanity: the crafted upstream really is serving the lie. If this breaks, every
# "blocked" below would be a false positive for the wrong reason.
say "sanity: the crafted upstream serves the borrowed claim"
CLAIM="$(curl -fsS http://${E2E_HOST}:8000/lodash/latest 2>/dev/null | tr -d ' \n')"
case "$CLAIM" in
  *expressjs/express*) pass "upstream claims expressjs/express for lodash (the lie is in place)" ;;
  *) bad "crafted upstream is not serving the borrowed claim: $CLAIM" ;;
esac

# ─────────────────────────── A. npm, borrowed repo ───────────────────────────
say "A) npm: real client installs 'lodash', which claims expressjs/express"
NPM_OUT="$(docker run --rm --network "$NET" \
  -e npm_config_registry=http://firewall:8080/ \
  -e npm_config_cache=/tmp/npmcache -e npm_config_fund=false -e npm_config_audit=false \
  node:22-alpine npm install --no-save lodash 2>&1)"
NPM_CODE=$?
[ "$NPM_CODE" != "0" ] && pass "A: real npm install FAILED (borrowed package not served)" \
                       || bad "A: npm install SUCCEEDED — a borrowed-score package was allowed"
CODE_A="$(curl -s -o /dev/null -w '%{http_code}' http://${E2E_HOST}:8080/lodash)"
[ "$CODE_A" = "403" ] && pass "A: firewall answers 403 (terminal block, not a retryable 503)" \
                      || bad "A: firewall code=$CODE_A (want 403)"
if logmatch firewall 'does not match'; then
  pass "A: firewall logged the mismatch (borrow-a-score tripwire)"
else
  bad "A: no mismatch log line — the block may be for an unrelated reason"
  printf '%s\n' "$NPM_OUT" | tail -5
fi
assert_no_scan "expressjs/express" "A"

# ─────────────────────────── B. npm, honest repo ───────────────────────────
say "B) npm: 'left-pad' declares the repo deps.dev records -> must reach the scanner"
# One request: the pull launches a background scan, so a second could see a
# different state and flake in a way that mimics a contract regression.
RESP_B="$(curl -s -w '
%{http_code}' http://${E2E_HOST}:8080/left-pad)"
CODE_B="$(printf '%s' "$RESP_B" | tail -n1)"
BODY_B="$(printf '%s' "$RESP_B" | sed '$d')"
[ "$CODE_B" = "403" ] && pass "B: cold pull of a VERIFIED package is 403 (D102)" \
                      || bad "B: code=$CODE_B (want 403)"
# Since D102 a pending cold pull and a block share the status, so matching 403 alone
# would also accept the package being DENIED — the opposite of what this leg claims.
has "$BODY_B" "still scanning" \
  && pass "B: it is PENDING (async contract intact), not a denial" \
  || bad "B: cold pull of a verified package is not pending: $BODY_B"
wait_for_scan "github.com/stevemao/left-pad" "B"

# ──────────────── G. npm, DURABLY UNVERIFIED (no deps.dev record) ────────────────
# The D36 leg (issue #18). Legs A/C/E cover a CONTRADICTED claim; this one covers the
# claim deps.dev can neither confirm nor contradict, which is the far more common — and
# pre-D36 wide open — case: a package published minutes ago has no deps.dev record, so
# the cross-check found nothing and fell back to scoring whatever repo it claimed.
#
# The fixture name is published NOWHERE, which is exactly why it is a faithful stand-in
# for a brand-new typosquat: deps.dev really does 404 it (no mock involved). It claims
# lodash's ~9-scoring repo, so pre-D36 this was allowed on a borrowed score.
say "G) npm: 'yj-unverifiable-d36' has NO deps.dev record and claims lodash's repo"
NPM_OUT_G="$(docker run --rm --network "$NET" \
  -e npm_config_registry=http://firewall:8080/ \
  -e npm_config_cache=/tmp/npmcache -e npm_config_fund=false -e npm_config_audit=false \
  node:22-alpine npm install --no-save yj-unverifiable-d36 2>&1)"
NPM_CODE_G=$?
[ "$NPM_CODE_G" != "0" ] && pass "G: real npm install FAILED (unverifiable package not served)" \
                         || bad "G: npm install SUCCEEDED — an unverifiable package was allowed (D36 regression)"
BODY_G="$(curl -s http://${E2E_HOST}:8080/yj-unverifiable-d36)"
CODE_G="$(curl -s -o /dev/null -w '%{http_code}' http://${E2E_HOST}:8080/yj-unverifiable-d36)"
# "deps.dev has no record" is a DURABLE answer, so it is a verdict the client should
# not retry — as opposed to the transient branch, which means we never decided.
#
# This leg used to prove that with the STATUS CODE (403 verdict vs 503 transient).
# D102 made both 403, so that discriminator is gone and checking the status alone
# would accept exactly the regression this leg exists to catch. The explanation is
# now what separates them, so that is what is asserted.
[ "$CODE_G" = "403" ] && pass "G: firewall answers 403" \
                      || bad "G: firewall code=$CODE_G (want 403)"
has "$BODY_G" "blocked by firewall" \
  && pass "G: it is a DURABLE VERDICT" \
  || bad "G: response is not a verdict: $BODY_G"
has "$BODY_G" "could not verify this package" \
  && bad "G: the durable no-record case was treated as TRANSIENT — the exact D36 "\
"regression this leg guards, now invisible to a status-code check: $BODY_G" \
  || pass "G: not misreported as a transient failure"
if logmatch firewall 'could not be verified'; then
  pass "G: firewall logged the unverified linkage (fail-closed, D36)"
else
  bad "G: no 'could not be verified' log line — the block may be for an unrelated reason"
  printf '%s\n' "$NPM_OUT_G" | tail -5
fi
# Same load-bearing assertion as the mismatch legs: verification gates the scan, so an
# unverifiable package must never reach the scheduler on the repo it claimed.
assert_no_scan "lodash/lodash" "G"

# ─────────────────────────── C. pypi, borrowed repo ───────────────────────────
say "C) pypi: real pip installs 'six', which claims pallets/flask"
PIP_OUT="$(docker run --rm --network "$NET" \
  -e PIP_INDEX_URL=http://firewall-pypi:8080/simple/ \
  -e PIP_TRUSTED_HOST=firewall-pypi \
  python:3.12-slim pip install --no-cache-dir six 2>&1)"
PIP_CODE=$?
[ "$PIP_CODE" != "0" ] && pass "C: real pip install FAILED (borrowed package not served)" \
                       || bad "C: pip install SUCCEEDED — a borrowed-score package was allowed"
if logmatch firewall-pypi 'does not match'; then
  pass "C: pypi firewall logged the mismatch"
else
  bad "C: no mismatch log line on the pypi firewall"
  printf '%s\n' "$PIP_OUT" | tail -5
fi
assert_no_scan "pallets/flask" "C"

# ─────────────────────────── D. pypi, honest repo ───────────────────────────
say "D) pypi: 'certifi' declares the repo deps.dev records -> must reach the scanner"
RESP_D="$(curl -s -w '
%{http_code}' http://${E2E_HOST}:8182/simple/certifi/)"
CODE_D="$(printf '%s' "$RESP_D" | tail -n1)"
BODY_D="$(printf '%s' "$RESP_D" | sed '$d')"
[ "$CODE_D" = "403" ] && pass "D: cold pull of a VERIFIED package is 403 (D102)" \
                      || bad "D: code=$CODE_D (want 403)"
has "$BODY_D" "still scanning" \
  && pass "D: it is PENDING, not a denial" \
  || bad "D: cold pull of a verified package is not pending: $BODY_D"
wait_for_scan "github.com/certifi/python-certifi" "D"

# ─────────────────────────── E. maven, borrowed repo ───────────────────────────
say "E) maven: real mvn resolves guava, whose POM claims junit-team/junit5"
# Route ARTIFACTS through the firewall but leave PLUGINS on real Central. This is the
# only shape that makes a local-mode maven leg meaningful, and it took three tries to
# find — recorded here so nobody repeats them:
#
#   1. <mirrorOf>*</mirrorOf> (what the api-mode e2e uses) also routes maven's own plugin
#      tree through the gate. In local mode with no GITHUB_TOKEN every gated artifact ends
#      as unscorable -> 403, so `mvn` dies on maven-dependency-plugin and never reaches
#      the artifact under test. A "failing" leg that proves nothing.
#   2. Pre-warming the plugin tree from Central first doesn't help: maven re-validates
#      plugin POMs against the remote, and its `_remote.repositories` origin tracking
#      re-resolves anything whose repo id changed — so the warmed plugins get fetched
#      through the gate anyway and 403 again.
#   3. This works: `-gs` REPLACES maven's global settings (dropping the
#      `external:http:*` blocker, which is why plain-http is reachable at all), and we
#      then override the `central` REPOSITORY to point at the firewall while pointing the
#      `central` PLUGIN repository at real Central. Artifacts cross the gate; the
#      toolchain does not. No mirror, so nothing else is captured.
MVN_SETTINGS='<settings>
  <profiles><profile><id>yj</id>
    <repositories><repository><id>central</id>
      <url>http://firewall-maven:8080/</url>
      <releases><enabled>true</enabled></releases>
    </repository></repositories>
    <pluginRepositories><pluginRepository><id>central</id>
      <url>https://repo.maven.apache.org/maven2</url>
    </pluginRepository></pluginRepositories>
  </profile></profiles>
  <activeProfiles><activeProfile>yj</activeProfile></activeProfiles>
</settings>'
MVN_OUT="$(docker run --rm --network "$NET" -e YJ_SETTINGS="$MVN_SETTINGS" \
  maven:3.9-eclipse-temurin-21 sh -c \
  'printf "%s" "$YJ_SETTINGS" > /tmp/settings.xml && mvn -q -gs /tmp/settings.xml -Dmaven.repo.local=/tmp/m2 dependency:get -Dartifact=com.google.guava:guava:33.6.0-jre' 2>&1)"
MVN_CODE=$?
[ "$MVN_CODE" != "0" ] && pass "E: real mvn resolve FAILED (borrowed artifact not served)" \
                       || bad "E: mvn resolve SUCCEEDED — a borrowed-score artifact was allowed"
# Guard against the false-signal failure this leg hit repeatedly: mvn dying on its own
# plugin tree instead of on the artifact under test proves nothing about verification.
# Asserted from the FIREWALL side rather than by grepping mvn's output — the gate's own
# decision log is authoritative, and mvn mentions plugin names in incidental warnings.
if logmatch_re firewall-maven 'GET (\[[a-z-]+\] )?com\.google\.guava:guava'; then
  pass "E: mvn actually requested guava THROUGH the gate (not a plugin-tree failure)"
else
  bad "E: the gate never saw com.google.guava:guava — mvn died before reaching it, so this leg proves nothing"
  printf '%s\n' "$MVN_OUT" | tail -8
fi
# ...and the toolchain must NOT have been routed through the gate, or a future settings
# change could silently reintroduce the plugin-bootstrap deadlock.
if logmatch_re firewall-maven 'GET (\[[a-z-]+\] )?org\.apache\.maven\.plugins'; then
  bad "E: maven's own plugin tree was routed through the gate — settings.xml split is broken"
else
  pass "E: maven's plugin tree bypassed the gate (only the artifact under test crossed it)"
fi
if logmatch firewall-maven 'does not match'; then
  pass "E: maven firewall logged the mismatch"
else
  bad "E: no mismatch log line on the maven firewall"
  printf '%s\n' "$MVN_OUT" | tail -8
fi
assert_no_scan "junit-team/junit5" "E"

# ─────────────────────────── F. oci, no deps.dev index ───────────────────────────
# deps.dev has no package index for OCI, so a self-declared repo can NEVER be
# cross-checked. Until #33 this degraded OPEN — keep the claim, log the gap — while every
# other durably unverifiable link failed closed under FW_UNVERIFIED_POLICY (D42). D48
# ruled that everything fails closed with the configurable override, so the REQUIRED
# behavior is now: the pull is REFUSED as unverified under the closed default this rig's
# firewall runs with, the log says why (no deps.dev index) and which knob lifts it, no
# mismatch is ever claimed (there is nothing to mismatch against), and — the D39
# property this rig exists for — no scan is launched on the claimed repo.
#
# library/traefik on purpose: the refusal is about an unverifiable CLAIM, so it only
# fires when the image actually DECLARES a repo (org.opencontainers.image.source).
# traefik declares github.com/traefik/traefik. (This comment used to say alpine declares
# none; it declares github.com/alpinelinux/docker-alpine — the #33 pipeline showed it.)
say "F) oci: real crane pull; deps.dev cannot index OCI -> refused as unverified (D48), no scan"
if docker run --rm --network "$NET" gcr.io/go-containerregistry/crane:latest \
  pull --insecure firewall-oci-verify:8080/library/traefik:latest /tmp/traefik.tar >/dev/null 2>&1; then
  bad "F: crane pull of an image with an unverifiable self-declared repo SUCCEEDED under the closed default"
else
  pass "F: crane pull refused (unverifiable claim, closed default)"
fi
if logmatch firewall-oci-verify 'cannot be verified: deps.dev has no oci index'; then
  pass "F: oci firewall logged WHY (no deps.dev index) and that it failed closed"
else
  bad "F: oci firewall did not log the unverifiable-claim refusal"
fi
if logmatch firewall-oci-verify 'does not match'; then
  bad "F: oci must never produce a mismatch block (deps.dev cannot index it)"
else
  pass "F: no spurious mismatch on oci"
fi
assert_no_scan "traefik/traefik" "F"

say "RESULT"
[ "$FAIL" = "0" ] && echo "VERIFY-REPO LOCAL E2E: PASS" || echo "VERIFY-REPO LOCAL E2E: FAIL"
exit "$FAIL"
