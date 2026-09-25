#!/usr/bin/env bash
# REGISTRY-IN-FRONT E2E (#98, D177) — the topology the whole integration story rests on,
# and until now the largest untested assumption in the design.
#
#   client -> Yellow Jack -> the customer's registry -> the public registry
#
# D177 put the gate IN FRONT of the customer's registry, and the reason that survives is
# ENFORCEMENT: from BEHIND a registry, a cache hit never reaches us, so a verdict cannot
# land on anything the registry already holds. From in front, every pull is seen (leg 4),
# every pull is judged (leg 7), and a package the customer has already cached can still
# be withdrawn (leg 9).
#
# D290 then made the position a DEPLOYMENT CHOICE rather than a ruling, because the two
# positions stop different events and neither dominates:
#
#   in front   stops the INSTALL, cache hits included   -- cannot stop ingest
#   behind     stops INGEST: the package never enters   -- cannot see a cache hit, and
#              the customer's registry at all (leg 10)     cannot withdraw what is cached
#
# Behind has one property worth stating because it is easy to miss: the only client is
# the registry itself, whose upstream the operator sets in a config file. Nothing on a
# developer machine changes, and there is nothing for a developer to re-point.
#
# ── WHY THIS RIG RUNS BOTH DIRECTIONS ────────────────────────────────────────────────
#
# "We see 100% of pulls including cache hits" is not a property of our code. It is a
# DIFFERENCE between two topologies, and a rig that stands up only the new one cannot
# show it — every assertion would pass equally well against a firewall that happened to
# be consulted twice for unrelated reasons. So the same registry image is wired both
# ways, the same package is pulled twice through each, and the leg asserts the two
# counts DIFFER. That also turns D151's prose ("a cache hit never reaches us") into a
# measured number for the first time.
#
# ── SUBSTRATE BEHAVIOUR WAS PROBED BEFORE THIS SCRIPT WAS WRITTEN ────────────────────
#
# A rig built on assumed substrate behaviour is the blind-assertion failure this project
# keeps writing negative controls against. Verified by hand on 2026-09-02, verdaccio:6:
#   - uplink up,      GET /left-pad -> 200
#   - uplink STOPPED, GET /left-pad -> 200, 31,157 bytes  (served from its own cache)
#   - uplink STOPPED, GET /lodash   -> 503                (never fetched: nothing cached)
# Leg 5 re-asserts that third line inside the rig, because it is what makes "it still
# worked" evidence rather than luck.
#
# ── STANDING NEGATIVE CONTROLS (run these when changing this leg) ─────────────────────
#
#  1. Point firewall-front's FW_UPSTREAM straight at `uplink` instead of at
#     custreg-front. Leg 4's "the customer registry served it from cache" then fails,
#     because there is no longer a caching registry in the path at all.
#  2. Point verdaccio-behind's uplink at `uplink` instead of at firewall-behind. Leg 2's
#     "its miss should reach it" then fails, because the firewall is no longer in that
#     path at all.
#     ⚠️ DO NOT use `cache: false` for this — it was tried and did NOT fire. That flag
#     governs TARBALL caching; packument metadata is stored locally regardless, so leg 6
#     kept passing. Leg 6b exists because of that miss: it proves the counter can move
#     inside the same run, which is what an external sabotage was failing to establish.
#  4. LEG 9 (revocation): change the `/lists` mount in the compose from the DIRECTORY to
#     the file (`./e2e/registryfront/lists/deny.txt:/lists/deny.txt`). Leg 9's in-front
#     assertion then fails and its message names the cause, because the driver's rewrite
#     produces a new inode the container never sees. Also: comment out the `printf >>
#     "$DENY_FILE"` line — the poll must time out and fail, never pass on a stale list.
#  5. LEG 10 (ingest): point verdaccio-behind's uplink at `uplink` instead of at
#     firewall-behind (the same edit as control 2). The denied package is then INGESTED:
#     the pull returns 200 and the storage probe finds it, so leg 10 fails on both. That
#     is what shows the refusal and the empty storage are the gate's doing.
#  6. LEG 11 (integrity): set TAMPER_MATCH on tamperfront to a string no path contains
#     (e.g. "/never/"). The hop then corrupts nothing: "THE TAMPER FIRED" fails, and so
#     does "TAMPERED: the pull FAILED" -- crane pulls a good image through the hop. That
#     is what ties the refusal to the damaged byte rather than to the extra hop.
#  3. Remove yj-registryfront-blocked from the feed. Leg 7 stops refusing and the
#     enforcement half is shown to be load-bearing rather than incidental.
#
# Run from the repo root:  bash e2e/registry_front.sh
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
E2E_HOST="${E2E_HOST:-localhost}"
# POSTGRES_PASSWORD is REQUIRED by docker-compose.yml since #22 — the shipped file no
# longer carries a credential. This is a FIXTURE, not a secret: it is invented here, lives
# only in a throwaway stack this rig tears down, and grants nothing outside it. Same
# standing as the console credential docker-compose.e2e.yml already documents. NOTE it is
# also interpolated by compose for every command, including `logs` and `down`, so it is
# exported before the COMPOSE array rather than beside `up`.
export POSTGRES_PASSWORD="yj-e2e-fixture-not-a-secret"
COMPOSE=(docker compose -f docker-compose.yml -f docker-compose.registryfront.yml)
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

# The package pulled through both topologies. left-pad is small, real, and stable.
PKG="left-pad"
# The package layer 1 refuses. It does not exist upstream, and that is deliberate: the
# refusal must be OURS, so a 404 from the registry could never be mistaken for a block.
BLOCKED="yj-registryfront-blocked"

# Leg 9 edits this list while the stack runs. It must exist and be EMPTY before the
# firewalls start: an absent path is a config error, and a leftover entry from a previous
# run would make leg 9's "before" assertion pass for the wrong reason.
LISTS_DIR="$(cd "$(dirname "$0")/.." && pwd)/e2e/registryfront/lists"
DENY_FILE="${LISTS_DIR}/deny.txt"
mkdir -p "$LISTS_DIR"
: > "$DENY_FILE"

cleanup() {
  : > "$DENY_FILE" 2>/dev/null || true
  "${COMPOSE[@]}" down -v --remove-orphans >/dev/null 2>&1 || true
}
trap cleanup EXIT

say "0) bring up both topologies"
"${COMPOSE[@]}" up -d --build uplink custreg-front custreg-behind firewall-front firewall-behind \
  firewall-oci-behind custreg-oci-behind tamperfront custreg-oci-tampered \
  >/tmp/rif-up.log 2>&1 || { cat /tmp/rif-up.log; fail "compose up"; exit 1; }

# Wait for both firewalls AND both registries. A leg that starts before the stack is
# ready reports a topology failure that is really a startup race.
ready() {
  local url="$1" name="$2" i
  for i in $(seq 1 60); do
    if curl -fsS -m 3 "$url" >/dev/null 2>&1; then pass "$name is up"; return 0; fi
    sleep 1
  done
  fail "$name never became ready at $url"; return 1
}
ready "http://${E2E_HOST}:8185/healthz" "firewall-front" || exit 1
ready "http://${E2E_HOST}:8186/healthz" "firewall-behind" || exit 1
ready "http://${E2E_HOST}:4873/-/ping"  "custreg-front (customer registry)" || exit 1
ready "http://${E2E_HOST}:4874/-/ping"  "custreg-behind (control)" || exit 1

# decisions <service> <pkg> — how many verdicts this firewall rendered for a package.
# Counted from the firewall's own decision log line, which is the same source an
# operator would read, rather than from a test-only counter that could drift from it.
# uplink_answers — is the nginx uplink serving HTTP *right now*?
#
# Probed from INSIDE the compose network on purpose: `uplink` publishes no host port
# (see docker-compose.registryfront.yml), so there is nothing for the host's curl to
# poll, which is how the wrong service came to be polled instead — see leg 6b.
#
# busybox wget prints the response status line to stderr under -S, so an `HTTP/` line
# means nginx answered — including a 404, which is still proof it is listening. Measured
# against the pinned uplink image before this was written: connection refused → no
# `HTTP/` line (not ready); nginx serving → `HTTP/` line; nginx answering 404 → `HTTP/`
# line. A *stopped* container makes `exec` itself fail, which also reports not-ready —
# and leg 3 asserts exactly that, so this probe is checked before it is trusted.
uplink_answers() {
  "${COMPOSE[@]}" exec -T uplink sh -c 'out=$(wget -S -q -O /dev/null http://127.0.0.1:80/ 2>&1); case "$out" in *"HTTP/"*) exit 0 ;; esac; exit 1' >/dev/null 2>&1
}

# diagnose_chain WHICH RC ERRFILE — say WHY a precondition pull failed, before exiting.
#
# Legs 1 and 2 exit(1) when their chain does not resolve, which is right: every count
# below them is meaningless if the topology is broken. But they exit BEFORE the log dump
# at the end of the run, so the entire diagnostic for "the chain did not resolve" was
# that one sentence. Measured on this rig's own MR (!229): leg 2 failed in CI, the job
# trace carried no curl error and no service log, and the cause had to be inferred from
# a local re-run. That is the same "named, distinguishable failure" gap #106 records
# against a generic build failure.
#
# curl's exit code alone separates the cases that matter, and the services in that chain
# say the rest. This prints and does not decide: the leg still fails.
diagnose_chain() {
  which="$1"; rc="$2"; err="$3"
  printf '  curl exit=%s (28=timeout, 7=connection refused, 52=empty reply, 56=recv error, 22=HTTP error)\n' "$rc"
  [ -s "$err" ] && printf '  curl says: %s\n' "$(tr -d '\r' < "$err" | tail -3 | tr '\n' ' ')"
  case "$which" in
    front)  svcs="firewall-front custreg-front uplink" ;;
    *)      svcs="custreg-behind firewall-behind uplink" ;;
  esac
  for s in $svcs; do
    printf '  --- %s (last 12 lines) ---\n' "$s"
    "${COMPOSE[@]}" logs --tail 12 "$s" 2>&1 | sed 's/^/    /'
  done
}

decisions() {
  "${COMPOSE[@]}" logs "$1" 2>/dev/null | grep -c "\] $2 ->" || true
}

say "1) ANTI-VACUITY: the in-front chain resolves at all"
# Everything below is a comparison of counts; if the chain is broken they are all zero
# and the negative assertions pass by accident. So this runs first and hard-fails.
if curl -fsS -m 30 "http://${E2E_HOST}:8185/${PKG}" -o /tmp/rif-front1.json 2>/tmp/rif-front1.err; then
  SIZE=$(wc -c < /tmp/rif-front1.json)
  if [ "$SIZE" -gt 1000 ]; then
    pass "client -> Yellow Jack -> customer registry -> public registry resolved ($SIZE bytes)"
  else
    fail "the in-front chain returned only $SIZE bytes; nothing below can be trusted"
    diagnose_chain front "(a short body, not a transport failure)" /tmp/rif-front1.err
    exit 1
  fi
else
  rc=$?
  fail "the in-front chain did not resolve at all; nothing below can be trusted"
  diagnose_chain front "$rc" /tmp/rif-front1.err
  exit 1
fi

say "2) the same pull through the BEHIND topology also resolves"
if curl -fsS -m 30 "http://${E2E_HOST}:4874/${PKG}" -o /tmp/rif-behind1.json 2>/tmp/rif-behind1.err; then
  pass "client -> customer registry -> Yellow Jack -> public registry resolved"
else
  rc=$?
  fail "the behind-the-registry chain did not resolve; the control is unusable"
  # This chain is the tighter budget of the two, which is worth knowing when reading the
  # output above: the customer registry's own uplink timeout (10s, verdaccio-behind.yaml)
  # has to cover OUR firewall plus the nginx uplink plus the public registry, whereas in
  # the in-front topology that same 10s covers only nginx plus the public registry and our
  # firewall sits under curl's 30s. Measured on the dev host: front cold 1.4s, behind cold
  # 2.0-2.7s — roughly 4x headroom here, which a loaded shared runner can plausibly spend.
  # Stated as a lead for whoever reads a `curl exit=28` above, NOT as a diagnosis.
  diagnose_chain behind "$rc" /tmp/rif-behind1.err
  exit 1
fi

FRONT_1=$(decisions firewall-front "$PKG")
BEHIND_1=$(decisions firewall-behind "$PKG")
printf 'decisions after one pull each: in-front=%s behind=%s\n' "$FRONT_1" "$BEHIND_1"
[ "$FRONT_1" -ge 1 ] || fail "the in-front firewall rendered no decision on the first pull"
[ "$BEHIND_1" -ge 1 ] || fail "the behind firewall rendered no decision on the first pull (its miss should reach it)"

say "3) cut the wire to the public registry"
"${COMPOSE[@]}" stop uplink >/dev/null 2>&1 && pass "uplink stopped: nothing can reach the public registry now" \
  || { fail "could not stop the uplink"; exit 1; }
# INSTRUMENT CHECK for leg 6b's readiness gate, taken here because this is the one
# moment in the run when the uplink is KNOWN to be down. A readiness probe that can only
# answer "ready" is the defect leg 6b just had: it waits zero seconds and reads as a wait.
if uplink_answers; then
  fail "the uplink readiness probe reports READY while the uplink is stopped, so it cannot " \
       "gate leg 6b's restart — every wait it performs would be vacuous"
else
  pass "the uplink readiness probe can say NOT ready (checked while the uplink is stopped)"
fi

say "4) IN FRONT: the second pull is served from the customer registry's own cache — and WE STILL SEE IT"
if curl -fsS -m 30 "http://${E2E_HOST}:8185/${PKG}" -o /tmp/rif-front2.json 2>/dev/null; then
  pass "the pull succeeded with the public registry unreachable, so it was served locally"
else
  fail "the pull failed with the uplink down; the customer registry did not serve from cache, " \
       "so this leg cannot distinguish the two topologies"
fi
FRONT_2=$(decisions firewall-front "$PKG")
printf 'in-front decisions: before=%s after=%s\n' "$FRONT_1" "$FRONT_2"
if [ "$FRONT_2" -gt "$FRONT_1" ]; then
  pass "VISIBILITY (D177): a locally-served pull still reached us and was judged"
else
  fail "a locally-served pull did NOT reach us. A verdict cannot apply to a pull the gate " \
       "never sees, which is the entire reason D177 put us in front."
fi

say "5) ANTI-VACUITY for the cache: a package never fetched must NOT resolve with the uplink down"
# Without this, leg 4 passes for a registry that is quietly passing requests through
# rather than serving anything from a cache — "it still worked" would prove nothing.
if curl -fsS -m 30 "http://${E2E_HOST}:8185/lodash" -o /dev/null 2>/dev/null; then
  fail "a package that was never fetched resolved with the public registry unreachable — " \
       "the customer registry is not really caching, so leg 4 proves nothing"
else
  pass "an uncached package fails with the uplink down, so leg 4's success WAS the cache"
fi

say "6) THE CONTROL — BEHIND the registry, the same cache hit never reaches us"
if curl -fsS -m 30 "http://${E2E_HOST}:4874/${PKG}" -o /dev/null 2>/dev/null; then
  pass "the behind-topology pull was served (from the registry's cache)"
else
  fail "the behind-topology second pull failed; the control cannot be measured"
fi
BEHIND_2=$(decisions firewall-behind "$PKG")
printf 'behind decisions: before=%s after=%s\n' "$BEHIND_1" "$BEHIND_2"
if [ "$BEHIND_2" -eq "$BEHIND_1" ]; then
  pass "MEASURED: from behind, the cache hit did NOT reach us — D151's prose claim, now a number"
else
  fail "the behind-topology firewall saw the cache hit (before=$BEHIND_1 after=$BEHIND_2). " \
       "Either the registry did not serve from cache, or the topologies are not actually different — " \
       "and if they are not, leg 4 proves nothing either."
fi

say "6b) ANTI-VACUITY for the control: that counter must be able to MOVE"
# Leg 6 asserts a count STAYED THE SAME. On its own that is satisfied by a firewall
# nothing ever reaches — a stuck counter and a correct measurement look identical.
#
# This was found by a negative control that did NOT fire: setting `cache: false` on the
# behind-topology registry left leg 6 passing, because verdaccio's uplink cache flag
# governs TARBALLS while packument metadata is stored locally regardless. The control
# was aimed at the wrong knob. Rather than hunt for a sharper external sabotage, the
# discriminator belongs here, in the run: bring the wire back and pull a package that
# registry has never seen. That is a MISS, so it must reach us, and the same counter
# must increase.
"${COMPOSE[@]}" start uplink >/dev/null 2>&1 && pass "uplink restarted" || fail "could not restart the uplink"
# READINESS MUST WATCH THE SERVICE THAT WAS RESTARTED.
#
# This loop used to poll `http://$E2E_HOST:4874/-/ping` — that is custreg-behind, which
# this rig never stops. It answered on the first iteration, so the loop waited ZERO
# seconds and the pull below raced nginx's startup inside the uplink container.
#
# Measured, twice, on 2026-09-10: once here on an MR and once on UNTOUCHED `main`
# (pipeline 2835766917), both failing on this exact leg with the firewall-behind log
# showing `upstream temporarily unavailable: Get "http://uplink:80/is-number/latest"`.
# The tell is the clock: the restart and that dial error carry the same second, so no
# wait happened at all. 2 failures in 49 runs since 2026-09-07 — rare enough to look
# like weather, which is why it is worth fixing rather than re-running.
#
# Same shape as !212's wait-until-gone: a probe pointed at the wrong thing is a no-op
# that reads as a wait. The fix is the gate, never the assertion below it.
waited=0
uplink_up=0
while [ "$waited" -le 60 ]; do
  if uplink_answers; then uplink_up=1; break; fi
  sleep 1
  waited=$((waited + 1))
done
if [ "$uplink_up" = "1" ]; then
  pass "the uplink is answering again (${waited}s after the restart)"
else
  fail "the uplink did not answer within ${waited}s of being restarted, so the miss below " \
       "cannot be attributed: a failure would mean 'nginx was still starting', not 'the counter is stuck'"
fi
if curl -fsS -m 30 "http://${E2E_HOST}:4874/is-number" -o /dev/null 2>/dev/null; then
  BEHIND_3=$(decisions firewall-behind "is-number")
  if [ "$BEHIND_3" -ge 1 ]; then
    pass "a MISS through the same behind-topology firewall DID reach it, so leg 6's unchanged count is a real observation and not a stuck counter"
  else
    fail "a miss did not reach the behind-topology firewall either — that firewall is not in "          "the path at all, so leg 6 measured nothing"
  fi
else
  fail "could not pull an uncached package through the behind topology to prove the counter moves"
fi

say "7) ENFORCEMENT: from in front, a cached package cannot bypass the gate"
# The other half of D177. Being in the path for 100% of pulls is only worth having if
# the verdict still applies to the ones the customer's registry could serve itself.
CODE=$(curl -s -o /tmp/rif-blocked.json -w '%{http_code}' -m 30 "http://${E2E_HOST}:8185/${BLOCKED}" 2>/dev/null)
if [ "$CODE" = "403" ]; then
  pass "layer 1 refused the blocked package from in front (403)"
  if grep -q 'MAL-RIF-1' /tmp/rif-blocked.json 2>/dev/null; then
    pass "the refusal names the advisory, so a developer can look it up"
  else
    fail "the refusal does not name the advisory: $(head -c 200 /tmp/rif-blocked.json)"
  fi
else
  fail "the blocked package returned $CODE, not 403 — being in front buys nothing if the " \
       "verdict does not apply"
fi

say "8) OCI, from behind: registry:2 pull-through HEADs the manifest at the gate (#108)"
# Legs 1-7 are npm over curl GETs. This is the leg the rig was missing: the OCI form of
# the behind-topology is a registry:2 PULL-THROUGH pointed at an OCI-mode gate, and
# registry:2 HEADs a manifest before it GETs it. #108 was that HEAD being aborted as a
# short transfer, which registry:2 reported to the client as "not found". Measured on
# 2026-09-09 through exactly this topology -- pre-fix image: HEAD 404 / GET 404 / 2
# SHORT lines; fixed image: 200 / 200 / 0. Those numbers are what the three checks
# below assert.
ready "http://${E2E_HOST}:8187/healthz" "firewall-oci-behind" || FAIL=1
ready "http://${E2E_HOST}:5001/v2/"     "custreg-oci-behind (registry:2 pull-through)" || FAIL=1
# The Accept header is LOAD-BEARING, not decoration. alpine:3.19 is a multi-arch index
# and registry:2 refuses to hand an index to a client that did not say it accepts one
# ("OCI index found, but accept header does not support OCI indexes" -> 404). A bare
# curl therefore 404s on a FIXED gate too -- a different failure from #108, and one
# that cost a false diagnosis while building this leg. Real clients send these.
ACCEPT='Accept: application/vnd.oci.image.index.v1+json, application/vnd.docker.distribution.manifest.list.v2+json, application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.v2+json'
OCI_REF="http://${E2E_HOST}:5001/v2/library/alpine/manifests/3.19"
OH=$(curl -s -o /dev/null -D /tmp/rif-oci-head.txt -w '%{http_code}' -m 90 -I -H "$ACCEPT" "$OCI_REF" 2>/dev/null)
OG=$(curl -s -o /tmp/rif-oci-manifest.json -w '%{http_code}' -m 90 -H "$ACCEPT" "$OCI_REF" 2>/dev/null)
if [ "$OH" = "200" ] && [ "$OG" = "200" ] && grep -q schemaVersion /tmp/rif-oci-manifest.json 2>/dev/null; then
  pass "registry:2 resolved alpine:3.19 through the OCI gate (HEAD $OH, GET $OG, a real manifest)"
else
  fail "OCI pull-through failed: HEAD=$OH GET=$OG -- the #108 shape (a docker pull reports not found)"
fi
# Anti-vacuity: the HEAD must actually have REACHED the gate, or the pass above says
# nothing about the request #108 broke. Logs are read into a variable and never piped
# straight into grep -q: under pipefail a still-writing `compose logs` dies of SIGPIPE
# and reports a FOUND match as missing (the !54 lesson).
OCILOG=$("${COMPOSE[@]}" logs --no-color firewall-oci-behind 2>/dev/null || true)
HEADS=$(printf '%s\n' "$OCILOG" | grep -c 'HEAD /v2/library/alpine/manifests/3.19' || true)
if [ "${HEADS:-0}" -ge 1 ]; then
  pass "the gate relayed $HEADS manifest HEAD(s) -- the request #108 broke was exercised, not assumed"
else
  fail "no manifest HEAD reached the gate, so this leg did not test the #108 path at all"
fi
SHORTS=$(printf '%s\n' "$OCILOG" | grep -c 'SHORT upstream transfer for HEAD' || true)
if [ "${SHORTS:-0}" -eq 0 ]; then
  pass "no HEAD was aborted as a short transfer"
else
  fail "$SHORTS HEAD(s) aborted as SHORT upstream transfer -- #108 has regressed"
fi

# Leg 9 -- a digest in tag position (#109). A request for manifests/sha256-<hex> is the
# OCI 1.1 referrers-tag fallback (cosign's convention too): a lookup ABOUT the image whose
# digest that is. One reached the gate through registry:2 in the #98 run, and the gate
# read it as a tag, 404'd on it, and filed an image it had scored seconds earlier as
# unscorable -- waved through fail-open, refused fail-closed. The behind-gate runs
# fail-closed here for exactly that reason: under FW_UNSCORABLE_POLICY=allow this leg
# could not fail. registry:2 does not send the lookup on its own on a plain warm GET
# (measured 2026-09-09: zero such requests), so the leg SENDS it, for the digest leg 8's
# HEAD just returned -- through registry:2, so the pull-through forwards it to the gate.
OCI_DIGEST=$(grep -i '^docker-content-digest:' /tmp/rif-oci-head.txt 2>/dev/null | tr -d '\r' | awk '{print $2}')
case "$OCI_DIGEST" in
  sha256:*) pass "leg 8's HEAD named the manifest digest ($OCI_DIGEST)" ;;
  *)        fail "leg 8's HEAD carried no Docker-Content-Digest, so leg 9 has no digest to look up" ;;
esac
REF_TAG="sha256-${OCI_DIGEST#sha256:}"
RT=$(curl -s -o /dev/null -w '%{http_code}' -m 90 -H "$ACCEPT" "http://${E2E_HOST}:5001/v2/library/alpine/manifests/${REF_TAG}" 2>/dev/null)
OCILOG=$("${COMPOSE[@]}" logs --no-color firewall-oci-behind 2>/dev/null || true)
# Anti-vacuity: the tag-position request must actually have reached the gate.
REVALS=$(printf '%s\n' "$OCILOG" | grep -c "manifests/${REF_TAG}" || true)
if [ "${REVALS:-0}" -ge 1 ]; then
  pass "the referrers-tag lookup for $OCI_DIGEST reached the gate $REVALS time(s) through registry:2 (client saw $RT)"
else
  fail "no manifests/${REF_TAG} request reached the gate, so this leg did not test #109 at all (client saw $RT)"
fi
# The gate must have judged it as the IMAGE the digest names -- the identity carries
# @sha256:, and the decision is the same allow the cold pull got -- never as a tag it
# then failed to fetch.
JUDGED=$(printf '%s\n' "$OCILOG" | grep -c 'library/alpine@sha256:' || true)
if [ "${JUDGED:-0}" -ge 1 ]; then
  pass "the gate judged the lookup under the digest identity library/alpine@sha256:... ($JUDGED line(s))"
else
  fail "no decision names library/alpine@sha256:... -- the digest in tag position was not read as the image's digest"
fi
MISFILED=$(printf '%s\n' "$OCILOG" | grep -c 'manifest fetch returned 404' || true)
if [ "${MISFILED:-0}" -eq 0 ]; then
  pass "no lookup fetched the digest AS A TAG and 404'd"
else
  fail "$MISFILED lookup(s) fetched the digest as a tag and got 404 -- #109 has regressed"
fi
REFUSED=$(printf '%s\n' "$OCILOG" | grep -c "manifests/${REF_TAG}.*403\|BLOCKED.*sha256-" || true)
if [ "${REFUSED:-0}" -eq 0 ]; then
  pass "the lookup was not refused as unscorable under FW_UNSCORABLE_POLICY=block"
else
  fail "the lookup was refused ($REFUSED line(s)) -- under fail-closed that is the #109 shape"
fi
say "9) REVOCATION: a package already CACHED by the customer registry can still be withdrawn — from in front only"
# The third thing being in front buys, after visibility (leg 4) and enforcement (leg 7),
# and the one D153 found another product doing that we could not demonstrate.
#
# Leg 7 is NOT this. It pulls a package that was blocked from the start and was never
# fetched, so it shows the gate refuses -- it cannot show that a verdict REACHES an
# artifact the customer already holds. That is the whole question for revocation: an
# advisory lands after the package is in the customer's cache. This leg answers it, and
# the uplink is still down from leg 3, so nothing here can be served from upstream.
#
# left-pad is cached in BOTH registries by now (legs 4 and 6 proved it), which is what
# makes the control free: the same deny list is wired into both firewalls.
if curl -fsS -m 30 "http://${E2E_HOST}:8185/${PKG}" -o /dev/null 2>/dev/null; then
  pass "before revocation, the cached package resolves through the front (the 'before' state is real)"
else
  fail "the cached package did not resolve before revocation, so a later 403 would prove nothing"
fi

printf '%s\n' "$PKG" >> "$DENY_FILE"
# Wait on the MECHANISM, not on a duration. listReloadTTL is 5s, so poll for the verdict
# to flip and fail if it never does -- a fixed sleep would pass vacuously if the mount
# were wrong (the exact failure the compose comment warns about), and leg 6b already cost
# this rig one vacuous wait.
REVOKED=""
for _ in $(seq 1 20); do
  CODE=$(curl -s -o /tmp/rif-revoked.json -w '%{http_code}' -m 30 "http://${E2E_HOST}:8185/${PKG}" 2>/dev/null)
  if [ "$CODE" = "403" ]; then REVOKED=yes; break; fi
  sleep 1
done
if [ -n "$REVOKED" ]; then
  pass "IN FRONT: the cached package is refused after the deny list changed — revocation reaches a package the customer already has"
  if grep -qiE 'deny|operator|organi[sz]ation' /tmp/rif-revoked.json 2>/dev/null; then
    pass "the refusal is attributed to the operator, not to an advisory (D193)"
  else
    fail "the refusal does not say WHO decided: $(head -c 200 /tmp/rif-revoked.json)"
  fi
else
  fail "the package was still served $(printf '%s' "${CODE:-?}") after the deny list changed and the reload TTL elapsed — " \
       "either the list is not being re-read, or the /lists DIRECTORY mount is wrong (a FILE mount pins the inode)"
fi
# INSTRUMENT CHECK: the flip above must be the list reloading, not something else.
#
# The entry COUNT is load-bearing and was got wrong once. Matching "deny-list .* reloaded"
# alone passes under the sabotage below, because both firewalls log a reload of the EMPTY
# list at startup ("reloaded: 0 entries") -- so the check said the mechanism fired when
# nothing had been read. Requiring a non-zero count is what ties this line to the edit.
# POLLED, not read once. The first version grepped immediately after the 403 arrived and
# failed in CI while passing locally: the client sees the refusal before `compose logs`
# has surfaced the line that explains it, so a single read races log propagation. The
# assertion is unchanged; only the patience is.
RELOADED=""
for _ in $(seq 1 15); do
  if hasre "$("${COMPOSE[@]}" logs firewall-front 2>/dev/null)" 'deny-list .* reloaded: [1-9][0-9]* entries'; then
    RELOADED=yes; break
  fi
  sleep 1
done
if [ -n "$RELOADED" ]; then
  pass "the firewall logged a deny-list reload with entries, so the flip is the mechanism under test"
else
  fail "no NON-EMPTY deny-list reload appears in the front firewall's log; the 403 (if any) may be " \
       "arriving for another reason, and a startup reload of the empty list does not count"
fi

# THE CONTROL. Same package, same deny list, same firewall image -- only the topology
# differs. From behind, the customer's registry answers from its own cache and never
# asks us, so the withdrawal cannot land. If this ever returns 403, the two topologies
# are not actually different and leg 9's headline proves nothing.
BCODE=$(curl -s -o /dev/null -w '%{http_code}' -m 30 "http://${E2E_HOST}:4874/${PKG}" 2>/dev/null)
if [ "$BCODE" = "200" ]; then
  pass "CONTROL: from BEHIND, the revoked package is still served from the registry's cache — revocation is a property of being IN FRONT"
elif [ "$BCODE" = "403" ]; then
  fail "the behind topology also refused ($BCODE): the topologies are not different here, so leg 9 measures nothing"
else
  fail "the behind-topology pull returned $BCODE, neither served nor refused; the control is unreadable"
fi

say "10) INGEST, from BEHIND: a denied package never enters the customer's registry"
# The converse of leg 9, and the thing the behind position is FOR (D290). Leg 9 showed
# what behind cannot do: withdraw a package the registry already holds. This shows what
# it can: keep a refused package out of the registry altogether, with nothing changed on
# any client -- the registry is the only client here, and its uplink is one line of its
# own config (verdaccio-behind.yaml).
#
# Leg 7's package will not do. yj-registryfront-blocked does not exist upstream, so a
# registry could not have ingested it with or without us, and "it is not in storage"
# would be true for the wrong reason. This leg needs a REAL package the registry has
# never fetched, refused by the gate while the wire to the public registry is UP -- so
# the only thing between the registry and those bytes is the verdict.
INGEST_DENIED="is-odd"       # real, tiny, never requested above; denied below
INGEST_ALLOWED="is-even"     # real, tiny, never requested above; the control
# Where verdaccio keeps a package it has ingested (storage: /verdaccio/storage in both
# configs). The CONTROL below proves this probe can see a package, so an absent file
# for the denied one is an observation and not a wrong path.
stored() { "${COMPOSE[@]}" exec -T custreg-behind sh -c "test -f /verdaccio/storage/$1/package.json" >/dev/null 2>&1; }

if uplink_answers; then
  pass "the public-registry wire is UP, so a refusal below cannot be blamed on an outage"
else
  fail "the uplink is not answering, so this leg cannot attribute a failed pull to the gate"
fi

printf '%s\n' "$INGEST_DENIED" >> "$DENY_FILE"
# Wait on the mechanism, as leg 9 does -- but on the BEHIND gate, which reloads the list
# on its own clock. Asked directly (8186), so this wait adds nothing to the registry's
# storage and nothing to what the registry has seen.
DENIED_LIVE=""
for _ in $(seq 1 20); do
  CODE=$(curl -s -o /dev/null -w '%{http_code}' -m 30 "http://${E2E_HOST}:8186/${INGEST_DENIED}" 2>/dev/null)
  if [ "$CODE" = "403" ]; then DENIED_LIVE=yes; break; fi
  sleep 1
done
if [ -n "$DENIED_LIVE" ]; then
  pass "the behind gate refuses $INGEST_DENIED when asked directly (403), so the deny list is live there"
else
  fail "the behind gate still answers ${CODE:-?} for $INGEST_DENIED after the reload TTL; nothing below can be attributed to the list"
fi

# THE PULL, through the registry. Decisions are counted around it so the refusal can be
# tied to THIS request reaching the gate, not to the direct probes above.
ING_BEFORE=$(decisions firewall-behind "$INGEST_DENIED")
ICODE=$(curl -s -o /dev/null -w '%{http_code}' -m 60 "http://${E2E_HOST}:4874/${INGEST_DENIED}" 2>/dev/null)
ING_AFTER=$(decisions firewall-behind "$INGEST_DENIED")
printf 'behind decisions for %s: before=%s after=%s; the registry answered its client %s\n' "$INGEST_DENIED" "$ING_BEFORE" "$ING_AFTER" "$ICODE"
# MEASURED 2026-09-20, verdaccio 6: the gate answers the registry 403 and the registry answers
# ITS client 404. The refusal holds, but its reason does not survive the hop -- from behind, a
# developer sees absence, not policy (the #79 shape, one hop further out). So the assertion is
# "not served", never "403": the status the client sees belongs to the registry, not to us.
if [ "$ICODE" != "200" ]; then
  pass "the customer's registry (verdaccio 6) could not serve the denied package to its client ($ICODE)"
else
  fail "the customer's registry served the denied package (200): from behind, the gate did not stop ingest"
fi
if [ "$ING_AFTER" -gt "$ING_BEFORE" ]; then
  pass "CONTACT: the registry's miss reached the behind gate and was judged there, so the refusal is ours"
else
  fail "no new decision for $INGEST_DENIED at the behind gate: the registry failed for some other reason, and this leg proved nothing about the gate"
fi
if stored "$INGEST_DENIED"; then
  fail "the denied package IS in the customer registry's storage: it was ingested despite the refusal"
else
  pass "INGEST STOPPED: the denied package is not in the customer registry's storage"
fi

# THE CONTROL. Same registry, same gate, same wire, same moment -- an allowed package
# that was also never fetched before. It must be served AND land in storage; otherwise
# "not in storage" above is what a broken chain, or a wrong probe path, looks like too.
ACODE=$(curl -s -o /dev/null -w '%{http_code}' -m 60 "http://${E2E_HOST}:4874/${INGEST_ALLOWED}" 2>/dev/null)
if [ "$ACODE" = "200" ] && stored "$INGEST_ALLOWED"; then
  pass "CONTROL: an allowed package pulled the same way is served (200) and IS in storage, so the probe sees ingested packages and the chain works"
else
  fail "CONTROL: the allowed package answered $ACODE and stored=$(if stored "$INGEST_ALLOWED"; then echo yes; else echo no; fi); the absent file above is unreadable as evidence"
fi

say "11) INTEGRITY through the pull-through cache: a real client, blobs included, and a hop that corrupts one (#147)"
# #147's "pull-through-cache path" box. Legs 8-9 are NOT this: they are curl asking for one
# MANIFEST. No blob is pulled, no client verifies anything, and nothing there can fail on
# a damaged byte. The claim under test is that integrity material survives our relay well
# enough for a REAL verifier downstream of a caching registry to accept what we forward --
# and a claim like that is only worth the control that shows the verifier can refuse.
#
#   clean:     crane -> custreg-oci-behind   ->               firewall-oci-behind -> Docker Hub
#   tampered:  crane -> custreg-oci-tampered -> tamperfront -> firewall-oci-behind -> Docker Hub
#
# SAME gate, same image, same client. The only difference is one hop that inverts the last
# byte of every blob body and leaves every header alone (e2e/tamperfront) -- so the
# response still CLAIMS the digest its bytes no longer have. It is the container form of
# tamperingFront in integritypreserved_test.go, placed where this topology needs it.
#
# crane, not docker: a docker daemon will not talk to a plain-HTTP registry on another host
# without daemon reconfiguration, which under dind means reconfiguring the CI service.
# `--insecure` is what lets crane speak plain HTTP to the rig's registries; it does not
# touch digest verification, which is the quantity here (and the tampered pull failing is
# the proof it was still on).
CRANE="gcr.io/go-containerregistry/crane:latest@sha256:1f968817b95790bed063f71175aa6b8ff879fa17064020415f3e18bb6e6a36e1"
OCI_IMG="library/alpine:3.19"
ready "http://${E2E_HOST}:5002/v2/" "custreg-oci-tampered (registry:2 pull-through, via the tampering hop)" || FAIL=1
# crane runs ON the compose network and dials the registries by service name, so the leg
# is identical on a laptop and under dind. The network is read off a running container
# rather than guessed: compose derives it from the checkout's directory name.
RIF_NET=$(docker inspect "$("${COMPOSE[@]}" ps -q custreg-oci-behind)" \
  --format '{{range $k, $v := .NetworkSettings.Networks}}{{$k}}{{end}}' 2>/dev/null)
case "$RIF_NET" in
  "") fail "could not read the compose network off custreg-oci-behind, so crane cannot be placed on it" ;;
  *)  pass "crane will run on the rig's own network ($RIF_NET)" ;;
esac
crane_pull() {   # crane_pull <registry-service> ; the image tar is discarded with the container
  MSYS_NO_PATHCONV=1 docker run --rm --network "$RIF_NET" "$CRANE" pull --insecure "$1:5000/${OCI_IMG}" /tmp/img.tar 2>&1
}
blob_gets() { "${COMPOSE[@]}" logs --no-color firewall-oci-behind 2>/dev/null | grep -c 'GET /v2/library/alpine/blobs/sha256:' || true; }
tamper()    { curl -s -m 10 "http://${E2E_HOST}:8188/_tamper" | sed -n "s/.*\"$1\": *\([0-9]*\).*/\1/p"; }

# 11a -- the CLEAN path. A real client pulls the image, layers and all, through the
# pull-through cache and the gate. The pass condition is not "crane exited 0": it is that
# the BLOBS crossed the gate (its log gains blob GETs), so what crane verified is what we
# relayed and not something the registry already had.
BG0=$(blob_gets)
CLEAN_OUT=$(crane_pull custreg-oci-behind); CLEAN_RC=$?
BG1=$(blob_gets)
if [ "$CLEAN_RC" -eq 0 ] && [ "$BG1" -gt "$BG0" ]; then
  pass "CLEAN: crane pulled ${OCI_IMG} through registry:2 and the gate, and verified it (gate relayed $((BG1-BG0)) blob GET(s))"
else
  fail "CLEAN: crane rc=$CLEAN_RC, gate blob GETs $BG0 -> $BG1. Without a clean pull whose blobs crossed the gate, the tampered leg below has nothing to be contrasted with: $(printf '%s' "$CLEAN_OUT" | tail -3 | tr '\n' ' ')"
fi

# 11b -- the HOP CONTROL. Before blaming a failed pull on the corruption, show the hop
# relays what it is NOT told to corrupt: the manifest comes back 200 through it.
TM=$(curl -s -o /dev/null -w '%{http_code}' -m 90 -H "$ACCEPT" "http://${E2E_HOST}:5002/v2/library/alpine/manifests/3.19" 2>/dev/null)
if [ "$TM" = "200" ]; then
  pass "HOP CONTROL: a manifest (not a matched class) is relayed intact through the tampering hop (200)"
else
  fail "HOP CONTROL: the manifest through the tampering hop answered $TM, so the hop itself is broken and a failed pull below would prove nothing about corruption"
fi

# 11c -- the TAMPERED path. Same client, same image, same gate; one inverted byte per blob.
F0=$(tamper fired); F0=${F0:-0}
TAMP_OUT=$(crane_pull custreg-oci-tampered); TAMP_RC=$?
F1=$(tamper fired); F1=${F1:-0}
printf 'tamper hop: fired %s -> %s (seen=%s matched=%s); crane rc=%s\n' "$F0" "$F1" "$(tamper seen)" "$(tamper matched)" "$TAMP_RC"
if [ "$F1" -gt "$F0" ]; then
  pass "THE TAMPER FIRED: $((F1-F0)) blob body(ies) were corrupted in flight, so the pull below met damaged bytes"
else
  fail "the tamper never fired (fired=$F1): the blobs did not pass through the hop as 200 bodies -- a redirect, or a cache hit -- so whatever crane did below says nothing about corruption"
fi
if [ "$TAMP_RC" -ne 0 ]; then
  pass "TAMPERED: the pull FAILED (crane rc=$TAMP_RC) -- a byte damaged between the gate and the registry does not reach a client as a good image"
elif [ "$F1" -gt "$F0" ]; then
  fail "TAMPERED: crane pulled a corrupted image successfully. Nothing downstream of us verified the bytes against their digest"
else
  # Say what actually happened: with no corruption, a successful pull is the hop working,
  # not a verifier failing. The leg still fails -- it measured nothing -- but for that reason.
  fail "TAMPERED: crane pulled successfully, but NOTHING WAS CORRUPTED (see above), so this pull says nothing about verification"
fi
# THE REASON, not just the exit code: a non-zero rc is shared with a dozen other causes
# (network, auth, a missing tag). The failure must be ABOUT the digest. Whichever
# verifier caught it -- crane on the stream, or registry:2 refusing to commit the blob --
# says so in those words; both logs are read, and which one spoke is printed.
TREG_LOG=$("${COMPOSE[@]}" logs --no-color custreg-oci-tampered 2>/dev/null || true)
WHO=""
if hasre "$TAMP_OUT" 'digest|sha256|checksum|verif'; then WHO="crane"; fi
# registry:2's own words, measured 2026-09-20: "Error committing to storage: invalid digest for
# referenced layer: sha256:..., content does not match digest". Matched on that, not on a
# looser "digest", which every ordinary request line in its log also contains.
if hasre "$TREG_LOG" 'content does not match digest'; then WHO="${WHO:+$WHO and }registry:2"; fi
if [ -n "$WHO" ]; then
  pass "the failure NAMES the digest (reported by: $WHO): $(printf '%s' "$TAMP_OUT" | grep -iE 'digest|sha256|checksum|verif' | tail -1 | cut -c1-200)"
else
  fail "the pull failed but neither crane nor registry:2 mentions a digest, so it may have failed for an unrelated reason: $(printf '%s' "$TAMP_OUT" | tail -2 | tr '\n' ' ')"
fi

# 11d -- THE CACHE DID NOT POISON ITSELF. The property a customer with a registry in front
# actually depends on, and it is not implied by 11c: registry:2 TEES a pulled-through blob
# to the client while writing its own copy, and checks the digest only when that copy is
# committed. So the client is sent the damaged bytes (and refuses them, above) -- the
# question is whether the registry then KEEPS them under the good digest, to hand to the
# next client with no upstream in the path at all.
#
# The digest is the one crane said it WANTED, so this probes the blob that was actually
# damaged. CONTROL: the clean registry, which pulled the same blob undamaged, DOES hold it
# at the same path -- so an absent file is an observation, not a wrong path.
WANT=$(printf '%s' "$TAMP_OUT" | sed -n 's/.*want "sha256:\([0-9a-f]\{64\}\)".*/\1/p' | tail -1)
blob_stored() { "${COMPOSE[@]}" exec -T "$1" sh -c "test -f /var/lib/registry/docker/registry/v2/blobs/sha256/$(printf '%s' "$2" | cut -c1-2)/$2/data" >/dev/null 2>&1; }
if [ -z "$WANT" ]; then
  fail "crane's error did not carry a 'want \"sha256:...\"' digest, so the damaged blob cannot be identified for the cache check"
elif blob_stored custreg-oci-tampered "$WANT"; then
  fail "CACHE POISONED: registry:2 kept the damaged bytes under sha256:$WANT -- the next client would be served them from cache"
elif blob_stored custreg-oci-behind "$WANT"; then
  pass "THE CACHE DID NOT POISON ITSELF: sha256:$(printf '%s' "$WANT" | cut -c1-12)... is absent from the tampered registry's store, and PRESENT in the clean one (so the probe sees stored blobs)"
else
  fail "sha256:$WANT is in NEITHER registry's store, so the probe path is wrong or the clean pull did not cache it; its absence from the tampered one proves nothing"
fi

say "RESULT"
if [ "$FAIL" -eq 0 ]; then
  echo "REGISTRY-IN-FRONT E2E: PASS"
else
  echo "REGISTRY-IN-FRONT E2E: FAIL"
fi

say "logs (all three firewalls, tails)"
"${COMPOSE[@]}" logs --tail=25 firewall-front firewall-behind firewall-oci-behind 2>/dev/null || true
exit "$FAIL"
