#!/usr/bin/env bash
# HA + ROLLING-UPDATE DRILL (#23, D133) — the two operability claims, demonstrated.
#
# ── WHY THIS EXISTS ──────────────────────────────────────────────────────────
#
# Two of our loudest claims are asserted everywhere and demonstrated nowhere:
# redundancy without a database or a licence tier, and an upgrade that is just a
# redeploy. Both incumbents are genuinely bad here — Artifactory HA needs Enterprise X
# (Pro X is licensed for exactly ONE server), an external database, shared storage and a
# load balancer; Nexus HA needs Pro plus external PostgreSQL plus a shared blob store —
# so the contrast is the strongest line we have for the admin buyer (D9). A claim that
# strong has to be provable on demand, not on a slide.
#
# D133 absorbed the sharper version of it, and that sentence is the acceptance criterion:
# **a rolling update with no user interruption.** The replica drill is the means.
#
# ── WHAT IT DOES AND DOES NOT PROVE ──────────────────────────────────────────
#
# PROVES, here, offline:
#   * N replicas of the same image, sharing NOTHING — no database, no volume, no
#     coordination — render byte-identical refusals for the same request.
#   * Replaced one at a time behind a load balancer, a client hitting it continuously
#     sees ZERO failed requests. Then rolled BACK the same way, also zero.
#   * The replicas hold no durable state to migrate: read-only rootfs, no writable mount.
#
# PROVES, legs 7-9, with the approval database and the operator lists in the picture
# (#23's last box, D210; #131):
#   * The GATE keeps serving when the approval database disappears, and again when the
#     approval service itself disappears: healthz up, refusals rendered, and each request
#     completes promptly rather than hanging on the outage. What it LOSES is stated
#     exactly: a human ruling lives in the database, so with the database gone the verdict
#     falls back to POLICY. That is the fail-safe by design (firewall.go applyHumanRuling),
#     and the drill shows the log line that proves the path was exercised rather than
#     skipped. "Restorable by redeploying" then means: a fresh, empty database and a fresh
#     approval come up with no restore ritual, the gate is unchanged, and the ruling has to
#     be made again -- which is precisely the durable half D210 puts on replicated storage.
#   * N approval replicas started at the SAME MOMENT against an EMPTY database, several
#     times over, all bootstrap the schema. That is D210's "config database is bootstrapped"
#     read the way D133 needs it -- HA-safe, not merely automatic. The leg checks that the
#     replicas really did start within a narrow window, because a sequential start would
#     pass on a bootstrap that races.
#   * A LIST EDIT reaches every replica (leg 9, #131). N gates share one list DIRECTORY;
#     one entry is added the way the console adds it (a temp file, then a rename) while
#     one replica restarts. Every replica enforces it within a stated bound, measured PER
#     REPLICA against the container clock; a control replica on an unedited copy never
#     does, and the instrument says so. Offline: the verdict flips in KIND and RULE, not
#     in status, so a status-only check could not see it.
#
# DOES NOT prove, and says so rather than implying it:
#   * A schema MIGRATION across versions with old and new replicas live together. The two
#     "versions" here share one schema, so leg 8 shows concurrent CREATE is safe and says
#     nothing about a future ALTER that old code cannot read. That is the additive-first
#     migration discipline, and it wants its own drill when a real migration exists.
#   * Anything about a genuinely different BUILD. The two "versions" here are two tags of
#     one image, so this measures the rollover mechanism and the absence of migration —
#     not that vN+1's code is compatible with vN's on-disk state, because there is no
#     on-disk state for it to be compatible with. That absence is asserted in leg 3.
#
# ── WHY THE VERDICTS ARE OFFLINE ─────────────────────────────────────────────
#
# Every request this drill compares is one the firewall answers ENTIRELY ITSELF: a
# layer-1 refusal from an injected feed, and a refused unknown path. Those bodies are
# produced by our code and our config, so byte-identical is a real assertion rather than
# a statement about npm's CDN being consistent. It also means the rolling-update loop can
# run flat out without touching a public registry.
#
# Run from the repo root:  bash e2e/ha_drill.sh      (or: sh scripts/dev.sh ha)
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
E2E_HOST="${E2E_HOST:-localhost}"
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

NET="yj-ha-net"
LB_PORT="${YJ_HA_PORT:-18711}"
REPLICAS="${YJ_HA_REPLICAS:-3}"
BLOCKED="yj-ha-blocked"
FEED="$ROOT/.ha-feed.ndjson"
NGINX_CONF="$ROOT/.ha-nginx.conf"
FEED_ODD="$ROOT/.ha-feed-odd.ndjson"
# Pinned, and the same image the hardening rig uses for a container that HAS a shell.
LB_IMAGE='nginx:1.27-alpine@sha256:65645c7bb6a0661892a8b03b89d0743208a18dd2f3f17a54ef4b76fb8e2f2a10'

# MSYS_NO_PATHCONV: Git Bash on the Windows dev host rewrites arguments that look like
# Unix paths, so `-v x:/feed/f` reaches Docker as `-v x:C:/Program Files/Git/feed/f` — and
# it mangles the ENV VALUE too, which is how this first ran: every replica died with
# `known-malware feed "C:/Program Files/Git/feed/ha.ndjson" must be an absolute path`.
# Applied PER COMMAND rather than exported, for the reason e2e/hardening.sh records:
# exporting it globally breaks host-side curl, which then receives an MSYS path it cannot
# open. Harmless on Linux, where the variable means nothing.
NOPATHCONV="env MSYS_NO_PATHCONV=1"

UPSTREAM_DIR="$ROOT/.ha-upstream"
UPSTREAM_CONF="$ROOT/.ha-upstream-nginx.conf"
PG_IMAGE='postgres:17@sha256:67f41722b7a8cbdb868a44a4995c846eddfdc2973bccb291ce937dce88ad5675'
# How many approval replicas race the bootstrap in leg 8, and how many fresh databases they
# race it on. The window is milliseconds wide, so one attempt proves little either way.
BOOT_REPLICAS="${YJ_HA_BOOT_REPLICAS:-8}"
BOOT_ATTEMPTS="${YJ_HA_BOOT_ATTEMPTS:-6}"
# Leg 9: the list directory the gates share, and a COPY nobody edits for the control replica.
LISTS_DIR="$ROOT/.ha-lists"
LISTS_STALE="$ROOT/.ha-lists-stale"
POLL_SH="$ROOT/.ha-poll.sh"
# How long an edit may take to be enforced on every replica: the 5s reload TTL, checked on
# lookup, plus margin for a replica restarting mid-window and for docker exec overhead.
LIST_EDIT_BOUND="${YJ_HA_LIST_EDIT_BOUND:-8}"

cleanup() {
  docker rm -f yj-ha-lb yj-ha-client yj-ha-upstream yj-ha-pg yj-ha-approval >/dev/null 2>&1
  for i in $(seq 1 9); do docker rm -f "yj-ha-r$i" "yj-ha-a$i" "yj-ha-rl$i" >/dev/null 2>&1; done
  docker rm -f yj-ha-rl0 >/dev/null 2>&1
  docker network rm "$NET" >/dev/null 2>&1
  rm -rf "$FEED" "$FEED_ODD" "$NGINX_CONF" "$UPSTREAM_DIR" "$UPSTREAM_CONF" \
    "$LISTS_DIR" "$LISTS_STALE" "$POLL_SH"
}
trap cleanup EXIT
cleanup

# start_replica N IMAGE [extra env...] — one stateless firewall replica.
#
# --read-only and no writable mount, deliberately: that IS the statelessness claim, and
# leg 3 reads it back off the running containers rather than trusting these flags.
start_replica() {
  n="$1"; image="$2"; shift 2
  $NOPATHCONV docker run -d --name "yj-ha-r$n" --network "$NET" --read-only \
    -v "$FEED:/feed/ha.ndjson:ro" \
    -e FW_LISTEN_ADDR=":8080" -e FW_ECOSYSTEM=npm -e FW_SCORECARD_MODE=stub \
    -e FW_UPSTREAM="https://registry.npmjs.org" \
    -e FW_MALWARE_LIST=/feed/ha.ndjson \
    -e "FW_PUBLIC_URL=http://${E2E_HOST}:${LB_PORT}" \
    "$@" "$image" >/dev/null 2>&1
}

# verdict_of URL — the wire-visible verdict: status + the three D182 fields + a hash of
# the body. Everything a client can see, in one comparable string.
verdict_of() {
  docker exec yj-ha-client sh -c "
    b=\$(mktemp)
    code=\$(curl -s -o \$b -w '%{http_code}' -m 20 -D /tmp/h '$1' 2>/dev/null)
    k=\$(grep -i '^X-Yellowjack-Kind:'   /tmp/h | tr -d '\r' | cut -d' ' -f2-)
    r=\$(grep -i '^X-Yellowjack-Rule:'   /tmp/h | tr -d '\r' | cut -d' ' -f2-)
    s=\$(grep -i '^X-Yellowjack-Source:' /tmp/h | tr -d '\r' | cut -d' ' -f2-)
    printf '%s|%s|%s|%s|%s' \"\$code\" \"\$k\" \"\$r\" \"\$s\" \"\$(sha256sum < \$b | cut -c1-16)\"
    rm -f \$b
  " 2>/dev/null
}

say "0) build the firewall image once — every replica is the SAME image, which is the claim"
docker build -q -f Dockerfile -t yj-ha-fw:va . >/dev/null 2>&1 || { bad "could not build the firewall image"; exit 1; }
docker tag yj-ha-fw:va yj-ha-fw:vb
pass "one image, tagged va and vb (no licence tier, no per-node anything)"

printf '{"id":"MAL-HA-1","ecosystem":"npm","name":"%s"}\n' "$BLOCKED" > "$FEED"
# The same package under a DIFFERENT advisory id. Both feeds refuse it, so both replicas
# answer 403 from their own logic with no upstream involved — and the only difference on
# the wire is the rule the refusal names. That is what leg 2 requires the comparison to see.
printf '{"id":"MAL-HA-DIFFERENT","ecosystem":"npm","name":"%s"}\n' "$BLOCKED" > "$FEED_ODD"
docker network create "$NET" >/dev/null 2>&1 || { bad "could not create the drill network"; exit 1; }

say "1) start $REPLICAS replicas sharing NOTHING, plus a client container"
for i in $(seq 1 "$REPLICAS"); do start_replica "$i" yj-ha-fw:va; done
docker run -d --name yj-ha-client --network "$NET" --entrypoint sleep "$LB_IMAGE" 3600 >/dev/null 2>&1
up=0
for i in $(seq 1 "$REPLICAS"); do
  for _ in $(seq 1 30); do
    if docker exec yj-ha-client curl -fsS -m 2 "http://yj-ha-r$i:8080/healthz" >/dev/null 2>&1; then
      up=$((up + 1)); break
    fi
    sleep 1
  done
done
if [ "$up" = "$REPLICAS" ]; then pass "all $REPLICAS replicas serving, with no database and no shared store between them"
else bad "only $up of $REPLICAS replicas came up"; docker logs yj-ha-r1 2>&1 | tail -5; exit 1; fi

say "2) INSTRUMENT CHECK — the comparison must be able to see a difference"
# Every assertion below says two things are the SAME. That family passes trivially if the
# comparison is broken, so before trusting it: one replica configured DIFFERENTLY must be
# detected.
#
# The lever is a second feed naming the same package under a different advisory id, chosen
# after a first attempt with FW_UNKNOWN_PATH_POLICY did NOT differ: for npm every path is
# either a package or an enumerated control-plane endpoint, so nothing reaches the
# unknown-path rule and both replicas answered identically — an instrument check that
# passes for the wrong reason is exactly what this leg exists to prevent, so it is recorded
# rather than quietly replaced. The feed difference keeps the whole check offline: both
# replicas refuse from their own logic, and only the rule they name differs.
start_replica 9 yj-ha-fw:va -v "$FEED_ODD:/feed/odd.ndjson:ro" -e FW_MALWARE_LIST=/feed/odd.ndjson
for _ in $(seq 1 30); do docker exec yj-ha-client curl -fsS -m 2 "http://yj-ha-r9:8080/healthz" >/dev/null 2>&1 && break; sleep 1; done
v1=$(verdict_of "http://yj-ha-r1:8080/$BLOCKED")
v9=$(verdict_of "http://yj-ha-r9:8080/$BLOCKED")
if [ -n "$v1" ] && [ "$v1" != "$v9" ]; then
  pass "a differently-configured replica IS detected ($v1 vs $v9)"
else
  bad "a replica with a different policy compared EQUAL ($v1 vs $v9) — every 'identical' below would be vacuous"
fi
docker rm -f yj-ha-r9 >/dev/null 2>&1

say "3) the replicas hold no durable state to migrate"
# Read back off the RUNNING containers, not from the flags above: the claim is about what
# is actually running. A writable mount or a writable rootfs would both be state.
bad_state=0
for i in $(seq 1 "$REPLICAS"); do
  ro=$(docker inspect -f '{{.HostConfig.ReadonlyRootfs}}' "yj-ha-r$i" 2>/dev/null)
  rw=$(docker inspect -f '{{range .Mounts}}{{if not .RW}}{{else}}{{.Destination}} {{end}}{{end}}' "yj-ha-r$i" 2>/dev/null)
  [ "$ro" = "true" ] || { bad "replica $i is not running with a read-only rootfs (ReadonlyRootfs=$ro)"; bad_state=1; }
  [ -z "$rw" ] || { bad "replica $i has a WRITABLE mount ($rw) — that is durable state, and it would have to be migrated"; bad_state=1; }
done
[ "$bad_state" = 0 ] && pass "every replica: read-only rootfs, no writable mount, nothing to back up or migrate"

say "4) identical verdicts across replicas, with no coordination between them"
# Both cases are answered ENTIRELY by the firewall and reach no registry: a layer-1 feed
# refusal, and an ambiguous path refused by the normalisation guard (#59). So byte-identical
# is an assertion about OUR determinism rather than about npm's CDN being consistent — and
# it is why this leg cannot flake on a network wobble.
for path in "/$BLOCKED" "//$BLOCKED"; do
  first=""; same=1
  for i in $(seq 1 "$REPLICAS"); do
    v=$(verdict_of "http://yj-ha-r$i:8080$path")
    [ -z "$v" ] && { bad "replica $i returned nothing for $path"; same=0; break; }
    if [ -z "$first" ]; then first="$v"; elif [ "$v" != "$first" ]; then
      bad "replica $i disagreed on $path: $v vs $first"; same=0
    fi
  done
  [ "$same" = 1 ] && pass "$REPLICAS replicas agree byte-for-byte on $path -> $first"
done

say "5) ROLLING UPDATE with a client hitting the load balancer throughout"
cat > "$NGINX_CONF" <<NGX
upstream yjha {
$(for i in $(seq 1 "$REPLICAS"); do echo "    server yj-ha-r$i:8080 max_fails=1 fail_timeout=1s;"; done)
}
server {
    listen 8080;
    location / {
        proxy_pass http://yjha;
        proxy_next_upstream error timeout http_502 http_503 http_504;
        proxy_connect_timeout 2s;
    }
}
NGX
$NOPATHCONV docker run -d --name yj-ha-lb --network "$NET" -p "$LB_PORT:8080" \
  -v "$NGINX_CONF:/etc/nginx/conf.d/default.conf:ro" "$LB_IMAGE" >/dev/null 2>&1
for _ in $(seq 1 30); do curl -fsS -m 2 "http://${E2E_HOST}:${LB_PORT}/healthz" >/dev/null 2>&1 && break; sleep 1; done
if curl -fsS -m 2 "http://${E2E_HOST}:${LB_PORT}/healthz" >/dev/null 2>&1; then pass "load balancer up in front of $REPLICAS replicas"
else bad "the load balancer never served"; exit 1; fi

# roll IMAGE LABEL — replace each replica with IMAGE, one at a time, while a client loops.
# The loop requests the BLOCKED package on purpose: that verdict needs no upstream, so the
# only thing that can make a request fail is us being unavailable.
roll() {
  image="$1"; label="$2"
  docker exec -d yj-ha-client sh -c "
    ok=0; err=0
    while [ ! -f /tmp/stop ]; do
      c=\$(curl -s -o /dev/null -w '%{http_code}' -m 5 'http://yj-ha-lb:8080/$BLOCKED' 2>/dev/null)
      if [ \"\$c\" = '403' ]; then ok=\$((ok+1)); else err=\$((err+1)); echo \"\$c\" >> /tmp/errs; fi
      echo \"\$ok \$err\" > /tmp/count
    done
  "
  sleep 3
  for i in $(seq 1 "$REPLICAS"); do
    docker rm -f "yj-ha-r$i" >/dev/null 2>&1
    start_replica "$i" "$image"
    for _ in $(seq 1 30); do
      docker exec yj-ha-client curl -fsS -m 2 "http://yj-ha-r$i:8080/healthz" >/dev/null 2>&1 && break
      sleep 1
    done
    sleep 1
  done
  sleep 2
  docker exec yj-ha-client sh -c 'touch /tmp/stop' >/dev/null 2>&1
  sleep 2
  counts=$(docker exec yj-ha-client sh -c 'cat /tmp/count 2>/dev/null' | tr -d '\r')
  errs=$(docker exec yj-ha-client sh -c 'cat /tmp/errs 2>/dev/null | sort | uniq -c | tr "\n" " "' | tr -d '\r')
  docker exec yj-ha-client sh -c 'rm -f /tmp/stop /tmp/count /tmp/errs' >/dev/null 2>&1
  set -- $counts
  ok="${1:-0}"; err="${2:-0}"
  if [ "${ok:-0}" -lt 20 ]; then
    bad "$label: only $ok requests completed during the rollover — too few to claim anything"
  elif [ "${err:-0}" -eq 0 ]; then
    pass "$label: all $REPLICAS replicas replaced, $ok requests served, ZERO failed"
  else
    bad "$label: $err of $((ok+err)) requests FAILED during the rollover [$errs]"
  fi
}

roll yj-ha-fw:vb "va -> vb"
on_vb=$(for i in $(seq 1 "$REPLICAS"); do docker inspect -f '{{.Config.Image}}' "yj-ha-r$i" 2>/dev/null; done | grep -c 'vb$')
[ "$on_vb" = "$REPLICAS" ] && pass "every replica is now on vb (the rollover really happened)" \
  || bad "only $on_vb of $REPLICAS replicas are on vb — the rollover did not complete"

say "6) ROLL BACK by redeploying the previous version — no restore, no migration"
roll yj-ha-fw:va "vb -> va (rollback)"
on_va=$(for i in $(seq 1 "$REPLICAS"); do docker inspect -f '{{.Config.Image}}' "yj-ha-r$i" 2>/dev/null; done | grep -c 'va$')
[ "$on_va" = "$REPLICAS" ] && pass "every replica is back on va — rollback is a redeploy, not a restore" \
  || bad "only $on_va of $REPLICAS replicas are on va"

say "7) the gate keeps serving with the approval DATABASE gone — and says exactly what it lost"
# Everything before this leg ran with no database at all. This leg puts one in the picture
# and then takes it away, because #23's last box is about the gate's independence from it.
#
# The approval path is only consulted for a package the gate cannot score on its own, and
# no offline request so far reaches it. So this leg brings its own UPSTREAM: an nginx
# serving a version manifest that declares no repository, which makes the package
# UNSCORABLE -> policy block -> the human-ruling lookup. Still offline, still ours.
docker build -q -f approval/Dockerfile -t yj-ha-approval . >/dev/null 2>&1 \
  || { bad "could not build the approval image"; exit 1; }
UNSC="yj-ha-unscorable"
mkdir -p "$UPSTREAM_DIR/$UNSC"
printf '{"name":"%s","version":"1.0.0"}\n' "$UNSC" > "$UPSTREAM_DIR/$UNSC/latest"
printf '{"name":"%s","dist-tags":{"latest":"1.0.0"},"versions":{"1.0.0":{"name":"%s","version":"1.0.0"}}}\n' \
  "$UNSC" "$UNSC" > "$UPSTREAM_DIR/$UNSC/index.json"
# `root` at SERVER level, not inside `location /`: try_files in the exact-match block
# resolves against the server root, and the first run of this leg served 404 from
# nginx's default html directory -- which read as the GATE refusing an approved package
# until the approval log showed it had relayed. A stand-in that fails the way the
# product would fail is the worst kind.
cat > "$UPSTREAM_CONF" <<NGX
server {
    listen 80;
    root /srv;
    default_type application/json;
    location = /$UNSC { try_files /$UNSC/index.json =404; }
    location / { }
}
NGX
$NOPATHCONV docker run -d --name yj-ha-upstream --network "$NET" \
  -v "$UPSTREAM_DIR:/srv:ro" -v "$UPSTREAM_CONF:/etc/nginx/conf.d/default.conf:ro" \
  "$LB_IMAGE" >/dev/null 2>&1

# start_pg / start_approval NAME — the durable half, as two ordinary containers.
start_pg() {
  docker run -d --name yj-ha-pg --network "$NET" \
    -e POSTGRES_PASSWORD=drill -e POSTGRES_DB=yellowjack "$PG_IMAGE" >/dev/null 2>&1
  for _ in $(seq 1 40); do
    docker exec yj-ha-pg pg_isready -U postgres -d yellowjack >/dev/null 2>&1 && return 0
    sleep 1
  done
  return 1
}
start_approval() {
  docker run -d --name "$1" --network "$NET" \
    -e APPROVAL_LISTEN_ADDR=":8090" \
    -e APPROVAL_DATABASE_URL="postgres://postgres:drill@yj-ha-pg:5432/yellowjack?sslmode=disable" \
    yj-ha-approval >/dev/null 2>&1
}
wait_healthy() { # wait_healthy HOST:PORT
  for _ in $(seq 1 30); do
    docker exec yj-ha-client curl -fsS -m 2 "http://$1/healthz" >/dev/null 2>&1 && return 0
    sleep 1
  done
  return 1
}
approval_put() { # approval_put VERDICT
  docker exec yj-ha-client curl -fsS -m 5 -X PUT -H 'Content-Type: application/json' \
    -d "{\"package\":\"$UNSC\",\"verdict\":\"$1\",\"note\":\"ha drill\",\"decided_by\":\"drill\"}" \
    http://yj-ha-approval:8090/v1/decisions >/dev/null 2>&1
}
status_of() { # status_of URL -> "CODE SECONDS"
  docker exec yj-ha-client sh -c "curl -s -o /dev/null -w '%{http_code} %{time_total}' -m 20 '$1'" 2>/dev/null | tr -d '\r'
}

start_pg || { bad "postgres never became ready"; exit 1; }
start_approval yj-ha-approval
wait_healthy yj-ha-approval:8090 || { bad "the approval service never served"; docker logs yj-ha-approval 2>&1 | tail -5; exit 1; }
# FW_MIN_RELEASE_AGE_DAYS=0: the offline stand-in serves packuments with no publish times,
# which the default 14-day cooldown (D335) refuses outright -- so an approval could never
# flip the verdict and this leg would measure the window, not the ruling path.
start_replica 7 yj-ha-fw:va -e FW_UPSTREAM="http://yj-ha-upstream:80" \
  -e FW_APPROVAL_URL="http://yj-ha-approval:8090" -e FW_UNSCORABLE_POLICY=block \
  -e FW_MIN_RELEASE_AGE_DAYS=0
wait_healthy yj-ha-r7:8080 || { bad "replica 7 never served"; docker logs yj-ha-r7 2>&1 | tail -5; exit 1; }
pass "postgres + approval + a gate pointed at them are up; upstream is an offline stand-in"

# 7a: the package is refused on POLICY (unscorable), and approval now holds it as pending.
set -- $(status_of "http://yj-ha-r7:8080/$UNSC"); c7a="${1:-}"
pend=$(docker exec yj-ha-client curl -s -m 5 "http://yj-ha-approval:8090/v1/decisions?package=$UNSC" 2>/dev/null | tr -d '\r')
if [ "$c7a" = "403" ] && has "$pend" '"pending"'; then
  pass "unscorable package refused (403) and queued as pending in the database"
else
  bad "expected 403 + a pending row; got status $c7a, approval says: ${pend:-<nothing>}"
  docker logs yj-ha-r7 2>&1 | tail -6
fi

# 7b: INSTRUMENT CHECK — a human APPROVAL must flip the verdict, or nothing below is about
# the database: an outage that changes nothing is indistinguishable from a path never taken.
approval_put approved
set -- $(status_of "http://yj-ha-r7:8080/$UNSC"); c7b="${1:-}"
if [ "$c7b" = "200" ]; then
  pass "a human approval in the database flips the verdict to 200 -- the approval path is LIVE"
else
  bad "after PUT approved the package still returns $c7b -- the ruling path is not being consulted, so the outage legs would be vacuous"
  docker logs yj-ha-r7 2>&1 | tail -6
fi

# 7c: THE DATABASE GOES AWAY. The approval service is still up but has nothing to read from.
docker rm -f yj-ha-pg >/dev/null 2>&1
set -- $(status_of "http://yj-ha-r7:8080/$UNSC"); c7c="${1:-}"; t7c="${2:-0}"
hz=$(docker exec yj-ha-client curl -s -o /dev/null -w '%{http_code}' -m 2 http://yj-ha-r7:8080/healthz 2>/dev/null)
fwlog=$(docker logs yj-ha-r7 2>&1 | tail -20)
if [ "$c7c" = "403" ] && [ "$hz" = "200" ] && has "$fwlog" "approval lookup failed"; then
  pass "database gone: gate healthy, verdict falls back to POLICY (403), and the log says so -- 'approval lookup failed ... falling back to policy'"
elif [ "$c7c" = "403" ] && [ "$hz" = "200" ]; then
  bad "database gone: gate healthy and 403, but NO 'approval lookup failed' line -- so the 403 may not be the fallback, it may be a path that never asked"
  printf '%s\n' "$fwlog" | tail -6
else
  bad "database gone: status $c7c (want 403), healthz $hz (want 200), ${t7c}s"
  printf '%s\n' "$fwlog" | tail -6
fi

# 7d: THE APPROVAL SERVICE GOES AWAY TOO — two different ways, because they cost differently.
#
# (i) The service is DEAD BUT ITS ADDRESS EXISTS: a container at the same name with nothing
#     listening. This is the Kubernetes reality — a Service keeps its ClusterIP with zero
#     ready endpoints and connections are refused at once — and it must be immediate.
# (ii) The NAME IS GONE: the container removed outright. Now the gate pays a DNS failure
#     path instead of a refused connect, and the first run of this leg measured it at 8.0s
#     — which is the resolver, not us, and is bounded by the 10s client timeout. Pinned
#     separately so a hang is caught while the real-world case keeps its tight bound.
docker rm -f yj-ha-approval >/dev/null 2>&1
docker run -d --name yj-ha-approval --network "$NET" --entrypoint sleep "$LB_IMAGE" 3600 >/dev/null 2>&1
set -- $(status_of "http://yj-ha-r7:8080/$UNSC"); c7d="${1:-}"; t7d="${2:-0}"
if [ "$c7d" = "403" ] && awk "BEGIN{exit !($t7d < 3)}"; then
  pass "approval dead at a live address: still 403 on policy, refused in ${t7d}s (the Kubernetes case)"
else
  bad "approval dead at a live address: status $c7d in ${t7d}s (want 403 in under 3s)"
fi
docker rm -f yj-ha-approval >/dev/null 2>&1
set -- $(status_of "http://yj-ha-r7:8080/$UNSC"); c7d2="${1:-}"; t7d2="${2:-0}"
if [ "$c7d2" = "403" ] && awk "BEGIN{exit !($t7d2 < 12)}"; then
  pass "approval NAME gone: still 403, answered in ${t7d2}s — the DNS path, bounded by the 10s client timeout, never a hang"
else
  bad "approval name gone: status $c7d2 in ${t7d2}s (want 403 within the client timeout)"
fi

# 7e: RESTORE BY REDEPLOYING. Fresh empty database, fresh approval, no restore step. The gate
# is untouched; the human ruling is gone with the old database, and that is the half D210
# puts on replicated storage. Making it again is the whole recovery.
start_pg || { bad "fresh postgres never became ready"; exit 1; }
start_approval yj-ha-approval
wait_healthy yj-ha-approval:8090 || { bad "redeployed approval never served"; docker logs yj-ha-approval 2>&1 | tail -5; exit 1; }
set -- $(status_of "http://yj-ha-r7:8080/$UNSC"); c7e1="${1:-}"
approval_put approved
set -- $(status_of "http://yj-ha-r7:8080/$UNSC"); c7e2="${1:-}"
if [ "$c7e1" = "403" ] && [ "$c7e2" = "200" ]; then
  pass "redeployed from empty: 403 (the ruling lived in the database and is gone), then 200 once re-approved -- no restore ritual, the gate never restarted"
else
  bad "after redeploy: $c7e1 before re-approval (want 403), $c7e2 after (want 200)"
fi
docker rm -f yj-ha-r7 yj-ha-approval yj-ha-pg >/dev/null 2>&1

say "8) $BOOT_REPLICAS approval bootstraps at the SAME MOMENT against an EMPTY database, x$BOOT_ATTEMPTS"
# "Config database is bootstrapped" (D210) is the easy reading; the one D133 needs is that
# N replicas coming up TOGETHER on a fresh install do not race the schema creation.
# migrate() is CREATE ... IF NOT EXISTS, which Postgres does not make race-safe: two
# sessions can both pass the existence check and the loser dies on a duplicate-key error.
# That process exits ("database init failed") -- on Kubernetes, a crash loop on first
# boot, exactly when every replica starts at once.
#
# WHY THIS LEG RUNS A GO TEST AND NOT N CONTAINERS. It tried containers first, twice.
# `docker run -d` x6 spread the starts over 4.1s; `docker create` x8 then ONE `docker
# start` still spread them over 2.3-3.4s, because Docker Desktop starts containers
# serially. The whole migration takes milliseconds, so nothing ever raced anything, and
# a clean result was a measurement of Docker's scheduler. Goroutines start microseconds
# apart. approval/pgstore_bootstrap_test.go calls the SAME newPGStore path the container
# runs, N times at once, against THIS leg's real Postgres -- concurrency the instrument
# can actually produce. Measured on the unlocked code: 67 of 80 bootstraps failed.
#
# It runs inside a golang container on the drill network rather than on the host, so it
# works identically on a laptop and on CI's docker:27-cli image, which has no Go.
GO_IMAGE='golang:1.26@sha256:9d2f36f06329b2a141b9db99ffa32765cf695ee57b813ca29e245e8670bcbfff'
start_pg || { bad "postgres never became ready"; exit 1; }
boot_out=$($NOPATHCONV docker run --rm --network "$NET" \
  -v "$ROOT:/src:ro" -w /src -e GOFLAGS=-mod=mod -e GOCACHE=/tmp/gocache -e GOMODCACHE=/tmp/gomod \
  -e APPROVAL_TEST_DSN="postgres://postgres:drill@yj-ha-pg:5432/yellowjack?sslmode=disable" \
  -e YJ_BOOT_REPLICAS="$BOOT_REPLICAS" -e YJ_BOOT_ATTEMPTS="$BOOT_ATTEMPTS" \
  "$GO_IMAGE" go test -count=1 -run 'TestConcurrentBootstrap' -v ./approval/ 2>&1)
boot_rc=$?
docker rm -f yj-ha-pg >/dev/null 2>&1
# Both halves must have RUN: the assertion and its negative control. A skip (no DSN
# reached the test) or a missing control would read as green on nothing.
if [ "$boot_rc" -eq 0 ] \
   && has "$boot_out" "--- PASS: TestConcurrentBootstrapDoesNotRace" \
   && has "$boot_out" "--- PASS: TestConcurrentBootstrapInstrumentCanSeeAFailure"; then
  pass "$(printf '%s' "$boot_out" | grep -o '[0-9]* concurrent bootstraps across [0-9]* attempts, 0 failures') (goroutines, not containers -- see above)"
elif has "$boot_out" "--- SKIP"; then
  bad "the bootstrap test SKIPPED -- the DSN did not reach it, so nothing was raced"
  printf '%s\n' "$boot_out" | tail -5
else
  bad "concurrent bootstrap FAILED (rc=$boot_rc):"
  printf '%s\n' "$boot_out" | grep -E "FAILED across|first error|--- FAIL|cannot|error" | head -6
fi

# ── LEG 9 BEGIN ──────────────────────────────────────────────────────────────
say "9) a LIST EDIT reaches EVERY replica -- $REPLICAS gates sharing one list DIRECTORY, plus a control (#131)"
# Everything above shares nothing. Operator lists are the one input that changes while
# the gates run: the console writes them (a temp file, then a rename, into a bind-mounted
# DIRECTORY -- D193), or a `helm upgrade` rewrites the ConfigMap. #23 closed without
# this, so #131 asks it: after one edit, how long until EVERY replica enforces it?
#
# Offline, like every other leg. The package is leg 7's unscorable one, so before the edit
# each replica refuses it on POLICY (unscorable, no approval service configured), and
# after the edit refuses it as operator-denied with the deny-list rule on the wire. The
# flip is in the KIND and the RULE, not the status: a status-only instrument would read
# "403 before, 403 after" and see nothing, which is the shape #122 and #128 were made of.
#
# PREDICTED SHAPE, written before the first run. The reload is checked on LOOKUP, at most
# once per 5s TTL (operatorlist.go, reloadingList). The WORST case is a replica whose last
# lookup was just before the edit, so every replica is touched from inside the client
# immediately before the rename: the untouched replicas should then flip about 5s after
# the edit and within a few hundred ms of EACH OTHER; the replica restarted mid-window
# should flip when it is back (a fresh process loads the file it finds), which is the
# stop timeout plus its start. The first run did NOT touch: the sequential baseline reads
# had already aged every replica past its TTL, all three flipped at the first sample
# (0.56s, spread 0.00), and the restarting one was caught BEFORE its stop -- a pass that
# measured exec latency, not the reload. The control replica mounts a copy of the directory that nobody edits: it must
# NEVER flip, and the instrument must report that rather than average it away. If an
# edit LOSES to a cached verdict (the deny list consulted after the score cache), no
# untouched replica flips inside the bound, and that is the finding this leg exists for.
rm -rf "$LISTS_DIR" "$LISTS_STALE"; mkdir -p "$LISTS_DIR" "$LISTS_STALE"
printf '# ha drill leg 9: this file is edited while the gates run\n' > "$LISTS_DIR/deny.txt"
cp "$LISTS_DIR/deny.txt" "$LISTS_STALE/deny.txt"

# poll.sh runs INSIDE the client container: one exec for the whole watch rather than one
# per sample, and the container's own /proc/uptime as the clock, because BusyBox `date`
# (the CI image, and this image) has no sub-second field. It prints "rlI UPTIME" the first
# time replica I answers with the deny-list rule, and "end UPTIME" when it stops: when every
# real replica has flipped AND the control has had a full TTL plus margin to flip too (it
# must not), or after 30s regardless.
cat > "$POLL_SH" <<'POLL'
#!/bin/sh
pkg="$1"; n="$2"; settle="$3"
start=$(cut -d' ' -f1 /proc/uptime); s0=${start%.*}
done_=" "; pending=$n
while :; do
  now=$(cut -d' ' -f1 /proc/uptime); el=$(( ${now%.*} - s0 ))
  i=0
  while [ "$i" -le "$n" ]; do
    case "$done_" in *" $i "*) i=$((i+1)); continue;; esac
    rule=$(curl -s -o /dev/null -m 3 -D - "http://yj-ha-rl$i:8080/$pkg" 2>/dev/null \
      | grep -i '^X-Yellowjack-Rule:' | tr -d '\r' | cut -d' ' -f2-)
    if [ "$rule" = "deny-list:$pkg" ]; then
      echo "rl$i $now"; done_="$done_$i "
      [ "$i" != 0 ] && pending=$((pending-1))
    fi
    i=$((i+1))
  done
  if [ "$pending" -eq 0 ] && [ "$el" -ge "$settle" ]; then break; fi
  [ "$el" -ge 30 ] && break
  sleep 0.2
done
echo "end $(cut -d' ' -f1 /proc/uptime)"
POLL

# rl0 is the control on the unedited copy; rl1..rlN share the directory that gets edited.
for i in $(seq 0 "$REPLICAS"); do
  src="$LISTS_DIR"; [ "$i" = 0 ] && src="$LISTS_STALE"
  start_replica "l$i" yj-ha-fw:va -e FW_UPSTREAM="http://yj-ha-upstream:80" \
    -e FW_DENY_LIST=/lists/deny.txt -v "$src:/lists:ro"
done
up=0
for i in $(seq 0 "$REPLICAS"); do
  for _ in $(seq 1 30); do
    if docker exec yj-ha-client curl -fsS -m 2 "http://yj-ha-rl$i:8080/healthz" >/dev/null 2>&1; then
      up=$((up + 1)); break
    fi
    sleep 1
  done
done
if [ "$up" != "$((REPLICAS + 1))" ]; then
  bad "only $up of $((REPLICAS + 1)) list-sharing replicas came up"; docker logs yj-ha-rl1 2>&1 | tail -5
fi

# 9a: BASELINE -- identical across replicas, a 403, and NOT the deny list. Otherwise the
# edit could not be seen landing, and a leg that cannot see its own edit proves nothing.
base_ok=1; base0=""
for i in $(seq 0 "$REPLICAS"); do
  v=$(verdict_of "http://yj-ha-rl$i:8080/$UNSC")
  [ -n "$base0" ] || base0="$v"
  case "$v" in
    *operator-denied*) bad "rl$i refuses $UNSC by the DENY LIST before the edit -- the edit would be invisible"; base_ok=0 ;;
    403\|*) ;;
    *) bad "rl$i baseline is '$v' (want a 403 that is not operator-denied)"; base_ok=0 ;;
  esac
  [ "$v" = "$base0" ] || { bad "rl$i baseline '$v' differs from rl0 '$base0'"; base_ok=0; }
done
[ "$base_ok" = 1 ] && pass "baseline on $((REPLICAS + 1)) replicas: '$base0' -- identical, refused on policy, not by the list"

# 9b: THE EDIT, the way the console does it (temp file, then rename over the name), with
# one replica restarted in the same instant. t0 is read from the client container's clock
# BEFORE the rename, so the exec's own latency makes every delta below conservative.
# The poll script travels over STDIN (`sh -s`), not `docker cp`: on the Windows dev host
# the CLI cannot open a Git-Bash-form source path (/c/Users/...) even with path
# conversion off, although the daemon accepts that form in a -v mount -- so the first
# two runs of this leg copied nothing, the exec printed nothing, every delta read 0.00,
# and 9c below passed on its own. Arguments that begin with "/" still need NOPATHCONV.
printf '# ha drill leg 9: this file is edited while the gates run\n%s\n' "$UNSC" > "$LISTS_DIR/deny.txt.tmp"
# Touch every replica NOW so each one's last list check is fresh: the worst case for an
# edit is the lookup that happened just before it. One exec, curls inside the container.
# A touch only re-stamps the check when the previous one is already older than the TTL,
# so first let one TTL pass since the baseline reads: without this, the replicas whose
# baseline was read last kept an OLDER stamp than the touch, expired before the others,
# and flipped at the first sample (the second run: rl1=4.76s, rl2=0.51s, spread 4.25s).
sleep 6
docker exec yj-ha-client sh -c "for i in $(seq -s ' ' 0 "$REPLICAS"); do curl -s -o /dev/null -m 3 http://yj-ha-rl\$i:8080/$UNSC; done" >/dev/null 2>&1
t0=$($NOPATHCONV docker exec yj-ha-client cut -d' ' -f1 /proc/uptime 2>/dev/null | tr -d '\r')
mv "$LISTS_DIR/deny.txt.tmp" "$LISTS_DIR/deny.txt"
# -t 2: two seconds of grace, then SIGKILL -- the leg measures a replica COMING BACK on the
# new list, not how politely the old one stops.
docker restart -t 2 "yj-ha-rl$REPLICAS" >/dev/null 2>&1 &
flips=$($NOPATHCONV docker exec -i yj-ha-client sh -s -- "$UNSC" "$REPLICAS" "$((LIST_EDIT_BOUND + 1))" < "$POLL_SH" 2>/dev/null | tr -d '\r')
wait
report=$(printf '%s\n' "$flips" | awk -v t0="$t0" -v n="$REPLICAS" '
  /^rl/  { d[$1] = $2 - t0 }
  /^end/ { end = $2 - t0 }
  END {
    miss = ""; maxd = 0
    for (i = 1; i <= n; i++) { k = "rl" i; if (!(k in d)) miss = miss (miss == "" ? "" : ",") k; else if (d[k] > maxd) maxd = d[k] }
    if (miss == "") miss = "none"
    ctrl = ("rl0" in d) ? sprintf("%.2f", d["rl0"]) : "never"
    umin = 1e9; umax = 0
    for (i = 1; i < n; i++) { k = "rl" i; if (k in d) { if (d[k] < umin) umin = d[k]; if (d[k] > umax) umax = d[k] } }
    spread = (umax >= umin) ? umax - umin : -1
    printf "miss=%s max=%.2f ctrl=%s end=%.2f spread=%.2f", miss, maxd, ctrl, end, spread
    for (i = 1; i <= n; i++) { k = "rl" i; if (k in d) printf " %s=%.2f", k, d[k] }
  }')
for kv in $report; do case "$kv" in
  miss=*)   miss="${kv#miss=}" ;;  max=*) maxd="${kv#max=}" ;;  ctrl=*) ctrl="${kv#ctrl=}" ;;
  end=*)    endt="${kv#end=}" ;;   spread=*) spread="${kv#spread=}" ;;
esac; done
times=$(printf '%s' "$report" | sed 's/.*end=[0-9.]* spread=[0-9.-]*//')
if [ "$miss" = "none" ] && awk "BEGIN{exit !($maxd <= $LIST_EDIT_BOUND)}"; then
  pass "every replica enforced the edit within ${LIST_EDIT_BOUND}s:${times}s (rl$REPLICAS was RESTARTED mid-window); untouched replicas spread ${spread}s"
elif [ "$miss" = "none" ]; then
  bad "every replica flipped, but the slowest took ${maxd}s against a ${LIST_EDIT_BOUND}s bound:${times}"
else
  bad "replica(s) $miss never enforced the edit in ${endt}s -- an edit that is not seen is a deny list that does not deny${times:+; seen:$times}"
  for i in $(seq 1 "$REPLICAS"); do echo "--- rl$i log:"; docker logs "yj-ha-rl$i" 2>&1 | tail -4; done
fi
if [ "$ctrl" = "never" ]; then
  pass "CONTROL: the replica on an unedited copy never flipped in ${endt}s -- the instrument can see a replica that misses an edit"
else
  bad "CONTROL flipped at ${ctrl}s: it mounts a copy nobody edited, so the instrument is not measuring the edit"
fi

# 9c: NO FLIP BACK, and the reason is the operator's. One more TTL later every replica
# still names the deny-list rule and the operator as the source; the restarted one got
# there by a FRESH load, and its log says so (a count of 1, not a reload line).
sleep 6
stuck=0
for i in $(seq 1 "$REPLICAS"); do
  v=$(verdict_of "http://yj-ha-rl$i:8080/$UNSC")
  case "$v" in
    403\|operator-denied\|deny-list:$UNSC\|"operator deny list"\|*) ;;
    *) bad "rl$i one TTL later: '$v' (want 403|operator-denied|deny-list:$UNSC|operator deny list|...)"; stuck=1 ;;
  esac
done
[ "$stuck" = 0 ] && pass "one TTL later all $REPLICAS replicas still refuse by rule deny-list:$UNSC, source 'operator deny list' -- no flip back"
# Captured first, then matched with a shell pattern -- never `docker logs | grep -q` under
# this script's pipefail: grep -q exits on the first match and closes the pipe, a still-
# writing `docker logs` dies of SIGPIPE, and pipefail reports THAT status, so the `if`
# reads a present line as absent. It passed four times on a laptop (the log had finished
# before grep quit) and failed on CI's dind on the first run, with the line in the output.
rl_log=$(docker logs "yj-ha-rl$REPLICAS" 2>&1)
case "$rl_log" in
  *"1 package(s) blocked outright"*) pass "the restarted replica came up on the NEW list (fresh load of 1 entry), not on a reload" ;;
  *) bad "the restarted replica's log has no fresh-load line for 1 entry:"; printf '%s
' "$rl_log" | grep -i "deny-list" | tail -3 ;;
esac
for i in $(seq 0 "$REPLICAS"); do docker rm -f "yj-ha-rl$i" >/dev/null 2>&1; done
# ── LEG 9 END ────────────────────────────────────────────────────────────────

say "RESULT"
if [ "$FAIL" -eq 0 ]; then
  echo "ALL PASS: $REPLICAS replicas, no database, no shared store, no licence tier;"
  echo "          rolling update and rollback with zero failed requests (#23, D133);"
  echo "          gate independent of the approval database, and the database bootstrap"
  echo "          survives $BOOT_REPLICAS replicas starting together (#23 last box, D210);"
  echo "          a list edit is enforced by every replica within ${LIST_EDIT_BOUND}s (#131)."
else
  echo "FAILED"
fi
exit "$FAIL"
