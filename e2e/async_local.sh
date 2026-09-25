#!/usr/bin/env bash
# Async-local-mode E2E (D18, MR-D). Drives the REAL pipeline — firewall(local) ->
# scheduler -> run-once scanner container -> result sink -> approval Postgres L2 ->
# firewall — and asserts the async contract on BOTH terminal outcomes:
#
#   ALLOW leg   (lodash, fixture score 9.0 >= threshold 5.0)
#     1. cold pull                       -> 403 "still scanning" (verdict pending, D102)
#     2. ONE background scan writes L2   -> the row carries the EXACT score 9.0
#     3. the next pull is decisive       -> 200 ALLOWED
#     4. NO second scan is launched      (the durable row prevents re-scan)
#
#   BLOCK leg   (express, fixture refuses to score it)
#     6. cold pull -> 403 pending, scan writes the durable NEGATIVE MARKER, next pull
#        -> 403 BLOCKED. Both ends are 403 since D102, so a status comparison here
#        would pass whatever happened in between; the transition is asserted on the
#        EXPLANATION changing (still-scanning -> blocked by firewall) instead.
#
#   OPERATOR RE-SCAN (issue #12)
#     7. DELETE /v1/scores clears L2; the pull is masked by L1 until it expires,
#        then goes cold again and a SECOND scan runs.
#
# WHY THE SCANNER IS FAKED (issue #55 — read e2e/fakescanner/README.md).
# This rig used to obtain its decisive answer from the REAL scorecard binary FAILING
# AUTH, because CI sets no GITHUB_TOKEN: the 403 it asserted was produced by scanning
# being BROKEN. So the required gate could not tell "the pipeline works" from "every
# scan fails", it went RED when run with a working token, and it would have gone red
# the day scanning was fixed. The scheduler now launches a deterministic fixture image
# whose score is chosen at build time. Everything else stays real — scheduler,
# launchers, container lifecycle, capability-token sink, Postgres L2, firewall.
#
# NEGATIVE CONTROL — prove this rig can fail before trusting it:
#   FAKE_SCORE=1.0 bash e2e/async_local.sh     # must FAIL the leg-3 allow assertion
#   Remove FW_DENY_LIST from docker-compose.asyncfake.yml      # must FAIL leg 21's deny half
#   Remove FW_ALLOW_LIST from docker-compose.asyncfake.yml     # must FAIL leg 21's allow half
#      VERIFIED 2026-09-05, both run separately, and the deny control found something:
#      with FW_DENY_LIST removed, left-pad STILL returns 403 -- the async cold-scan
#      "still scanning" refusal wears the same status code as a deny. Only the REASON
#      assertions caught it. That is why leg 21 asserts the refusal is a verdict rather
#      than a pending scan, and why "the code was 403" is not evidence here.
#      The fixture pair is what makes the leg non-vacuous in both directions: each
#      package's DEFAULT verdict is the opposite of the one its list produces.
#   Set FW_FLOW_FLUSH_INTERVAL: "0" in docker-compose.e2e.yml  # must FAIL all of leg 9
#     (verified 2026-07-29: all four flow assertions go red with emission disabled, and
#      green with it on — so leg 9 detects a broken telemetry chain rather than merely
#      co-existing with a working one)
#   Set APPROVAL_SMTP_HOST: "nonexistent-relay" in docker-compose.e2e.yml # must FAIL leg 12
#     (an unreachable relay must surface as "no alert email arrived", not as a green run --
#      an alerting leg that cannot detect undelivered mail is worse than no leg at all)
#   In approval/store.go Put, write EXCLUDED.first_seen instead of decisions.first_seen
#                                                              # must FAIL leg 15's AGE check
#     (the queue then reports every entry as newly arrived no matter how long it waited,
#      which is the exact way an unbounded queue stays invisible -- leg 15 is the only
#      place the POSTGRES first_seen path runs at all, so if this control does not go red
#      that code has no coverage anywhere)
#     (control EXERCISED 2026-08-31 without a Docker daemon: the console's own template
#      was rendered from a test double into an HTML fixture, leg 15's seven `case`
#      patterns were run against it -- all seven matched -- and the fixture was then
#      re-rendered with FirstSeen dropped, at which point the AGE pattern went red. So the
#      MATCHING is verified even though the live service wiring is not; a wrong pattern
#      would otherwise have shown up as a silent green.)
#
#   In console/server.go sameOrigin, `return true` unconditionally   # must FAIL leg 18
#   In console/gitstore.go Apply, pass "" as actor to the identity helpers          # must FAIL leg 26
#   In console/oidc.go, return the session payload without verifying its MAC         # must FAIL leg 27
#   In e2e/oidcstub/idp.py id_token, never set the "nonce" claim                     # must FAIL leg 25
#   In scorecardfloor.go partialReportVerdict, `return nil` before the floor         # must FAIL leg 29 half 2
#   In scorecardfloor.go, `required = map[string]bool{}` for a nil set               # must FAIL leg 29 half 2
#   Remove "Dangerous-Workflow" from defaultRequiredChecks                             # must FAIL leg 29 half 2 (the unit guard reddens first)
#     (EXERCISED 2026-09-05: the cross-origin POST answered 303 instead of 403. This is
#      the control that matters most in this group -- deleting the CSRF guard breaks
#      nothing a human would ever notice, because every legitimate use keeps working.)
#   In console/server.go handleOverride, skip the s.approval.Put(d) call
#                                                                # must FAIL 3 of leg 19
#     (EXERCISED 2026-09-05 in the same run: the console still answered 303, and the
#      store assertion, the decidedBy assertion and -- the one that matters -- "the block
#      actually lifted" all went red. That is what proves leg 19 is not passing merely
#      because the package was allowed anyway.)
#     THE CONTROL ALSO CORRECTED THE TEST: the failure message used to say "The record is
#     in the store (asserted above)", which under this sabotage is FALSE and would send
#     the next reader to the wrong half of the system. It now tells them to read the two
#     preceding assertions, which split store-side from request-path causes. Both matchers
#     were tightened at the same time -- `grep 'approved'` and `grep "$OP_USER"` were both
#     satisfiable by the note text this rig itself submits, i.e. self-satisfying.
#
#   In console/flowclient.go, rename the `bytes_client` json tag on flowSummary
#                                                          # must FAIL leg 20's "0 B" check
#   In console/flowclient.go, rename the `package` json tag on flowPackage
#                                                      # must FAIL leg 20's lodash check
#     (BOTH EXERCISED TOGETHER 2026-09-05, disjoint assertions so one run proves both:
#      exactly those two went red out of 70 and nothing else moved. This is the control
#      that justifies leg 20 existing alongside the unit test in console/capacity_test.go
#      -- that test pins the tags against a LITERAL, which is a claim about the wire
#      format; this one asserts against the real approval service.
#      The discriminator worth noting: leg 20's "not in its empty state" assertion stayed
#      GREEN under both sabotages, because the `requests` tag was untouched. That is the
#      exact shape of the bug -- the page knows traffic happened and still shows 0 B --
#      and it is why the byte check is separate from the empty-state check rather than
#      folded into it.)
#
# Prereq: the base scanner image must exist; this script builds it and the fixture.
# Run from the repo root:  bash e2e/async_local.sh
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
# Exported: docker-compose.e2e.yml interpolates it into console-oidc's redirect URL and
# oidcstub's browser-facing base (legs 24-27). Unexported, both silently fall back to
# "localhost", which is wrong under dind and would fail leg 25 with a handshake cookie
# that never comes back.
export E2E_HOST
# docker-compose.asyncfake.yml is layered LAST and is specific to this rig: it points
# the scheduler at the deterministic scanner fixture and shortens the firewall's L1 TTL.
# It is deliberately not folded into docker-compose.e2e.yml, which verify_repo_local.sh
# also layers — see the header of that file.
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
COMPOSE=(docker compose -f docker-compose.yml -f docker-compose.e2e.yml -f docker-compose.asyncfake.yml)

# The ALLOW package: the fixture scores it, so the pipeline ends in a real allow driven
# by a real number. The BLOCK package: its repo matches the fixture's unscorable
# substring, so the scan fails and the durable negative marker path is exercised.
# Both are top-tier npm packages with stable deps.dev records (checked by the preflight),
# because local mode runs the D33/D36 repo cross-check on the hot path.
PKG="lodash"
REPO="github.com/lodash/lodash"
PKG_BLOCK="express"
# The operator-list fixtures (D193, issue #58). Declared HERE rather than in leg 21
# because leg 14 asserts them on the console page and runs FIRST — a name defined
# inside the later leg would expand to empty there and the assertion would pass
# vacuously against "the page contains the empty string".
DENIED_PKG="left-pad"
ALLOWED_PKG="body-parser"
REPO_BLOCK="github.com/expressjs/express"

# The score baked into the fixture image. Overridable ONLY to run the negative control
# above — the leg-3 assertion below deliberately hard-codes "200 allowed", so building
# the fixture with a sub-threshold score must make this rig fail.
FAKE_SCORE="${FAKE_SCORE:-9.0}"
SCANNER_FAKE_IMAGE="yellowjack-scanner-fake:e2e"

# Which launcher the scheduler uses to spawn each run-once scanner (D16). Default
# docker-run; set SCHEDULER_LAUNCHER=docker-api to drive the SAME async pipeline
# over the raw Docker Engine API. Exported so docker-compose.e2e.yml interpolates it.
LAUNCHER="${SCHEDULER_LAUNCHER:-docker-run}"
export SCHEDULER_LAUNCHER="$LAUNCHER"
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

# The run-scoped operator-list git working tree, and its bare remote.
#
# A COPY of the committed fixture rather than the fixture itself. Legs 22 and 23 both
# mutate these files -- 22 from the host, 23 through the console -- and doing that to a
# TRACKED file left the repo dirty whenever a leg failed between the edit and the
# restore. A throwaway directory removes the restore step entirely, which is the more
# reliable shape: there is nothing to put back.
#
# It must be a GIT repo because leg 23 requires one: the console COMMITS its edits
# (D193 option (c)), so the audit trail is git history and there has to be a history to
# write to. The bare remote is real too, so the push half is exercised rather than
# assumed -- it is a local path rather than a network, but it is the same push code.
LIST_DIR=".e2e-lists"
LIST_REMOTE_DIR=".e2e-lists-remote"
DENY_FIXTURE="$LIST_DIR/deny.txt"

# The run-scoped known-malware feed (#160). A directory of its own, created EMPTY, so the
# gate boots with a feed configured that names nothing -- see leg 21b for why the empty
# start is the interesting one. Not a git repo: nothing edits this through the console.
FEED_DIR=".e2e-feed"
FEED_FIXTURE="$FEED_DIR/malware.ndjson"

cleanup() {
  rm -rf "$LIST_DIR" "$LIST_REMOTE_DIR" "$FEED_DIR" .e2e-lists-gitconfig
  say "logs (firewall, scheduler tails)"
  "${COMPOSE[@]}" logs --tail=30 firewall scheduler 2>/dev/null
  say "teardown"
  "${COMPOSE[@]}" down -v >/dev/null 2>&1
}
trap cleanup EXIT

# code <path> — HTTP status for a firewall pull.
code() { curl -s -o /dev/null -w '%{http_code}' "http://${E2E_HOST}:8080/$1"; }

# l2_score <repo> — the numeric score on the approval L2 row, or "" when the row is
# absent or carries the negative marker (score null).
l2_score() {
  curl -s "http://${E2E_HOST}:8090/v1/scores?repo=$1" \
    | grep -Eo '"score"[[:space:]]*:[[:space:]]*[0-9.]+' | head -1 | grep -Eo '[0-9.]+$'
}

# num_eq <a> <b> — numeric equality, so 9 and 9.0 compare equal (the JSON encoder
# drops a trailing .0, which a string compare would call a failure).
num_eq() { [ -n "$1" ] && awk -v a="$1" -v b="$2" 'BEGIN{exit !(a+0==b+0)}'; }

# scans_for <repo> — how many background scans the firewall COMPLETED for a repo.
scans_for() { "${COMPOSE[@]}" logs firewall 2>/dev/null | grep -c "background scan .*($1)"; }

# Before building anything: local mode runs the deps.dev repo cross-check on the hot path,
# so a 429 does not merely fail an assertion here — it changes WHICH refusal the firewall
# returns (transient-unavailable instead of the verdict-pending one that assertion 1
# expects). Since D102 both are 403, so the difference is in the explanation rather than
# the status — which makes naming the real cause here MORE important, not less: a bare
# "403 != 403" would tell you nothing. The preflight exits 3/4/5 accordingly.
bash e2e/depsdev_preflight.sh async || exit $?

# Build the run-scoped operator-list repo from the committed fixture, BEFORE compose
# starts: the firewall and the console both bind-mount into it, and a missing mount
# source is a stack that does not come up (with an error that names a path, not a cause).
#
# `git init` here rather than a committed nested repo: a repo inside the source tree
# confuses every tool that walks it, and this one is disposable by design.
say "0) build the run-scoped operator-list git repo"
rm -rf "$LIST_DIR" "$LIST_REMOTE_DIR" "$FEED_DIR"
mkdir -p "$LIST_DIR" "$FEED_DIR"
: > "$FEED_FIXTURE"
# Copy with CRLF STRIPPED. On a Windows host core.autocrlf=true checks the committed
# fixture out as CRLF, and these files are consumed by Linux containers -- one of which
# (the console) commits them back. Seeding CRLF made the first run of leg 23 report
# +13/-11 for a one-entry add: the host had stored LF, the container stored what it
# found, and every line differed. Normalising here keeps the repo byte-identical on
# every host, which is what makes the audit-diff assertion mean the same thing anywhere.
tr -d '' < e2e/operator-lists/allow.txt > "$LIST_DIR/allow.txt"
tr -d '' < e2e/operator-lists/deny.txt  > "$LIST_DIR/deny.txt"
git init -q -b main "$LIST_DIR"
# core.sharedRepository, on both repos, and set BEFORE anything is written so it
# governs the seed commit too (#112).
#
# The chmod at the end of this block fixes the permissions of files that exist AT
# THAT MOMENT. It cannot fix objects git writes LATER, and those are created with the
# writing process's default mode -- so a directory created by one uid can be
# unwritable by the other. Which .git/objects/<xx>/ fanout directory a new object
# lands in depends on its CONTENT HASH, and the content carries the actor and the
# timestamp, so whether a run hits an already-shared directory or a fresh restrictive
# one varies per run. That is why #112 is intermittent rather than simply broken.
#
# core.sharedRepository is git's own mechanism for a repository written by more than
# one uid: it makes git create new objects and fanout directories group- and
# other-writable itself, which is the half chmod structurally cannot cover.
git -C "$LIST_DIR" config core.sharedRepository 0777
# ...and stop git re-introducing it. Without this the host's global autocrlf applies to
# this throwaway repo too, and the seed commit would translate the LF back on checkout.
git -C "$LIST_DIR" config core.autocrlf false
git -C "$LIST_DIR" config core.eol lf
# -b main matters: without it the bare repo HEAD symrefs to refs/heads/master while the
# console pushes refs/heads/main, so the two never line up for anything reading HEAD.
git init -q --bare -b main "$LIST_REMOTE_DIR"
# The remote is written by the CONSOLE (uid 65532) on push while being created here
# by the rig, so it has the same two-uid problem as the working tree above.
git -C "$LIST_REMOTE_DIR" config core.sharedRepository 0777
# Identity and signing set LOCALLY, so a developer's global config (a signing key they
# do not have in this shell, a different name) cannot fail the rig. The console sets its
# OWN identity per commit with -c, so these apply only to this seed commit.
git -C "$LIST_DIR" config user.name  "e2e fixture"
git -C "$LIST_DIR" config user.email "e2e@yellowjack.invalid"
git -C "$LIST_DIR" config commit.gpgsign false
git -C "$LIST_DIR" add -A
git -C "$LIST_DIR" commit -q -m "seed operator lists from the committed fixture"
# The remote is addressed by its path INSIDE THE CONSOLE CONTAINER, because the console
# is what pushes. The host path and the container path differ, and using the host one
# here would fail only at push time, deep inside leg 23.
# MSYS_NO_PATHCONV=1 matters ONLY on a Windows host, and its absence is silent until
# the push. Git Bash rewrites a leading-slash argument into a Windows path, so
# "/srv/lists-remote" was stored as "C:/Program Files/Git/srv/lists-remote" -- which,
# having a colon in it, git then treated as an SCP-style address and tried to reach over
# SSH ("cannot run ssh: No such file or directory"). The variable is unset and harmless
# on Linux. The path is the one INSIDE THE CONSOLE CONTAINER, because the console pushes.
MSYS_NO_PATHCONV=1 git -C "$LIST_DIR" remote add origin /srv/lists-remote

# A gitconfig for the console container, mounted at its HOME.
#
# git refuses to touch a repository owned by another uid ("detected dubious ownership")
# and that is exactly what a bind mount produces: the host owns the files, the console
# runs as 65532. The console already declares its OWN repo safe per invocation, but a
# push also opens the REMOTE, and a process cannot vouch for a repository it was not
# pointed at. So the deployer says so -- which is what this file is, and what a real
# operator using a local-path remote would have to do too.
printf '[safe]
	directory = /srv/lists
	directory = /srv/lists-remote
'   > "$LIST_DIR/../.e2e-lists-gitconfig"
chmod a+r "$LIST_DIR/../.e2e-lists-gitconfig"
# The console container runs as uid 65532 (non-root, matching the distroless image it
# replaces) while THIS shell creates the repo as whoever runs the rig -- root in CI. A
# bind mount carries host ownership straight through, so without this the console cannot
# write the file, commit, or update .git at all.
#
# It cost a CI-only failure to find: on Docker Desktop bind mounts are permissive, so
# every local run passed while the first CI run wrote nothing. The console reported the
# refusal correctly; the LEG was what failed to notice, because it asserted on the 303
# rather than on the outcome.
#
# a+rwX (capital X) so directories get traversable and files do not become executable.
chmod -R a+rwX "$LIST_DIR" "$LIST_REMOTE_DIR"
pass "operator-list repo seeded at $LIST_DIR (bare remote at $LIST_REMOTE_DIR)"


# Build the run-once scanner and the deterministic fixture layered on top of it. Doing
# this here (rather than documenting it as a prerequisite) is the point: the fixture
# only means anything if it is rebuilt from the CURRENT scanner, and a stale image is
# exactly the kind of silent wrong-reason pass this rig was rewritten to eliminate.
say "build scanner image + deterministic fixture (FAKE_SCORE=$FAKE_SCORE)"
# Through the mirror wrapper (#106): in CI the bases come from our own registry and
# the wrapper refuses if the build resolved one anywhere else; on a laptop with no
# mirror configured it is a plain, quiet docker build.
sh scripts/mirror-bases.sh build scanner/Dockerfile -t yellowjack-scanner:dev . || {
  bad "could not build yellowjack-scanner:dev"; exit 1; }
docker build -q -f e2e/fakescanner/Dockerfile \
  --build-arg "FAKE_SCORE=$FAKE_SCORE" \
  -t "$SCANNER_FAKE_IMAGE" . >/dev/null || {
  bad "could not build $SCANNER_FAKE_IMAGE"; exit 1; }
# A preflight with teeth: the scheduler instantiates the fixture BY TAG, and a missing
# image surfaces only as scans that never report — i.e. as a timed-out async contract,
# which reads as a firewall bug. Name the real problem here instead.
docker image inspect "$SCANNER_FAKE_IMAGE" >/dev/null 2>&1 || {
  echo "PREFLIGHT: $SCANNER_FAKE_IMAGE is missing after a reportedly successful build." >&2
  echo "The scheduler launches it by tag; without it every scan silently never reports." >&2
  exit 6; }
echo "  ok        $SCANNER_FAKE_IMAGE present"

# The SMTP sink for leg 12 (#32 C4c). Built by tag for the same reason as the scanner
# fixture: docker-compose.e2e.yml references yellowjack-fakesmtp:e2e by image, and a
# missing tag would surface only as an approval service that cannot send — i.e. as an
# alerting bug rather than a missing fixture.
say "build the SMTP sink fixture (leg 12)"
docker build -q -f e2e/fakesmtp/Dockerfile -t yellowjack-fakesmtp:e2e . >/dev/null || {
  bad "could not build yellowjack-fakesmtp:e2e"; exit 1; }
docker image inspect yellowjack-fakesmtp:e2e >/dev/null 2>&1 || {
  echo "PREFLIGHT: yellowjack-fakesmtp:e2e is missing after a reportedly successful build." >&2
  echo "Leg 12 would then fail as 'no alert email arrived', which reads as a product bug." >&2
  exit 6; }
echo "  ok        yellowjack-fakesmtp:e2e present"
# The stub OpenID Provider for legs 24-27 (#149), same shape as fakesmtp: built here,
# referenced by image in docker-compose.e2e.yml.
docker build -q -f e2e/oidcstub/Dockerfile -t yellowjack-oidcstub:e2e . >/dev/null || {
  bad "could not build yellowjack-oidcstub:e2e"; exit 1; }
docker image inspect yellowjack-oidcstub:e2e >/dev/null 2>&1 || {
  echo "PREFLIGHT: yellowjack-oidcstub:e2e is missing after a reportedly successful build." >&2
  exit 1; }
echo "  ok        yellowjack-oidcstub:e2e present"

say "bring up postgres + approval + scheduler + firewall + fakesmtp + console x2 (local mode, launcher=$LAUNCHER)"
"${COMPOSE[@]}" up -d --build postgres approval scheduler firewall fakesmtp oidcstub console console-auth console-oidc || { bad "compose up"; exit 1; }

say "wait for firewall + approval health"
for i in $(seq 1 30); do
  curl -fsS http://${E2E_HOST}:8080/healthz >/dev/null 2>&1 && \
  curl -fsS http://${E2E_HOST}:8090/healthz >/dev/null 2>&1 && break
  sleep 2
done

say "1) cold pull -> expect 403 carrying the PENDING explanation (D102)"
# ONE request, not a curl for the body plus a curl for the status. The background scan
# this very pull kicked off can finish between two requests, flipping the second from
# pending to allowed — a race that would make this leg flake for a reason that looks
# like a contract regression. Under the old contract the assertion needed only the
# status, so a single -o /dev/null call sufficed; needing body AND status together is
# what introduced the hazard.
RESP="$(curl -s -w '\n%{http_code}' "http://${E2E_HOST}:8080/$PKG")"
CODE="$(printf '%s' "$RESP" | tail -n1)"
BODY="$(printf '%s' "$RESP" | sed '$d')"
[ "$CODE" = "403" ] && pass "cold pull returned 403" || bad "cold pull code=$CODE (want 403)"
# The status alone no longer separates "still scanning" from "we said no" — both are
# 403 since D102. The explanation is the only thing that distinguishes them, so it is
# what gets asserted. A cold pull that read as a verdict would be a real regression,
# and under the old contract the status code would have caught it for free.
has "$BODY" "still scanning" \
  && pass "body carries the PENDING explanation" \
  || bad "body does not say a scan is running: $BODY"
has "$BODY" "blocked by firewall" \
  && bad "cold pull reads as a VERDICT, but nothing has been evaluated yet: $BODY" \
  || pass "cold pull does not masquerade as a verdict"
# The configured wait rode on Retry-After before. With that header gone it must reach
# the developer through the reason text, or it reaches them nowhere at all.
has "$BODY" "60" \
  && pass "pending wait (60s) surfaced in the reason text" \
  || bad "pending wait not surfaced anywhere the developer sees it: $BODY"

say "2) wait for the background scan to write L2, carrying the EXACT fixture score"
SCORED=0
for i in $(seq 1 40); do
  SC="$(curl -s -o /dev/null -w '%{http_code}' "http://${E2E_HOST}:8090/v1/scores?repo=$REPO")"
  if [ "$SC" = "200" ]; then SCORED=1; break; fi
  sleep 3
done
if [ "$SCORED" = "1" ]; then
  pass "L2 row present after background scan"
  printf 'L2 body: %s\n' "$(curl -s "http://${E2E_HOST}:8090/v1/scores?repo=$REPO")"
  # The row must carry the number the fixture emitted. This is what proves a real
  # SCORE traversed scanner -> sink -> scheduler -> L2, rather than merely proving
  # that something failed — which is all the old negative-marker assertion showed.
  GOT="$(l2_score "$REPO")"
  num_eq "$GOT" "$FAKE_SCORE" \
    && pass "L2 row carries the fixture score ($GOT)" \
    || bad "L2 score=${GOT:-<none>} (want $FAKE_SCORE — did the score survive the pipeline?)"
else
  bad "background scan never wrote L2 (timed out)"
fi

say "3) second pull -> decisive ALLOW (200), not another 503"
CODE2="$(code "$PKG")"
L1_WARMED_AT="$(date +%s)" # this pull filled $PKG's in-process L1 entry; leg 7a relies on it
[ "$CODE2" = "200" ] && pass "second pull allowed (200), decisive on a real score" \
  || bad "post-scan $PKG pull code=$CODE2 (want 200 allowed at score $FAKE_SCORE)"

say "4) exactly ONE background scan was launched for $REPO (no re-scan)"
SCANS="$(scans_for "$REPO")"
[ "$SCANS" = "1" ] && pass "exactly 1 background scan for $REPO" || bad "background scan count=$SCANS for $REPO (want 1)"

say "5) the scheduler actually used launcher=$LAUNCHER (not a silent default)"
LOGGED="$("${COMPOSE[@]}" logs scheduler 2>/dev/null | grep -c "launcher: $LAUNCHER")"
[ "$LOGGED" -ge 1 ] && pass "scheduler ran launcher=$LAUNCHER" || bad "scheduler did not log launcher=$LAUNCHER"

# The other terminal outcome. Reached because the FIXTURE refuses this repo, not
# because auth failed — so it stays true with or without a GITHUB_TOKEN in the env.
say "6) unscorable package -> durable negative marker -> decisive block (fail-closed)"
# CAREFUL: this leg used to assert a 503 -> 403 TRANSITION, and the status change was
# what proved the background scan had turned "no answer yet" into a durable verdict.
# Since D102 both ends are 403, so a status comparison here would pass no matter what
# happened in between — the leg would go vacuous while still looking green. The
# transition is therefore asserted on the EXPLANATION, which is now the only thing
# that actually changes.
# One request: this pull launches a scan, so a second one could catch a different state.
RESP_B1="$(curl -s -w '
%{http_code}' "http://${E2E_HOST}:8080/$PKG_BLOCK")"
CODE_B1="$(printf '%s' "$RESP_B1" | tail -n1)"
BODY_B1="$(printf '%s' "$RESP_B1" | sed '$d')"
[ "$CODE_B1" = "403" ] && pass "cold pull of $PKG_BLOCK returned 403" \
  || bad "cold pull of $PKG_BLOCK code=$CODE_B1 (want 403)"
has "$BODY_B1" "still scanning" \
  && pass "cold pull of $PKG_BLOCK is PENDING, not yet a verdict" \
  || bad "cold pull of $PKG_BLOCK is not pending — the 'before' half of this leg is "\
"missing, so a later block would not prove the scan decided anything: $BODY_B1"
MARKED=0
for i in $(seq 1 40); do
  SCB="$(curl -s -o /dev/null -w '%{http_code}' "http://${E2E_HOST}:8090/v1/scores?repo=$REPO_BLOCK")"
  if [ "$SCB" = "200" ]; then MARKED=1; break; fi
  sleep 3
done
if [ "$MARKED" = "1" ]; then
  pass "L2 row present for $REPO_BLOCK after its scan"
  # The marker is the ABSENCE of a numeric score (score: null). If a number shows up
  # here the fixture scored a repo it was told to refuse, and leg 6 is testing nothing.
  GOTB="$(l2_score "$REPO_BLOCK")"
  [ -z "$GOTB" ] && pass "row is the negative marker (score null)" \
    || bad "row for $REPO_BLOCK carries score=$GOTB (want the negative marker)"
else
  bad "no L2 row for $REPO_BLOCK (the unscorable scan never reported)"
fi
BODY_B2="$(curl -s "http://${E2E_HOST}:8080/$PKG_BLOCK")"
CODE_B2="$(code "$PKG_BLOCK")"
[ "$CODE_B2" = "403" ] && pass "second pull of $PKG_BLOCK blocked (403)" \
  || bad "post-scan $PKG_BLOCK pull code=$CODE_B2 (want 403 unscorable/fail-closed)"
# The half that makes this leg mean something: the answer must have CHANGED from
# "still scanning" to a real verdict. Same status both times, different explanation.
has "$BODY_B2" "blocked by firewall" \
  && pass "second pull is a decisive VERDICT, not still pending" \
  || bad "post-scan $PKG_BLOCK pull is still not a verdict — the durable negative "\
"marker did not become a block: $BODY_B2"
has "$BODY_B2" "still scanning" \
  && bad "post-scan $PKG_BLOCK pull is STILL pending; the scan never became decisive: $BODY_B2" \
  || pass "pending state did not persist past the scan"

# --- issue #12: operator-triggered re-scan (DELETE /v1/scores clears the L2 row) ---
say "7) operator clears the L2 row -> expect 204"
# 7a needs $PKG's L1 entry (FW_SCORE_CACHE_TTL=30s in docker-compose.asyncfake.yml, filled
# by leg 3's pull) to OUTLIVE the clear. Leg 6 waits on a real scanner container, and on a
# slow Docker host that wait can use up most of the 30s -- after which 7a failed on timing,
# not behaviour (twice on 2026-09-23, on gate code that passed it three times the same day).
# So when leg 3's entry may be near expiry, wait until it has CERTAINLY expired, refill L1
# from the still-present L2 row with one pull, and clear L2 straight after. The refill reads
# L2, so it launches no scan and leg 7b's scan count is unchanged.
L1_AGE=$(( $(date +%s) - L1_WARMED_AT ))
if [ "$L1_AGE" -ge 20 ]; then
  [ "$L1_AGE" -lt 32 ] && sleep $(( 32 - L1_AGE ))
  REWARM="$(code "$PKG")"
  [ "$REWARM" = "200" ] \
    && pass "refilled $PKG's L1 from L2 before the clear (leg 3's entry was ${L1_AGE}s old)" \
    || bad "refill pull of $PKG code=$REWARM (want 200, served from the L2 row)"
fi
DEL="$(curl -s -o /dev/null -w '%{http_code}' -X DELETE "http://${E2E_HOST}:8090/v1/scores?repo=$REPO")"
[ "$DEL" = "204" ] && pass "L2 row cleared (204)" || bad "delete code=$DEL (want 204)"
# The row must actually be gone now (a subsequent GET is 404 / cold).
GONE="$(curl -s -o /dev/null -w '%{http_code}' "http://${E2E_HOST}:8090/v1/scores?repo=$REPO")"
[ "$GONE" = "404" ] && pass "L2 row is gone (cold again)" || bad "post-delete GET code=$GONE (want 404)"

# 7a pins a REAL LIMITATION rather than hiding it: DELETE hits the approval service's
# durable L2 only. A firewall replica that already cached the score in its in-process L1
# keeps serving it until that entry expires — at the production default
# (FW_SCORE_CACHE_TTL=1h) an operator "re-scan" therefore does nothing visible for up to
# an hour. The rig runs with a 30s TTL (docker-compose.e2e.yml) so both halves are
# observable. Whether DELETE ought to punch through L1 is open on issue #55; until it is
# answered, this assertion is what stops the behavior from changing unnoticed in either
# direction.
say "7a) immediately after the clear, L1 still masks it (documented limitation)"
CODE3="$(code "$PKG")"
[ "$CODE3" = "200" ] && pass "pull still served from L1 (200) — DELETE does not reach L1" \
  || bad "post-clear pull code=$CODE3 (want 200: L1 should still mask the cleared L2 row)"

say "7b) once L1 expires -> cold again (403 pending) and a SECOND scan runs"
RECOLD=0
for i in $(seq 1 30); do
  # Matched on the explanation, not the status: 403 alone would also match a BLOCK,
  # so a status check here could report "cold again" for a package that had actually
  # been denied — the opposite outcome.
  if has "$(curl -s "http://${E2E_HOST}:8080/$PKG")" "still scanning"; then RECOLD=1; break; fi
  sleep 3
done
[ "$RECOLD" = "1" ] && pass "post-expiry pull is pending again (403 still-scanning)" \
  || bad "pull never returned to pending after L1 should have expired (re-scan unreachable)"
RESCAN=0
for i in $(seq 1 40); do
  if [ "$(scans_for "$REPO")" -ge 2 ]; then RESCAN=1; break; fi
  sleep 3
done
[ "$RESCAN" = "1" ] && pass "a second background scan ran after the clear (re-scan)" \
  || bad "no re-scan after clear (scan count for $REPO stayed at 1)"

# Issue #13: the result sink must require a per-scan capability token. The scan ids
# are a counter plus a timestamp, so without the token anyone who can reach the
# scheduler can POST a forged perfect score to a pending id and get a malicious
# package ALLOWED. Unit tests cover the match/mismatch logic; what only a live run
# proves is that the DEPLOYED scheduler enforces it on the real URL surface.
#
# This is a regression guard with teeth: revert the token and the tokenless POST
# below answers 200 ("unknown id, ignoring") instead of 400, and this fails.
say "8) the result sink rejects the pre-token URL shape (score-forgery guard)"
FORGED='{"repo":"github.com/lodash/lodash","result":{"repo":"github.com/lodash/lodash","score":10}}'
NOTOKEN="$(curl -s -o /dev/null -w '%{http_code}' -X POST -H 'Content-Type: application/json' \
  -d "$FORGED" http://${E2E_HOST}:8096/results/1-forged)"
[ "$NOTOKEN" = "400" ] && pass "tokenless POST /results/{id} refused (400)" \
  || bad "tokenless POST /results/{id} returned $NOTOKEN (want 400 — is the capability token still enforced?)"

# The counterpart, so the 400 above can't be passed off as "that route just 404s":
# the tokened shape IS routed, and an unknown id is accepted-and-dropped (200) so a
# late-reporting container never exits non-zero.
WITHTOKEN="$(curl -s -o /dev/null -w '%{http_code}' -X POST -H 'Content-Type: application/json' \
  -d "$FORGED" http://${E2E_HOST}:8096/results/1-forged/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA)"
[ "$WITHTOKEN" = "200" ] && pass "tokened POST for an unknown id is accepted-and-dropped (200)" \
  || bad "tokened POST for an unknown id returned $WITHTOKEN (want 200)"

# ---------------------------------------------------------------------------
# 9) CAPACITY TELEMETRY REACHES POSTGRES (#32 Phase C, C2)
#
# Everything above proves the SCORING pipeline. This leg proves the TELEMETRY one, and
# it is the only place it is proven end to end: the unit tests exercise memStore, and
# the pgStore SQL for the flow tables runs NOWHERE else — a broken INSERT or a column
# typo would ship green without this. The chain under test is the whole of it:
#
#   real client pull -> relay -> flowRecorder -> flowEmitter -> POST /v1/flow
#     -> approval -> pgStore -> flow_buckets -> GET /v1/flow/{summary,packages,sources}
#
# The legs above already drove real pulls through the firewall, so by now traffic has
# happened; we only have to wait for a flush interval to elapse.
say "9) capacity flow telemetry lands in Postgres and reads back"

# Wait up to 30s for the first batch. FW_FLOW_FLUSH_INTERVAL is 5s in this override and
# the emitter aligns to the wall clock, so one interval plus slack is plenty.
FLOW_BYTES=0
for _ in $(seq 1 30); do
  # grep -o | cut, NOT a sed backreference: a capture group here is one stray backslash
  # away from an empty replacement, and that failure is SILENT — the variable comes back
  # empty, the numeric test fails, and it reads as "the telemetry pipeline is broken"
  # when the pipeline is fine and the assertion is what is broken. That is exactly the
  # bug this line replaces, caught on the rig's first run.
  FLOW_BYTES="$(curl -s "http://${E2E_HOST}:8090/v1/flow/summary" | grep -o '"bytes_client":[0-9]*' | head -1 | cut -d: -f2)"
  [ -n "$FLOW_BYTES" ] && [ "$FLOW_BYTES" -gt 0 ] 2>/dev/null && break
  sleep 1
done

[ -n "$FLOW_BYTES" ] && [ "$FLOW_BYTES" -gt 0 ] 2>/dev/null   && pass "flow summary reports $FLOW_BYTES bytes served (counters reached Postgres)"   || bad "flow summary reported no bytes after 30s — the recorder->emitter->pgStore chain is broken"

# The per-package ranking must name a package we actually pulled. This is what
# distinguishes "some row landed" from "the identity survived the whole chain".
FLOW_PKGS="$(curl -s "http://${E2E_HOST}:8090/v1/flow/packages")"
case "$FLOW_PKGS" in
  *lodash*) pass "per-package ranking names lodash (identity survived recorder -> SQL)" ;;
  *)        bad "per-package ranking did not mention lodash: $FLOW_PKGS" ;;
esac

# And the per-source-IP aggregation (D92) must have at least one row, proving the
# SECOND table is written too — it has its own INSERT and its own GROUP BY, so a
# summary that works says nothing about it.
FLOW_SRCS="$(curl -s "http://${E2E_HOST}:8090/v1/flow/sources")"
case "$FLOW_SRCS" in
  *bytes_client*) pass "per-source-IP aggregation returned rows (flow_ip_buckets written)" ;;
  *)              bad "per-source-IP aggregation was empty: $FLOW_SRCS" ;;
esac

# The series endpoint is the one with gap-filling and a re-bucketing step; hitting it
# proves the SQL parses and the fill runs against real rows rather than a fixture.
FLOW_SERIES="$(curl -s "http://${E2E_HOST}:8090/v1/flow/series?step=1m")"
case "$FLOW_SERIES" in
  *start*) pass "flow series returns points over real data" ;;
  *)       bad "flow series returned nothing usable: $FLOW_SERIES" ;;
esac

# ---------------------------------------------------------------------------
# 10) THE HEARTBEAT REACHES POSTGRES (#32 Phase C, C4a)
#
# Leg 9 proves traffic counters land. This proves LIVENESS reporting lands, which is a
# separate path (its own table, its own upsert-REPLACE semantics) and the signal the
# "is the firewall alive?" alert is built on. Like the flow SQL before it, the
# instance_health SQL runs nowhere else — memStore covers the unit tests, and without
# this leg a broken INSERT or a mistyped column would ship green.
say "10) firewall heartbeat lands in Postgres"

HEALTH=""
for _ in $(seq 1 30); do
  HEALTH="$(curl -s "http://${E2E_HOST}:8090/v1/health")"
  case "$HEALTH" in
    *instance*) break ;;
  esac
  sleep 1
done

case "$HEALTH" in
  *instance*) pass "heartbeat row present: $(printf '%s' "$HEALTH" | cut -c1-120)" ;;
  *)          bad "no heartbeat after 30s — the firewall is not reporting liveness: $HEALTH" ;;
esac

# reported_at must be SERVER-stamped and non-empty; a blank one means the server trusted
# an absent client field, which is how a skewed replica reads as permanently fresh.
case "$HEALTH" in
  *reported_at*) pass "heartbeat carries a server-stamped reported_at" ;;
  *)             bad "heartbeat has no reported_at: $HEALTH" ;;
esac

# ---------------------------------------------------------------------------
# 11) THE ALERTS ENDPOINT ANSWERS FROM REAL DATA (#32 Phase C, C4b)
#
# The alert rules are unit-tested exhaustively as a pure function; what only a live run
# proves is that the ENDPOINT wires them to the real store — it reads instance_health and
# a windowed flow summary, both of which are pgStore paths here.
#
# The assertion is deliberately "a well-formed EMPTY array": this rig's firewall has been
# heartbeating every 5s throughout, so nothing should be silent, and a healthy run must
# produce NO alerts. An endpoint that returned junk, 500'd, or invented an alert on a
# healthy deployment all fail here — the last of those being the false positive that
# would greet every new operator.
say "11) alerts endpoint answers from real data, and a healthy stack is quiet"

ALERTS="$(curl -s -o /tmp/yj_alerts.json -w '%{http_code}' "http://${E2E_HOST}:8090/v1/alerts")"
ALERTS_BODY="$(cat /tmp/yj_alerts.json 2>/dev/null)"

[ "$ALERTS" = "200" ]   && pass "GET /v1/alerts -> 200"   || bad "GET /v1/alerts -> $ALERTS (want 200)"

case "$ALERTS_BODY" in
  "[]"|"[]"*) pass "healthy stack reports no alerts (body: $ALERTS_BODY)" ;;
  \[*)        bad "alerts fired on a HEALTHY stack — a false positive an operator would see on day one: $ALERTS_BODY" ;;
  *)          bad "alerts body is not a JSON array: $ALERTS_BODY" ;;
esac

# ---------------------------------------------------------------------------
# 12) AN ALERT ACTUALLY BECOMES AN EMAIL (#32 Phase C, C4c / D90)
#
# Leg 11 proves alerts are COMPUTED. This proves one is DELIVERED — over a real SMTP
# conversation to a real listener. That conversation (dial, EHLO, MAIL/RCPT, DATA, the
# end-of-data dot that carries the relay's actual verdict) is reachable by no unit test:
# the unit tests substitute a fake mailSender, which is right for testing dedup logic but
# leaves approval/mail.go's deliver() executed nowhere. Same argument as legs 9 and 10.
#
# The trigger is a synthetic heartbeat carrying audit_dropped=3 rather than waiting for a
# real instance to go silent: the silence threshold is 15 minutes and an e2e leg must not
# sit through it, while the "we dropped data" alert fires at any non-zero value instantly.
# It is a genuine alert through the genuine path — only the input is synthesized.
say "12) an alert is delivered as an email over real SMTP"

curl -fsS -X POST "http://${E2E_HOST}:8090/v1/health" \
  -H 'Content-Type: application/json' \
  -d '{"instance":"e2e-alert-probe","ecosystem":"npm","audit_dropped":3}' \
  -o /dev/null || bad "could not post the synthetic heartbeat that triggers the alert"

# The sweep runs every 5s here (APPROVAL_ALERT_SWEEP_INTERVAL in docker-compose.e2e.yml).
MAILS=""
for _ in $(seq 1 30); do
  MAILS="$(curl -s "http://${E2E_HOST}:1080/messages")"
  case "$MAILS" in
    *'"count":0'*|"") ;;
    *) break ;;
  esac
  sleep 2
done

case "$MAILS" in
  *'"count":0'*|"")
    bad "no alert email arrived within 60s — an alert was raised and nobody was told: $MAILS" ;;
  *)
    pass "alert email delivered over SMTP" ;;
esac

# The message must actually be about the condition. A delivered-but-empty or
# wrong-subject mail would pass a mere count check while telling the operator nothing.
case "$MAILS" in
  *"Yellow Jack"*) pass "email is identifiable as ours" ;;
  *)               bad "delivered mail has no Yellow Jack subject: $MAILS" ;;
esac
case "$MAILS" in
  *e2e-alert-probe*) pass "email names the instance the alert is about" ;;
  *)                 bad "delivered mail does not name the affected instance: $MAILS" ;;
esac
# Headers survived the trip intact — proof the message was framed correctly rather than
# merely accepted as bytes.
case "$MAILS" in
  *"Auto-Submitted: auto-generated"*) pass "email carries its RFC headers" ;;
  *)  bad "delivered mail is missing the Auto-Submitted header — message framing is wrong: $MAILS" ;;
esac

# THE DEDUP CONTRACT, END TO END. The condition is still active and sweeps keep running,
# so if "already notified" were not durable the operator would get an email every 5s. This
# is the assertion that would catch a claim that silently never persists (a migration that
# did not run, a table written but never read) — which the unit tests, running against
# memStore, structurally cannot see.
COUNT_BEFORE="$(printf '%s' "$MAILS" | sed 's/.*"count":\([0-9]*\).*/\1/')"
sleep 15   # at least two more sweep intervals
COUNT_AFTER="$(curl -s "http://${E2E_HOST}:1080/messages" | sed 's/.*"count":\([0-9]*\).*/\1/')"

if [ "$COUNT_BEFORE" = "$COUNT_AFTER" ]; then
  pass "standing condition was not re-mailed across further sweeps (count stayed $COUNT_AFTER)"
else
  bad "alert re-mailed while the condition merely persisted ($COUNT_BEFORE -> $COUNT_AFTER) — dedup is not durable, and this is how an alert address gets muted"
fi

# ---------------------------------------------------------------------------
# 13) THE FIREWALL REPORTS THE POLICY IT IS ENFORCING (#32 Phase D, D4)
#
# The policy view is unit-tested against the engine, and the ingest is unit-tested against
# memStore — but the instance_health policy columns are pgStore SQL that runs NOWHERE else,
# and this is an ALTER TABLE on a table that already shipped. A mistyped column or a
# migration that silently does not apply would present as every replica going silent at
# once (the INSERT fails on every beat), i.e. as a total outage rather than as a schema bug.
# Same argument as legs 9, 10 and 12.
say "13) the firewall's enforced policy reaches Postgres"

HEALTH_POLICY="$(curl -s "http://${E2E_HOST}:8090/v1/health")"

case "$HEALTH_POLICY" in
  *'"policy"'*) pass "heartbeat carries the reported policy" ;;
  *) bad "no policy on the heartbeat — the firewall is not reporting what it enforces: $(printf '%s' "$HEALTH_POLICY" | cut -c1-200)" ;;
esac

# The digest must be extracted into its own field, not merely buried in the document:
# that column is what a divergence check compares, and it is the half that needs the
# ingest-side parse to have worked.
case "$HEALTH_POLICY" in
  *'"policy_digest"'*) pass "the digest was extracted on ingest" ;;
  *) bad "policy stored but no policy_digest — comparing replicas would mean deep-comparing rule chains: $(printf '%s' "$HEALTH_POLICY" | cut -c1-200)" ;;
esac

# All three chains survived the trip. A view that lost one would describe a gate with
# fewer decision points than it has.
for CHAIN in verdict classification bytes; do
  case "$HEALTH_POLICY" in
    *"\"$CHAIN\""*) pass "chain '$CHAIN' present in the reported policy" ;;
    *) bad "chain '$CHAIN' missing from the reported policy" ;;
  esac
done

# THE MISLEADING-RENDER CHECK, end to end. This rig runs the shipped FW_BYTE_GATE default
# (allow-but-log), so the bytes chain's default action must NOT read as a block — an
# operator shown "block" here would believe their artifact route is fail-closed when D49
# deliberately leaves it visibility-first. Unit-tested too, but this proves the value
# survives serialization, Postgres and the read path rather than only the function call.
case "$HEALTH_POLICY" in
  *'"default_action":"allow-but-log"'*) pass "bytes chain reports its true visibility-first default" ;;
  *) bad "no allow-but-log default action in the reported policy — the byte gate's real posture did not survive the round trip: $(printf '%s' "$HEALTH_POLICY" | cut -c1-300)" ;;
esac

# ---------------------------------------------------------------------------
# 14) THE CONSOLE RENDERS THE REAL FIREWALL'S REAL POLICY (#32 Phase D, D4b)
#
# FIRST e2e COVERAGE OF THE CONSOLE AT ALL. Until now the console was exercised only by
# unit tests against a fake approval client — e2e/clearable_test.go says so explicitly
# ("does NOT test the console UI"). So the whole client path (HTTP to the approval
# service, JSON decode, template execution) ran nowhere but in-process, against data a
# test author wrote by hand.
#
# That is the same gap legs 9/10/12/13 exist to close, and it is worth closing here
# because this leg proves the chain END TO END with nothing hand-written in it: a real
# firewall compiled a real ruleset, described it, sent it on a heartbeat, Postgres stored
# it, the console fetched it over HTTP and rendered it.
say "14) the console renders the policy the real firewall reports"

# Port 18085, not the console's usual 8085. The base compose binds the console to
# 127.0.0.1 (D19 — the developer's browser, not the LAN), which is right and is also why it
# is the ONE service the rig cannot reach on its normal port under CI's dind, where
# $E2E_HOST is a service host rather than loopback. docker-compose.e2e.yml publishes an
# extra all-interfaces mapping for the rig; see the comment there.
POLICY_PAGE="$(curl -s -o /tmp/yj_policy.html -w '%{http_code}' "http://${E2E_HOST}:18085/policy")"
POLICY_BODY="$(cat /tmp/yj_policy.html 2>/dev/null)"

if [ "$POLICY_PAGE" = "200" ]; then
  pass "GET /policy -> 200"
elif [ "$POLICY_PAGE" = "000" ]; then
  # Name the real problem rather than leaving a bare curl failure. A 000 here is almost
  # always the port binding, not the page: it means nothing accepted the connection.
  bad "GET /policy -> could not connect at ${E2E_HOST}:18085. The console is bound to 127.0.0.1 in docker-compose.yml (D19); the rig needs the all-interfaces override in docker-compose.e2e.yml to reach it under dind."
else
  bad "GET /policy -> $POLICY_PAGE (want 200)"
fi

# The page must name the actual replica reporting, not a placeholder: this is what proves
# the console reached the control plane rather than rendering an empty shell.
case "$POLICY_BODY" in
  *"Enforced policy"*) pass "the policy page rendered" ;;
  *) bad "no policy page content: $(printf '%s' "$POLICY_BODY" | head -c 200)" ;;
esac
case "$POLICY_BODY" in
  *"OSSF score at or above threshold"*) pass "real rule names reached the browser" ;;
  *) bad "the rendered page carries no real rule names — the console is not reading the reported policy" ;;
esac

# THE OPERATOR'S OWN LISTS ON THE PAGE (D193, issue #58 increment 2).
#
# This is the last hop for the lists — firewall -> Postgres -> console client -> template
# — and it is the hop a unit test cannot cover. The console declares its own policyList
# struct rather than importing the firewall's ListView (it is an HTTP client of the
# control plane, not a library user of it), and the failure mode of that seam is SILENT
# and one-directional: a renamed json tag decodes to an EMPTY list, which this page
# renders as "the operator has not configured one" rather than as an error. That reads as
# a working page showing no policy.
#
# So the assertion is on a NAME the operator actually put on the list, not on the section
# heading: a heading proves the template ran, a name proves the data crossed the seam.
case "$POLICY_BODY" in
  *"Operator lists"*) pass "the policy page renders the operator-lists section" ;;
  *) bad "the policy page has no operator-lists section, though the firewall is running "\
"with FW_ALLOW_LIST and FW_DENY_LIST set (leg 21 proves both are enforced). Either the "\
"firewall is not REPORTING them or the console template is not rendering them." ;;
esac
case "$POLICY_BODY" in
  *"$DENIED_PKG"*) pass "the page names $DENIED_PKG — the list contents crossed the seam" ;;
  *) bad "the operator-lists section rendered but does not name $DENIED_PKG, which leg 21 "\
"proved is being ENFORCED. That is the signature of a json tag mismatch between "\
"console/client.go's policyList and the firewall's ListView: the names decode to empty "\
"and the page reads as an unconfigured list rather than erroring." ;;
esac
case "$POLICY_BODY" in
  *score_threshold*) pass "policy settings rendered" ;;
  *) bad "no policy settings on the page" ;;
esac

# THE MISLEADING-RENDER CHECK, at the very last mile. The rig runs the shipped
# FW_BYTE_GATE default (allow-but-log), so the byte chain's stated default must NOT read
# as a block. This is the one belief the whole D4 increment exists to get right, and this
# is the only place it is checked against a real engine, a real database and a real
# template at once.
case "$POLICY_BODY" in
  *"<strong>allow-but-log</strong>"*) pass "the byte chain's true visibility-first default survived to the page" ;;
  *) bad "the page does not state a true allow-but-log default — an operator would read their artifact route as fail-closed" ;;
esac

# A single-replica rig must NOT show the divergence warning. Getting this wrong means the
# very first thing an operator sees is a fleet-disagreement alarm on a one-node install.
case "$POLICY_BODY" in
  *"different policies"*) bad "divergence warning shown on a SINGLE-replica deployment — a false alarm on day one" ;;
  *) pass "no divergence warning on a single-replica deployment" ;;
esac

say "15) the queue exposes STATE, AGE and DECIDER for a package the FIREWALL queued"

# Issue #50 acceptance item 4: "a queued package's state/age/decider are observable
# through the real operator surface, not only in the DB".
#
# WHY THIS LEG EARNS ITS RUNTIME. The unit tests for queue age run against memStore. The
# POSTGRES half -- the ALTER that adds first_seen to an existing table, the COALESCE that
# reads legacy rows, and the ON CONFLICT branch that must read decisions.first_seen rather
# than EXCLUDED -- has no local coverage at all, because there is no Postgres on the dev
# host. This is the ONLY place that code executes.
#
# It also proves the value survives the whole real chain: firewall records the package as
# pending -> approval writes it to Postgres -> console reads it back -> the template
# renders an age. A break anywhere in that chain shows up here as a queue that says
# "unknown", which is exactly the symptom an operator would see.
#
# $PKG_BLOCK is used because leg 6 already drove the real firewall into recording it as
# unscorable, so by this point it is a genuinely queued package rather than a row this
# script inserted to please itself.
QUEUE_PAGE="$(curl -s -o /tmp/yj_queue.html -w '%{http_code}' "http://${E2E_HOST}:18085/decisions")"
QUEUE_BODY="$(cat /tmp/yj_queue.html 2>/dev/null)"

if [ "$QUEUE_PAGE" = "200" ]; then
  pass "GET /decisions -> 200"
elif [ "$QUEUE_PAGE" = "000" ]; then
  bad "GET /decisions -> could not connect at ${E2E_HOST}:18085 (see leg 14 on the console's 127.0.0.1 binding)"
else
  bad "GET /decisions -> $QUEUE_PAGE (want 200)"
fi

# ANTI-VACUITY. Every check below is a substring test against this page, so an empty or
# error body would satisfy the negative ones by accident and this leg would report a queue
# it never actually read.
case "$QUEUE_BODY" in
  *"Awaiting review"*) pass "the queue page rendered" ;;
  *) bad "no queue page content: $(printf '%s' "$QUEUE_BODY" | head -c 200)" ;;
esac

# The package the firewall queued must actually BE here. If it is not, the three checks
# that follow are about an empty table.
case "$QUEUE_BODY" in
  *"$PKG_BLOCK"*) pass "the queued package $PKG_BLOCK appears on the operator's page" ;;
  *) bad "$PKG_BLOCK is not on the queue page, so the firewall's pending record never reached the console" ;;
esac

# STATE.
case "$QUEUE_BODY" in
  *'badge pending'*) pass "STATE is shown per row" ;;
  *) bad "no per-row state badge -- the operator cannot tell where an entry is in the process" ;;
esac

# AGE. Each waiting row must carry a real duration. "unknown" is the value the page
# shows when first_seen did not survive, so it is the precise failure signal here: it
# means the Postgres column, the COALESCE, or the console mapping is broken. Matched on
# the ROW's own wording ("Waiting 3 minutes"): the page's tab strip says "Waiting" too,
# so the bare word would pass with no age on any row.
case "$QUEUE_BODY" in
  *'class="wait'*) pass "AGE is rendered per waiting row" ;;
  *) bad "no per-row wait -- age is not surfaced on the real operator surface" ;;
esac
case "$QUEUE_BODY" in
  *"Waiting under a minute"*|*"Waiting "[0-9]*)
    pass "AGE carries a real duration, so first_seen survived firewall -> Postgres -> console" ;;
  *"unknown"*)
    bad "the queue shows an UNKNOWN age for a package the firewall just queued. first_seen did not survive the real path -- check the decisions.first_seen ALTER, the COALESCE on read, and that Put writes decisions.first_seen rather than EXCLUDED." ;;
  *)
    bad "no age value rendered for any queued row" ;;
esac

# DECIDER. This rig sets no CONSOLE_AUTH_USER, so the honest answer is that nobody is
# accountable -- and the page must SAY so rather than leaving the field blank. A blank
# decider on a deployment with no credential is indistinguishable from one with a named
# reviewer, which is the misreading #50 exists to prevent.
case "$QUEUE_BODY" in
  *"no one is accountable"*)
    pass "DECIDER: the page states plainly that no reviewer is configured" ;;
  *"Who decides"*)
    bad "the page names a decider, but this rig configures no CONSOLE_AUTH_USER -- so it is naming someone who does not exist" ;;
  *)
    bad "the queue says nothing about who decides or what happens next" ;;
esac

# What happens next. A block that does not say this is the configuration the study found
# people route around.
case "$QUEUE_BODY" in
  *"What happens next"*) pass "the queue says what happens next" ;;
  *) bad "the queue never says what happens next -- entries sit with no stated process" ;;
esac


# ── THE CONSOLE'S WRITE PATH (legs 16-19) ───────────────────────────────────
#
# THE GAP THIS CLOSES. `/override` is the ONLY endpoint in the entire operator UI that
# changes anything: it is the button a human presses to unblock a developer. Until now it
# had no end-to-end coverage at all. e2e/clearable_test.go proves the MECHANISM works and
# says so explicitly in its own comment --
#
#     "In production this is console/handleOverride writing an approval record;
#      here it is the same record arriving by the same read path."
#
# -- which is an accurate description of a hole. The record was proven to unblock a
# client; the console was never proven to write that record. Everything between the form
# and the store (basic auth, the CSRF origin check, form parsing, the read-modify-write
# against the approval service, the redirect) was unit-tested only.
#
# The three refusal legs come FIRST and are not decoration. Leg 19 alone would pass on a
# console that accepted the write from anybody, or on one where the package had never
# really been blocked. Each of 16-18 is a way the happy path could be green for the wrong
# reason.
CONSOLE_RO="http://${E2E_HOST}:18085"     # overrides DISABLED (no credential)
CONSOLE_RW="http://${E2E_HOST}:18086"     # overrides ENABLED  (fixture credential)
OP_USER="e2e-operator"
OP_PASS="e2e-fixture-not-a-secret"

say "16) the read-only console REFUSES to write, and says why"
# The default posture. A console with no credential configured must not act on a POST
# even though nothing stopped the request reaching the handler -- defence in depth, and
# what an operator relies on when they deploy the console without setting a password.
RO_RESP="$(curl -s -w '\n%{http_code}' -X POST "$CONSOLE_RO/override" \
  --data-urlencode "package=$PKG_BLOCK" --data-urlencode 'verdict=approved')"
RO_CODE="$(printf '%s' "$RO_RESP" | tail -n1)"
RO_BODY="$(printf '%s' "$RO_RESP" | sed '$d')"
[ "$RO_CODE" = "403" ] && pass "read-only console refuses the override (403)" \
  || bad "read-only console POST /override code=$RO_CODE (want 403) -- a console with no "\
"credential configured accepted a write"
has "$RO_BODY" "overrides are disabled" \
  && pass "the refusal NAMES the missing configuration" \
  || bad "the refusal does not say overrides are disabled, so an operator cannot tell a "\
"misconfiguration from a bug: $RO_BODY"

say "17) the write console refuses an UNAUTHENTICATED override"
NA_CODE="$(curl -s -o /dev/null -w '%{http_code}' -X POST "$CONSOLE_RW/override" \
  --data-urlencode "package=$PKG_BLOCK" --data-urlencode 'verdict=approved')"
[ "$NA_CODE" = "401" ] && pass "unauthenticated override refused (401)" \
  || bad "unauthenticated POST /override code=$NA_CODE (want 401) -- the credential is "\
"configured but not enforced, so the queue is writable by anyone who can reach the port"

say "18) the write console refuses a CROSS-ORIGIN override even with valid credentials"
# The CSRF guard, and the assertion most likely to rot unnoticed: a browser attaches Basic
# Auth to a cross-site form POST automatically, so correct credentials are NOT evidence
# the operator intended the request. Removing sameOrigin() breaks nothing a human would
# notice -- every legitimate use keeps working -- which is exactly why it needs a test
# rather than a comment.
XO_CODE="$(curl -s -o /dev/null -w '%{http_code}' -X POST "$CONSOLE_RW/override" \
  -u "$OP_USER:$OP_PASS" -H 'Origin: http://attacker.example' \
  --data-urlencode "package=$PKG_BLOCK" --data-urlencode 'verdict=approved')"
[ "$XO_CODE" = "403" ] && pass "cross-origin override refused (403) despite valid credentials" \
  || bad "cross-origin POST /override code=$XO_CODE (want 403) -- the CSRF guard is gone; "\
"a page on any site could approve a package using the operator's own browser session"

say "19) THE LOOP: firewall blocks -> operator approves in the console -> firewall allows"
# BEFORE. Re-asserted here rather than inherited from leg 6: several legs have run since,
# and a package that is already allowed would make the 'after' half prove nothing.
BEFORE_CODE="$(code "$PKG_BLOCK")"
if [ "$BEFORE_CODE" = "200" ]; then
  bad "$PKG_BLOCK is ALREADY allowed before the operator approved anything -- this leg "\
"cannot observe an unblock, and leg 6's block did not hold"
else
  pass "before: $PKG_BLOCK is refused ($BEFORE_CODE), so an unblock is observable"
fi

# THE ACT. Exactly what the queue page's form submits: same fields, same method, same
# endpoint. curl sends no Origin header, which sameOrigin() treats as same-origin -- CSRF
# is a browser attack and a non-browser client is not one. Leg 18 covers the browser case.
OV_CODE="$(curl -s -o /dev/null -w '%{http_code}' -X POST "$CONSOLE_RW/override" \
  -u "$OP_USER:$OP_PASS" \
  --data-urlencode "package=$PKG_BLOCK" --data-urlencode 'verdict=approved' \
  --data-urlencode 'note=approved by the e2e rig (leg 19)')"
[ "$OV_CODE" = "303" ] && pass "the console accepted the override (303 back to the queue)" \
  || bad "authenticated same-origin POST /override code=$OV_CODE (want 303) -- the "\
"operator pressed approve and the console did not record it"

# The record must exist in the CONTROL PLANE, not merely have been accepted. A 303 with no
# write behind it is precisely the failure this leg exists to catch, and it would be
# invisible from the response alone.
DEC="$(curl -s "http://${E2E_HOST}:8090/v1/decisions?package=$PKG_BLOCK")"
has "$DEC" '"verdict":"approved"' \
  && pass "the approval service holds an approved record for $PKG_BLOCK" \
  || bad "no approved record reached the approval service -- the console redirected "\
"without writing: $DEC"
# And it must be attributed. An audit trail whose decider is empty cannot answer "who
# approved this", which is the first question asked afterwards (#41/D150).
has "$DEC" '"decidedBy":"'"$OP_USER"'"' \
  && pass "the record names the operator who decided it ($OP_USER)" \
  || bad "the approved record does not carry the deciding operator ($OP_USER), so the "\
"approval is unattributable: $DEC"

# AFTER. The assertion that matters to a developer: the block actually lifts. Polled,
# because the firewall's in-process L1 keeps serving the old verdict until it expires
# (30s in this rig, 1h at the production default) -- the limitation leg 7a pins.
CLEARED=0
for i in $(seq 1 30); do
  if [ "$(code "$PKG_BLOCK")" = "200" ]; then CLEARED=1; break; fi
  sleep 3
done
[ "$CLEARED" = "1" ] \
  && pass "after: $PKG_BLOCK is served -- the console override reached the developer" \
  || bad "THE OVERRIDE NEVER REACHED THE CLIENT: $PKG_BLOCK is still refused after the "\
"operator approved it in the console. Read the two assertions ABOVE first, because they "\
"split the cause: if the record reached the store, the break is between the store and the "\
"request path -- a cached verdict, a memoised 4xx, or an L1 entry holding the old "\
"decision (#20/#49). If it did not, the console never wrote it and IT is the cause."


# ── 20) THE CAPACITY PAGE RENDERS THE REAL NUMBERS (#32 Pillar 2, D80/D81) ───
#
# Leg 9 proved the telemetry chain as far as the approval service's API. This leg proves
# the LAST HOP, which nothing else covers:
#
#   GET /v1/flow/{summary,packages}  ->  console client  ->  html/template  ->  the page
#
# The console declares its own structs for these payloads rather than importing the
# approval service's (it is an HTTP client of the control plane, not a library user of
# it). That seam is deliberate and it has a specific failure mode: a JSON tag renamed on
# one side decodes to ZERO on the other. It does not error. The page renders "0 B" and
# reads as a quiet week.
#
# console/capacity_test.go pins the tags against a literal, but a literal is a claim about
# the wire format. THIS is the assertion made against the real service, and it is why the
# page is checked here rather than only in unit tests.
#
# Served from the READ-ONLY console (18085, no credential configured), which also holds
# D88's line: this page is computed from the operator's own data and must never be gated.
say "20) the capacity page renders the real flow numbers, not zeroes"

CAP_RESP="$(curl -s -w '\n%{http_code}' "${CONSOLE_RO}/capacity")"
CAP_CODE="$(printf '%s' "$CAP_RESP" | tail -n1)"
CAP_BODY="$(printf '%s' "$CAP_RESP" | sed '$d')"

[ "$CAP_CODE" = "200" ] && pass "GET /capacity served by the read-only console (200)" \
  || bad "GET /capacity code=$CAP_CODE (want 200) at ${CONSOLE_RO} -- the page is either "\
"unrouted or gated behind the credential D88 forbids gating it with"

# ANTI-VACUITY, and the reason this leg is not just a 200 check. Every leg above drove
# real pulls, and leg 9 already asserted the bytes reached Postgres -- so an empty-state
# page here means the console could not read what the API demonstrably holds.
case "$CAP_BODY" in
  *"No traffic recorded"*)
    bad "the capacity page shows its empty state, but leg 9 proved the flow summary "\
"holds $FLOW_BYTES bytes. The console is not reading what the approval service is "\
"serving -- check the /v1/flow/summary client and its JSON tags" ;;
  *) pass "the page is not in its empty state (it read the traffic that leg 9 proved)" ;;
esac

# THE DRIFT ASSERTION. The totals tile renders as `<div class="v">0 B</div>` when a byte
# field decodes to zero -- exactly what a renamed json tag produces, silently. Traffic has
# certainly happened by now, so a zero here is a wiring fault and never a quiet window.
#
# The pattern is the TILE's, `class="v">0 B<`, and it used to be `>0 B<` anywhere on the
# page. That flaked (twice in about six runs, passing on re-run with nothing changed)
# because the per-package table renders a byte cell the same way, and a ROW with requests
# and no bytes is a legitimate state: the gate counts a relay's request when the upstream
# opens and its bytes only when the stream finishes, so a package that is in flight, was a
# HEAD, or drew an empty answer has one without the other, depending on which 5s flush has
# landed. console/capacityzero_test.go proves both halves deterministically: the old
# pattern fires on a healthy page, and the tile pattern still catches a zeroed summary.
#
# NOT proven: which row tripped it in the failing runs -- the page was not captured. So a
# zero-byte row is now REPORTED (not failed), and the next occurrence documents itself.
case "$CAP_BODY" in
  *'class="v">0 B<'*)
    bad "a byte TOTAL rendered as '0 B' after real traffic. That is the signature of a "\
"JSON tag mismatch between console/flowclient.go and approval/flowstore.go -- the field "\
"decoded to zero rather than erroring: $(printf '%s' "$CAP_BODY" | grep -o 'class="v">[^<]*<' | tr '\n' ' ')" ;;
  *) pass "the byte totals are non-zero (the wire format agrees across the seam)" ;;
esac
case "$CAP_BODY" in
  *'<td class="num">0 B</td>'*)
    echo "NOTE: a package ROW shows 0 B while the totals do not (requests counted, bytes not yet). Rows: $(printf '%s' "$CAP_BODY" | tr -d '\n' | grep -o '<tr>.\{0,260\}<td class="num">0 B</td>' | sed 's/<[^>]*>/ /g' | tr -s ' ' | cut -c1-200 | head -3 | tr '\n' '|')" ;;
esac

# And the per-package identity must survive the last hop too. Leg 9 asserted lodash
# reaches the API; this asserts it reaches the OPERATOR, which is the claim the page makes.
case "$CAP_BODY" in
  *lodash*) pass "the heaviest-packages ranking names lodash (D81 Q1, end to end)" ;;
  *)        bad "the capacity page does not name lodash, though leg 9 proved the API "\
"ranks it. The per-package read or its rendering is broken." ;;
esac

# D81 Q5's counters must be on the page. They are the half an operator acts on, and they
# come from the same payload as the totals -- so their absence would mean the template,
# not the transport.
case "$CAP_BODY" in
  *"Truncated relays"*) pass "the integrity counters are rendered (D81 Q5)" ;;
  *)                    bad "the capacity page omits the integrity counters (D81 Q5)" ;;
esac

# --- 21) THE OPERATOR'S OWN ALLOW/DENY LISTS TAKE EFFECT (D193, issue #58) -----
#
# D192 trimmed the open-source launch to "time gating on package version age with a
# whitelist/blacklist"; D193 settled that the published-advisory feed STAYS and the
# operator adds their own list on top. This leg proves the operator half reaches a real
# client, which no unit test can: operatorlist_test.go drives Evaluate() directly, and
# the thing that has broken repeatedly in this project is the WIRING between a correct
# predicate and the request path (#59, #67).
#
# The two fixtures are chosen so each one's DEFAULT outcome is the opposite of the
# outcome the list produces. That is what makes this leg non-vacuous:
#
#   left-pad     scores 9.0, resolves fine   -> allowed by default -> deny list must BLOCK it
#   body-parser  repo matches "expressjs/"   -> blocked by default -> allow list must SERVE it
#
# So a rig where the lists were never loaded fails in BOTH directions, rather than
# quietly agreeing with the default in one of them.
say "21) the operator's own allow/deny lists take effect through a real pull"

DENY_RESP="$(curl -s -w '\n%{http_code}' "http://${E2E_HOST}:8080/${DENIED_PKG}")"
DENY_CODE="$(printf '%s' "$DENY_RESP" | tail -n1)"
DENY_BODY="$(printf '%s' "$DENY_RESP" | sed '$d')"

[ "$DENY_CODE" = "403" ] \
  && pass "$DENIED_PKG is refused (403)" \
  || bad "$DENIED_PKG code=$DENY_CODE (want 403) -- FW_DENY_LIST was not consulted on "\
"the request path (the list loaded; check the startup count) or the verdict did not "\
"reach the client."

# ⚠️ THE 403 ALONE PROVES NOTHING, and this is not a hypothetical. Running this leg with
# FW_DENY_LIST removed (2026-09-05) STILL produced a 403 for left-pad -- the async
# cold-scan "not yet approved, still scanning" refusal, which is the same status code
# for an entirely different reason. So the deny half is carried by the assertions below,
# and this guard names the specific impostor rather than leaving the code to stand alone.
# Same family as the gate-script finding: an exit code cannot validate a gate.
case "$DENY_BODY" in
  *"still scanning"*|*"not yet approved"*)
    bad "$DENIED_PKG was refused because a SCAN IS PENDING, not because the operator "\
"denied it. The status code is identical, so this is the one way this leg can look green "\
"while the deny list does nothing at all." ;;
  *) pass "the refusal is a verdict, not a pending cold scan" ;;
esac

# The REASON, not just the refusal. D137's finding is that a block a developer cannot
# attribute gets routed around, and the whole point of keeping the operator list separate
# from the malware feed is that these two refusals send them to different people.
case "$DENY_BODY" in
  *"deny list"*) pass "the refusal names the deny list as the decider" ;;
  *) bad "the 403 body does not mention the deny list: $(printf '%s' "$DENY_BODY" | head -c 200)" ;;
esac
case "$DENY_BODY" in
  *"not a published malware advisory"*)
    pass "the refusal distinguishes itself from a published advisory (D193)" ;;
  *) bad "the refusal does not distinguish a LOCAL policy decision from a published "\
"malware advisory. A developer reading this cannot tell whether to drop the dependency "\
"or to go ask a colleague, which is exactly the confusion D193 required us to avoid." ;;
esac

ALLOW_CODE="$(code "$ALLOWED_PKG")"
[ "$ALLOW_CODE" = "200" ] \
  && pass "$ALLOWED_PKG is served (200) -- the allow list overrides the unscorable block" \
  || bad "$ALLOWED_PKG code=$ALLOW_CODE (want 200). This fixture is UNVERIFIABLE by "\
"construction, so with FW_UNSCORABLE_POLICY=block it is refused unless the allow list "\
"is consulted. A 403 means FW_ALLOW_LIST is loaded but not reaching the decision, or is "\
"being consulted AFTER the unscorable branch instead of before the network."

# --- 21c) THE CONSOLE EXPLAINS THE REFUSAL IT JUST WATCHED (console redesign, part 4) ---
#
# Leg 21 made the real gate refuse $DENIED_PKG from the operator's deny list. The Stopped
# page is the console's account of that refusal, and only this rig can show the account is
# of the REAL event: the audit record crossed gate -> control plane -> Postgres -> console,
# carrying the structured kind (#142) the page is written from. The event is posted
# asynchronously, so the list is polled briefly rather than read once.
say "21c) the Stopped page lists leg 21's refusal and explains it as the operator's own"
STOP_LINK=""
for _ in $(seq 1 20); do
  STOP_LIST="$(curl -s "${CONSOLE_RO}/stopped?kind=operator")"
  STOP_LINK="$(printf '%s' "$STOP_LIST" | grep -o "/stopped/view?id=[0-9]*&amp;package=${DENIED_PKG}\"" | head -1 | sed 's/&amp;/\&/; s/"$//')"
  [ -n "$STOP_LINK" ] && break
  sleep 1
done
if [ -n "$STOP_LINK" ]; then
  pass "the Stopped page lists the $DENIED_PKG refusal under 'Your block list'"
  STOP_RESP="$(curl -s -w '\n%{http_code}' "${CONSOLE_RO}${STOP_LINK}")"
  STOP_CODE="$(printf '%s' "$STOP_RESP" | tail -n1)"
  STOP_BODY="$(printf '%s' "$STOP_RESP" | sed '$d')"
  [ "$STOP_CODE" = "200" ] && pass "the refusal's page opens (200)" \
    || bad "GET ${STOP_LINK} -> $STOP_CODE (want 200)"
  case "$STOP_BODY" in
    *"On your block list"*"not a published advisory"*)
      pass "the page explains it as the organisation's own decision, not an advisory" ;;
    *) bad "the refusal page does not explain an operator deny as one: $(printf '%s' "$STOP_BODY" | grep -o 'kicker[^<]*<' | head -1)" ;;
  esac
  # The discriminator: the page is written from the structured kind, so an operator deny
  # must NOT borrow the advisory's explanation. A page that said both would pass the
  # check above while telling the developer the wrong person to ask.
  case "$STOP_BODY" in
    *"named on the known-malware list"*)
      bad "the operator-deny page describes the refusal as a published advisory" ;;
    *) pass "the page does not describe the operator deny as an advisory" ;;
  esac
else
  bad "no /stopped/view link for $DENIED_PKG under ?kind=operator after 20s. Either the "\
"refusal's audit event did not reach the control plane with deny_kind=operator-denied (#142), "\
"or the Stopped page is not reading it: $(printf '%s' "$STOP_LIST" | grep -o 'Your block list<span class="n">[^<]*' | head -1)"
fi

# --- 22) AN EDITED LIST REACHES A RUNNING REPLICA (D195, issue #58 increment 3a) ---
#
# D193 has the console editing these lists while the process runs. Until the reload
# landed, the firewall read them once in NewFirewall and never again -- so an edit
# would have needed a restart, and a whitelist that needs a deploy is not the feature
# that was asked for.
#
# Only a real run can prove this. The unit tests drive reloadingList directly; what
# they cannot show is that a container actually observes a change made on the HOST
# through a bind mount, which is how every real deployment of this will work.
#
# The fixture is mounted :ro -- that stops the CONTAINER writing it, not the host.
# 21b) a refreshed known-malware feed reaches the running firewall, with no restart (#160)
#
# The unit tests drive reloadingFeed directly. What they cannot show is what every real
# refresh actually is: a change made on the HOST, observed by a CONTAINER through a bind
# mount, and consulted by the request path rather than merely re-read.
#
# The feed starts EMPTY on purpose. "Configured, and naming nothing" is the state a
# deployment sits in between refreshes, and it is exactly where a stale reader is
# invisible -- nothing is blocked either way, so only a package that becomes listed
# WHILE the gate runs can tell a working reload from a dead one.
#
# Ordering: this runs BEFORE leg 22, because leg 22 appends $PKG to the deny list and
# from then on it is refused for a different reason. The leg restores the empty feed at
# the end, which also asserts the half nobody thinks to test -- withdrawing an advisory
# takes effect too -- and hands leg 22 the served baseline it needs.
say "21b) a refreshed known-malware feed is enforced without a restart"

FEED_PKG="$PKG"
FEED_ADVISORY="MAL-E2E-FEED"

# The feed must be CONFIGURED, or "nothing is blocked" below would be true for the
# boring reason and the leg would prove nothing about reloading.
if has "$("${COMPOSE[@]}" logs firewall 2>/dev/null)" "known-malware feed"; then
  pass "baseline: the firewall booted with a feed configured (and empty)"
else
  bad "the firewall did not report a known-malware feed at startup, so FW_MALWARE_LIST "\
"is not reaching it and this leg cannot distinguish a reload from an absent feature"
fi

FEED_BEFORE="$(code "$FEED_PKG")"
if [ "$FEED_BEFORE" != "200" ]; then
  bad "$FEED_PKG is not served (code $FEED_BEFORE) before its advisory is added, so this "\
"leg cannot tell a reload from a verdict that was already there"
else
  pass "baseline: $FEED_PKG is served (200) with the feed empty"

  printf '{"id":"%s","ecosystem":"npm","name":"%s"}\n' "$FEED_ADVISORY" "$FEED_PKG" >> "$FEED_FIXTURE"

  # malwareStatTTL is 60s in the product, so poll instead of sleeping a fixed interval:
  # the leg must not be tuned to that constant, and must not go flaky if it changes.
  FEED_BLOCKED=0
  for _ in $(seq 1 24); do
    if [ "$(code "$FEED_PKG")" = "403" ]; then FEED_BLOCKED=1; break; fi
    sleep 5
  done

  if [ "$FEED_BLOCKED" = "1" ]; then
    pass "$FEED_PKG is now refused -- the refreshed feed reached the running replica"
  else
    bad "$FEED_PKG is STILL served two minutes after its advisory was appended to the "\
"feed. The firewall is not re-reading FW_MALWARE_LIST, so a refreshed feed would need a "\
"restart to take effect and the deployment would enforce an old one while believing it "\
"had refreshed"
  fi

  # It must be refused BY THE ADVISORY, not by some other 403 that happens to be there --
  # the cold-scan pending state wears the same status code (leg 1), which is exactly the
  # impostor legs 21 and 22 already guard against.
  FEED_BODY="$(curl -s "http://${E2E_HOST}:8080/${FEED_PKG}")"
  case "$FEED_BODY" in
    *"$FEED_ADVISORY"*) pass "the refusal names the advisory from the reloaded feed" ;;
    *) bad "$FEED_PKG is refused, but not by the feed: $(printf '%s' "$FEED_BODY" | head -c 200)" ;;
  esac

  # Withdrawing it must take effect too. An advisory is retracted about as often as it is
  # added (a false positive on a real package), and a reload that only ever ADDS denials
  # would leave the operator unable to undo one without a restart. This also restores the
  # served baseline leg 22 depends on.
  : > "$FEED_FIXTURE"
  if [ "$FEED_BLOCKED" != "1" ]; then
    # ANTI-VACUITY, and it was MEASURED rather than imagined. The negative control run
    # for this leg (malwareFeed() pinned to the startup field, so nothing ever reloads)
    # left $FEED_PKG served throughout -- and "it is served after the withdrawal" was
    # then true without the withdrawal doing anything, so this assertion printed PASS
    # inside a leg that was failing. An assertion that holds when the thing it tests
    # never happened is decoration.
    printf 'SKIP: the withdrawal half did not run -- %s was never blocked, so serving it now proves nothing\n' "$FEED_PKG"
  else
    FEED_CLEARED=0
    for _ in $(seq 1 24); do
      if [ "$(code "$FEED_PKG")" = "200" ]; then FEED_CLEARED=1; break; fi
      sleep 5
    done
    [ "$FEED_CLEARED" = "1" ] \
      && pass "withdrawing the advisory is enforced too -- $FEED_PKG is served again" \
      || bad "$FEED_PKG is still refused two minutes after the advisory was removed from "\
"the feed; a reload that cannot undo a denial leaves the operator with a restart as the "\
"only retraction"
  fi
fi

say "22) an edited deny list reaches the running firewall without a restart"

RELOAD_PKG="$PKG"
# $PKG (lodash), because it is the one package this rig has already pulled, scored and
# SERVED by the time leg 22 runs. A fresh name would be 403 on its first pull -- the
# async cold-scan pending state -- and the baseline guard below would (correctly)
# refuse to run: with a 403 before AND after, the leg could not tell a reload from a
# verdict that was already there. Nothing after this leg uses it.

# Baseline FIRST. Without it a package that was already refused for some other reason
# would make the "now blocked" assertion below pass while the reload did nothing.
RELOAD_BEFORE="$(code "$RELOAD_PKG")"
if [ "$RELOAD_BEFORE" = "403" ]; then
  bad "$RELOAD_PKG is ALREADY refused (403) before being added to the deny list, so this "\
"leg cannot tell a reload from the pre-existing verdict. Pick a package this rig serves."
else
  pass "baseline: $RELOAD_PKG is served (code $RELOAD_BEFORE), not refused"

  # The page must not ALREADY name it, or the "reflects the edited list" assertion
  # below would pass without the edit ever landing.
  case "$(curl -s "http://${E2E_HOST}:18085/policy")" in
    *"$RELOAD_PKG"*) bad "the policy page already names $RELOAD_PKG before the edit, so "\n"the page assertion at the end of this leg proves nothing" ;;
    *) pass "baseline: the policy page does not name $RELOAD_PKG yet" ;;
  esac

  printf '%s\n' "$RELOAD_PKG" >> "$DENY_FIXTURE"

  # listReloadTTL is 5s; poll rather than sleeping a fixed interval so the leg is not
  # tuned to that constant and does not go flaky if it changes.
  RELOADED=0
  for _ in $(seq 1 20); do
    if [ "$(code "$RELOAD_PKG")" = "403" ]; then RELOADED=1; break; fi
    sleep 2
  done

  [ "$RELOADED" = "1" ] \
    && pass "$RELOAD_PKG is now refused -- the edit reached the running replica" \
    || bad "$RELOAD_PKG is STILL served 40s after being appended to the deny list. The "\
"firewall is not re-reading the file, so a console edit would never reach a running "\
"replica and the whitelist would need a deploy to take effect."

  # And the refusal must be the OPERATOR's, not some other verdict that happens to be
  # a 403 -- the same impostor leg 21 already guards against.
  RELOAD_BODY="$(curl -s "http://${E2E_HOST}:8080/${RELOAD_PKG}")"
  case "$RELOAD_BODY" in
    *"deny list"*) pass "the refusal is attributed to the operator deny list" ;;
    *) bad "$RELOAD_PKG is refused, but not by the deny list: $(printf '%s' "$RELOAD_BODY" | head -c 200)" ;;
  esac

  # The policy page must agree too -- but it necessarily LAGS the gate, on a different
  # clock. The gate re-reads the file every listReloadTTL (5s); the console renders what
  # the firewall last REPORTED, and that rides the flow heartbeat (FW_FLOW_FLUSH_INTERVAL,
  # 5s here and 60s by default). So an operator can briefly see the gate act on an edit the
  # page has not caught up with. That is expected and worth knowing; what would NOT be is
  # the page never catching up, which is what this polls for.
  PAGE_OK=0
  for _ in $(seq 1 20); do
    case "$(curl -s "http://${E2E_HOST}:18085/policy")" in
      *"$RELOAD_PKG"*) PAGE_OK=1; break ;;
    esac
    sleep 2
  done
  [ "$PAGE_OK" = "1" ] \
    && pass "the console policy page caught up with the edited list" \
    || bad "the gate enforces $RELOAD_PKG but the policy page never listed it, 40s and "\
"several heartbeats later -- the page is rendering the list loaded at BOOT rather than the "\
"one in force, so the console would show an operator a policy that is not being applied."
fi

# --- 23) THE CONSOLE EDITS THE LIST, AND THE GATE OBEYS (D193, issue #58 inc. 3b) ---
#
# Legs 21 and 22 prove the gate READS these lists and re-reads them when the file
# changes. Neither says anything about who may change the file: leg 22 edits it with a
# shell redirect on the host, which is not a feature, it is a test harness.
#
# This leg is the increment's actual claim, end to end and through a real client:
#
#   an operator POSTs a package to the console  ->  the console commits it to git
#     ->  the console pushes it to a remote  ->  the firewall re-reads the file
#       ->  a real pull of that package is refused, naming the deny list
#
# It is the only assertion in the suite that crosses the console/firewall boundary in
# the WRITE direction, and no unit test can stand in for it: the console and the gate
# are separate services in separate packages, and everything between them (the bind
# mount, the container's git, the file the gate re-reads) exists only in a real run.
say "23) an operator edits the deny list THROUGH THE CONSOLE and the gate enforces it"

CONSOLE_LISTS="http://${E2E_HOST}:18086"
CONSOLE_CRED="e2e-operator:e2e-fixture-not-a-secret"
# $ALLOWED_PKG (body-parser), and the choice is doing two jobs.
#
# It has to be a package this rig SERVES at this point, or the baseline guard below
# correctly refuses to run -- a fresh name is 403 here (the async cold-scan pending
# state, not a denial), and $PKG has already been denied by leg 22.
#
# body-parser is served because the ALLOW list overrides its unscorable block. So
# denying it through the console also proves the PRECEDENCE: the deny list is consulted
# before the allow list (firewall.go), and an operator who adds a package to deny while
# it sits on allow must get a block, not a coin flip.
WRITE_PKG="$ALLOWED_PKG"

# The console must actually have list editing ON. Without this guard the whole leg
# degrades into "the page rendered", which would pass with the write path disabled --
# the console reports editing DISABLED and renders read-only when it cannot find a git
# repo or a git binary, and that is a page with HTTP 200 on it.
LISTS_PAGE="$(curl -s -u "$CONSOLE_CRED" "${CONSOLE_LISTS}/lists")"
case "$LISTS_PAGE" in
  *"Editing is off"*)
    bad "the console reports list editing as OFF, so nothing below tests a write. Either "\
"CONSOLE_LIST_REPO is unset, or the console image has no git binary (the default image "\
"is distroless/static and has none -- the rig must build the console-git target)." ;;
  *"Authored"*) pass "the console has list editing enabled" ;;
  *) bad "the /lists page did not render: $(printf '%s' "$LISTS_PAGE" | head -c 200)" ;;
esac

# BASELINE FIRST, for the same reason leg 22 takes one: a package that was already
# refused would make the assertion below pass with the console doing nothing at all.
WRITE_BEFORE="$(code "$WRITE_PKG")"
if [ "$WRITE_BEFORE" = "403" ]; then
  bad "$WRITE_PKG is ALREADY refused before the console edit, so this leg cannot tell a "\
"console write from a verdict that was already there. Pick a package this rig serves."
else
  pass "baseline: $WRITE_PKG is served (code $WRITE_BEFORE) before the console edit"

  # Leg 22 appended to this file on the HOST and never committed it. The console commits
  # the file CURRENT CONTENT, so that pending edit rides along in the console commit and
  # the one-line-diff assertion below would be measuring two changes -- the console one
  # and leg 22 one. Commit it first, so what follows is the console own diff.
  #
  # Worth knowing rather than merely worked around: this is real behaviour, not a rig
  # artifact. A file-backed store commits what is in the file, so a hand-edit made
  # between a read and a write is swept into the console commit. For a shared file that
  # is the honest outcome -- the history records what the file actually became -- but it
  # does mean a commit subject can understate what its commit contains.
  if [ -n "$(git -C "$LIST_DIR" status --porcelain)" ]; then
    git -C "$LIST_DIR" add -A
    git -C "$LIST_DIR" commit -q -m "leg 22: hand edit made directly on the host"
    pass "committed leg 22 host-side edit so leg 23 measures only the console diff"
  fi

  HEAD_BEFORE="$(git -C "$LIST_DIR" rev-parse HEAD)"

  # The write. A form POST, exactly as the browser sends it.
  #
  # ⚠️ THE STATUS CODE ALONE PROVES NOTHING HERE, and this leg learned it the hard way:
  # redirectLists answers 303 for a SUCCESSFUL edit and for a REFUSED one alike -- it is
  # post-redirect-get either way, and the outcome rides in the notice. The first version
  # of this leg asserted only "303" and reported PASS while the console had written
  # nothing at all, which is the same impostor shape as the pending-403 guard below.
  # So the LEVEL in the redirect is the assertion, and the notice text is printed when it
  # is not "ok", because that text is the console's own diagnosis of what stopped it.
  WRITE_HDRS="$(curl -s -o /dev/null -D - -u "$CONSOLE_CRED" \
    -X POST "${CONSOLE_LISTS}/lists" \
    --data-urlencode "kind=deny" \
    --data-urlencode "entry=${WRITE_PKG}" \
    --data-urlencode "action=add")"
  WRITE_CODE="$(printf '%s' "$WRITE_HDRS" | head -1 | awk '{print $2}')"
  WRITE_LOC="$(printf '%s' "$WRITE_HDRS" | grep -i '^location:' | tr -d '\r' | head -1)"

  [ "$WRITE_CODE" = "303" ] \
    && pass "the console accepted the edit (303, post-redirect-get)" \
    || bad "POST /lists returned $WRITE_CODE (want 303). 403 means writes are disabled or "\
"the credential was refused; 500 means the store failed."

  case "$WRITE_LOC" in
    *level=ok*)
      pass "the console reports the edit SUCCEEDED, not merely that it answered" ;;
    *)
      bad "the console answered 303 but the edit did not succeed. Its own notice says why: ${WRITE_LOC:-<no Location header>}"
      # #112 was a permission failure inside .git/objects, and diagnosing it cost a
      # full investigation across four pipelines because the leg reported only the
      # console's notice. Ownership and mode are the two facts that settle it, so
      # print them HERE, where the failure is, rather than requiring someone to
      # reproduce a run that is intermittent by nature.
      echo "--- #112 diagnostics: who owns the repo the console must write to ---"
      echo "console runs as uid: $(${COMPOSE[@]} exec -T console id -u 2>/dev/null || echo unknown)"
      ls -ldn "$LIST_DIR/.git" "$LIST_DIR/.git/objects" 2>/dev/null || true
      echo "fanout dirs (mode owner group):"
      # stat -c, not find -printf: this job runs on docker:27-cli, which is ALPINE, and
      # BusyBox find has no -printf. Measured in the real image: it prints
      # "find: unrecognized: -printf" and -- because of the pipe -- still exits 0, so the
      # diagnostic would have been SILENT exactly when it was needed. An instrument that
      # reports nothing is worse than none, because it looks like it ran.
      find "$LIST_DIR/.git/objects" -maxdepth 1 -type d \
        -exec stat -c "  mode=%a uid=%u gid=%g %n" {} \; 2>/dev/null | head -12 || true
      echo "--- end #112 diagnostics ---" ;;
  esac

  # 1. IT REACHED GIT. This is the D193 claim that the audit trail comes for free, so it
  #    is asserted rather than assumed -- and asserted from the HOST with plain git,
  #    which is the point: an auditor does not need our console to read it.
  HEAD_AFTER="$(git -C "$LIST_DIR" rev-parse HEAD)"
  if [ "$HEAD_BEFORE" = "$HEAD_AFTER" ]; then
    bad "the deny list file may have changed but NO COMMIT was made, so the change has no "\
"audit record and nothing to push. git log is the entire audit story for D193 option (c)."
  else
    pass "the console made a commit ($(git -C "$LIST_DIR" rev-parse --short HEAD))"

    SUBJECT="$(git -C "$LIST_DIR" log -1 --format=%s)"
    case "$SUBJECT" in
      *deny*"$WRITE_PKG"*) pass "the commit subject names the list and the package: $SUBJECT" ;;
      *) bad "the commit subject does not say what changed: $SUBJECT" ;;
    esac

    # WHO. Without this the audit trail records that something happened but not who did
    # it, which is the half an auditor actually asks for.
    AUTHOR="$(git -C "$LIST_DIR" log -1 --format=%an)"
    case "$AUTHOR" in
      *e2e-operator*) pass "the commit is attributed to the operator who acted ($AUTHOR)" ;;
      *) bad "the commit author is $AUTHOR, which does not name the console operator. The "\
"audit trail cannot answer the question an auditor actually asks." ;;
    esac

    # A ONE-LINE diff. If a console edit rewrote the file, git log -p would be unreadable
    # and the free audit trail would not be one.
    ADDED="$(git -C "$LIST_DIR" show --format= --unified=0 HEAD | grep -c '^+[^+]' || true)"
    REMOVED="$(git -C "$LIST_DIR" show --format= --unified=0 HEAD | grep -c '^-[^-]' || true)"
    if [ "$ADDED" = "1" ] && [ "$REMOVED" = "0" ]; then
      pass "the audit diff is one added line (+$ADDED/-$REMOVED)"
    else
      bad "adding one entry produced +$ADDED/-$REMOVED lines -- the console is rewriting the file rather than editing it, so its history is not reviewable."
      # Print the EVIDENCE. A count on its own does not say which shape went wrong, and
      # the two candidates need different fixes: a file whose last line lacks a trailing
      # newline rewrites that line (-1/+2), while a line-ending flip rewrites everything.
      echo "--- the commit diff:"
      git -C "$LIST_DIR" show --format= --unified=0 HEAD | cat -A
      echo "--- last bytes of deny.txt in the PREVIOUS commit:"
      git -C "$LIST_DIR" show "$HEAD_BEFORE:deny.txt" | tail -c 40 | od -c | tail -3
    fi

    # The operator's own comments must survive: they are the only record of WHY an entry
    # is there, and the fixture ships with some.
    grep -q '^#' "$DENY_FIXTURE" \
      && pass "the operator's comments survived the console write" \
      || bad "the console write stripped the comments out of the deny list."
  fi

  # 2. IT REACHED THE REMOTE. "Committed here" and "shared with the fleet" are different
  #    states, and the second is the one a multi-replica deployment depends on.
  # refs/heads/main EXPLICITLY, not HEAD: what the console pushed is a branch, and the
  # bare repo's HEAD is a symref that may point somewhere else entirely. The first run
  # of this leg reported "the commit did not reach the remote" while the push had in
  # fact landed -- the assertion was pointed at the wrong handle, which is the same
  # family of mistake as trusting an exit code.
  if [ "$(git -C "$LIST_REMOTE_DIR" rev-parse refs/heads/main 2>/dev/null)" = "$HEAD_AFTER" ]; then
    pass "the commit was pushed to the remote"
  else
    bad "the commit did not reach the remote, so other replicas would never see it -- the "\
"difference between an edit that is durable and one that lives on the console's disk."
  fi

  # 3. IT REACHED THE GATE. The point of the whole increment.
  WRITE_ENFORCED=0
  for _ in $(seq 1 20); do
    if [ "$(code "$WRITE_PKG")" = "403" ]; then WRITE_ENFORCED=1; break; fi
    sleep 2
  done
  [ "$WRITE_ENFORCED" = "1" ] \
    && pass "$WRITE_PKG is now refused -- the console edit reached the running firewall" \
    || bad "$WRITE_PKG is STILL served 40s after being denied through the console. The write "\
"landed in git but never reached the gate, so the console is editing a file nothing reads."

  # And the refusal must be the OPERATOR's. A 403 alone proves nothing here either: the
  # async cold-scan pending refusal wears the same status code, and it is the impostor
  # that made leg 21 look green with the deny list removed.
  WRITE_BODY="$(curl -s "http://${E2E_HOST}:8080/${WRITE_PKG}")"
  case "$WRITE_BODY" in
    *"still scanning"*|*"not yet approved"*)
      bad "$WRITE_PKG is refused because a SCAN IS PENDING, not because the console denied "\
"it. Same status code, different reason -- this is the one way this leg looks green while "\
"the console write did nothing." ;;
    *"deny list"*) pass "the refusal names the deny list, so it is the console edit taking effect" ;;
    *) bad "$WRITE_PKG is refused but not by the deny list: $(printf '%s' "$WRITE_BODY" | head -c 200)" ;;
  esac

  # 4. AND IT CAN BE UNDONE. An operator who can only ever ADD has a one-way ratchet, and
  #    the remove path is the one that weakens policy, so it is the one worth proving.
  curl -s -o /dev/null -u "$CONSOLE_CRED" -X POST "${CONSOLE_LISTS}/lists" \
    --data-urlencode "kind=deny" --data-urlencode "entry=${WRITE_PKG}" \
    --data-urlencode "action=remove"

  UNDONE=0
  for _ in $(seq 1 20); do
    if [ "$(code "$WRITE_PKG")" != "403" ]; then UNDONE=1; break; fi
    sleep 2
  done
  [ "$UNDONE" = "1" ] \
    && pass "removing the entry through the console served $WRITE_PKG again" \
    || bad "$WRITE_PKG is still refused after the console removed it from the deny list. An "\
"operator can add a block but not lift one, which makes the console unusable for the case "\
"it exists for: unblocking a developer."
fi


# ── OIDC sign-in through the console (#149): legs 24-27 against the THIRD console ──────
# Tier 2 for !330. The unit tests proved the handlers; these prove the PATH: a real
# authorization-code round trip through a real (stub) IdP, and that a write made through
# it is attributed to the person who signed in. #132 is the precedent -- unit green, and
# the defect was in which path a request takes, which a test that calls the function
# cannot see. Leg 24 is the control and runs FIRST; without it leg 26 cannot distinguish
# "the cookie authenticated me" from "this instance accepts anyone".
say "OIDC sign-in through the console (legs 24-27, #149)"
CONSOLE_OIDC="http://${E2E_HOST}:18087"
IDP_HITS="http://${E2E_HOST}:19000/_hits"
OIDC_PKG="leftpad-oidc-e2e"                      # not on any fixture list
JAR="$(mktemp)"
hit()   { curl -s "$IDP_HITS" | sed -n "s/.*\"$1\": *\([0-9]*\).*/\1/p"; }
hits()  { curl -s "$IDP_HITS" | tr -d ' \n'; }
moved() { if [ "$1" != "$2" ]; then echo yes; else echo no; fi; }

# leg 24 -- CONTROL: no session, no credential. Refused, and the list repo must not move.
HEAD0="$(git -C "$LIST_DIR" rev-parse HEAD)"
C24="$(curl -s -o /dev/null -w '%{http_code}' -X POST "$CONSOLE_OIDC/lists" \
  --data-urlencode "kind=deny" --data-urlencode "entry=$OIDC_PKG" --data-urlencode "action=add")"
HEAD1="$(git -C "$LIST_DIR" rev-parse HEAD)"
if [ "$C24" != "303" ] && [ "$HEAD0" = "$HEAD1" ]; then
  pass "leg 24 control: unauthenticated POST /lists refused ($C24) and the list repo did not move"
else
  bad "leg 24 control: unauthenticated POST /lists answered $C24, HEAD moved: $(moved "$HEAD0" "$HEAD1"). If that write went through, every leg below is meaningless"
fi

# leg 25 -- the SIGN-IN, with CONTACT asserted. curl plays the browser: /auth/login sets
# the handshake cookie and 302s to the IdP; the stub 302s straight back with a code; the
# console exchanges it at the token endpoint and sets the session; -L follows all of it
# through one cookie jar. The pass condition is NOT "a page came back" -- it is that the
# IdP's /authorize AND /token were both hit, that the token request carried the nonce
# back, and that it carried client auth. A console falling back to basic auth, or serving
# a cached session, hits neither. (!312: a success leg that loses contact goes GREEN.)
A0="$(hit authorize)"; T0="$(hit token)"
LOGIN_CODE="$(curl -s -o /dev/null -w '%{http_code}' -L -c "$JAR" -b "$JAR" "$CONSOLE_OIDC/auth/login")"
A1="$(hit authorize)"; T1="$(hit token)"; N1="$(hit token_nonce_echoed)"; B1="$(hit token_client_auth_basic)"
if [ "$((A1-A0))" -ge 1 ] && [ "$((T1-T0))" -ge 1 ] && [ "${N1:-0}" -ge 1 ] && [ "${B1:-0}" -ge 1 ]; then
  pass "leg 25 sign-in: IdP saw /authorize +$((A1-A0)) and /token +$((T1-T0)); nonce echoed; client_secret_basic sent (landed on $LOGIN_CODE)"
else
  bad "leg 25 sign-in: IdP saw authorize +$((A1-A0)) token +$((T1-T0)) nonce=${N1:-0} basic=${B1:-0}, landed on $LOGIN_CODE. A sign-in that never reached the IdP is not a sign-in whatever page came back. hits=$(hits)"
fi

# leg 26 -- ATTRIBUTION. The write goes through with the session, and the commit the
# console makes names the OIDC identity as its AUTHOR. gitstore.Apply commits with
# user.name="<actor> (Yellow Jack console)"; an EMPTY actor renders as
# "unknown-operator (Yellow Jack console)" (displayActor). The expected value is asserted
# AND the empty rendering is named, so this cannot pass by comparing nothing to nothing
# -- the !330 no-op-mutation lesson. This is #41's defect on the list path, fixed in
# fix/oidc-attribution-everywhere; sabotage it (header) to see this leg redden.
HEAD2="$(git -C "$LIST_DIR" rev-parse HEAD)"
C26="$(curl -s -o /dev/null -w '%{http_code}' -b "$JAR" -X POST "$CONSOLE_OIDC/lists" \
  --data-urlencode "kind=deny" --data-urlencode "entry=$OIDC_PKG" --data-urlencode "action=add")"
HEAD3="$(git -C "$LIST_DIR" rev-parse HEAD)"
AUTHOR="$(git -C "$LIST_DIR" log -1 --format='%an' 2>/dev/null)"
WANT="alice@example.test (Yellow Jack console)"
if [ "$C26" = "303" ] && [ "$HEAD2" != "$HEAD3" ] && [ "$AUTHOR" = "$WANT" ]; then
  pass "leg 26 attribution: the console committed the edit as \"$AUTHOR\""
else
  case "$AUTHOR" in
    *unknown-operator*) bad "leg 26 attribution: the edit was committed UNATTRIBUTED as \"$AUTHOR\" -- #41's defect on the list path (POST $C26, HEAD moved: $(moved "$HEAD2" "$HEAD3"))" ;;
    *) bad "leg 26 attribution: POST $C26, HEAD moved: $(moved "$HEAD2" "$HEAD3"), author \"$AUTHOR\" (want \"$WANT\")" ;;
  esac
fi

# leg 27 -- DISCRIMINATOR: a TAMPERED session cookie is refused and the repo does not
# move.
#
# WHICH CHARACTER IS CHANGED IS THE WHOLE LEG, and the first version got it wrong in the
# same way as the test it was written to improve on. !330's tamper test flipped the last
# byte to a fixed "X" -- a no-op 1 time in 64. This leg chose a replacement guaranteed to
# be a DIFFERENT CHARACTER and still changed the LAST one, and a different character is
# not different BYTES: the cookie is `payload.mac`, both unpadded base64url, and a
# 32-byte MAC is 43 characters whose last one carries 4 data bits and 2 UNUSED bits.
# Go's RawURLEncoding ignores those two, so "A" for "B", "C" or "D" decodes to the same
# MAC and the console is RIGHT to accept it. Measured after it failed in CI on an
# unrelated MR (pipeline 2866258594, "tampered cookie -> 303"): a no-op in 1,260 of
# 20,000 random MACs, 6.30% against a predicted 4/64. It passed locally and in three
# pipelines first, which is what a 1-in-16 flake looks like.
#
# So the FIRST character of the MAC is changed: all six of its bits are data (0 no-ops in
# 20,000), and the leg now ASSERTS the mutation changed the decoded bytes rather than
# trusting that argument. The cookie is picked by NAME from
# the jar (the handshake cookie is cleared by the callback, but selecting by name does
# not depend on that); `$1 != "#"` keeps curl's `#HttpOnly_` rows, which a plain
# comment filter would drop -- and the session cookie IS HttpOnly.
SESS_VAL="$(awk '$1 != "#" && NF >= 7 && $6 == "yj_session" {print $7}' "$JAR" | tail -1)"
SESS_PAYLOAD="${SESS_VAL%%.*}"; SESS_MAC="${SESS_VAL#*.}"
FIRST="${SESS_MAC:0:1}"; if [ "$FIRST" = "A" ]; then FLIP="B"; else FLIP="A"; fi
TAMPERED="${SESS_PAYLOAD}.${FLIP}${SESS_MAC:1}"
# The vacuity guard, in BYTES not characters, and in plain shell (base64 + od are in
# BusyBox, coreutils and Git Bash alike). base64url -> base64, re-padded, decoded, hexed.
mac_hex() {
  s="$(printf '%s' "$1" | tr -- '-_' '+/')"
  case $(( ${#s} % 4 )) in 2) s="$s==" ;; 3) s="$s=" ;; esac
  printf '%s' "$s" | base64 -d 2>/dev/null | od -An -v -tx1 | tr -d ' 
'
}
MAC_BEFORE="$(mac_hex "$SESS_MAC")"; MAC_AFTER="$(mac_hex "${FLIP}${SESS_MAC:1}")"
if [ -n "$MAC_BEFORE" ] && [ "$MAC_BEFORE" != "$MAC_AFTER" ]; then
  pass "leg 27 instrument: the tamper changes the DECODED MAC (${MAC_BEFORE:0:8}.. -> ${MAC_AFTER:0:8}..), not just its spelling"
else
  bad "leg 27 instrument: the tampered cookie decodes to the SAME MAC bytes, so a 303 below would be the console behaving correctly and this leg would prove nothing"
fi
HEAD4="$(git -C "$LIST_DIR" rev-parse HEAD)"
C27="$(curl -s -o /dev/null -w '%{http_code}' -b "yj_session=${TAMPERED}" -X POST "$CONSOLE_OIDC/lists" \
  --data-urlencode "kind=deny" --data-urlencode "entry=${OIDC_PKG}-2" --data-urlencode "action=add")"
HEAD5="$(git -C "$LIST_DIR" rev-parse HEAD)"
if [ -n "$SESS_VAL" ] && [ "$TAMPERED" != "$SESS_VAL" ] && [ "$C27" != "303" ] && [ "$HEAD4" = "$HEAD5" ]; then
  pass "leg 27 discriminator: a session cookie with one byte changed is refused ($C27) and the repo did not move"
else
  bad "leg 27 discriminator: tampered cookie -> $C27, HEAD moved: $(moved "$HEAD4" "$HEAD5"); cookie found: $(if [ -n "$SESS_VAL" ]; then echo yes; else echo no; fi); tamper differs: $(if [ "$TAMPERED" != "$SESS_VAL" ]; then echo yes; else echo no; fi)"
fi

# Restore: remove the entry through the same session, so the run leaves the list as it
# found it. Not a leg -- the removal path is leg 23's subject.
curl -s -o /dev/null -b "$JAR" -X POST "$CONSOLE_OIDC/lists" \
  --data-urlencode "kind=deny" --data-urlencode "entry=$OIDC_PKG" --data-urlencode "action=remove"
rm -f "$JAR"

# --- 28) OVERSIZED OPERATOR LISTS DO NOT COST THE GATE ITS HEARTBEAT (#139) ---------------
#
# The control plane refuses a heartbeat over 64 KiB, and the heartbeat carries the reported
# policy, which grows with the operator's lists. Before #139 a gate whose two lists were
# long enough had every beat refused -- "invalid JSON body", to a sender that never read
# the status -- and a HEALTHY firewall read as DEAD with no line anywhere saying why.
#
# The fix is on both sides (a 413 that says so; a sender that reads it) and, underneath,
# a beat that fits BY CONSTRUCTION: over budget it sheds the list NAMES and keeps digests
# and counts. The unit tests drive each half against a stub. What only this rig can show
# is the two REAL binaries agreeing: the real sender's beat, with real lists behind it,
# accepted by the real ingest and stored in real Postgres.
#
# WHY NO TIMESTAMP ARITHMETIC. The proof of acceptance is CONTENT, not time: a policy
# whose lists say "omitted: 250" can only be on the control plane if a beat sent AFTER the
# lists grew was accepted. A refused beat leaves the previous row in place, names and all.
#
# LAST on purpose. It appends to both list files without committing, and legs 23-27 drive
# the console's git path over those files; cleanup() removes the directory afterwards.
say "28) oversized operator lists: the gate keeps its heartbeat, and keeps enforcing"

OVS_TAG="yj-oversize-beat"
OVS_N=250
# 170 'a's makes each name ~192 characters (npm allows 214). 200 reported names x 2 lists
# x ~195 bytes is ~78 KB: over the 48 KiB sender budget AND over the 64 KiB ingest cap, so
# WITHOUT the fix this exact input is the refused beat.
OVS_PAD="$(printf 'a%.0s' $(seq 1 170))"
OVS_FIRST="${OVS_TAG}-001-${OVS_PAD}"

# CONTROL FIRST: before the edit the lists ARE reported by name. Without this, "no names
# in the report" below would also pass for a sender that never sends names at all.
HEALTH_BEFORE="$(curl -s "http://${E2E_HOST}:8090/v1/health")"
case "$HEALTH_BEFORE" in
  *'"names":['*) pass "control: before the edit, list names are reported in the heartbeat" ;;
  *) bad "control: the heartbeat carries no list names even with SMALL lists, so the shed assertion below proves nothing: $(printf '%s' "$HEALTH_BEFORE" | cut -c1-200)" ;;
esac
case "$HEALTH_BEFORE" in
  *"$OVS_TAG"*) bad "control: the heartbeat ALREADY mentions $OVS_TAG before the edit" ;;
  *) pass "control: the oversized names are not on the control plane yet" ;;
esac

# DISTINCT names per list. A name on both is legal (the deny list wins and says so), but it
# would make "refused by the deny list" ambiguous and log 250 conflict lines.
for i in $(seq 1 "$OVS_N"); do printf '%s-%03d-%s\n' "$OVS_TAG" "$i" "$OVS_PAD"; done >> "$DENY_FIXTURE"
for i in $(seq 1 "$OVS_N"); do printf '%s-allow-%03d-%s\n' "$OVS_TAG" "$i" "$OVS_PAD"; done >> "$LIST_DIR/allow.txt"

# The gate must pick the lists up (listReloadTTL 5s) and then report (flush interval 5s).
# Poll for the ENFORCEMENT first: it is the precondition -- if the gate never loaded the
# long list there is no oversized report to send, and a quiet heartbeat proves nothing.
OVS_LOADED=0
for _ in $(seq 1 30); do
  if [ "$(code "$OVS_FIRST")" = "403" ]; then OVS_LOADED=1; break; fi
  sleep 2
done
if [ "$OVS_LOADED" = "1" ]; then
  case "$(curl -s "http://${E2E_HOST}:8080/${OVS_FIRST}")" in
    *"deny list"*) pass "the gate loaded the long deny list and ENFORCES it ($OVS_FIRST -> 403, attributed to the deny list)" ;;
    *) bad "$OVS_FIRST is refused, but not by the deny list, so this does not show the long list was loaded" ;;
  esac
else
  bad "60s after the deny list grew by $OVS_N entries the gate still does not refuse $OVS_FIRST "\
"(code $(code "$OVS_FIRST")), so it never loaded the list and this leg cannot test the heartbeat"
fi

# THE ASSERTION. A three-digit "omitted" can only reach the control plane inside a beat
# that was sent after the lists grew AND was accepted.
OVS_SHED=0
HEALTH_AFTER=""
for _ in $(seq 1 30); do
  HEALTH_AFTER="$(curl -s "http://${E2E_HOST}:8090/v1/health")"
  case "$HEALTH_AFTER" in
    *'"omitted":'[0-9][0-9][0-9]*) OVS_SHED=1; break ;;
  esac
  sleep 2
done
if [ "$OVS_SHED" = "1" ]; then
  pass "the control plane holds a report sent AFTER the lists grew: the over-budget heartbeat was ACCEPTED"
else
  bad "60s after both lists grew, the control plane still holds the OLD report. The oversized "\
"heartbeat is being refused, so this healthy gate is about to read as STALE/DEAD: $(printf '%s' "$HEALTH_AFTER" | cut -c1-300)"
fi

# What was shed is the NAMES, and only the names.
#
# ONLY evaluated when a post-edit report was accepted. Run with the sender's shedding disabled
# (the negative control for this leg), these two passed VACUOUSLY: the report still on the
# control plane was the OLD one, which naturally holds no oversized names and has its
# digests. An assertion about "the accepted report" is meaningless without one.
if [ "$OVS_SHED" = "1" ]; then
  case "$HEALTH_AFTER" in
    *"$OVS_TAG"*) bad "the accepted report still carries the oversized names, so it was not shed -- it fit by luck, and this rig's input is too small to exercise the path" ;;
    *) pass "the accepted report carries no list names (shed), only counts" ;;
  esac
  case "$HEALTH_AFTER" in
    *'"policy_digest"'*'"digest"'*|*'"digest"'*'"policy_digest"'*) pass "the policy digest and the per-list digests survived the shedding" ;;
    *) bad "shedding lost a digest; replica divergence detection depends on them: $(printf '%s' "$HEALTH_AFTER" | cut -c1-300)" ;;
  esac
fi

# Both logs must tell the same story: the gate SAID it shed, and nobody refused anything.
OVS_FWLOG="$("${COMPOSE[@]}" logs firewall 2>/dev/null)"
OVS_APLOG="$("${COMPOSE[@]}" logs approval 2>/dev/null)"
case "$OVS_FWLOG" in
  *"NAMES are omitted from the report"*) pass "the gate logged that it shed list names to fit the heartbeat budget" ;;
  *) bad "the gate shed names without saying so; an operator looking at a truncated list on /policy would have no explanation" ;;
esac
case "$OVS_FWLOG$OVS_APLOG" in
  *"REFUSED as too large"*|*"REFUSED a heartbeat"*) bad "a heartbeat WAS refused as too large during this leg -- the budget did not keep the beat under the ingest cap" ;;
  *) pass "no heartbeat was refused on either side" ;;
esac

# And the page an operator actually looks at must say LOADED-BUT-UNNAMED, not EMPTY. This is
# the assertion that found a real defect on its first run: the console rendered a shed list
# as "loaded zero entries -- check the file this replica mounted", for a list enforcing 250.
OVS_PAGE="$(curl -s "http://${E2E_HOST}:18085/policy")"
case "$OVS_PAGE" in
  *"entries are loaded and enforced"*) pass "the console says the shed lists are loaded and enforced, names withheld" ;;
  *) bad "the console does not explain a list whose names were shed" ;;
esac
if [ "$OVS_SHED" = "1" ]; then
  case "$OVS_PAGE" in
    *"loaded <strong>zero</strong> entries"*) bad "the console tells the operator a list enforcing $OVS_N entries loaded ZERO, and sends them to check a mount that is fine" ;;
    *) pass "the console does not mistake a shed list for an empty one" ;;
  esac
fi

say "29) a PARTIAL Scorecard report: accepted when only low-weight checks errored, unscorable when a REQUIRED one did (#133, D271)"
# The fixture image errors checks BY NAME for two repos and exits 1 exactly as the real
# scorecard does (e2e/fakescanner/Dockerfile): chalk loses License, CI-Tests and
# Contributors; debug loses Dangerous-Workflow. Fifteen of eighteen scored in both cases
# -- the COUNT cannot tell them apart, which is why the floor is a named set and why
# this leg has two halves. The whole chain runs: fixture -> sink -> scheduler -> L2 ->
# the firewall's floor -> the developer's status code.
PARTIAL_OK_PKG="chalk";  PARTIAL_OK_REPO="github.com/chalk/chalk"
PARTIAL_NO_PKG="debug";  PARTIAL_NO_REPO="github.com/debug-js/debug"

# Kick both scans off, then wait on both, so the leg costs one scan's latency.
code "$PARTIAL_OK_PKG" >/dev/null; code "$PARTIAL_NO_PKG" >/dev/null
P29_OK=0; P29_NO=0
for i in $(seq 1 40); do
  [ "$P29_OK" = 1 ] || { [ "$(scans_for "$PARTIAL_OK_REPO")" -ge 1 ] && P29_OK=1; }
  [ "$P29_NO" = 1 ] || { [ "$(scans_for "$PARTIAL_NO_REPO")" -ge 1 ] && P29_NO=1; }
  [ "$P29_OK" = 1 ] && [ "$P29_NO" = 1 ] && break
  sleep 3
done
[ "$P29_OK" = 1 ] && [ "$P29_NO" = 1 ] || bad "background scans did not complete for both partial-report repos (chalk=$P29_OK debug=$P29_NO)"

# CONTACT: the fixture must have produced the PARTIAL shape for both, or the halves
# below measure the ordinary 9.0 path. The scanner logs the salvage when the exit was
# non-zero and the report usable; that line is the evidence the shape reached us.
FW29="$("${COMPOSE[@]}" logs firewall 2>/dev/null)"
SCHED29="$("${COMPOSE[@]}" logs scheduler 2>/dev/null)"
case "$SCHED29" in
  *"$PARTIAL_OK_REPO -> score"*"15 of 18 checks scored"*) pass "the scheduler carried a 15-of-18 report for $PARTIAL_OK_PKG" ;;
  *) bad "no 15-of-18 coverage line for $PARTIAL_OK_REPO in the scheduler log: the fixture did not produce the partial shape, so this leg is VOID" ;;
esac

# HALF 1: low-weight checks errored -> the floor lets the score through -> ALLOW.
CODE29A="$(code "$PARTIAL_OK_PKG")"
[ "$CODE29A" = "200" ] && pass "$PARTIAL_OK_PKG (partial report, only low-weight checks errored) is ALLOWED" \
  || bad "$PARTIAL_OK_PKG code=$CODE29A (want 200: a report missing only License/CI-Tests/Contributors is a score under D271)"
case "$FW29" in
  *"partial report for $PARTIAL_OK_REPO accepted"*"CI-Tests, Contributors, License"*) pass "the firewall logged WHICH checks the accepted score was computed without" ;;
  *) bad "no acceptance line naming CI-Tests, Contributors, License for $PARTIAL_OK_REPO in the firewall log" ;;
esac

# HALF 2: a REQUIRED check errored -> unscorable -> the block policy refuses -> 403,
# and the developer's reason must NOT read as a verdict on the package's score.
RESP29B="$(curl -s -w '\n%{http_code}' "http://${E2E_HOST}:8080/$PARTIAL_NO_PKG")"
CODE29B="$(printf '%s' "$RESP29B" | tail -n1)"
BODY29B="$(printf '%s' "$RESP29B" | sed '$d')"
[ "$CODE29B" = "403" ] && pass "$PARTIAL_NO_PKG (partial report, Dangerous-Workflow errored) is REFUSED" \
  || bad "$PARTIAL_NO_PKG code=$CODE29B (want 403: a report missing a REQUIRED check is unscorable under D271)"
hasre "$BODY29B" 'unscorable|could not be scored|no score' \
  && pass "the refusal reads as UNSCORABLE, not as a low score" \
  || bad "the refusal for $PARTIAL_NO_PKG does not read as unscorable: $BODY29B"
case "$FW29" in
  *"required check(s) Dangerous-Workflow did not run"*) pass "the firewall named the missing REQUIRED check" ;;
  *) bad "the firewall log does not name Dangerous-Workflow as the check that failed the floor" ;;
esac
# The two halves are the same count. If either assertion above passed for a reason other
# than the NAMES, this discriminator catches it: both L2 rows must exist, one scored and
# one carrying the negative marker.
L2A="$(l2_score "$PARTIAL_OK_REPO")"; L2B="$(l2_score "$PARTIAL_NO_REPO")"
[ -n "$L2A" ] && pass "L2 holds a numeric score for $PARTIAL_OK_REPO ($L2A)" || bad "L2 has no score for $PARTIAL_OK_REPO"
[ -z "$L2B" ] && pass "L2 holds the negative marker (no score) for $PARTIAL_NO_REPO" || bad "L2 holds a SCORE ($L2B) for $PARTIAL_NO_REPO, so the floor was not what refused it"

say "RESULT"
[ "$FAIL" = "0" ] && echo "ASYNC E2E: PASS" || echo "ASYNC E2E: FAIL"
exit "$FAIL"
