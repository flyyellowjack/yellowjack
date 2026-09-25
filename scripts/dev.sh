#!/usr/bin/env sh
# scripts/dev.sh — Yellow Jack HOST task runner.
#
# `make` is NOT installed on the Windows dev host (only go, docker, glab, git are),
# so the Makefile only runs in CI/Linux. This script is the host-runnable
# equivalent and mirrors the Makefile so host and CI do the same thing:
#
#   sh scripts/dev.sh <task>
#
# Tasks:
#   build            go build ./...
#   vet              THE vet gate, as CI runs it: go vet + gofmt + doclinks + e2e-rule
#   fmt [--fix]      are the COMMITTED Go blobs gofmt-clean? (not the CRLF working tree)
#   test             go test ./... -count=1          (fast, offline — the commit gate)
#   race [args]      race detector in Docker (scripts/race.sh; no host C toolchain)
#   e2e [selector]   real-client e2e; npm|pypi|oci|maven|coalesce|all (default all), or
#                    shard1|shard2|shard3 -- the three CI jobs, whose membership is
#                    e2e/shards.txt and whose coverage is asserted (#140)
#   flake <Test> [n] did this test already fail on origin/main? (add --docker for CI's OS)
#   waitci [branch]  block until the branch's pipeline is green ON ITS HEAD — before merging
#   corpus           malicious-corpus detection floor (#31; needs docker)
#   regfront         registry-in-front topology, both directions (#98/D177; needs docker)
#   harden           non-root + read-only rootfs + arbitrary UID (#22; needs docker)
#   env              generate the git-ignored .env (a per-machine POSTGRES_PASSWORD, #22)
#   ha               N replicas + a rolling update and rollback, zero dropped requests (#23)
#   helmdrill        a helm-upgrade list edit reaching every gate pod on a kind cluster (#131, local)
#   remotedaemon     a scan launched onto ANOTHER daemon with no socket mounted (#80, local)
#   pins             do the pinned base-image digests still resolve, and stay multi-arch?
#                    (#22; needs docker + registries. exit 2 = could not check, NOT green)
#   resolve <img:tag> the digest to paste into a FROM — never hand-copy one from
#                    `imagetools inspect`, which lists a per-platform digest per platform
#   up               start local app stack (pinned compose file)
#   down             stop local app stack
#   logs             follow app stack logs
#   doclinks         do markdown links resolve for someone who only has what we PUBLISHED?
#   publishcheck     is this HISTORY safe to make public? (launch preflight, NOT a CI gate —
#                    it exits 1 today on purpose; --selftest proves it can fail)
#   memcheck [dir]   fail if any memory file has grown into a transcript
#   malwarefeed      build the FW_MALWARE_LIST feed from public OSV data (#104)
#                    (--selftest proves the check can fail)
set -eu

ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
cd "$ROOT"

task="${1:-help}"
[ "$#" -gt 0 ] && shift

e2e_run() {
  case "${1:-all}" in
    all)   printf '' ;;
    npm)   printf -- '-run TestNpmEndToEnd' ;;
    pypi)  printf -- '-run TestPypiEndToEnd' ;;
    oci)   printf -- '-run TestOciEndToEnd' ;;
    maven) printf -- '-run TestMavenEndToEnd' ;;
    # Not an ecosystem but a SCENARIO (it drives the npm client): the request-coalescing
    # measurement, which points the firewall at a counting deps.dev stand-in via
    # FW_DEPSDEV_BASE. Selectable on its own because it is the slow one — every fake
    # response is deliberately held open to widen the concurrency window.
    coalesce) printf -- '-run TestNpmCoalescesUpstreamScoringCalls' ;;
    # The CI SHARDS (#140): three parallel jobs whose -run patterns together cover every
    # test in the package. The membership lives in e2e/shards.txt and is asserted by
    # TestEveryE2ETestIsInExactlyOneShard -- a test in no shard would simply stop being
    # gated, with no failure and no skip line anywhere.
    #
    # Built as an explicit ^(A|B|C)$ alternation rather than a prefix pattern: `go test
    # -run` silently matches nothing when a pattern is wrong, so the list has to be one a
    # guard can compare against the source.
    shard1|shard2|shard3)
      _n="${1#shard}"
      _names="$(awk -v s="$_n" '$1 == s && $2 ~ /^Test/ { printf "%s%s", sep, $2; sep="|" }' "$ROOT/e2e/shards.txt")"
      if [ -z "$_names" ]; then
        echo "shard $_n selected no tests -- e2e/shards.txt is missing or malformed; refusing to "              "run an empty gate" >&2
        exit 2
      fi
      printf -- '-run ^(%s)$' "$_names" ;;
    *) echo "unknown ecosystem '$1' -- use npm|pypi|oci|maven|coalesce|shard1|shard2|shard3|all" >&2; exit 2 ;;
esac
}

# STALENESS PREFLIGHT. Five recorded incidents (see scripts/staleness.sh for the table),
# the last of which was running `dev.sh vet` in a checkout 275 commits behind and reading
# exit 0 as "the branch is clean" — that tree's scripts/ held 9 files where the branch's
# held 19, so it ran an older, smaller gate and passed it.
#
# Guarded here rather than inside each task, and ONLY for the tasks whose output is a
# CLAIM ABOUT THE CODE. `up`/`down`/`logs`/`waitci` operate on things rather than
# reporting on them, and refusing them on drift would train people to set YJ_ALLOW_STALE
# permanently — which is how a guard becomes decoration.
#
# It warns on any drift and refuses only on a VERIFIED far-behind: a failed freshness
# fetch downgrades to a warning, because refusing on a network blip is a worse failure
# than the one being prevented, and this host's network fails asymmetrically.
case "$task" in
  build|vet|fmt|test|race|e2e|flake|corpus|doclinks|publishcheck|regfront|pins|harden)
    . "$ROOT/scripts/staleness.sh"
    check_staleness || exit 1
    ;;
esac

# TLS-interception mode is an optional build variant (`-tags intercept`), present only in a
# tree that carries its source. Where it is, every gate below runs BOTH variants, so the
# default build and the interception build are each proven; where it is not, the tag is
# never passed (it would compile the default stubs out and leave nothing in their place).
INTERCEPT=""
[ -f "$ROOT/intercept.go" ] && INTERCEPT="intercept"

case "$task" in
  build)
    go build ./...
    [ -z "$INTERCEPT" ] || go build -tags "$INTERCEPT" ./... ;;
  vet)
    # THE VET GATE — the single definition of it. .gitlab-ci.yml's vet job calls this
    # task rather than repeating the list, so "green locally" and "green in CI" cannot
    # drift apart. They already had: this task ran `go vet` alone while the CI job of the
    # same name ran five, so !149 passed every local gate and then failed CI on gofmt.
    # If you add a check to the CI job, add it HERE instead.
    go vet ./...
    [ -z "$INTERCEPT" ] || go vet -tags "$INTERCEPT" ./...
    # Formatting is a gate, not a habit: eight files' blobs had silently drifted by !49
    # precisely because nothing enforced it. Checks the COMMITTED blobs, so it gives the
    # same answer on the CRLF Windows host as on Linux (see scripts/gofmt_check.sh).
    sh scripts/gofmt_check.sh
    # Do our markdown links resolve for someone who only has what we PUBLISHED? Checked
    # against TRACKED paths, not the filesystem, and that distinction is the whole point:
    # README.md linked to CLAUDE.md, which is deliberately untracked, so the link resolved
    # on every developer's disk and would have 404'd on the front page of the public repo.
    sh scripts/check-doc-links.sh
    # The rule that decides whether the e2e gate may be skipped for a docs-only change.
    # Tested in a job that ALWAYS runs, because its failure mode is silent: if it ever
    # wrongly answers "skip", code merges with a green e2e that never executed.
    [ ! -f "$ROOT/.gitlab-ci.yml" ] || sh scripts/needs-e2e-test.sh  # GitLab-pipeline tooling: only where that CI exists
    # The rule that decides whether a GREEN pipeline is allowed to bless a merge — the
    # counterweight to D98 narrowing the e2e gate. Same silent failure mode: if it ever
    # wrongly answers "the gate ran", a merge is approved by a pipeline that never
    # executed e2e, and nothing goes red anywhere. Its suite includes the negative
    # control (a pipeline with no e2e jobs must be REJECTED), because a check that can
    # only pass proves nothing (issue #55). Needs python3 — CI installs it into the
    # golang image; the Windows host already has it.
    [ ! -f "$ROOT/.gitlab-ci.yml" ] || sh scripts/e2e_gate_check_test.sh  # GitLab-pipeline tooling: only where that CI exists
    # The other half of the same distinction: can the watcher tell "GitLab says there
    # is no pipeline" from "we could not reach GitLab"? Conflating them reported a
    # plainly-running pipeline as "nothing has gated this branch" twice on 2026-08-31.
    # Carries its own negative control -- a matcher broad enough to swallow a real
    # "failed" would wait through a RED pipeline as though the API were flaky.
    [ ! -f "$ROOT/.gitlab-ci.yml" ] || sh scripts/pipeline_read_test.sh  # GitLab-pipeline tooling: only where that CI exists
    # And the wiring between them, because every false refusal this family has produced
    # was a WIRING bug that a predicate test would have passed: the classifier existed
    # and the arm that needed it did not call it. This one runs the real watcher against
    # a stubbed glab and a throwaway git repo, and asserts on exit codes and on the text
    # an operator actually reads -- including the NEGATIVE assertion that "nothing has
    # gated this branch" is never printed about a branch we merely could not ask about.
    # Cost, measured rather than estimated: `vet` took 56.9s on the pipeline that
    # introduced this, against 70.5s and 88.2s on the two preceding MRs WITHOUT it.
    # Runner variance swamps the addition, so there is no detectable CI cost. On the
    # Windows host it is the opposite -- ~75s on its own, almost all of it `git
    # init`/`commit`/`push` building the scratch repo, because process spawn is slow
    # there. If this ever needs trimming, that setup is the target, not the scenarios.
    [ ! -f "$ROOT/.gitlab-ci.yml" ] || sh scripts/mr_wait_pipeline_test.sh  # GitLab-pipeline tooling: only where that CI exists
    # The third member of that family, and the one that guards THIS SCRIPT'S own answer:
    # can the staleness preflight tell "current" from "we could not check"? A checkout
    # that has never fetched reports 0 commits behind, so the naive check is most
    # confident exactly when it knows least. Its own negative control asserts the four
    # verdicts stay four — a classifier that answered "fresh" to everything would
    # otherwise satisfy the happy cases.
    sh scripts/staleness_test.sh
    # Base images must be pinned by digest (#22). OFFLINE on purpose: this reads the
    # Dockerfiles and contacts no registry, so it cannot go red because Docker Hub
    # rate-limited us — which is the failure that took every MR's e2e leg down on
    # 2026-08-31 (#106). The reachability half lives in `dev.sh pins`, off the gate.
    . "$ROOT/scripts/pinned-images.sh"
    check_pins_offline
    # And its own controls: an unpinned tag, a tagless digest, and — the one that
    # matters — a repo with no Dockerfiles must FAIL rather than report everything
    # pinned. A file-walking check degrades into a no-op silently.
    sh scripts/pinned-images_test.sh
    # The wrapper the e2e jobs build the scanner through (#106): its parser, the
    # once-per-digest copy, and — the one that matters — that a build which silently
    # IGNORED the mirror arguments is refused rather than reported as mirrored. All
    # against a fake docker; no network.
    sh scripts/mirror-bases_test.sh
    # Fixture hygiene (#46): every host a test fixture names is defanged, private, a
    # compose service name, or documented in e2e/fixture-hosts.txt with a reason. GuardDog
    # shipped samples that fetched from live threat-actor infrastructure for two years
    # (DataDog/guarddog#766). The other half — the shipped images carry no fixture at all —
    # needs the images built, so it lives in e2e/hardening.sh (leg 1b).
    . "$ROOT/scripts/fixture-hygiene.sh"
    check_fixture_hygiene
    # Its controls: a live URL, a bare payload domain, a public IP, an undocumented or a
    # stale allowlist entry, and an EMPTY fixture root must each FAIL.
    sh scripts/fixture-hygiene_test.sh
    # No `producer | grep -q` in a rig that sets pipefail. grep -q exits at the first
    # match, the producer dies of SIGPIPE, and pipefail turns a PRESENT string into an
    # ABSENT one -- but only once the producer grows, so a leg passes for months and
    # then reports a product failure nobody caused. It cost a merge on 2026-09-22.
    . "$ROOT/scripts/pipefail-grep.sh"
    check_pipefail_grep
    # Its controls: the defect reproduced LIVE (a long producer really does read as
    # absent), every spelling a narrow recogniser would miss, and -- the one that keeps
    # the rule honest -- the same pipe in a script WITHOUT pipefail staying green.
    sh scripts/pipefail-grep_test.sh
    # Only the product's front doors may be published on all interfaces. Found on
    # 2026-09-08: docker-compose.yml put the UNAUTHENTICATED approval control plane
    # (#13 item 2) on 0.0.0.0:8090 while the console -- the one service that DOES
    # authenticate -- was correctly on 127.0.0.1. The protection was inverted, and
    # nothing used those host ports: every service reaches approval over the compose
    # network. Inverted rule, so adding a service cannot silently open a port.
    . "$ROOT/scripts/exposed-ports.sh"
    check_exposed_ports
    # No credential literal in the compose files people RUN OR COPY (#22) — the shipped
    # one and the reference deployment. Both used to carry POSTGRES_PASSWORD: postgres,
    # twice each: one identical database password on every installation, and on every
    # installation that started by copying the example. scripts/gen-env.sh mints a
    # per-machine one; this is what stops the convenient default coming back during a
    # debugging session.
    . "$ROOT/scripts/no-default-creds.sh"
    check_no_default_creds
    # Its controls: a literal password, a password hidden in a DSN, and a file the
    # patterns no longer match must each FAIL.
    sh scripts/no-default-creds_test.sh
    # And the generator's own, which it had none of. The branch that carries the weight
    # is docker UNREACHABLE: on a dev machine docker is up, so a probe that conflated
    # "no volume" with "could not ask" looked right every time anyone ran it by hand.
    sh scripts/gen-env_test.sh
    # Its controls, including the one that matters: a compose file with ZERO parsed
    # ports must FAIL, or a parser that stops matching reports every file clean.
    sh scripts/exposed-ports_test.sh
    # The corpus scanner's per-fixture timeout (#82): proves the bound fires, that a
    # normal scan passes through untouched, and that a timed-out container is removed.
    sh e2e/malicious-corpus/scan_corpus.sh --selftest ;;
  test)
    go test ./... -count=1
    [ -z "$INTERCEPT" ] || go test -tags "$INTERCEPT" ./... -count=1 ;;
  race)
    # Native gcc (CI/Linux) → run -race directly. No gcc (Windows host) → Docker.
    # The interception build is the superset (only the default stubs differ), so it is
    # the one raced when present.
    rargs="$*"; [ -n "$rargs" ] || rargs="${INTERCEPT:+-tags $INTERCEPT }./... -count=1"
    if command -v gcc >/dev/null 2>&1; then
      echo "race: native gcc → go test -race $rargs"
      CGO_ENABLED=1 go test -race $rargs
    else
      echo "race: no host gcc → Docker (scripts/race.sh)"
      sh scripts/race.sh $rargs
    fi ;;
  fmt)   sh scripts/gofmt_check.sh "$@" ;;
  # -timeout 30m, not 20m: green e2e jobs measure 17.5-18.5 min (five pipelines, 2026-09-13/14)
  # and two runs died at 21.4 min with `panic: test timed out after 20m0s` in two DIFFERENT
  # tests, each a few seconds in -- the suite brushes its own deadline and whichever test is
  # executing at minute 20 gets blamed. 30m is headroom, not a licence: if the suite passes
  # 25 min it wants splitting, not a longer rope.
  e2e)   go test -tags "e2e${INTERCEPT:+,$INTERCEPT}" $(e2e_run "${1:-all}") -count=1 -timeout 30m -v ./e2e/... ;;
  flake) sh scripts/flake_baseline.sh "$@" ;;
  waitci) sh scripts/mr_wait_pipeline.sh "$@" ;;
  corpus) sh e2e/malicious-corpus/scan_corpus.sh ;;
  # The REGISTRY-IN-FRONT topology (#98, D177): us in front of a real caching
  # registry, and the old D151 arrangement behind one, measured against each other.
  # Needs docker; ~90s.
  regfront) bash e2e/registry_front.sh ;;
  # Container hardening (#22): every service under a read-only rootfs and an
  # unmapped OpenShift-style UID, plus a real verdict rendered under those
  # constraints. Needs docker; builds six images, ~3 min cold.
  harden) bash e2e/hardening.sh ;;
  # The HA + rolling-update drill (#23, D133): N replicas sharing nothing, byte-identical
  # verdicts, and a rolling replacement plus rollback with zero failed requests. Needs
  # docker; ~3 min. Offline — every compared request is one we answer ourselves.
  ha) bash e2e/ha_drill.sh ;;
  # The Kubernetes half of #131: a helm-upgrade list edit reaching every gate pod, on a
  # three-worker kind cluster. Local only (kind, kubectl, helm; set HELM= if not on PATH).
  helmdrill) bash e2e/helm_list_drill.sh ;;
  # #80's hardened option, run rather than argued: the scheduler with NO docker socket,
  # given only DOCKER_HOST + client certs, launching a scan onto a second daemon. Local
  # only -- it needs a PRIVILEGED container, and CI is already dind (same call as
  # helmdrill). scheduler/launcher_env_test.go is the CI-side half.
  remotedaemon) bash e2e/remote_daemon_drill.sh ;;
  # The Helm chart's own gate (#83): lint, the default and a production-shaped render,
  # and five half-configured inputs that must be REFUSED at render time. Separate from
  # `vet` on purpose -- helm is not on every dev host, and a check that quietly skips
  # when its tool is missing is the failure this repo keeps finding. Without helm this
  # exits 2 and says so; CI runs it in a pinned helm image.
  chart) sh scripts/chart_check.sh ;;
  # The reachability half of the pinning invariant (#22). Needs docker + the registries,
  # so it is NOT on the vet gate: exit 2 means "could not check", which is not green.
  pins) . "$ROOT/scripts/pinned-images.sh"; verify_pins_online ;;
  # Resolve a tag to the digest to paste into a FROM. Use this rather than copying one
  # out of `imagetools inspect`, which prints a per-platform digest for every platform
  # right next to the index digest — pick the wrong one and only arm64 builds break.
  resolve)
    [ -n "${1:-}" ] || { echo "usage: sh scripts/dev.sh resolve <image:tag>" >&2; exit 2; }
    . "$ROOT/scripts/pinned-images.sh"; resolve_image_digest "$1" ;;
  # --build is NOT optional here. Without it compose reuses whatever image already
  # exists, and a stale image does not present as staleness -- it presents as MISSING
  # FEATURES. Measured 2026-09-08: an image 6 weeks old served the console with no
  # authentication (200 with no password, though CONSOLE_AUTH_* were set and `docker
  # inspect` confirmed they reached the container) and 404'd seven of its eight pages,
  # which reads as 'auth is broken and those pages were never built'. Both readings were
  # wrong. The tell was the startup log missing a suffix main.go prints -- comparing the
  # LOG to the SOURCE, not poking the running service.
  #
  # The cost is a cached rebuild on every `up`, which is seconds when nothing changed.
  # The cost of the alternative is debugging a binary that is not in the tree.
  # Generate the local .env if it is missing, so `up` stays one command even though the
  # shipped compose file carries no credential (#22). Idempotent: never overwrites.
  env)   sh scripts/gen-env.sh ;;
  up)    sh scripts/gen-env.sh >/dev/null && docker compose -f docker-compose.yml up -d --build ;;
  down)  docker compose -f docker-compose.yml down ;;
  logs)  docker compose -f docker-compose.yml logs -f --tail=100 ;;
  doclinks) sh scripts/check-doc-links.sh "$@" ;;
  publishcheck) sh scripts/check-publish-safety.sh "$@" ;;
  memcheck) sh scripts/check-memory-size.sh "$@" ;;
  malwarefeed) python3 scripts/build-malware-feed.py "$@" ;;
  help|-h|--help) sed -n '3,32p' "$0" ;;
  *) echo "unknown task '$task' — run: sh scripts/dev.sh help" >&2; exit 2 ;;
esac
