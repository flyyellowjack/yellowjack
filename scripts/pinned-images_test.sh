#!/bin/sh
# Tests for scripts/pinned-images.sh.
#
# The offline gate is the part that runs on every MR, so it is the part that has
# to be proven able to FAIL. A pinning check is unusually easy to write in a way
# that can only ever print green: it walks a file list, and an empty file list
# produces "no violations found".
#
# Each case below builds a throwaway git repo containing Dockerfiles, because
# check_pins_offline deliberately reads `git ls-files` rather than `find` — see
# the note on dockerfiles() for why.
set -u

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
. "$ROOT/scripts/pinned-images.sh"

PASS=0
FAIL=0
ok()   { PASS=$((PASS + 1)); printf 'ok   %s\n' "$1"; }
bad()  { FAIL=$((FAIL + 1)); printf 'FAIL %s\n' "$1"; }

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

DIGEST='@sha256:1111111111111111111111111111111111111111111111111111111111111111'

# scratch_repo NAME — a git repo with N pinned Dockerfiles, enough to clear the
# anti-vacuity floor, so a case can add exactly one violation and attribute the
# failure to it.
scratch_repo() {
  d="$TMP/$1"
  mkdir -p "$d"
  (
    cd "$d" || exit 1
    git init -q .
    i=1
    while [ "$i" -le 12 ]; do
      mkdir -p "svc$i"
      printf 'FROM golang:1.26%s AS build\n' "$DIGEST" > "svc$i/Dockerfile"
      i=$((i + 1))
    done
    git add -A >/dev/null 2>&1
  )
  printf '%s\n' "$d"
}

run_offline() {
  ( cd "$1" && check_pins_offline >"$TMP/out" 2>&1; echo $? )
}

# ── 1. the happy path ────────────────────────────────────────────────────────
d=$(scratch_repo clean)
rc=$(run_offline "$d")
if [ "$rc" = "0" ]; then ok "a fully pinned repo passes"; else
  bad "a fully pinned repo was rejected: $(cat "$TMP/out")"; fi

# ── 2. NEGATIVE CONTROL: one unpinned tag must fail ──────────────────────────
# Without this the whole file could be a no-op that prints a reassuring count.
d=$(scratch_repo unpinned)
printf 'FROM golang:1.26 AS build\n' > "$d/svc3/Dockerfile"
( cd "$d" && git add -A >/dev/null 2>&1 )
rc=$(run_offline "$d")
if [ "$rc" != "0" ] && grep -q 'not pinned by digest' "$TMP/out"; then
  ok "an unpinned tag is caught, and the message names the problem"
else
  bad "an unpinned tag passed the check — the gate is decorative: $(cat "$TMP/out")"
fi

# ── 3. NEGATIVE CONTROL: a digest with no tag must fail ──────────────────────
# This one is easy to get wrong in the permissive direction, because the bytes
# really are pinned. What is lost is REVIEWABILITY: nothing on the line says
# whether a bump was a patch or a major.
d=$(scratch_repo notag)
printf 'FROM golang%s AS build\n' "$DIGEST" > "$d/svc4/Dockerfile"
( cd "$d" && git add -A >/dev/null 2>&1 )
rc=$(run_offline "$d")
if [ "$rc" != "0" ] && grep -q 'carries no tag' "$TMP/out"; then
  ok "a bare digest with no tag is caught"
else
  bad "a tagless digest passed: $(cat "$TMP/out")"
fi

# ── 4. THE VACUITY CONTROL ───────────────────────────────────────────────────
# An empty repo is the shape every "walk the files and assert" check silently
# degrades into. It must be a failure, not a pass.
d="$TMP/empty"
mkdir -p "$d"
( cd "$d" && git init -q . )
rc=$(run_offline "$d")
if [ "$rc" != "0" ] && grep -q 'looked at nothing' "$TMP/out"; then
  ok "a repo with no Dockerfiles FAILS rather than reporting everything pinned"
else
  bad "an empty repo reported success — the check cannot distinguish 'all pinned' from 'nothing examined'"
fi

# ── 5. the exclusions are real, not accidental ───────────────────────────────
# scratch, a previous stage, and our own locally-built image are not mutable
# third-party pointers. If any of them were treated as one, the gate would be
# unsatisfiable and someone would weaken it.
d=$(scratch_repo exclusions)
cat > "$d/svc5/Dockerfile" <<'DF'
FROM golang:1.26@sha256:1111111111111111111111111111111111111111111111111111111111111111 AS build
FROM scratch
COPY --from=build /x /x
DF
cat > "$d/svc6/Dockerfile" <<'DF'
FROM golang:1.26@sha256:1111111111111111111111111111111111111111111111111111111111111111 AS build
FROM build
DF
cat > "$d/svc7/Dockerfile" <<'DF'
FROM yellowjack-scanner:dev
DF
( cd "$d" && git add -A >/dev/null 2>&1 )
rc=$(run_offline "$d")
if [ "$rc" = "0" ]; then
  ok "scratch, an earlier stage, and a locally-built image are not demanded to be pinned"
else
  bad "an exclusion was treated as an external image: $(cat "$TMP/out")"
fi

# ── 6. ANTI-VACUITY FOR CASE 5 ───────────────────────────────────────────────
# Case 5 passes if the exclusions work — and equally if from_refs_in returns
# nothing at all for those files. Assert the parser actually reads FROM lines.
got=$(from_refs_in "$d/svc5/Dockerfile" | tr '\n' ' ')
case "$got" in
  *golang*) ok "from_refs_in really parses FROM lines (got: $got)" ;;
  *) bad "from_refs_in returned '$got' — case 5 passed because it parsed nothing" ;;
esac

# ── 7. the real repo is what CI will actually check ──────────────────────────
rc=$( cd "$ROOT" && check_pins_offline >"$TMP/out" 2>&1; echo $? )
if [ "$rc" = "0" ]; then
  ok "this repo passes: $(cat "$TMP/out")"
else
  bad "this repo does not pass its own pinning gate:"; cat "$TMP/out"
fi

# ── 8. resolve_image_digest refuses the two inputs that produce a bad pin ─────
# No network needed: both refusals happen before the registry is contacted.
if resolve_image_digest "golang:1.26$DIGEST" >/dev/null 2>&1; then
  bad "resolving an already-pinned reference was allowed, which would stack digests"
else
  ok "an already-pinned reference is refused"
fi
if resolve_image_digest "golang" >/dev/null 2>&1; then
  bad "an untagged image was resolved — pinning a moving target to today's bytes hides which version it is"
else
  ok "an untagged image is refused"
fi

# ── 9. compose files are covered too, and the SHIPPED one is why ─────────────
# postgres:17 in docker-compose.yml is the closest thing we have to Nexus #544
# itself. A check that walked only Dockerfiles would report "all pinned" while the
# one image a customer runs unmodified was still a moving tag.
d=$(scratch_repo composeclean)
printf 'services:\n  db:\n    image: postgres:17%s\n' "$DIGEST" > "$d/docker-compose.yml"
( cd "$d" && git add -A >/dev/null 2>&1 )
rc=$(run_offline "$d")
if [ "$rc" = "0" ]; then ok "a pinned compose image passes"; else
  bad "a pinned compose image was rejected: $(cat "$TMP/out")"; fi

# ── 10. NEGATIVE CONTROL: an unpinned compose image must fail ────────────────
d=$(scratch_repo composeunpinned)
printf 'services:\n  db:\n    image: postgres:17\n' > "$d/docker-compose.yml"
( cd "$d" && git add -A >/dev/null 2>&1 )
rc=$(run_offline "$d")
if [ "$rc" != "0" ] && grep -q 'image: postgres:17 is not pinned' "$TMP/out"; then
  ok "an unpinned compose image is caught, and the message says image: not FROM"
else
  bad "an unpinned compose image passed, or the message misnames it: $(cat "$TMP/out")"
fi

# ── 11. a locally-built compose image is not demanded to be pinned ───────────
# docker-compose.e2e.yml names yellowjack-fakesmtp:e2e, which the rig builds itself
# and which has no registry to pin against. Demanding it would make the gate
# unsatisfiable, and an unsatisfiable gate gets weakened.
d=$(scratch_repo composelocal)
printf 'services:\n  smtp:\n    image: yellowjack-fakesmtp:e2e\n' > "$d/docker-compose.e2e.yml"
( cd "$d" && git add -A >/dev/null 2>&1 )
rc=$(run_offline "$d")
if [ "$rc" = "0" ]; then ok "a locally-built compose image is exempt"; else
  bad "a locally-built compose image was demanded: $(cat "$TMP/out")"; fi

# ── 12. ANTI-VACUITY FOR 11 ──────────────────────────────────────────────────
# Case 11 passes if the exemption works, and equally if image_refs_in parses
# nothing at all. This pins that it really reads image: lines.
printf 'services:\n  db:\n    image: postgres:17\n' > "$d/docker-compose.yml"
got=$(image_refs_in "$d/docker-compose.yml" | tr '\n' ' ')
case "$got" in
  *postgres*) ok "image_refs_in really parses image: lines (got: $got)" ;;
  *) bad "image_refs_in returned '$got' — case 11 passed by parsing nothing" ;;
esac

# ── 13. a FROM that names a build ARG resolves to the ARG's pinned default ───
# scanner/Dockerfile names each base once, as `ARG X_BASE=<ref>@sha256:...` and
# `FROM ${X_BASE}`, so CI can substitute a mirror for the default (issue #106).
# The gate must see THROUGH the variable — or every such file reads as unpinned
# and the ARG form becomes a way to smuggle a floating tag past the check — and
# what it returns must be the RESOLVED ref, so the online check can inspect it.
d=$(scratch_repo argpinned)
printf 'ARG SCORECARD_BASE=ghcr.io/ossf/scorecard:v5.2.1%s\n' "$DIGEST" > "$d/svc8/Dockerfile"
printf 'FROM ${SCORECARD_BASE} AS scorecard\nFROM $SCORECARD_BASE\n' >> "$d/svc8/Dockerfile"
( cd "$d" && git add -A >/dev/null 2>&1 )
rc=$(run_offline "$d")
got=$(from_refs_in "$d/svc8/Dockerfile" | tr '\n' ' ')
if [ "$rc" = "0" ]; then
  case "$got" in
    "ghcr.io/ossf/scorecard:v5.2.1$DIGEST ghcr.io/ossf/scorecard:v5.2.1$DIGEST ")
      ok "a FROM naming a build ARG resolves to the ARG's pinned default, in both spellings" ;;
    *) bad "the ARG form passed but resolved to '$got', not the default" ;;
  esac
else
  bad "a pinned ARG default was rejected: $(cat "$TMP/out")"
fi

# ── 14. NEGATIVE CONTROL: an ARG default that is a floating tag must fail ─────
d=$(scratch_repo argunpinned)
printf 'ARG GOLANG_BASE=golang:1.26\nFROM ${GOLANG_BASE} AS build\n' > "$d/svc9/Dockerfile"
( cd "$d" && git add -A >/dev/null 2>&1 )
rc=$(run_offline "$d")
if [ "$rc" != "0" ] && grep -q 'FROM golang:1.26 is not pinned by digest' "$TMP/out"; then
  ok "an unpinned ARG default is caught, and reported as the ref it resolves to"
else
  bad "an unpinned ARG default passed, or was misreported: $(cat "$TMP/out")"
fi

# ── 15. NEGATIVE CONTROL: a FROM naming an ARG with no default must fail ──────
# `ARG BASE` with no default is a pointer whose target is chosen at build time —
# the opposite of a pin — and the message has to say what to add.
d=$(scratch_repo argnodefault)
printf 'ARG BASE\nFROM ${BASE}\n' > "$d/svc10/Dockerfile"
( cd "$d" && git add -A >/dev/null 2>&1 )
rc=$(run_offline "$d")
if [ "$rc" != "0" ] && grep -q 'names a build ARG with no pinned default' "$TMP/out" && grep -q 'ARG BASE=name:tag@sha256' "$TMP/out"; then
  ok "a FROM naming an ARG with no default is caught, and the fix is spelled out"
else
  bad "a defaultless ARG passed, or the message does not name the fix: $(cat "$TMP/out")"
fi

# ── 16. the single-platform marker is read above an ARG line too ─────────────
# The marker used to be looked for above `FROM <ref>`. With the ARG form the FROM
# line no longer contains the ref, so the declaration moves above the ARG — and
# the online check must find it there, or every mirrored single-arch base would be
# reported NARROWED. Negative control alongside: no marker, no declaration.
d=$(scratch_repo argmarker)
printf '# single-platform: upstream publishes no index\nARG SCORECARD_BASE=ghcr.io/ossf/scorecard:v5.2.1%s\nFROM ${SCORECARD_BASE}\n' "$DIGEST" > "$d/svc11/Dockerfile"
printf 'ARG OTHER_BASE=ghcr.io/other/thing:v1%s\nFROM ${OTHER_BASE}\n' "$DIGEST" > "$d/svc12/Dockerfile"
( cd "$d" && git add -A >/dev/null 2>&1 )
if ( cd "$d" && declared_single_platform "ghcr.io/ossf/scorecard:v5.2.1$DIGEST" ); then
  ok "a single-platform marker above an ARG default is read as the declaration"
else
  bad "the marker above an ARG default was not found — mirrored single-arch pins would read as NARROWED"
fi
if ( cd "$d" && declared_single_platform "ghcr.io/other/thing:v1$DIGEST" ); then
  bad "an undeclared ARG default was reported as declared single-platform"
else
  ok "an ARG default without the marker is not declared (the negative control holds)"
fi

# ── 17. NEGATIVE CONTROL: an unpinned external image in a Helm values file must fail ──
# The chart is the file a Kubernetes shop installs and keeps (#83). This case exists
# because the first version of the chart walk checked NOTHING and reported every image
# pinned: the chart directory was gitignored by an unanchored `yellowjack` pattern, so
# `git ls-files` saw no values file, and a file-walking check that finds no files is a
# no-op that looks like a pass. A fixture the walk MUST find is the only guard for that.
chart_values() { # chart_values DIR DIGEST-OR-EMPTY
  mkdir -p "$1/deploy/helm/yellowjack"
  printf 'images:\n  firewall:\n    repository: yellowjack/firewall\n    tag: dev\n    digest: ""\n  postgres:\n    repository: postgres\n    tag: "17"\n    digest: "%s"\n' "$2" > "$1/deploy/helm/yellowjack/values.yaml"
}
d=$(scratch_repo chartunpinned)
chart_values "$d" ""
( cd "$d" && git add -A >/dev/null 2>&1 )
rc=$(run_offline "$d")
if [ "$rc" != "0" ] && grep -q 'values.yaml: images.<name> postgres:17 is not pinned' "$TMP/out"; then
  ok "an unpinned external image in a chart values file is caught, and the message names the values key"
else
  bad "an unpinned chart image passed, or the message misnames it: $(cat "$TMP/out")"
fi

# ── 18. a pinned chart image passes AND is counted ───────────────────────────
# Counted is the half that matters: 12 pinned Dockerfiles clear the floor on their own,
# so a walk that silently skipped the chart would still pass. The summary line carries
# the count, and it must be one higher than the Dockerfiles alone.
d=$(scratch_repo chartpinned)
chart_values "$d" "${DIGEST#@}"
( cd "$d" && git add -A >/dev/null 2>&1 )
rc=$(run_offline "$d")
if [ "$rc" = "0" ] && grep -q 'pinned-images: 13 external base images' "$TMP/out"; then
  ok "a pinned chart image passes and is COUNTED (13 = 12 Dockerfiles + the chart's postgres)"
else
  bad "a pinned chart image was rejected, or was not counted: $(cat "$TMP/out")"
fi

# ── 19. our own chart images are not demanded to be pinned ───────────────────
# yellowjack/* is built by the operator from this repo and has no registry digest,
# the same exclusion the compose walk makes for yellowjack-*. Case 18's fixture
# already carries an unpinned yellowjack/firewall and passed, which IS this
# assertion — restated here so a reader looking for it finds it by name.
if [ "$rc" = "0" ]; then
  ok "an unpinned yellowjack/* chart image is not a violation (built here, nothing to pin against)"
else
  bad "the yellowjack/* exclusion is not applied to chart values"
fi

printf '\n%s passed, %s failed\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
