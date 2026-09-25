#!/bin/sh
# Tests for scripts/mirror-bases.sh — against a FAKE docker, no network.
#
# The wrapper decides whether the merge gate's scanner build touched a third-party
# registry. The failure it exists to catch is silent: a build that IGNORED the mirror
# arguments (an env var misspelled in CI, an ARG renamed in the Dockerfile) still
# succeeds, still produces a working image, and is still an anonymous pull from a
# registry that can revoke us — the exact shape of 2026-08-31 (#106), with a green
# check on top. So the cases that matter here are the refusals: the wrapper must go
# red when the build resolved a base anywhere but the mirror (or a base the Dockerfile
# declares upstream, at exactly its pinned digest), when the log names no base at all,
# when a copy claimed success but the digest cannot be read back, and when a
# declared-upstream base cannot be resolved at its registry.
set -u

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
. "$ROOT/scripts/mirror-bases.sh"

PASS=0
FAIL=0
ok()  { PASS=$((PASS + 1)); printf 'ok   %s\n' "$1"; }
bad() { FAIL=$((FAIL + 1)); printf 'FAIL %s\n' "$1"; }

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

G=1111111111111111111111111111111111111111111111111111111111111111
S=2222222222222222222222222222222222222222222222222222222222222222
D=3333333333333333333333333333333333333333333333333333333333333333
MIRROR=example.test/yj/base

# Fixture 1: three bases, all mirrored.
DF="$TMP/Dockerfile"
printf 'ARG GOLANG_BASE=golang:1.26@sha256:%s\n' "$G" > "$DF"
printf '# single-platform: upstream publishes no index\n' >> "$DF"
printf 'ARG SCORECARD_BASE=ghcr.io/ossf/scorecard:v5.2.1@sha256:%s\n' "$S" >> "$DF"
printf 'ARG DISTROLESS_BASE=gcr.io/distroless/static:nonroot@sha256:%s\n' "$D" >> "$DF"
printf 'FROM ${GOLANG_BASE} AS build\nFROM ${SCORECARD_BASE} AS scorecard\nFROM ${DISTROLESS_BASE}\n' >> "$DF"

# Fixture 2: scanner/Dockerfile's real shape — the Go toolchain declared upstream.
DF2="$TMP/Dockerfile.upstream"
printf '# mirror: upstream — 6.5 GB multi-platform index; preflighted, not copied\n' > "$DF2"
printf 'ARG GOLANG_BASE=golang:1.26@sha256:%s\n' "$G" >> "$DF2"
printf '# single-platform: upstream publishes no index\n' >> "$DF2"
printf 'ARG SCORECARD_BASE=ghcr.io/ossf/scorecard:v5.2.1@sha256:%s\n' "$S" >> "$DF2"
printf 'ARG DISTROLESS_BASE=gcr.io/distroless/static:nonroot@sha256:%s\n' "$D" >> "$DF2"
printf 'FROM ${GOLANG_BASE} AS build\nFROM ${SCORECARD_BASE} AS scorecard\nFROM ${DISTROLESS_BASE}\n' >> "$DF2"

# The fake docker. `imagetools inspect REF` answers from $FAKE_PRESENT; `imagetools
# create` records the call and (unless told to fail, or to lose the digest) makes the
# destination digest present; `build` prints one FROM line per --build-arg value, and
# the UPSTREAM line for any base it was not given an arg for — which is what a real
# build does with the Dockerfile's defaults.
mkdir -p "$TMP/bin"
cat > "$TMP/bin/docker" <<'FAKE'
#!/bin/sh
printf '%s\n' "$*" >> "$FAKE_CALLS"
case "${1:-} ${2:-} ${3:-}" in
  "buildx imagetools inspect")
    grep -qxF "$4" "$FAKE_PRESENT" 2>/dev/null && exit 0
    echo "fake: no such manifest: $4" >&2; exit 1 ;;
  "buildx imagetools create")
    dst="$5"; src="$6"
    [ "${FAKE_COPY_FAILS:-0}" = 1 ] && { echo "fake: upstream refused" >&2; exit 1; }
    [ "${FAKE_COPY_LOSES_DIGEST:-0}" = 1 ] || printf '%s@%s\n' "${dst%:*}" "${src#*@}" >> "$FAKE_PRESENT"
    exit 0 ;;
esac
case "${1:-}" in
  build)
    shift; sc=0; go=0
    while [ $# -gt 0 ]; do
      if [ "$1" = "--build-arg" ]; then
        if [ "${FAKE_BUILD_IGNORES_ARGS:-0}" != 1 ]; then
          printf '#5 [stage 1/1] FROM %s\n' "${2#*=}"
          case "$2" in SCORECARD_BASE=*) sc=1 ;; GOLANG_BASE=*) go=1 ;; esac
        fi
        shift
      fi
      shift
    done
    [ "$sc" = 1 ] || printf '#5 [scorecard 1/1] FROM ghcr.io/ossf/scorecard:v5.2.1@sha256:%s\n' "$FAKE_SCORECARD_DIGEST"
    [ "$go" = 1 ] || printf '#4 [build 1/6] FROM docker.io/library/golang:1.26@sha256:%s\n' "$FAKE_GOLANG_DIGEST"
    [ "${FAKE_BUILD_FAILS:-0}" = 1 ] && exit 1
    exit 0 ;;
esac
echo "fake docker: unexpected invocation: $*" >&2; exit 99
FAKE
chmod +x "$TMP/bin/docker"
PATH="$TMP/bin:$PATH"; export PATH
FAKE_PRESENT="$TMP/present"; FAKE_CALLS="$TMP/calls"; FAKE_SCORECARD_DIGEST="$S"; FAKE_GOLANG_DIGEST="$G"
export FAKE_PRESENT FAKE_CALLS FAKE_SCORECARD_DIGEST FAKE_GOLANG_DIGEST
: > "$FAKE_PRESENT"; : > "$FAKE_CALLS"
reset_fake() { : > "$FAKE_PRESENT"; : > "$FAKE_CALLS"; unset FAKE_COPY_FAILS FAKE_COPY_LOSES_DIGEST FAKE_BUILD_IGNORES_ARGS FAKE_BUILD_FAILS; }
creates() { grep -c '^buildx imagetools create ' "$FAKE_CALLS"; }
all_present() { printf '%s/golang@sha256:%s\n%s/scorecard@sha256:%s\n%s/distroless@sha256:%s\n' "$MIRROR" "$G" "$MIRROR" "$S" "$MIRROR" "$D" > "$FAKE_PRESENT"; }

# ── 1. the parser reads all three bases, resolved, in order, each mode right ──
got=$(bases_of "$DF" | tr '\n' ';')
case "$got" in
  "GOLANG_BASE golang:1.26@sha256:$G mirror;SCORECARD_BASE ghcr.io/ossf/scorecard:v5.2.1@sha256:$S mirror;DISTROLESS_BASE gcr.io/distroless/static:nonroot@sha256:$D mirror;")
    ok "bases_of reads every *_BASE ARG with its pinned default" ;;
  *) bad "bases_of returned: $got" ;;
esac
got=$(bases_of "$DF2" | tr '\n' ';')
case "$got" in
  "GOLANG_BASE golang:1.26@sha256:$G upstream;SCORECARD_BASE ghcr.io/ossf/scorecard:v5.2.1@sha256:$S mirror;DISTROLESS_BASE gcr.io/distroless/static:nonroot@sha256:$D mirror;")
    ok "a '# mirror: upstream' line directly above an ARG marks that base declared-upstream, and only that one" ;;
  *) bad "bases_of on the declared-upstream fixture returned: $got" ;;
esac

# ── 2. no mirror configured: args prints nothing, and that is a success ───────
out=$(YJ_BASE_MIRROR= build_args_for "$DF"; echo "rc=$?")
if [ "$out" = "rc=0" ]; then ok "with no mirror, args prints nothing (the build uses the upstream defaults)"; else
  bad "with no mirror, args printed: $out"; fi

# ── 3. with a mirror: one --build-arg per MIRRORED base, same digest, repo per NAME ──
out=$(YJ_BASE_MIRROR=$MIRROR build_args_for "$DF")
n=$(printf '%s\n' "$out" | grep -c '^--build-arg ')
if [ "$n" = 3 ] \
  && printf '%s\n' "$out" | grep -qxF -- "--build-arg SCORECARD_BASE=$MIRROR/scorecard@sha256:$S" \
  && printf '%s\n' "$out" | grep -qxF -- "--build-arg GOLANG_BASE=$MIRROR/golang@sha256:$G" \
  && printf '%s\n' "$out" | grep -qxF -- "--build-arg DISTROLESS_BASE=$MIRROR/distroless@sha256:$D"; then
  ok "args names the mirror repo per ARG and keeps the pinned digest"
else
  bad "args printed:
$out"
fi
out=$(YJ_BASE_MIRROR=$MIRROR build_args_for "$DF2")
if [ "$(printf '%s\n' "$out" | grep -c '^--build-arg ')" = 2 ] && ! printf '%s\n' "$out" | grep -q GOLANG_BASE; then
  ok "a declared-upstream base gets no --build-arg (the build uses its pinned default)"
else
  bad "args on the declared-upstream fixture printed:
$out"
fi

# ── 4. NEGATIVE: a *_BASE without a digest cannot be mirrored BY anything ─────
printf 'ARG GOLANG_BASE=golang:1.26\nFROM ${GOLANG_BASE}\n' > "$TMP/unpinned.Dockerfile"
if YJ_BASE_MIRROR=$MIRROR build_args_for "$TMP/unpinned.Dockerfile" >"$TMP/out" 2>&1; then
  bad "an unpinned *_BASE was accepted — the mirror would be addressed by a mutable tag"
elif grep -q 'carries no @sha256 digest' "$TMP/out" && grep -q 'GOLANG_BASE' "$TMP/out"; then
  ok "an unpinned *_BASE is refused, and the message names the ARG"
else
  bad "an unpinned *_BASE was refused with the wrong message: $(cat "$TMP/out")"
fi

# ── 5. NEGATIVE: a Dockerfile with no *_BASE is not 'mirrored', it is a mistake ──
printf 'FROM golang:1.26@sha256:%s\n' "$G" > "$TMP/plain.Dockerfile"
if YJ_BASE_MIRROR=$MIRROR ensure_mirrored "$TMP/plain.Dockerfile" >"$TMP/out" 2>&1; then
  bad "ensure on a Dockerfile with no *_BASE ARG reported success — vacuous"
elif grep -q 'declares no \*_BASE' "$TMP/out"; then
  ok "ensure on a Dockerfile with no *_BASE ARG fails and says so"
else
  bad "ensure on a plain Dockerfile failed with the wrong message: $(cat "$TMP/out")"
fi

# ── 6. ensure with everything present copies nothing ─────────────────────────
reset_fake; all_present
if YJ_BASE_MIRROR=$MIRROR ensure_mirrored "$DF" >"$TMP/out" 2>&1 && [ "$(creates)" = 0 ] && [ "$(grep -c 'present ' "$TMP/out")" = 3 ]; then
  ok "ensure with every digest present makes no copy (no upstream contact)"
else
  bad "ensure with everything present: rc/copies wrong: $(cat "$TMP/out"); creates=$(creates)"
fi

# ── 7. ensure copies exactly the missing digest, once, and is idempotent ──────
reset_fake
printf '%s/golang@sha256:%s\n%s/distroless@sha256:%s\n' "$MIRROR" "$G" "$MIRROR" "$D" > "$FAKE_PRESENT"
if YJ_BASE_MIRROR=$MIRROR ensure_mirrored "$DF" >"$TMP/out" 2>&1 \
  && [ "$(creates)" = 1 ] \
  && grep -qxF "buildx imagetools create -t $MIRROR/scorecard:v5.2.1 ghcr.io/ossf/scorecard:v5.2.1@sha256:$S" "$FAKE_CALLS" \
  && grep -q "mirrored  ghcr.io/ossf/scorecard:v5.2.1@sha256:$S -> $MIRROR/scorecard@sha256:$S" "$TMP/out"; then
  ok "ensure copies the one missing digest from its upstream, tagged for humans, addressed by digest"
else
  bad "ensure did not copy exactly the missing base: $(cat "$TMP/out"); calls: $(cat "$FAKE_CALLS")"
fi
if YJ_BASE_MIRROR=$MIRROR ensure_mirrored "$DF" >"$TMP/out" 2>&1 && [ "$(creates)" = 1 ]; then
  ok "a second ensure copies nothing (idempotent — upstream is contacted once per digest)"
else
  bad "a second ensure copied again or failed: $(cat "$TMP/out"); creates=$(creates)"
fi

# ── 8. NEGATIVE: the upstream refusing is named as such, not as a build failure ──
reset_fake
FAKE_COPY_FAILS=1; export FAKE_COPY_FAILS
if YJ_BASE_MIRROR=$MIRROR ensure_mirrored "$DF" >"$TMP/out" 2>&1; then
  bad "a failed copy was reported as success"
elif grep -q "could not copy golang:1.26@sha256:$G into the mirror" "$TMP/out" && grep -q 'UPSTREAM registry (docker.io)' "$TMP/out"; then
  ok "a failed copy names the upstream ref and the registry it needed"
else
  bad "a failed copy gave the wrong message: $(cat "$TMP/out")"
fi

# ── 9. NEGATIVE: a copy that 'succeeds' but does not serve the digest is refused ──
# The writer's exit status describes work attempted; the digest read back is the fact.
reset_fake
FAKE_COPY_LOSES_DIGEST=1; export FAKE_COPY_LOSES_DIGEST
if YJ_BASE_MIRROR=$MIRROR ensure_mirrored "$DF" >"$TMP/out" 2>&1; then
  bad "a copy whose digest cannot be read back was accepted — the pinned FROM would then fail"
elif grep -q "does not serve digest sha256:$G" "$TMP/out"; then
  ok "a copy is verified by reading the digest back, and refused when it is not there"
else
  bad "the lost-digest case failed with the wrong message: $(cat "$TMP/out")"
fi
reset_fake

# ── 10. a declared-upstream base is PREFLIGHTED, never copied ─────────────────
reset_fake
printf '%s/scorecard@sha256:%s\n%s/distroless@sha256:%s\ngolang:1.26@sha256:%s\n' "$MIRROR" "$S" "$MIRROR" "$D" "$G" > "$FAKE_PRESENT"
if YJ_BASE_MIRROR=$MIRROR ensure_mirrored "$DF2" >"$TMP/out" 2>&1 && [ "$(creates)" = 0 ] \
  && grep -q "upstream  golang:1.26@sha256:$G" "$TMP/out" \
  && grep -qxF "buildx imagetools inspect golang:1.26@sha256:$G" "$FAKE_CALLS"; then
  ok "a declared-upstream base is resolved at its registry (one lookup) and not copied"
else
  bad "declared-upstream ensure: $(cat "$TMP/out"); calls: $(cat "$FAKE_CALLS")"
fi

# ── 11. NEGATIVE, THE NAMED FAILURE: the upstream registry being unavailable ──
# #106's first acceptance box, second clause: the failure must say "external registry
# unavailable" and which one — in `ensure`, before any build runs.
reset_fake
printf '%s/scorecard@sha256:%s\n%s/distroless@sha256:%s\n' "$MIRROR" "$S" "$MIRROR" "$D" > "$FAKE_PRESENT"
if YJ_BASE_MIRROR=$MIRROR ensure_mirrored "$DF2" >"$TMP/out" 2>&1; then
  bad "a declared-upstream base that cannot be resolved passed ensure — the build would fail generically later"
elif grep -q 'EXTERNAL REGISTRY UNAVAILABLE' "$TMP/out" && grep -q 'docker.io' "$TMP/out" && grep -q 'GOLANG_BASE' "$TMP/out" && [ "$(creates)" = 0 ]; then
  ok "an unresolvable declared-upstream base is a NAMED failure: the registry, the ARG, and no copy attempted"
else
  bad "the unresolvable-upstream case gave the wrong message: $(cat "$TMP/out"); creates=$(creates)"
fi
reset_fake

# ── 12. check-log passes a log whose every base is the mirror ────────────────
printf '#4 [build 1/5] FROM %s/golang@sha256:%s\n#5 [scorecard 1/1] FROM %s/scorecard@sha256:%s\n#6 CACHED\n' "$MIRROR" "$G" "$MIRROR" "$S" > "$TMP/good.log"
if YJ_BASE_MIRROR=$MIRROR check_build_log "$TMP/good.log" "$DF" >"$TMP/out" 2>&1 && grep -q '2 base pull(s): 2 from' "$TMP/out"; then
  ok "a log whose bases all come from the mirror passes, and says how many it counted"
else
  bad "a clean log was refused: $(cat "$TMP/out")"
fi

# ── 13. NEGATIVE: one upstream FROM line fails, and the line is quoted ────────
printf '#4 [build 1/5] FROM %s/golang@sha256:%s\n#5 [scorecard 1/1] FROM ghcr.io/ossf/scorecard:v5.2.1@sha256:%s\n' "$MIRROR" "$G" "$S" > "$TMP/leak.log"
if YJ_BASE_MIRROR=$MIRROR check_build_log "$TMP/leak.log" "$DF" >"$TMP/out" 2>&1; then
  bad "a build that pulled from ghcr.io was reported as mirrored — the check is decorative"
elif grep -q 'OUTSIDE the mirror' "$TMP/out" && grep -q 'ghcr.io/ossf/scorecard' "$TMP/out"; then
  ok "a base resolved outside the mirror is refused, and the offending line is quoted"
else
  bad "the leak was refused with the wrong message: $(cat "$TMP/out")"
fi

# ── 14. NEGATIVE: a `# syntax=` frontend pull is a pull too ──────────────────
printf '#2 resolve image config for docker-image://docker.io/docker/dockerfile:1\n#4 [build 1/5] FROM %s/golang@sha256:%s\n' "$MIRROR" "$G" > "$TMP/frontend.log"
if YJ_BASE_MIRROR=$MIRROR check_build_log "$TMP/frontend.log" "$DF" >"$TMP/out" 2>&1; then
  bad "a Dockerfile frontend pulled from Docker Hub was not counted as an upstream pull"
else
  ok "the BuildKit frontend image counts as a base pull and is refused from Docker Hub"
fi

# ── 15. VACUITY: a log that names no base is a refusal, not a pass ───────────
printf '#1 [internal] load build definition\n#2 DONE 0.0s\n' > "$TMP/empty.log"
if YJ_BASE_MIRROR=$MIRROR check_build_log "$TMP/empty.log" "$DF" >"$TMP/out" 2>&1; then
  bad "a log with no FROM lines passed — 'all from the mirror' was concluded from nothing"
elif grep -q 'names no base image at all' "$TMP/out"; then
  ok "a log that names no base at all is refused"
else
  bad "the empty log was refused with the wrong message: $(cat "$TMP/out")"
fi
if YJ_BASE_MIRROR= check_build_log "$TMP/good.log" "$DF" >"$TMP/out" 2>&1; then
  bad "check-log with no mirror configured passed — there was nothing to check against"
else
  ok "check-log with no mirror configured refuses rather than passing vacuously"
fi

# ── 16. a declared-upstream base is accepted in the log AT ITS DIGEST ONLY ────
printf '#4 [build 1/6] FROM docker.io/library/golang:1.26@sha256:%s\n#5 [scorecard 1/1] FROM %s/scorecard@sha256:%s\n' "$G" "$MIRROR" "$S" > "$TMP/declared.log"
if YJ_BASE_MIRROR=$MIRROR check_build_log "$TMP/declared.log" "$DF2" >"$TMP/out" 2>&1 && grep -q '2 base pull(s): 1 from .* 1 declared upstream' "$TMP/out"; then
  ok "a declared-upstream base pulled at its pinned digest passes, and is counted as declared"
else
  bad "the declared-upstream log was refused or miscounted: $(cat "$TMP/out")"
fi
if YJ_BASE_MIRROR=$MIRROR check_build_log "$TMP/declared.log" "$DF" >"$TMP/out" 2>&1; then
  bad "the same golang pull passed against a Dockerfile that does NOT declare it upstream"
else
  ok "the declaration is per Dockerfile: the same upstream pull is refused where it is not declared"
fi
printf '#4 [build 1/6] FROM docker.io/library/golang:1.26@sha256:%s\n#5 [scorecard 1/1] FROM %s/scorecard@sha256:%s\n' "$D" "$MIRROR" "$S" > "$TMP/wrongdigest.log"
if YJ_BASE_MIRROR=$MIRROR check_build_log "$TMP/wrongdigest.log" "$DF2" >"$TMP/out" 2>&1; then
  bad "a declared-upstream base at a DIFFERENT digest passed — the declaration is by name, not by pin"
else
  ok "a declared-upstream base at any other digest is refused (declared means declared at that pin)"
fi

# ── 17. the build wrapper wires the args through and gates on the log ────────
reset_fake
if YJ_BASE_MIRROR=$MIRROR build_with_mirror "$DF" -t yellowjack-scanner:dev . >"$TMP/out" 2>&1 \
  && grep -q '^build --progress=plain ' "$FAKE_CALLS" \
  && grep -q -- "--build-arg SCORECARD_BASE=$MIRROR/scorecard@sha256:$S" "$FAKE_CALLS" \
  && grep -q -- "-f $DF -t yellowjack-scanner:dev \.$" "$FAKE_CALLS" \
  && grep -q '3 base pull(s): 3 from' "$TMP/out"; then
  ok "build passes --progress=plain and every --build-arg, then checks the log it captured"
else
  bad "build wiring: $(cat "$TMP/out"); calls: $(cat "$FAKE_CALLS")"
fi
reset_fake
if YJ_BASE_MIRROR=$MIRROR build_with_mirror "$DF2" -t x . >"$TMP/out" 2>&1 \
  && ! grep -q -- '--build-arg GOLANG_BASE' "$FAKE_CALLS" \
  && grep -q '3 base pull(s): 2 from .* 1 declared upstream' "$TMP/out"; then
  ok "build on the real shape: two bases through the mirror, the Go toolchain from its declared upstream"
else
  bad "build on the declared-upstream fixture: $(cat "$TMP/out"); calls: $(cat "$FAKE_CALLS")"
fi

# ── 18. NEGATIVE, THE ONE THAT MATTERS: a build that ignored the args is refused ──
# A green image, a successful exit, and an anonymous upstream pull underneath — this
# is what a misspelled variable or a renamed ARG produces, and the wrapper must go red.
reset_fake
FAKE_BUILD_IGNORES_ARGS=1; export FAKE_BUILD_IGNORES_ARGS
if YJ_BASE_MIRROR=$MIRROR build_with_mirror "$DF" -t x . >"$TMP/out" 2>&1; then
  bad "a build that pulled the upstream default despite the mirror args was reported as mirrored"
elif grep -q 'OUTSIDE the mirror' "$TMP/out"; then
  ok "a build that silently ignored the mirror args is refused"
else
  bad "the ignored-args build was refused with the wrong message: $(cat "$TMP/out")"
fi
reset_fake

# ── 19. a failed docker build is a failed build, with the log shown ──────────
FAKE_BUILD_FAILS=1; export FAKE_BUILD_FAILS
if YJ_BASE_MIRROR=$MIRROR build_with_mirror "$DF" -t x . >"$TMP/out" 2>&1; then
  bad "a failing docker build was reported as success"
elif grep -q 'docker build -f .* failed' "$TMP/out"; then
  ok "a failing docker build fails the wrapper and prints its log"
else
  bad "the failing build gave the wrong message: $(cat "$TMP/out")"
fi
reset_fake

# ── 20. no mirror: a plain build, no --build-arg, no log gate ────────────────
if YJ_BASE_MIRROR= build_with_mirror "$DF" -t x . >"$TMP/out" 2>&1 \
  && ! grep -q -- '--build-arg' "$FAKE_CALLS" && [ ! -s "$TMP/out" ]; then
  ok "with no mirror the wrapper is a plain quiet docker build (a dev laptop is unchanged)"
else
  bad "no-mirror build: out='$(cat "$TMP/out")' calls: $(cat "$FAKE_CALLS")"
fi

# ── 21. the real scanner Dockerfile is in the shape all of this assumes ───────
got=$(bases_of "$ROOT/scanner/Dockerfile" | awk '{print $1 ":" $3}' | tr '\n' ' ')
if [ "$got" = "GOLANG_BASE:upstream SCORECARD_BASE:mirror DISTROLESS_BASE:mirror " ]; then
  ok "scanner/Dockerfile names its three bases as *_BASE ARGs: Go declared upstream, the other two mirrored"
else
  bad "scanner/Dockerfile bases: '$got' — the CI job mirrors what this parser finds"
fi
if grep -q '^# syntax=' "$ROOT/scanner/Dockerfile"; then
  bad "scanner/Dockerfile carries a # syntax= directive, which pulls the BuildKit frontend from Docker Hub at build time"
else
  ok "scanner/Dockerfile has no # syntax= directive (no frontend pull)"
fi

printf '\n%s passed, %s failed\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
