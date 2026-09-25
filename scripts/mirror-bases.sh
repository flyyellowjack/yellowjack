#!/bin/sh
# mirror-bases.sh — the merge gate builds from base images WE host (issue #106).
#
# ── THE PROBLEM ──────────────────────────────────────────────────────────────
#
# On 2026-08-31 gcr.io withdrew anonymous pull from openssf/scorecard, and the
# e2e-local-async job — which builds the scanner image from that base — went red on
# every open MR at once. Nothing in this repo had changed. The fix that day moved the
# FROM to ghcr.io and pinned it by digest, which fixed INTEGRITY (the bytes cannot
# change) and not AVAILABILITY (the registry can still say no): the gate still ended in
# an anonymous pull from a registry we do not control, and any base image can be
# revoked the same way, by any registry, without notice.
#
# ── THE MECHANISM ────────────────────────────────────────────────────────────
#
# A Dockerfile names each external base ONCE, as a build ARG whose default is the
# upstream reference pinned by digest:
#
#     ARG SCORECARD_BASE=ghcr.io/ossf/scorecard:v5.2.1@sha256:...
#     FROM ${SCORECARD_BASE} AS scorecard
#
# A developer's plain `docker build` uses the defaults and pulls from upstream, as it
# always did. CI sets YJ_BASE_MIRROR to a repository prefix inside the project's own
# container registry and runs:
#
#   ensure FILE        copy every *_BASE digest the mirror does not yet hold. This is
#                      the ONLY step that ever contacts an upstream registry, and it
#                      does so only when a digest is new — i.e. when someone bumped a
#                      pin. Idempotent; a second run does nothing.
#   build  FILE ARGS.. `docker build -f FILE ARGS..` with --build-arg NAME=<mirror>@<digest>
#                      for every *_BASE, followed by a refusal if the build log names
#                      ANY base image outside the mirror.
#   args   FILE        print those --build-arg words (what `build` passes).
#   check-log LOG FILE the refusal on its own, for a log produced elsewhere.
#
# THE DIGEST IS THE IDENTITY IN BOTH WORLDS. The mirror is addressed by the same
# sha256 the Dockerfile pins, so a mirror that lacked it, or held something else under
# that name, fails the build rather than substituting. The copy is digest-preserving
# (`docker buildx imagetools create` pushes the upstream manifest bytes verbatim; a
# tag is added for humans browsing the registry, but nothing builds from the tag), and
# `ensure` reads the digest back from the mirror after copying instead of trusting the
# copy's exit status — a writer's success output describes work attempted.
#
# ── THE DECLARED EXCEPTION: `# mirror: upstream` ─────────────────────────────
#
# A base whose ARG line is preceded by a comment starting `# mirror: upstream` is NOT
# copied. It is built from upstream, and `ensure` PREFLIGHTS it — one manifest lookup
# — so an unreachable or revoked registry fails in a step that names the registry
# rather than as a generic build failure. That is the second half of #106's first
# acceptance box, for the cases where the first half is not worth its cost.
#
# The case that needed it: golang:1.26. Its index spans 16 manifests including two
# Windows variants, about 6.5 GB, and a registry refuses a sparse copy — measured:
# registry:2 answers MANIFEST_BLOB_UNKNOWN for every child left out of a pushed index
# — so a digest-faithful mirror would cost the entire index, per Go version, out of a
# namespace storage quota. The scorecard base (single manifest, the one that actually
# failed) and distroless (a few MB) are copied; the Go toolchain is declared.
#
# REFRESHING: bump the digest in the ARG default. The next pipeline's `ensure` finds it
# missing, copies it once, and every pipeline after that pulls from the mirror. An
# upstream that is unreachable, rate-limiting, or has revoked access fails in `ensure`,
# in a line that names the upstream and the digest — not as a generic build failure
# many steps later, which is what cost three retries and a manual investigation on
# 2026-08-31.
#
# WHAT THIS DOES NOT COVER, on purpose: the job image and the dind service are pulled
# by the runner before any script runs; and a Dockerfile that still writes its bases
# as plain FROM lines is built exactly as before. Converting one is mechanical — name
# each base as an ARG default — and `build` then enforces the mirror for it.
#
# Needs: docker with buildx (docker:27-cli ships it) and a `docker login` to the
# mirror's registry before `ensure` or `build`.

set -u

: "${YJ_BASE_MIRROR:=}"
: "${YJ_MIRROR_UPSTREAM_MARKER:=# mirror: upstream}"

# base_args_in FILE — "NAME REF MODE" for every `ARG NAME_BASE=REF` line, unvalidated.
# MODE is `upstream` when the line directly above the ARG starts with the marker,
# else `mirror`.
base_args_in() {
  awk -v m="$YJ_MIRROR_UPSTREAM_MARKER" '
    /^ARG[ \t]+[A-Za-z0-9_]*_BASE=/ {
      line = $0; sub(/\r$/, "", line)
      name = line; sub(/^ARG[ \t]+/, "", name); sub(/=.*$/, "", name)
      ref = line; sub(/^[^=]*=/, "", ref); sub(/[ \t].*$/, "", ref)
      mode = (index(prev, m) == 1) ? "upstream" : "mirror"
      print name, ref, mode
    }
    { prev = $0; sub(/\r$/, "", prev) }
  ' "$1"
}

# bases_of FILE — the validated list. Every *_BASE must carry a digest (the
# pinned-images gate says the same thing; this says it where the mirror is built), and
# a Dockerfile with no *_BASE at all is reported rather than silently "mirrored".
bases_of() {
  file="$1"
  list=$(base_args_in "$file")
  if [ -z "$list" ]; then
    printf 'mirror-bases: %s declares no *_BASE build ARG; nothing to mirror.\n' "$file" >&2
    printf '    Name each external base once, as  ARG NAME_BASE=name:tag@sha256:...  and FROM ${NAME_BASE}\n' >&2
    return 1
  fi
  old_ifs=$IFS; IFS='
'
  for line in $list; do
    IFS=$old_ifs
    name=${line%% *}; rest=${line#* }; ref=${rest%% *}
    case "$ref" in
      *@sha256:*) ;;
      *)
        printf 'mirror-bases: %s: ARG %s=%s carries no @sha256 digest, so there is nothing to mirror BY.\n' "$file" "$name" "$ref" >&2
        printf '    resolve one with:  sh scripts/dev.sh resolve %s\n' "$ref" >&2
        IFS=$old_ifs; return 1 ;;
    esac
    printf '%s\n' "$line"
  done
  IFS=$old_ifs
}

# mirror_repo NAME — where NAME's digests live: SCORECARD_BASE -> $YJ_BASE_MIRROR/scorecard
mirror_repo() {
  n=$(printf '%s' "$1" | sed 's/_BASE$//' | tr '[:upper:]_' '[:lower:]-')
  printf '%s/%s\n' "$YJ_BASE_MIRROR" "$n"
}

ref_digest() { printf '%s\n' "${1#*@}"; }

# ref_tag REF — the upstream tag, kept on the mirror copy for humans only.
ref_tag() {
  n="${1%%@*}"; n="${n##*/}"
  case "$n" in *:*) printf '%s\n' "${n##*:}" ;; *) printf 'latest\n' ;; esac
}

# ref_host REF — which registry a pull of REF has to reach.
ref_host() {
  case "$1" in
    */*) h="${1%%/*}"; case "$h" in *.*|*:*|localhost) printf '%s\n' "$h" ;; *) printf 'docker.io\n' ;; esac ;;
    *) printf 'docker.io\n' ;;
  esac
}

# build_args_for FILE — the --build-arg words, for the mirrored bases only. Nothing
# when there is no mirror: a dev laptop builds from the upstream defaults.
build_args_for() {
  [ -n "$YJ_BASE_MIRROR" ] || return 0
  list=$(bases_of "$1") || return 1
  old_ifs=$IFS; IFS='
'
  for line in $list; do
    IFS=$old_ifs
    name=${line%% *}; rest=${line#* }; ref=${rest%% *}; mode=${rest#* }
    [ "$mode" = "mirror" ] || continue
    printf '%s %s=%s@%s\n' '--build-arg' "$name" "$(mirror_repo "$name")" "$(ref_digest "$ref")"
  done
  IFS=$old_ifs
}

mirror_has() { docker buildx imagetools inspect "$1" >/dev/null 2>&1; }

# ensure_mirrored FILE — every mirrored *_BASE digest is served by the mirror, copying
# the missing ones from upstream; every declared-upstream *_BASE resolves at its
# registry. Exit 1 names the registry that could not be reached, either way.
ensure_mirrored() {
  file="$1"
  if [ -z "$YJ_BASE_MIRROR" ]; then
    printf 'mirror-bases: YJ_BASE_MIRROR is unset; nothing to ensure (builds use the upstream defaults)\n'
    return 0
  fi
  list=$(bases_of "$file") || return 1
  old_ifs=$IFS; IFS='
'
  for line in $list; do
    IFS=$old_ifs
    name=${line%% *}; rest=${line#* }; ref=${rest%% *}; mode=${rest#* }
    if [ "$mode" = "upstream" ]; then
      if mirror_has "$ref"; then
        printf 'mirror-bases: upstream  %s  (%s: declared "%s", resolves at %s)\n' "$ref" "$name" "$YJ_MIRROR_UPSTREAM_MARKER" "$(ref_host "$ref")"
      else
        printf 'mirror-bases: EXTERNAL REGISTRY UNAVAILABLE: %s cannot be resolved at %s.\n' "$ref" "$(ref_host "$ref")"
        printf '    %s is declared "%s" (not mirrored), so the build would pull it from there and fail.\n' "$name" "$YJ_MIRROR_UPSTREAM_MARKER"
        printf '    Unreachable, rate-limiting us, or anonymous pull withdrawn (#106). Nothing in this repo changed.\n'
        IFS=$old_ifs; return 1
      fi
      continue
    fi
    repo=$(mirror_repo "$name"); dg=$(ref_digest "$ref"); tag=$(ref_tag "$ref")
    if mirror_has "$repo@$dg"; then
      printf 'mirror-bases: present   %s@%s  (%s)\n' "$repo" "$dg" "$name"
      continue
    fi
    printf 'mirror-bases: MISSING   %s@%s — copying from %s\n' "$repo" "$dg" "$ref"
    if ! docker buildx imagetools create -t "$repo:$tag" "$ref"; then
      printf 'mirror-bases: could not copy %s into the mirror.\n' "$ref"
      printf '    Either side can be the one refusing; the output above says which:\n'
      printf '    - the UPSTREAM registry (%s): unreachable, rate-limiting us, or anonymous pull withdrawn,\n' "$(ref_host "$ref")"
      printf '      which is what gcr.io did on 2026-08-31 (#106). Nothing in this repo changed, and retrying\n'
      printf '      the BUILD will not help: the copy has to succeed once per digest, in this step.\n'
      printf '    - the MIRROR (%s): not logged in, or the credential cannot push to it.\n' "$(ref_host "$YJ_BASE_MIRROR/x")"
      IFS=$old_ifs; return 1
    fi
    if ! mirror_has "$repo@$dg"; then
      printf 'mirror-bases: copied %s, but the mirror does not serve digest %s under %s.\n' "$ref" "$dg" "$repo"
      printf '    The copy did not preserve the manifest bytes, so the pinned FROM would not resolve. Refusing.\n'
      IFS=$old_ifs; return 1
    fi
    printf 'mirror-bases: mirrored  %s -> %s@%s\n' "$ref" "$repo" "$dg"
  done
  IFS=$old_ifs
}

# check_build_log LOG FILE — every base the build resolved came from the mirror, or
# is one FILE declares upstream (matched by DIGEST, so a declared base at a different
# digest is still a refusal).
#
# With --progress=plain BuildKit prints one line per stage source:
#     #5 [scorecard 1/1] FROM registry.gitlab.com/.../base/scorecard@sha256:...
# and, if the Dockerfile carries a `# syntax=` directive, a frontend image pull:
#     #2 resolve image config for docker-image://docker.io/docker/dockerfile:1
# Both are pulls; both are judged. A log that names NO base at all is a refusal too —
# that is what a build which never ran, or ran without plain progress, looks like, and
# it must not read as "all from the mirror".
check_build_log() {
  log="$1"; file="${2:-}"
  if [ -z "$YJ_BASE_MIRROR" ]; then
    printf 'mirror-bases: YJ_BASE_MIRROR is unset; no mirror to check the build against\n' >&2
    return 1
  fi
  allow=""
  if [ -n "$file" ]; then
    list=$(bases_of "$file") || return 1
    old_ifs=$IFS; IFS='
'
    for line in $list; do
      IFS=$old_ifs
      rest=${line#* }; ref=${rest%% *}; mode=${rest#* }
      [ "$mode" = "upstream" ] && allow="$allow $(ref_digest "$ref")"
    done
    IFS=$old_ifs
  fi
  lines=$(grep -E '\] FROM |docker-image://' "$log" | tr -d '\r' | sort -u)
  n=0; mirrored=0; declared=0; rc=0
  old_ifs=$IFS; IFS='
'
  for line in $lines; do
    IFS=$old_ifs
    n=$((n + 1))
    case "$line" in *"$YJ_BASE_MIRROR"*) mirrored=$((mirrored + 1)); continue ;; esac
    hit=0
    for dg in $allow; do case "$line" in *"@$dg"*) hit=1 ;; esac; done
    if [ "$hit" = 1 ]; then declared=$((declared + 1)); continue; fi
    printf 'mirror-bases: the build pulled a base from OUTSIDE the mirror (and it is not declared upstream):\n    %s\n' "$line"
    rc=1
  done
  IFS=$old_ifs
  if [ "$n" -eq 0 ]; then
    printf 'mirror-bases: the build log names no base image at all (expected --progress=plain output).\n'
    printf '    Refusing to call that mirrored: a check that saw nothing has checked nothing.\n'
    return 1
  fi
  [ "$rc" -eq 0 ] && printf 'mirror-bases: %s base pull(s): %s from %s, %s declared upstream\n' "$n" "$mirrored" "$YJ_BASE_MIRROR" "$declared"
  return "$rc"
}

# build_with_mirror FILE [docker build args...] — the one build path the rigs and the
# CI job share. Quiet on success, the whole log on failure; with a mirror configured,
# the resolved FROM lines are printed as the reviewer-facing evidence and the log check
# is the gate. A Dockerfile with no *_BASE ARGs is built plainly (no mirror to enforce).
build_with_mirror() {
  file="$1"; shift
  args=""; gate=0
  if [ -n "$YJ_BASE_MIRROR" ] && [ -n "$(base_args_in "$file")" ]; then
    args=$(build_args_for "$file") || return 1
    gate=1
  fi
  log="${YJ_BUILD_LOG:-$(mktemp)}"
  # shellcheck disable=SC2086  # word-splitting the --build-arg words is the point
  if ! docker build --progress=plain $args -f "$file" "$@" >"$log" 2>&1; then
    cat "$log"
    printf 'mirror-bases: docker build -f %s failed (log above)\n' "$file"
    return 1
  fi
  if [ "$gate" = 1 ]; then
    grep -E '\] FROM ' "$log" | tr -d '\r' | sort -u
    check_build_log "$log" "$file" || return 1
  fi
}

usage() {
  cat >&2 <<'EOF'
usage: sh scripts/mirror-bases.sh <command> ...
  args      <Dockerfile>                  print --build-arg NAME=<mirror>@<digest> per mirrored *_BASE ARG
  ensure    <Dockerfile>                  copy every missing *_BASE digest into $YJ_BASE_MIRROR; preflight the declared-upstream ones
  build     <Dockerfile> [docker args..]  docker build through the mirror, then refuse any undeclared upstream pull
  check-log <build.log> <Dockerfile>      the refusal alone, for a --progress=plain log made elsewhere
YJ_BASE_MIRROR unset => no mirror: `args` prints nothing, `build` builds from the upstream defaults.
EOF
}

# Dispatch only when executed; the test suite sources this file for its functions.
case "$0" in
  *mirror-bases.sh)
    cmd="${1:-}"; [ $# -gt 0 ] && shift
    case "$cmd" in
      args)      build_args_for "$@" ;;
      ensure)    ensure_mirrored "$@" ;;
      build)     build_with_mirror "$@" ;;
      check-log) check_build_log "$@" ;;
      *)         usage; exit 2 ;;
    esac ;;
esac
