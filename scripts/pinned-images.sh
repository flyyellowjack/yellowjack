#!/bin/sh
# Base-image pinning: the invariant, and the one way to change it (issue #22).
#
# Nexus bug #544 is the case this exists for: pulling a newer `:latest` triggered
# an unintended database migration. A tag is a MUTABLE POINTER — the same
# Dockerfile can build different bytes on different days, and a self-hoster who
# has to explain a change they did not make is exactly the buyer D54 says we are
# building for.
#
# ── TWO CHECKS, DELIBERATELY SPLIT BY WHETHER THEY NEED A NETWORK ────────────
#
#   check_pins_offline   every external FROM carries a tag AND an @sha256 digest.
#                        No network, deterministic, runs in the vet gate.
#   verify_pins_online   each pinned digest still RESOLVES, and is a multi-arch
#                        index unless the file says otherwise. Needs a registry,
#                        so it is its own task (sh scripts/dev.sh pins).
#
# The split matters: a gate that needs a third-party registry in order to pass is
# a gate that goes red when that registry rate-limits us — which is what happened
# to gcr.io/openssf/scorecard on 2026-08-31 (issue #106) and took every open MR's
# e2e leg down at once.
#
# ── THE ARCH-NARROWING TRAP ──────────────────────────────────────────────────
#
# `docker buildx imagetools inspect golang:1.26` prints the index digest AND a
# separate per-platform digest for each of its 8 platforms. Copying the wrong one
# pins the build to linux/amd64, and NOTHING FAILS until someone builds on arm64
# — where the error is an unrelated-looking manifest/exec-format failure, not
# "you narrowed the platform". resolve_image_digest exists to remove the choice:
# it always emits the digest the TAG resolves to.
#
# Genuinely single-platform upstreams exist — ghcr.io/ossf/scorecard:v5.2.1
# publishes one linux/amd64 manifest and no index at all. Those are declared with
# a marker comment on the line above the line that names the ref — its FROM, or
# the ARG default a FROM resolves through (scanner/Dockerfile names each base as
# `ARG X_BASE=...` + `FROM ${X_BASE}` so CI can substitute a mirror, #106):
#
#     # single-platform: upstream publishes no index
#     FROM ghcr.io/ossf/scorecard:v5.2.1@sha256:...
#
# so the exception lives where the decision is, not in a list elsewhere that
# nobody reads.
#
# ── SCOPE: Dockerfile FROM lines AND compose `image:` lines ─────────────────
#
# Both, because they fail the same way and only one of them is ours to rebuild.
# `postgres:17` in the SHIPPED docker-compose.yml is the closest thing we have to
# Nexus bug #544 itself: an unpinned database image whose minor version can move
# under a self-hoster who changed nothing.
#
# The e2e rigs are pinned for a different reason. e2e/registry_front.sh asserts
# against verdaccio's CACHING BEHAVIOUR, probed by hand before that rig was written.
# If that tag is republished with different cache semantics, the rig keeps passing
# while measuring something else — a green test that has quietly changed its subject
# is worse than a red one.

: "${YJ_PIN_MARKER:=# single-platform:}"

# from_refs_in FILE — the external image references a Dockerfile depends on.
#
# Excluded, because none of them is a mutable third-party pointer:
#   scratch          the empty base; there is nothing to pin
#   a previous stage FROM build, FROM dockercli — resolved inside the file
#   yellowjack-*     our own locally-built images (e2e/fakescanner)
# arg_default FILE NAME — the default a Dockerfile gives build ARG NAME, if any.
arg_default() {
  sed -n "s/^ARG[[:space:]]\{1,\}$2=\([^[:space:]]*\).*/\1/p" "$1" | tr -d '\r' | head -1
}

# resolve_from_ref FILE REF — a FROM that names a build ARG (`FROM ${X}` or
# `FROM $X`) resolves to that ARG's default in the same file. scanner/Dockerfile
# names each base this way so CI can substitute a mirror for the default (#106);
# the gate has to see THROUGH the variable, or every such file would read as
# unpinned and the ARG form would become a way past the check. An ARG with no
# default stays unresolved, and check_pins_offline reports it as such.
resolve_from_ref() {
  case "$2" in
    '${'*'}') name="${2#\${}"; name="${name%\}}" ;;
    '$'*)     name="${2#\$}" ;;
    *)        printf '%s\n' "$2"; return 0 ;;
  esac
  d=$(arg_default "$1" "$name")
  if [ -n "$d" ]; then printf '%s\n' "$d"; else printf '%s\n' "$2"; fi
}

from_refs_in() {
  file="$1"
  stages=$(sed -n 's/^FROM[[:space:]]\{1,\}[^[:space:]]\{1,\}[[:space:]]\{1,\}[Aa][Ss][[:space:]]\{1,\}\([^[:space:]]*\).*/\1/p' "$file")
  sed -n 's/^FROM[[:space:]]\{1,\}\([^[:space:]]*\).*/\1/p' "$file" | while IFS= read -r ref; do
    ref=$(resolve_from_ref "$file" "$ref")
    [ "$ref" = "scratch" ] && continue
    case "$ref" in yellowjack-*) continue ;; esac
    # a bare word naming an earlier stage in this same file
    if [ -n "$stages" ] && printf '%s\n' "$stages" | grep -qx "$ref"; then continue; fi
    printf '%s\n' "$ref"
  done
}

# dockerfiles — every Dockerfile git actually tracks.
#
# git ls-files rather than find: the working tree also holds sibling worktrees
# under .claude/ and CI runner leftovers under builds/, which carry stale copies
# of these same files. A find-based check sees 60+ Dockerfiles and would "fail"
# on files that are not in the repo at all.
dockerfiles() { git ls-files '*Dockerfile' | sort -u; }

# composefiles — every tracked compose file, AT ANY DEPTH.
#
# The leading '*' is load-bearing and was missing until the reference deployment was
# written. A git pathspec without it is anchored at the repo root, so
# 'docker-compose*.yml' matched the five files beside this script and silently missed
# deploy/reference/docker-compose.yml — a file that pulls two external images and is
# meant to be COPIED by evaluators. The comment above already claimed "every tracked
# compose file"; the glob is what now makes that true.
composefiles() { git ls-files '*docker-compose*.yml' '*docker-compose*.yaml' | sort -u; }

# image_refs_in FILE — the external images a compose file pulls.
#
# Same exclusion as from_refs_in for our own locally-built images: docker-compose.e2e.yml
# names `yellowjack-fakesmtp:e2e`, which is built by the rig itself and has no registry
# to pin against.
image_refs_in() {
  # No sed backreference here on purpose: the ref is extracted with shell parameter
  # expansion, which has no escaping layer to get wrong.
  grep -E '^[[:space:]]*image:[[:space:]]*[^[:space:]#]' "$1" 2>/dev/null | tr -d '\r' | while IFS= read -r line; do
    ref=${line#*image:}
    ref=${ref%%#*}
    ref=$(printf '%s' "$ref" | tr -d '[:space:]')
    case "$ref" in yellowjack-*|"") continue ;; esac
    printf '%s\n' "$ref"
  done
}

# check_pins_offline — the gate. Prints every violation, returns 1 if any.
# chartvalues — every tracked Helm values file. The chart is the file a Kubernetes shop
# installs and then keeps (#83), so an unpinned external image there is the same
# defect as one in a compose file: a tag is a mutable pointer, and the evaluator who
# installs next month gets something we never tested.
chartvalues() { git ls-files '*/helm/*/values.yaml' | sort -u; }

# chart_refs_in FILE — the external images a values file names, rendered as
# repository[:tag][@digest] from the `images:` block's repository/tag/digest keys.
#
# Our own images (repository yellowjack/...) are built by the operator from this repo
# and have no registry digest to pin against — the same exclusion the compose reader
# makes for yellowjack-*. Everything else must carry a digest. Read with awk rather
# than a YAML parser for the reason the compose reader uses grep: no dependency, and
# the shape is ours to keep simple (two-space keys under `images:`, four-space fields).
chart_refs_in() {
  awk '
    function flush() {
      if (repo != "" && repo !~ /^yellowjack\//) {
        ref = repo
        if (tag != "") ref = ref ":" tag
        if (dig != "") ref = ref "@" dig
        print ref
      }
      repo = ""; tag = ""; dig = ""
    }
    /^images:/             { inblock = 1; next }
    inblock && /^[^ ]/     { flush(); inblock = 0 }
    !inblock               { next }
    /^  [a-zA-Z0-9_-]+:/   { flush(); next }
    /^    repository:/     { repo = $2; gsub(/"/, "", repo) }
    /^    tag:/            { tag = $2; gsub(/"/, "", tag) }
    /^    digest:/         { dig = $2; gsub(/"/, "", dig) }
    END                    { flush() }
  ' "$1" 2>/dev/null | tr -d '\r'
}

check_pins_offline() {
  rc=0
  checked=0
  # Dockerfiles are walked by FROM, compose files by image:, chart values by the
  # images: block. Same assertions on all three — a mutable tag is a mutable tag
  # wherever it is written.
  for f in $(dockerfiles) $(composefiles) $(chartvalues); do
    [ -f "$f" ] || continue
    case "$f" in
      *docker-compose*) refs=$(image_refs_in "$f"); kw="image:" ;;
      */helm/*/values.yaml) refs=$(chart_refs_in "$f"); kw="images.<name>" ;;
      *) refs=$(from_refs_in "$f"); kw="FROM" ;;
    esac
    for ref in $refs; do
      checked=$((checked + 1))
      case "$ref" in
        *@sha256:*)
          # A digest with no tag pins the bytes but hides WHICH version they are,
          # so a reviewer cannot tell a patch bump from a major one.
          case "${ref%%@*}" in
            *:*) ;;
            *)
              printf '%s: %s %s is pinned but carries no tag\n' "$f" "$kw" "$ref"
              printf '    keep name:tag@sha256:... so a reviewer can see which version moved\n'
              rc=1 ;;
          esac ;;
        *)
          printf '%s: %s %s is not pinned by digest\n' "$f" "$kw" "$ref"
          case "$ref" in
            '$'*)
              printf '    the FROM names a build ARG with no pinned default in this file; give it one:\n'
              printf '      ARG %s=name:tag@sha256:...\n' "$(printf '%s' "${ref#\$}" | tr -d '{}')" ;;
            *) printf '    a tag is a mutable pointer; resolve one with:  sh scripts/dev.sh resolve %s\n' "$ref" ;;
          esac
          rc=1 ;;
      esac
    done
  done
  # ANTI-VACUITY. Every assertion above sits inside a loop; if dockerfiles() ever
  # returns nothing — a rename, a run from the wrong directory, a broken glob —
  # this function prints nothing and returns 0, which reads exactly like "all
  # images are pinned". The floor is well under the real count so an added
  # service does not have to touch this number, but well over zero.
  if [ "$checked" -lt 10 ]; then
    printf 'pinned-images: only %s external FROM references were examined, fewer than\n' "$checked"
    printf '    this repo has. The check found nothing because it looked at nothing.\n'
    return 1
  fi
  [ "$rc" -eq 0 ] && printf 'pinned-images: %s external base images, all pinned by digest\n' "$checked"
  return "$rc"
}

# resolve_image_digest REF — print name:tag@sha256:... for a tag.
#
# Always the digest the TAG resolves to, which for a multi-arch image is the
# index. See the arch-narrowing note at the top of this file.
resolve_image_digest() {
  ref="$1"
  case "$ref" in
    *@sha256:*) printf 'already pinned: %s\n' "$ref" >&2; return 1 ;;
    *:*) ;;
    *) printf 'refusing to resolve %s: no tag. Pin a version, not a moving target.\n' "$ref" >&2; return 1 ;;
  esac
  digest=$(docker buildx imagetools inspect "$ref" --format '{{.Manifest.Digest}}' 2>/dev/null)
  case "$digest" in
    sha256:*) ;;
    *) printf 'could not resolve %s (is docker running, and the registry reachable?)\n' "$ref" >&2; return 1 ;;
  esac
  media=$(docker buildx imagetools inspect "$ref" --format '{{.Manifest.MediaType}}' 2>/dev/null)
  case "$media" in
    *index*|*manifest.list*) ;;
    *)
      printf 'note: %s publishes a single-platform manifest, not an index.\n' "$ref" >&2
      printf '      Put "%s upstream publishes no index" above the FROM (or ARG) line that names it.\n' "$YJ_PIN_MARKER" >&2 ;;
  esac
  printf '%s@%s\n' "$ref" "$digest"
}

# pinned_refs — the unique pinned references across all tracked Dockerfiles.
#
# UNIQUE matters. `golang:1.26` appears in nine Dockerfiles; inspecting it nine
# times is nine registry round-trips for one answer, and doing exactly that is
# what produced `429 Too Many Requests` from Docker Hub on the first run of this
# function (2026-09-02) — the check broke itself on its own traffic.
pinned_refs() {
  for f in $(dockerfiles); do
    [ -f "$f" ] || continue
    from_refs_in "$f"
  done
  for f in $(composefiles); do
    [ -f "$f" ] || continue
    image_refs_in "$f"
  done
  for f in $(chartvalues); do
    [ -f "$f" ] || continue
    chart_refs_in "$f"
  done
}

# pinned_refs_unique — pinned_refs deduplicated, which is what callers want.
pinned_refs_unique() { pinned_refs | grep '@sha256:' | sort -u; }

# classify_pin REF — one of: index | single | unverified
#
# THE THREE-WAY SPLIT IS THE POINT. A registry that rate-limits us is not a
# finding about our Dockerfile, and reporting it as one is how a check trains
# people to ignore it. This is the same mistake in miniature that issue #106
# records against gcr.io: an unreachable registry took every MR red, and the
# useful sentence was "anonymous pull was withdrawn", not "the build is broken".
#
# Docker Hub returns 429 to unauthenticated clients after a modest number of
# manifest reads, so `unverified` is a routine outcome on a dev host, not an
# exotic one.
classify_pin() {
  out=$(docker buildx imagetools inspect "$1" --format '{{.Manifest.MediaType}}' 2>&1)
  case "$out" in
    *index*|*manifest.list*) printf 'index\n' ;;
    *manifest.v2*|*manifest.v1*) printf 'single\n' ;;
    *) printf 'unverified\n' ;;
  esac
}

# declared_single_platform REF — does some Dockerfile declare this ref as
# deliberately single-platform, on the line directly above the line that names
# it? That line is its FROM, or the `ARG X_BASE=` default a FROM resolves through;
# a pinned ref (name:tag@digest) appears nowhere else in a file, so matching the
# ref itself finds either form.
declared_single_platform() {
  for f in $(dockerfiles); do
    [ -f "$f" ] || continue
    if grep -B1 -F "$1" "$f" 2>/dev/null | grep -qF "$YJ_PIN_MARKER"; then return 0; fi
  done
  for f in $(composefiles); do
    [ -f "$f" ] || continue
    if grep -B1 -F "image: $1" "$f" 2>/dev/null | grep -qF "$YJ_PIN_MARKER"; then return 0; fi
  done
  return 1
}

# verify_pins_online — each pinned digest resolves, and is a multi-arch index
# unless the Dockerfile declares the image single-platform.
#
# Exit codes are deliberately three-valued, like classify_staleness:
#   0  every pin verified
#   1  a real defect — an undeclared single-platform pin
#   2  nothing was wrong, but not everything could be checked. NOT green.
verify_pins_online() {
  rc=0
  checked=0
  unverified=0
  for ref in $(pinned_refs_unique); do
    checked=$((checked + 1))
    name="${ref%%@*}"
    case "$(classify_pin "$ref")" in
      index) printf '  ok          %s (multi-arch index)\n' "$name" ;;
      single)
        if declared_single_platform "$ref"; then
          printf '  ok          %s (single-platform, declared)\n' "$name"
        else
          printf '  NARROWED    %s is pinned to a SINGLE PLATFORM with no declaration.\n' "$name"
          printf '              Every non-amd64 build fails, with an unrelated-looking error.\n'
          printf '              Re-resolve:  sh scripts/dev.sh resolve %s\n' "$name"
          printf '              or declare it on the line above the FROM (or ARG) that names it:\n'
          printf '                %s upstream publishes no index\n' "$YJ_PIN_MARKER"
          rc=1
        fi ;;
      unverified)
        printf '  unverified  %s (registry unreachable or rate-limited — NOT a finding)\n' "$name"
        unverified=$((unverified + 1)) ;;
    esac
  done
  # Anti-vacuity: with no refs the loop prints nothing and rc stays 0.
  if [ "$checked" -lt 4 ]; then
    printf 'pinned-images: only %s pinned references examined — the check looked at nothing.\n' "$checked"
    return 1
  fi
  if [ "$rc" -ne 0 ]; then
    printf '\npinned-images: %s of %s references are narrowed to one platform.\n' "$rc" "$checked"
    return 1
  fi
  if [ "$unverified" -gt 0 ]; then
    printf '\npinned-images: %s of %s references could NOT be checked (registry limits).\n' "$unverified" "$checked"
    printf '    Nothing is known to be wrong, and nothing is proven right. Re-run later, or\n'
    printf '    `docker login` to raise the anonymous pull ceiling.\n'
    return 2
  fi
  printf '\npinned-images: all %s pinned references verified.\n' "$checked"
  return 0
}
