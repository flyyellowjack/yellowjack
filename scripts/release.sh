#!/bin/sh
# release.sh -- build and publish one tagged release: the three images the chart deploys,
# pinned by digest in the chart that is published beside them (D358).
#
#   sh scripts/release.sh check  vX.Y.Z   the tag is semver and CHANGELOG + Chart agree with it
#   sh scripts/release.sh images vX.Y.Z   build firewall/approval/console (FIPS, multi-arch), push,
#                                         write each digest to $OUT/digests.env
#   sh scripts/release.sh chart  vX.Y.Z   package the chart with those digests and push it
#   sh scripts/release.sh notes  vX.Y.Z   print this version's CHANGELOG section
#   sh scripts/release.sh values vX.Y.Z FILE   rewrite FILE's three image blocks from
#                                         $OUT/digests.env (what `chart` does to its copy)
#
# Environment:
#   REGISTRY   where images and the chart go, e.g. ghcr.io/flyyellowjack (required for images/chart)
#   PLATFORMS  default linux/amd64,linux/arm64
#   OUT        scratch directory, default ./release-out
#   INSECURE   set to 1 for a plain-HTTP registry (a local registry:2 in a dry run only)
#
# Everything a release does is in this file, so it can be run end to end against a local
# registry before anything is tagged. The GitHub workflow only calls it.
set -eu

CMD=${1:-}; TAG=${2:-}
PLATFORMS=${PLATFORMS:-linux/amd64,linux/arm64}
OUT=${OUT:-release-out}
CHART_DIR=deploy/helm/yellowjack
# Image name in the registry -> Dockerfile. The chart's values keys are the same words.
IMAGES="firewall:Dockerfile approval:approval/Dockerfile console:console/Dockerfile"

die() { echo "release: $*" >&2; exit 1; }

version_of() {
  case "$1" in
    v[0-9]*.[0-9]*.[0-9]*) ;;
    *) die "tag '$1' is not vMAJOR.MINOR.PATCH" ;;
  esac
  v=${1#v}
  # Only digits and two dots: no pre-release suffix on a published line yet.
  printf '%s' "$v" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+$' || die "tag '$1' is not vMAJOR.MINOR.PATCH"
  printf '%s' "$v"
}

check() {
  v=$(version_of "$TAG")
  grep -Eq "^## \[$v\]" CHANGELOG.md || die "CHANGELOG.md has no '## [$v]' section: a release nobody wrote down"
  grep -Eq "^appVersion: \"?$v\"?\$" "$CHART_DIR/Chart.yaml" || die "$CHART_DIR/Chart.yaml appVersion is not $v"
  grep -Eq "^version: $v\$" "$CHART_DIR/Chart.yaml" || die "$CHART_DIR/Chart.yaml version is not $v"
  echo "release: $TAG agrees with CHANGELOG.md and the chart"
}

images() {
  v=$(version_of "$TAG")
  : "${REGISTRY:?set REGISTRY, e.g. ghcr.io/flyyellowjack}"
  mkdir -p "$OUT"
  : > "$OUT/digests.env"
  src=$(git config --get remote.origin.url 2>/dev/null || echo "")
  for spec in $IMAGES; do
    name=${spec%%:*}; file=${spec#*:}
    ref="$REGISTRY/yellowjack-$name:$v"
    out="type=image,name=$ref,push=true"
    [ "${INSECURE:-}" = 1 ] && out="$out,registry.insecure=true"
    echo "release: building $ref ($PLATFORMS) from $file"
    # GOFIPS140 is the Dockerfile's own default (v1.0.0, the certified module); it is passed
    # explicitly so a release can never inherit an override from the environment.
    docker buildx build --platform "$PLATFORMS" -f "$file" \
      --build-arg GOFIPS140=v1.0.0 \
      --label "org.opencontainers.image.source=${SOURCE_URL:-$src}" \
      --label "org.opencontainers.image.version=$v" \
      --provenance=false \
      --metadata-file "$OUT/$name.json" \
      --output "$out" .
    digest=$(sed -n 's/.*"containerimage.digest"[[:space:]]*:[[:space:]]*"\(sha256:[0-9a-f]\{64\}\)".*/\1/p' "$OUT/$name.json" | head -n 1)
    [ -n "$digest" ] || die "no digest for $ref in $OUT/$name.json"
    echo "$name=$digest" >> "$OUT/digests.env"
    echo "release: $ref@$digest"
  done
}

chart() {
  v=$(version_of "$TAG")
  : "${REGISTRY:?set REGISTRY}"
  [ -s "$OUT/digests.env" ] || die "$OUT/digests.env is missing: run 'images' first"
  work="$OUT/chart"
  rm -rf "$work"; mkdir -p "$work"
  cp -R "$CHART_DIR" "$work/yellowjack"
  rewrite_values "$work/yellowjack/values.yaml"
  helm package "$work/yellowjack" --destination "$work" >/dev/null
  pkg="$work/yellowjack-$v.tgz"
  [ -f "$pkg" ] || die "helm package did not produce $pkg"
  flag=""
  [ "${INSECURE:-}" = 1 ] && flag="--plain-http"
  helm push "$pkg" "oci://$REGISTRY/charts" $flag
  echo "release: chart oci://$REGISTRY/charts/yellowjack:$v"
}

# rewrite_values FILE -- point FILE's firewall/approval/console blocks at the published
# images, by tag AND digest. Applied to the PACKAGED copy only: the source chart keeps
# building from source (yellowjack/*:dev), and the published chart names what was published,
# so a reviewer can read the tag and the cluster pulls the digest.
rewrite_values() {
  v=$(version_of "$TAG")
  : "${REGISTRY:?set REGISTRY}"
  values="$1"
  [ -s "$OUT/digests.env" ] || die "$OUT/digests.env is missing: run 'images' first"
  # LF only. A Windows checkout (or `git archive` from one) carries CRLF, and the exact-line
  # match below would then match nothing and fail the release -- measured in the rehearsal.
  tr -d '\r' < "$values" > "$values.lf" && mv "$values.lf" "$values"
  for spec in $IMAGES; do
    name=${spec%%:*}
    digest=$(tr -d '\r' < "$OUT/digests.env" | sed -n "s/^$name=//p")
    [ -n "$digest" ] || die "no digest recorded for $name"
    awk -v key="  $name:" -v repo="$REGISTRY/yellowjack-$name" -v tag="$v" -v dig="$digest" '
      $0 == key { print; inblk=1; next }
      inblk && /^    repository:/ { print "    repository: " repo; next }
      inblk && /^    tag:/        { print "    tag: \"" tag "\""; next }
      inblk && /^    digest:/     { print "    digest: \"" dig "\""; inblk=0; next }
      { print }' "$values" > "$values.tmp" && mv "$values.tmp" "$values"
    grep -q "repository: $REGISTRY/yellowjack-$name\$" "$values" || die "values rewrite missed $name"
    grep -q "digest: \"$digest\"" "$values" || die "values rewrite missed $name's digest"
  done
}

notes() {
  v=$(version_of "$TAG")
  awk -v hdr="## [$v]" '
    index($0, hdr) == 1 { on=1; next }
    on && /^## \[/ { exit }
    on { print }' CHANGELOG.md
}

case "$CMD" in
  check) check ;;
  images) images ;;
  chart) chart ;;
  notes) notes ;;
  values) rewrite_values "${3:?usage: release.sh values vX.Y.Z FILE}" ;;
  *) die "usage: release.sh check|images|chart|notes vX.Y.Z" ;;
esac
