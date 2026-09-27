#!/bin/sh
# release_test.sh -- the parts of scripts/release.sh that decide WHAT gets published, tested
# without a registry: the tag grammar, the CHANGELOG/chart agreement, the release notes, and
# the rewrite that pins the published chart to the published image digests. Each check has a
# control that must fail, so a release.sh that stopped checking anything would be caught.
set -u
ROOT=$(cd "$(dirname "$0")/.." && pwd)
PASS=0; FAIL=0
ok()  { PASS=$((PASS+1)); echo "ok   $*"; }
bad() { FAIL=$((FAIL+1)); echo "FAIL $*"; }
TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT

# A scratch tree shaped like the repository: CHANGELOG.md, the chart, the script.
mk() {
  d="$TMP/$1"; mkdir -p "$d/deploy/helm/yellowjack" "$d/scripts"
  cp "$ROOT/scripts/release.sh" "$d/scripts/"
  cp "$ROOT/deploy/helm/yellowjack/values.yaml" "$d/deploy/helm/yellowjack/"
  printf 'apiVersion: v2\nname: yellowjack\nversion: %s\nappVersion: "%s"\n' "$2" "$2" > "$d/deploy/helm/yellowjack/Chart.yaml"
  printf '# Changelog\n\n## [Unreleased]\n\n## [%s] - 2026-09-27\n\nThe first release.\n\n## [0.0.9] - 2026-01-01\n\nOlder.\n' "$3" > "$d/CHANGELOG.md"
  echo "$d"
}
run() { ( cd "$1" && shift && sh scripts/release.sh "$@" ) > "$TMP/out" 2>&1; echo $?; }

# 1. the tag grammar
d=$(mk grammar 1.2.3 1.2.3)
for t in v1.2.3 v10.0.12; do
  [ "$(run "$d" notes "$t")" = 0 ] && ok "tag $t is accepted" || bad "tag $t was refused: $(cat "$TMP/out")"
done
for t in 1.2.3 v1.2 v1.2.3-rc1 vx.y.z ""; do
  [ "$(run "$d" notes "$t")" != 0 ] && ok "tag '$t' is refused" || bad "tag '$t' was accepted"
done

# 2. check: the tag must agree with CHANGELOG.md and the chart
d=$(mk agree 1.2.3 1.2.3)
[ "$(run "$d" check v1.2.3)" = 0 ] && ok "check passes when CHANGELOG and chart both say 1.2.3" || bad "check refused an agreeing tree: $(cat "$TMP/out")"
d=$(mk nochangelog 1.2.3 1.2.4)
rc=$(run "$d" check v1.2.3)
[ "$rc" != 0 ] && grep -q "no '## \[1.2.3\]' section" "$TMP/out" && ok "check refuses a tag with no CHANGELOG section" || bad "a tag with no CHANGELOG section passed check: $(cat "$TMP/out")"
d=$(mk chartskew 1.2.2 1.2.3)
rc=$(run "$d" check v1.2.3)
[ "$rc" != 0 ] && grep -q "appVersion is not 1.2.3" "$TMP/out" && ok "check refuses a chart whose appVersion disagrees" || bad "a disagreeing chart passed check: $(cat "$TMP/out")"

# 3. notes: exactly this version's section, nothing from the next one
d=$(mk notes 1.2.3 1.2.3)
run "$d" notes v1.2.3 >/dev/null
if grep -q "The first release." "$TMP/out" && ! grep -q "Older." "$TMP/out"; then
  ok "notes prints this version's section and stops at the next"
else
  bad "notes printed the wrong text: $(cat "$TMP/out")"
fi

# 4. values: the three published images, by tag AND digest; CRLF input; postgres untouched
d=$(mk values 1.2.3 1.2.3)
mkdir -p "$d/out"
printf 'firewall=sha256:%s\r\napproval=sha256:%s\r\nconsole=sha256:%s\r\n' \
  "$(printf 'a%.0s' $(seq 64))" "$(printf 'b%.0s' $(seq 64))" "$(printf 'c%.0s' $(seq 64))" > "$d/out/digests.env"
v="$d/deploy/helm/yellowjack/values.yaml"
awk '{ printf "%s\r\n", $0 }' "$v" > "$v.crlf" && mv "$v.crlf" "$v"
rc=$( cd "$d" && OUT=out REGISTRY=ghcr.io/example sh scripts/release.sh values v1.2.3 "$v" > "$TMP/out" 2>&1; echo $? )
if [ "$rc" = 0 ] \
  && grep -q '^    repository: ghcr.io/example/yellowjack-firewall$' "$v" \
  && grep -q '^    repository: ghcr.io/example/yellowjack-console$' "$v" \
  && [ "$(grep -c '^    tag: "1.2.3"$' "$v")" = 3 ] \
  && grep -q "digest: \"sha256:$(printf 'b%.0s' $(seq 64))\"" "$v" \
  && grep -q 'repository: postgres' "$v" && grep -q 'tag: "17"' "$v"; then
  ok "values pins all three images by tag and digest from a CRLF file, and leaves postgres alone"
else
  bad "values rewrite is wrong (rc=$rc): $(cat "$TMP/out"); $(grep -n -A3 '^  [a-z]*:$' "$v" | head -20)"
fi
# control: a digest missing for one image must refuse, not publish a half-pinned chart
d=$(mk missing 1.2.3 1.2.3); mkdir -p "$d/out"
printf 'firewall=sha256:%s\n' "$(printf 'a%.0s' $(seq 64))" > "$d/out/digests.env"
rc=$( cd "$d" && OUT=out REGISTRY=ghcr.io/example sh scripts/release.sh values v1.2.3 deploy/helm/yellowjack/values.yaml > "$TMP/out" 2>&1; echo $? )
[ "$rc" != 0 ] && grep -q "no digest recorded for approval" "$TMP/out" && ok "a missing digest refuses the chart instead of half-pinning it" || bad "a half-pinned chart was produced: $(cat "$TMP/out")"

printf '\n%s passed, %s failed\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
