#!/bin/sh
# Tests for scripts/fixture-hygiene.sh.
#
# A "no live hosts in fixtures" check has the classic shape that degrades into a
# no-op: it walks a file list and reports "nothing found". So the cases that matter
# are the refusals — a live URL, a bare payload domain, a public IP, an allowlist
# entry with no reason, a stale allowlist entry, and an EMPTY fixture root — each
# proven to go red, beside the clean cases proven to stay green.
set -u

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
. "$ROOT/scripts/fixture-hygiene.sh"

PASS=0
FAIL=0
ok()  { PASS=$((PASS + 1)); printf 'ok   %s\n' "$1"; }
bad() { FAIL=$((FAIL + 1)); printf 'FAIL %s\n' "$1"; }

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

# scratch_repo NAME — a git repo with a fixture root `fx/` holding 9 clean data files
# (over the anti-vacuity floor), so a case can add exactly one thing and attribute the
# outcome to it. Clean means: defanged hosts, a private IP, a single-label service
# name, and dotted things that are NOT hosts (versions, file names).
scratch_repo() {
  d="$TMP/$1"
  mkdir -p "$d/fx/pkg"
  (
    cd "$d" || exit 1
    git init -q .
    printf '{"dist":{"tarball":"http://fakeupstream:8000/lodash/-/lodash-4.17.21.tgz"},"version":"4.17.21"}\n' > fx/pkg/latest
    printf 'fetch("https://example.invalid/collect")\n' > fx/pkg/collect.js
    printf 'url = "http://203.0.113.7/beacon"\n' > fx/pkg/setup.py
    printf 'server 127.0.0.1; proxy_pass http://$upstream;\n' > fx/pkg/nginx.conf
    printf '<project><version>33.6.0-jre</version></project>\n' > fx/pkg/pom.xml
    printf 'name\tregistry.example.com\n' > fx/pkg/lines.tsv
    printf 'see README.md and index.js and setup.py\n' > fx/pkg/notes.txt
    printf '{"name":"clean-control","main":"index.js"}\n' > fx/pkg/package.json
    printf 'module.exports = 1;\n' > fx/pkg/index.js
    git add -A >/dev/null 2>&1
  )
  printf '%s\n' "$d"
}

# run_check DIR [ALLOWLIST] — check_fixture_hygiene inside DIR against root fx/.
run_check() {
  ( cd "$1" && YJ_FIXTURE_ROOTS="fx" YJ_FIXTURE_ALLOWLIST="${2:-fx/hosts.txt}" check_fixture_hygiene >"$TMP/out" 2>&1; echo $? )
}

# ── 1. the happy path ────────────────────────────────────────────────────────
d=$(scratch_repo clean)
rc=$(run_check "$d")
if [ "$rc" = "0" ] && grep -q 'none live' "$TMP/out"; then ok "clean fixtures pass: defanged, private, single-label, and dotted non-hosts"; else
  bad "clean fixtures were rejected: $(cat "$TMP/out")"; fi

# ── 2. ANTI-VACUITY FOR 1: the parser really extracts hosts ──────────────────
got=$(hosts_in "$d/fx/pkg/latest" | tr '\n' ' ')
case "$got" in
  *fakeupstream*) ok "hosts_in really reads URLs (got: $got)" ;;
  *) bad "hosts_in returned '$got' — case 1 passed because it parsed nothing" ;;
esac

# ── 3. NEGATIVE CONTROL: a live URL must fail, and the message must name it ──
d=$(scratch_repo liveurl)
printf 'fetch("https://c2.payload-host.ru/x")\n' > "$d/fx/pkg/collect.js"
( cd "$d" && git add -A >/dev/null 2>&1 )
rc=$(run_check "$d")
if [ "$rc" != "0" ] && grep -q 'fx/pkg/collect.js: names a LIVE host: c2.payload-host.ru' "$TMP/out" && grep -q 'defang it' "$TMP/out"; then
  ok "a live URL is caught, with the file, the host, and the fix"
else
  bad "a live URL passed, or was misreported: $(cat "$TMP/out")"
fi

# ── 4. NEGATIVE CONTROL: a bare payload domain (no scheme) must fail ─────────
d=$(scratch_repo bare)
printf 'const host = "update.evil-cdn.xyz";\n' > "$d/fx/pkg/index.js"
( cd "$d" && git add -A >/dev/null 2>&1 )
rc=$(run_check "$d")
if [ "$rc" != "0" ] && grep -q 'LIVE host: update.evil-cdn.xyz' "$TMP/out"; then
  ok "a bare domain without a scheme is caught"
else
  bad "a bare payload domain passed: $(cat "$TMP/out")"
fi

# ── 5. NEGATIVE CONTROL: a public IP literal fails; a documentation address passes ──
d=$(scratch_repo pubip)
printf 'url = "http://45.33.32.156/beacon"\n' > "$d/fx/pkg/setup.py"
( cd "$d" && git add -A >/dev/null 2>&1 )
rc=$(run_check "$d")
if [ "$rc" != "0" ] && grep -q 'LIVE host: 45.33.32.156' "$TMP/out"; then
  ok "a public IP literal is caught (203.0.113.7 in the clean set passes as RFC 5737)"
else
  bad "a public IP literal passed: $(cat "$TMP/out")"
fi

# ── 6. a listed host WITH a reason passes ────────────────────────────────────
d=$(scratch_repo listed)
printf '{"repository":"github.com/lodash/lodash"}\n' > "$d/fx/pkg/latest"
printf '# hosts a fixture may name\ngithub.com   # the borrow-a-score claim must name a real repo\n' > "$d/fx/hosts.txt"
( cd "$d" && git add -A >/dev/null 2>&1 )
rc=$(run_check "$d")
if [ "$rc" = "0" ]; then ok "a documented sentinel host passes"; else
  bad "a documented sentinel was rejected: $(cat "$TMP/out")"; fi

# ── 7. NEGATIVE CONTROL: the same host WITHOUT the allowlist fails ───────────
rm -f "$d/fx/hosts.txt"
( cd "$d" && git add -A >/dev/null 2>&1 )
rc=$(run_check "$d")
if [ "$rc" != "0" ] && grep -q 'LIVE host: github.com' "$TMP/out"; then
  ok "the same host is refused once it is no longer listed (the allowlist is load-bearing)"
else
  bad "an unlisted real host passed: $(cat "$TMP/out")"
fi

# ── 8. NEGATIVE CONTROL: a listed host with NO reason is not 'documented' ────
printf 'github.com\n' > "$d/fx/hosts.txt"
( cd "$d" && git add -A >/dev/null 2>&1 )
rc=$(run_check "$d")
if [ "$rc" != "0" ] && grep -q 'listed without a reason' "$TMP/out"; then
  ok "an allowlist entry without a reason is refused"
else
  bad "an undocumented allowlist entry passed: $(cat "$TMP/out")"
fi

# ── 9. NEGATIVE CONTROL: a stale allowlist entry fails ───────────────────────
printf 'github.com   # the claim\nold-mirror.example-cdn.net   # nothing uses this any more\n' > "$d/fx/hosts.txt"
( cd "$d" && git add -A >/dev/null 2>&1 )
rc=$(run_check "$d")
if [ "$rc" != "0" ] && grep -q 'old-mirror.example-cdn.net appears in no fixture' "$TMP/out"; then
  ok "a stale allowlist entry is refused, so the list cannot accumulate"
else
  bad "a stale allowlist entry passed: $(cat "$TMP/out")"
fi

# ── 10. THE VACUITY CONTROL: an empty fixture root must FAIL ─────────────────
d="$TMP/empty"
mkdir -p "$d/fx"
( cd "$d" && git init -q . )
rc=$(run_check "$d")
if [ "$rc" != "0" ] && grep -q 'looked at nothing' "$TMP/out"; then
  ok "an empty fixture root FAILS rather than reporting every fixture defanged"
else
  bad "an empty root reported success — the check cannot tell 'all defanged' from 'nothing examined'"
fi

# ── 11. scope: *.md and *.sh under the roots are not fixtures ────────────────
d=$(scratch_repo scope)
printf 'cites https://github.com/DataDog/guarddog/issues/766\n' > "$d/fx/README.md"
printf 'docker run ghcr.io/some/scanner:latest\n' > "$d/fx/run.sh"
( cd "$d" && git add -A >/dev/null 2>&1 )
rc=$(run_check "$d")
if [ "$rc" = "0" ]; then ok "a README citing a real URL and a runner pulling an image are out of scope, as documented"; else
  bad "a doc or runner under the root was treated as a fixture: $(cat "$TMP/out")"; fi

# ── 12. the real repo is what CI will actually check ─────────────────────────
rc=$( cd "$ROOT" && check_fixture_hygiene >"$TMP/out" 2>&1; echo $? )
if [ "$rc" = "0" ]; then
  ok "this repo passes: $(cat "$TMP/out")"
else
  bad "this repo does not pass its own fixture-hygiene gate:"; cat "$TMP/out"
fi
# and its allowlist is really consulted: every listed host is one some fixture names
n=$(cd "$ROOT" && listed_hosts | wc -l | tr -d ' ')
if [ "$n" -ge 1 ]; then ok "the repo's allowlist has $n documented sentinel(s), each checked against the fixtures above"; else
  bad "the repo's allowlist is empty or unreadable — the sentinel mechanism is untested against real fixtures"; fi

printf '\n%s passed, %s failed\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
