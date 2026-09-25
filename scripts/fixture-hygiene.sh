#!/bin/sh
# fixture-hygiene.sh — no test fixture names a live host (issue #46).
#
# ── WHY ──────────────────────────────────────────────────────────────────────
#
# We keep attack-shaped fixtures on purpose: e2e/fakeupstream* is a registry that
# lies about a package's source repo, e2e/malicious-corpus reproduces the static shape
# of real malware. The liability that comes with them is not hypothetical. A GDATA
# malware analyst filed DataDog/guarddog#766 because that project's test files
# "download and run malware from existing threat actor infrastructure" — samples a
# maintainer had added two years earlier, shipped to every user since, found by an
# outsider. Their own reply: "we should have defanged them nevertheless."
#
# For security software that is a credibility event, not a tidiness one, and it has a
# two-year fuse: nobody re-reads a fixture. So the rule is mechanical.
#
# ── THE RULE ─────────────────────────────────────────────────────────────────
#
# Every host a fixture DATA file names is one of:
#   defanged   *.invalid, *.example, *.test, *.localhost, localhost, example.com/net/org
#              (RFC 2606/6761 — reserved, never resolvable)
#   private    RFC 1918, loopback, link-local, RFC 5737 documentation ranges, 0.0.0.0
#   local      a single-label name (a compose service: fakeupstream, firewall) — no
#              public DNS can resolve it
#   listed     in e2e/fixture-hosts.txt WITH a reason — the explicitly-documented
#              sentinel the issue allows (the borrow-a-score fixtures must name real
#              GitHub repos, because deps.dev's record of them is what contradicts the lie)
# Anything else is a LIVE host and the check fails, naming the file and the two fixes.
#
# A listed host that no fixture uses any more is also a failure: an allowlist that
# accumulates is an allowlist nobody reads.
#
# Scope is DATA files under the fixture roots — *.md and *.sh are excluded, because a
# README that cites guarddog#766 and a runner that pulls a scanner image are not
# fixtures. The other half of #46 — the shipped images contain no fixture at all — needs
# the images built, so it lives in e2e/hardening.sh (leg 1b).
#
# Sourced by scripts/dev.sh vet (offline, no network) and by its own test.

set -u

# THE ROOT LIST IS THE SCOPE, AND AN INCOMPLETE ONE IS THE SILENT FAILURE.
# The anti-vacuity floor below catches "looked at nothing"; it cannot catch "looked at
# four of six fixture trees", because the count still clears the floor. So this list is
# every tracked directory under e2e/ (plus testdata/) that holds fixture DATA rather than
# rig code — verified by walking the tree when it was written, not by memory:
#   fakeupstream, fakeupstream-maven  a registry that lies about a package's source repo
#   malicious-corpus                  synthetic samples shaped like real malware
#   malware-feed-fixture              OSV malicious-package advisories the feed loader reads
#   feed-fetch-fixture                a SIGNED snapshot the gate pulls in the hardening rig (#157)
#   operator-lists                    allow/deny list fixtures
#   registryfront                     the in-front/behind rig's proxy + registry config
#   testdata                          the shared operator-list line corpus
# Directories holding only .go/Dockerfile/.sh (fakedns, fakescanner, fakesmtp, mitmproxy,
# credupstream) are rig code and are excluded by the file filter below anyway.
: "${YJ_FIXTURE_ROOTS:=e2e/fakeupstream e2e/fakeupstream-maven e2e/malicious-corpus e2e/malware-feed-fixture e2e/feed-fetch-fixture e2e/operator-lists e2e/registryfront testdata}"
: "${YJ_FIXTURE_ALLOWLIST:=e2e/fixture-hosts.txt}"

# Public TLDs a bare (scheme-less) hostname is recognised by. Deliberately a list, not
# "anything with a dot": version strings, file names and JSON keys all contain dots.
# `sh` and `py`/`js` are absent on purpose (setup.py, collect.js); a payload host on
# .sh would still be caught by its URL form.
YJ_TLDS='com|net|org|io|dev|co|cc|ru|cn|xyz|info|top|site|online|club|pw|su|tk|ml|ga|cf|gq|to|me|app|ly|gg|link|click|onion|biz|tv|in|us|uk|de|fr|nl|eu|ai|so|cloud|host|pro|live'

# fixture_files — the DATA files git tracks under the fixture roots. The allowlist
# itself is excluded wherever it lives: scanned as a fixture it would list every host
# it names as "used", and a stale entry could never be detected.
fixture_files() {
  for r in $YJ_FIXTURE_ROOTS; do
    git ls-files "$r" 2>/dev/null
  done | grep -v '\.md$' | grep -v '\.sh$' | grep -vx "$YJ_FIXTURE_ALLOWLIST"
}

# hosts_in FILE — every candidate host FILE names, one per line, deduplicated.
#   1. the host of every http(s) URL (scheme, userinfo and port stripped)
#   2. every bare name ending in a public TLD
#   3. every IPv4 literal
hosts_in() {
  {
    grep -oE 'https?://[^/"'"'"' <>)]+' "$1" 2>/dev/null | sed -E 's|^https?://||; s|^[^@]*@||; s|:[0-9]+$||'
    grep -oiE "([a-z0-9]([a-z0-9-]*[a-z0-9])?\.)+($YJ_TLDS)([^a-z0-9.-]|\$)" "$1" 2>/dev/null | sed 's/[^a-zA-Z0-9.-]$//'
    grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' "$1" 2>/dev/null
  } | tr 'A-Z' 'a-z' | tr -d '\r' | grep -v '^$' | sort -u
}

# listed_hosts — the allowlist's hosts (first field of every non-comment line).
listed_hosts() {
  [ -f "$YJ_FIXTURE_ALLOWLIST" ] || return 0
  tr -d '\r' < "$YJ_FIXTURE_ALLOWLIST" | grep -v '^[[:space:]]*#' | grep -v '^[[:space:]]*$' | awk '{print tolower($1)}'
}

# classify_host HOST — defanged | private | local | listed | live
classify_host() {
  h="$1"
  case "$h" in
    *'$'*|*'{'*|*'}'*|*'%'*) printf 'local\n'; return ;;   # a template variable, not a host
  esac
  case "$h" in
    localhost|*.localhost|*.invalid|*.example|*.test|example.com|*.example.com|example.net|*.example.net|example.org|*.example.org)
      printf 'defanged\n'; return ;;
  esac
  case "$h" in
    [0-9]*.[0-9]*.[0-9]*.[0-9]*)
      case "$h" in
        127.*|10.*|192.168.*|169.254.*|0.0.0.0|255.255.255.255|192.0.2.*|198.51.100.*|203.0.113.*)
          printf 'private\n'; return ;;
        172.1[6-9].*|172.2[0-9].*|172.3[01].*)
          printf 'private\n'; return ;;
      esac
      printf 'live\n'; return ;;
  esac
  case "$h" in
    *.*) ;;
    *) printf 'local\n'; return ;;
  esac
  if listed_hosts | grep -qx "$h"; then printf 'listed\n'; return; fi
  printf 'live\n'
}

# check_fixture_hygiene — the gate. Prints every violation, returns 1 if any.
check_fixture_hygiene() {
  rc=0
  files=0
  hosts=0
  used_listed=""
  for f in $(fixture_files); do
    [ -f "$f" ] || continue
    files=$((files + 1))
    for h in $(hosts_in "$f"); do
      hosts=$((hosts + 1))
      case "$(classify_host "$h")" in
        live)
          printf '%s: names a LIVE host: %s\n' "$f" "$h"
          printf '    a fixture must not point at anything resolvable. Either defang it (.invalid / .example /\n'
          printf '    RFC 5737 address) or, if the test needs the real name, list it in %s with a reason.\n' "$YJ_FIXTURE_ALLOWLIST"
          rc=1 ;;
        listed) used_listed="$used_listed $h" ;;
      esac
    done
  done
  # ANTI-VACUITY. Every assertion above sits inside a loop over git-tracked files; a
  # rename, a run from the wrong directory or a broken root list makes it print
  # nothing and return 0, which reads exactly like "all fixtures are defanged".
  if [ "$files" -lt 8 ]; then
    printf 'fixture-hygiene: only %s fixture files were examined under [%s], fewer than this repo has.\n' "$files" "$YJ_FIXTURE_ROOTS"
    printf '    The check found nothing because it looked at nothing.\n'
    return 1
  fi
  # The allowlist must document, not merely permit: every entry carries a reason, and
  # every entry is still used by some fixture.
  if [ -f "$YJ_FIXTURE_ALLOWLIST" ]; then
    tr -d '\r' < "$YJ_FIXTURE_ALLOWLIST" | grep -v '^[[:space:]]*#' | grep -v '^[[:space:]]*$' | while IFS= read -r line; do
      host=$(printf '%s' "$line" | awk '{print tolower($1)}')
      case "$line" in
        *'#'*) ;;
        *)
          printf '%s: %s is listed without a reason. A sentinel is only allowed when it is documented — add "  # why".\n' "$YJ_FIXTURE_ALLOWLIST" "$host"
          printf 'VIOLATION\n' ;;
      esac
      case " $used_listed " in
        *" $host "*) ;;
        *)
          printf '%s: %s appears in no fixture any more; remove it. An allowlist that accumulates is one nobody reads.\n' "$YJ_FIXTURE_ALLOWLIST" "$host"
          printf 'VIOLATION\n' ;;
      esac
    done > "${TMPDIR:-/tmp}/fixture-hygiene.$$"
    if grep -q '^VIOLATION$' "${TMPDIR:-/tmp}/fixture-hygiene.$$"; then
      grep -v '^VIOLATION$' "${TMPDIR:-/tmp}/fixture-hygiene.$$"
      rc=1
    fi
    rm -f "${TMPDIR:-/tmp}/fixture-hygiene.$$"
  fi
  [ "$rc" -eq 0 ] && printf 'fixture-hygiene: %s fixture files, %s host references, none live\n' "$files" "$hosts"
  return "$rc"
}
