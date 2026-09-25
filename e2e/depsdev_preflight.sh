#!/usr/bin/env bash
# deps.dev preflight for the local-mode e2e rigs.
#
# WHY THIS EXISTS
#
# `verify_repo_local.sh` (and, for lodash, `async_local.sh`) verify against the REAL
# api.deps.dev on purpose: the rig fakes only the half a publisher controls (the upstream
# registry's repo claim) and keeps the independent record authentic. Faking deps.dev too
# would test our own mock instead of the cross-check.
#
# That deliberate choice makes the rigs depend on something outside the repo, in two ways
# that both fail as a RED REQUIRED GATE while meaning "nothing is wrong with the firewall":
#
#   1. RATE LIMITING. On a shared CI runner IP, deps.dev can answer 429. The firewall
#      correctly treats that as TRANSIENT (a retryable 503, never a verdict) — but the
#      legs assert a BLOCK, so they fail. Diagnosing that from a leg failure means reading
#      a compose log and knowing the D25/D36 transient-vs-durable split.
#   2. PREMISE DRIFT. The legs assume specific deps.dev records: that it HAS a source-repo
#      record for lodash/left-pad/six/certifi/guava (so the crafted lie can be
#      contradicted), and that it has NO record at all for `yj-unverifiable-d36` (leg G's
#      whole point — D36's durably-unverified path). If deps.dev's data moves, or if
#      someone ever publishes that name to npm, a leg breaks — or worse, leg G silently
#      starts testing a different thing.
#
# So this runs BEFORE the legs and names the real cause, instead of leaving a human to
# infer it from a failed assertion. It is the "preflight that names the real problem"
# rule from CLAUDE.md, applied to the one dependency these rigs cannot control.
#
# It deliberately does NOT re-verify the package->repo MAPPING: that mapping is what the
# rigs themselves assert, and duplicating an assertion inside its own preflight would let
# the preflight mask the failure it exists to explain.
#
# USAGE
#   bash e2e/depsdev_preflight.sh [profile]   # profile: verifyrepo (default) | async
#   DEPSDEV_BASE=http://127.0.0.1:9 bash e2e/depsdev_preflight.sh   # point at a fake
#
# The profile selects which premises to check, so each rig is told about the records IT
# depends on and messages name real legs. `async` only pulls lodash.
#
# EXIT CODES (distinct on purpose — a caller, or a human reading CI, can tell these apart)
#   0  usable
#   3  rate limited            -> environmental, NOT a firewall regression
#   4  premise drift           -> the rig's assumptions about deps.dev data are stale
#   5  unreachable             -> network/DNS, NOT a firewall regression
set -uo pipefail

PROFILE="${1:-verifyrepo}"
DEPSDEV_BASE="${DEPSDEV_BASE:-https://api.deps.dev}"
# Same UA the firewall sends. Public APIs/CDNs reject generic agents (the original
# Phase-2 403), so probing with curl's default would test a different request than the
# one the firewall actually makes.
UA="yellowjack-e2e-preflight"

# Packages the legs need deps.dev to KNOW (system, path-escaped name, which leg), and
# packages they need it to NOT know. Leg G (D36) proves that a name with NO deps.dev
# record at all is a DURABLE negative and fails closed; if that name ever gets published,
# the leg keeps passing while testing something else entirely.
case "$PROFILE" in
  verifyrepo)
    MUST_EXIST="
npm|lodash|A (npm borrow)
npm|left-pad|B (npm honest)
pypi|six|C (pypi borrow)
pypi|certifi|D (pypi honest)
maven|com.google.guava%3Aguava|E (maven borrow)
"
    MUST_NOT_EXIST="
npm|yj-unverifiable-d36|G (durably unverified, D36)
"
    EXPECTED=6
    ;;
  async)
    # async_local.sh pulls lodash (the ALLOW leg) and express (the BLOCK leg). A 429 on
    # either does not merely fail an assertion, it changes which 503 the firewall returns
    # — transient-unavailable (Retry-After 30) instead of verdict-pending (60) — so the
    # Retry-After assertion fails with no hint that deps.dev was the cause.
    #
    # BOTH need a deps.dev record for the same reason: local mode runs the D33/D36 repo
    # cross-check on the hot path, so a package deps.dev cannot vouch for is refused
    # BEFORE any scan is launched. That would make the block leg pass for the wrong
    # reason — 403 from failed verification rather than from the durable negative marker
    # the leg exists to prove — which is the exact class of bug (issue #55) that this
    # rig was rewritten to stop having.
    MUST_EXIST="
npm|lodash|1-4 (async contract, ALLOW leg)
npm|express|6 (async contract, BLOCK leg)
"
    MUST_NOT_EXIST=""
    EXPECTED=2
    ;;
  *)
    echo "unknown profile '$PROFILE' — use verifyrepo|async" >&2
    exit 2
    ;;
esac

fail_rate_limited() {
  cat >&2 <<EOF

DEPS.DEV IS RATE LIMITING THIS HOST (HTTP 429) — $1

This is NOT a firewall regression and NOT a broken test. The local-mode rigs verify
against the real api.deps.dev by design, and this runner's IP is currently throttled.
The firewall itself handles 429 correctly (transient -> retryable 503, never a verdict,
per D25/D36); it is the rig's assertions, which expect a definite BLOCK, that cannot run.

What to do: re-run the job later. If it recurs often, give the legs that do NOT need the
live record a controlled deps.dev via FW_DEPSDEV_BASE (the seam added in !53) rather than
marking this gate allow_failure — a gate that is allowed to fail is not a gate.
EOF
  exit 3
}

fail_drift() {
  cat >&2 <<EOF

DEPS.DEV DATA NO LONGER MATCHES THE RIG'S PREMISE — $1

This is NOT a firewall regression either, but unlike a 429 it does NOT resolve on a
re-run: the rig is built on assumptions about what deps.dev records, and one of them has
moved. Fix the rig (pick a different package, or update the expectation) — do not
"fix" the firewall to match.
EOF
  exit 4
}

fail_unreachable() {
  cat >&2 <<EOF

DEPS.DEV IS UNREACHABLE — $1

Network or DNS problem on this runner (base: $DEPSDEV_BASE). Not a firewall regression.
EOF
  exit 5
}

# status <system> <escaped-package> — HTTP status for the package endpoint, or "000"
# when curl could not connect at all (curl writes 000 for a connection failure).
status() {
  curl -s -o /dev/null -w '%{http_code}' -A "$UA" --max-time 20 \
    "$DEPSDEV_BASE/v3/systems/$1/packages/$2"
}

echo "=== preflight: deps.dev usable and the '$PROFILE' premises still hold ($DEPSDEV_BASE) ==="

checked=0
while IFS='|' read -r sys pkg leg; do
  [ -z "${sys:-}" ] && continue
  code="$(status "$sys" "$pkg")"
  case "$code" in
    200) echo "  ok        $sys/$pkg has a deps.dev record (needed by leg $leg)" ;;
    429) fail_rate_limited "while checking $sys/$pkg (leg $leg)" ;;
    000) fail_unreachable "while checking $sys/$pkg (leg $leg)" ;;
    404) fail_drift "deps.dev no longer has a record for $sys/$pkg, which leg $leg needs it to contradict the crafted claim" ;;
    *)   fail_drift "unexpected HTTP $code for $sys/$pkg (leg $leg)" ;;
  esac
  checked=$((checked + 1))
done <<EOF
$MUST_EXIST
EOF

while IFS='|' read -r sys pkg leg; do
  [ -z "${sys:-}" ] && continue
  code="$(status "$sys" "$pkg")"
  case "$code" in
    404) echo "  ok        $sys/$pkg is unknown to deps.dev (leg $leg depends on that)" ;;
    429) fail_rate_limited "while checking $sys/$pkg (leg $leg)" ;;
    000) fail_unreachable "while checking $sys/$pkg (leg $leg)" ;;
    200) fail_drift "$sys/$pkg now HAS a deps.dev record. Leg $leg exists to prove that a package with NO record fails closed (D36) — with a record present it would still pass, while testing something else. Pick a new never-published name" ;;
    *)   fail_drift "unexpected HTTP $code for $sys/$pkg (leg $leg)" ;;
  esac
  checked=$((checked + 1))
done <<EOF
$MUST_NOT_EXIST
EOF

# Enumerating nothing is not success — the same trap that made gofmt_check report a green
# it had not earned (!50). If the lists above are ever emptied or mis-parsed, say so.
if [ "$checked" -ne "$EXPECTED" ]; then
  echo "PREFLIGHT BUG: checked $checked package(s), expected $EXPECTED — the expectation lists did not parse" >&2
  exit 4
fi

echo "  preflight OK: $checked deps.dev premises verified"
