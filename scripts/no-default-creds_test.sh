#!/usr/bin/env sh
# Tests for scripts/no-default-creds.sh.
#
# The check says a credential is ABSENT, which is what a broken check also reports. So
# the cases that carry weight are the refusals: a literal password, a password hidden
# inside a DSN, and a file the patterns no longer match.
set -u

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
. "$ROOT/scripts/no-default-creds.sh"

PASS=0
FAIL=0
ok()  { PASS=$((PASS + 1)); printf 'ok   %s\n' "$1"; }
bad() { FAIL=$((FAIL + 1)); printf 'FAIL %s\n' "$1"; }

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

run() { ( cd "$TMP" && YJ_SHIPPED_COMPOSE="$1" check_no_default_creds >"$TMP/out" 2>&1; echo $? ); }

# ── 1. the shape the fix produces ────────────────────────────────────────────
cat > "$TMP/clean.yml" <<'YML'
services:
  postgres:
    environment:
      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD:?not set - run `sh scripts/dev.sh env`}
  approval:
    environment:
      APPROVAL_DATABASE_URL: "postgres://postgres:${POSTGRES_PASSWORD}@postgres:5432/yj?sslmode=disable"
  console:
    environment:
      CONSOLE_AUTH_PASS: "${CONSOLE_AUTH_PASS:-}"
YML
rc=$(run clean.yml)
if [ "$rc" = "0" ]; then ok "an interpolated credential passes, and an empty one does too"; else
  bad "the fixed shape was rejected: $(cat "$TMP/out")"; fi

# ── 2. NEGATIVE CONTROL: the literal this issue is about ─────────────────────
cat > "$TMP/literal.yml" <<'YML'
services:
  postgres:
    environment:
      POSTGRES_PASSWORD: postgres
YML
rc=$(run literal.yml)
if [ "$rc" != "0" ] && grep -q 'written literally' "$TMP/out" && grep -q 'POSTGRES_PASSWORD' "$TMP/out"; then
  ok "a literal password is caught, and the message names the key"
else
  bad "a literal password passed, or was misreported: $(cat "$TMP/out")"
fi

# ── 3. NEGATIVE CONTROL: the same secret hidden inside a DSN ─────────────────
# The one that matters most: the key is interpolated and looks fixed, while the URL two
# lines down still carries the password. That is exactly how this shipped.
cat > "$TMP/dsn.yml" <<'YML'
services:
  postgres:
    environment:
      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD:?set it}
  approval:
    environment:
      APPROVAL_DATABASE_URL: "postgres://postgres:hunter2@postgres:5432/yj?sslmode=disable"
YML
rc=$(run dsn.yml)
if [ "$rc" != "0" ] && grep -q 'hunter2' "$TMP/out"; then
  ok "a password inside a DSN is caught even when the key above it is interpolated"
else
  bad "a DSN password passed: $(cat "$TMP/out")"
fi

# ── 4. THE VACUITY CONTROL ───────────────────────────────────────────────────
# A compose file with no credential-shaped key must FAIL, not pass: it means the patterns
# stopped matching, which is indistinguishable from "clean" by output alone.
cat > "$TMP/nokeys.yml" <<'YML'
services:
  firewall:
    image: yellowjack-firewall
YML
rc=$(run nokeys.yml)
if [ "$rc" != "0" ] && grep -q 'looked at nothing' "$TMP/out"; then
  ok "a file with no credential-shaped key FAILS rather than reporting it clean"
else
  bad "a file with no keys reported success — the check cannot tell 'clean' from 'not matching'"
fi

# ── 5. a missing file is a failure, not a pass ───────────────────────────────
rc=$(run absent.yml)
if [ "$rc" != "0" ]; then ok "a missing compose file fails"; else
  bad "a missing file passed: $(cat "$TMP/out")"; fi

# ── 6. the real repo is what CI will actually check ──────────────────────────
rc=$( cd "$ROOT" && check_no_default_creds >"$TMP/out" 2>&1; echo $? )
if [ "$rc" = "0" ]; then
  ok "this repo passes: $(cat "$TMP/out")"
else
  bad "the shipped compose file does not pass its own credential gate:"; cat "$TMP/out"
fi

# ── 7. ANTI-VACUITY FOR 6: the extractor really reads the shipped file ───────
# Case 6 passes if the file is clean, and equally if the grep matched nothing at all.
n=$(cd "$ROOT" && grep -cE '^[[:space:]]*[A-Z_]*(PASSWORD|SECRET|TOKEN|_KEY)[A-Z_]*[[:space:]]*[:=]' docker-compose.yml)
if [ "${n:-0}" -ge 1 ]; then
  ok "the shipped file really contains $n credential-shaped key(s) for case 6 to inspect"
else
  bad "no credential-shaped key found in docker-compose.yml — case 6 passed by reading nothing"
fi

printf '\n%s passed, %s failed\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
