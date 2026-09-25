#!/usr/bin/env sh
# Tests for scripts/gen-env.sh.
#
# The script had no test, and that is exactly why its header could promise a warning the
# code never printed for a year of nobody noticing. The branch that matters is the one
# nobody exercises by accident: docker UNREACHABLE. On a developer machine docker is
# usually up, so the two-state probe looked correct every single time it was run by hand.
#
# Every case drives a FAKE docker on PATH, because the real three states cannot be staged
# on one machine in one run: you cannot have a pgdata volume and not have one, and you
# cannot stop the daemon mid-suite without breaking everything else.
set -u

ROOT="$(cd "$(dirname "$0")/.." && pwd)"

PASS=0
FAIL=0
ok()  { PASS=$((PASS + 1)); printf 'ok   %s\n' "$1"; }
bad() { FAIL=$((FAIL + 1)); printf 'FAIL %s\n' "$1"; }

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
mkdir -p "$TMP/bin"

# PROJ — the compose project gen-env.sh derives from $TMP/.env: the lowercased,
# sanitised basename of the directory holding the env file. The volume it looks for is
# "${PROJ}_pgdata", so the fixtures must be named in those terms or case 2 tests nothing.
PROJ=$(basename "$TMP" | tr '[:upper:]' '[:lower:]' | tr -cd 'a-z0-9_-')

# fake_docker MODE — install a `docker` earlier on PATH than the real one.
#   present      THIS project's pgdata volume, exit 0
#   otherproject a DIFFERENT stack's pgdata volume, exit 0
#   absent       an unrelated volume, exit 0
#   unreachable  nothing on stdout, exit 1 (what a stopped Docker Desktop does; verified
#                against the real client, which exits 1)
fake_docker() {
  case "$1" in
    present)      body="echo ${PROJ}_pgdata; exit 0" ;;
    otherproject) body='echo someotherstack_pgdata; exit 0' ;;
    absent)       body='echo some_other_volume; exit 0' ;;
    unreachable)  body='echo "cannot connect to the docker daemon" >&2; exit 1' ;;
  esac
  printf '#!/bin/sh\n%s\n' "$body" > "$TMP/bin/docker"
  chmod +x "$TMP/bin/docker"
}

# run MODE — generate a fresh env file with that docker, print "exit<TAB>file"
run() {
  fake_docker "$1"
  rm -f "$TMP/.env"
  PATH="$TMP/bin:$PATH" YJ_ENV_FILE="$TMP/.env" sh "$ROOT/scripts/gen-env.sh" >"$TMP/out" 2>&1
  echo "$?"
}

password_of() { sed -n 's/^POSTGRES_PASSWORD=//p' "$TMP/.env"; }

# ── 1. no volume: a generated secret, and NOT the legacy literal ─────────────
rc=$(run absent)
pw=$(password_of)
if [ "$rc" = "0" ] && [ -n "$pw" ] && [ "$pw" != "postgres" ] && [ "${#pw}" -ge 16 ]; then
  ok "no pgdata volume -> a generated secret (${#pw} chars), not the shared literal"
else
  bad "expected a generated secret, got rc=$rc pw='$pw': $(cat "$TMP/out")"
fi

# ── 2. volume present: the LEGACY literal, on purpose, and it says so ────────
#
# Postgres applies POSTGRES_PASSWORD only when initialising an EMPTY data directory, so
# handing a fresh secret to an existing volume produces `password authentication failed`.
rc=$(run present)
pw=$(password_of)
if [ "$pw" = "postgres" ] && grep -q "LEGACY" "$TMP/out"; then
  ok "an existing pgdata volume keeps the legacy password AND the run says why"
else
  bad "expected the legacy password with an explanation, got pw='$pw': $(cat "$TMP/out")"
fi

# ── 3. THE CASE THAT WAS SILENT, and the reason this file exists ─────────────
#
# Docker unreachable is not "there is no volume". The first implementation collapsed
# them, so a developer with a stopped daemon and an existing volume got a fresh secret
# and a success message. Measured 2026-09-12 against the real client with Docker Desktop
# stopped: `docker volume ls` exits 1 and the old code took the "absent" branch.
rc=$(run unreachable)
pw=$(password_of)
if [ "$pw" = "postgres" ]; then
  bad "unreachable docker was treated as 'volume present' — a brand-new install would " \
      "be handed the shared literal, which is the defect this script removes"
elif grep -q "WARNING" "$TMP/out" && grep -qi "could not reach docker" "$TMP/out"; then
  ok "unreachable docker generates a secret AND warns that a volume may exist"
else
  bad "unreachable docker generated silently — the header promises a warning: $(cat "$TMP/out")"
fi

# ── 4. the rotate hint names the file it actually wrote ──────────────────────
#
# The hint used to be the literal `.env` + `sh scripts/dev.sh env`. This script is also
# used for deploy/reference/.env, and telling that reader to delete the repo-root .env
# points them at a different database.
fake_docker absent
PATH="$TMP/bin:$PATH" YJ_ENV_FILE="$TMP/.env" sh "$ROOT/scripts/gen-env.sh" >"$TMP/out2" 2>&1
if grep -q "already exists" "$TMP/out2" && grep -q "$TMP/.env" "$TMP/out2"; then
  ok "re-running is idempotent and the rotate hint names the file it wrote"
else
  bad "second run did not report the existing file by name: $(cat "$TMP/out2")"
fi

# ── 5. ANTI-VACUITY: the fake docker is actually the one being consulted ─────
#
# Every case above is staged through PATH. If the real docker were winning, cases 2 and 3
# would silently become "whatever this machine happens to have" — green on a laptop with
# no volumes, and untrue. So assert the fake is reachable and answers as written.
fake_docker present
got=$(PATH="$TMP/bin:$PATH" docker volume ls --format '{{.Name}}' 2>/dev/null)
if [ "$got" = "${PROJ}_pgdata" ]; then
  ok "the staged docker is the one on PATH, so cases 2 and 3 tested what they claim"
else
  bad "PATH staging did not take effect (got '$got'); every case above is inconclusive"
fi

# ── 6. A DIFFERENT stack's volume must not count ─────────────────────────────
#
# MEASURED 2026-09-12 before the probe was scoped: with only the main stack's
# `yellowjack_pgdata` present and NO reference volume at all, generating
# deploy/reference/.env wrote the legacy literal `postgres` — silently handing the
# example the one shared credential this change removes, for a database that had not
# even been created yet.
rc=$(run otherproject)
pw=$(password_of)
if [ "$pw" = "postgres" ]; then
  bad "another project's pgdata volume was treated as ours, so a brand-new stack was handed the shared literal"
elif [ -n "$pw" ] && [ "${#pw}" -ge 16 ]; then
  ok "a pgdata volume belonging to a DIFFERENT compose project does not trigger the legacy password"
else
  bad "unexpected result for a foreign volume: rc=$rc pw='$pw': $(cat "$TMP/out")"
fi

printf '\n%s passed, %s failed\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
