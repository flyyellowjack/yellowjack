#!/usr/bin/env sh
# gen-env.sh — generate the local .env once, so the shipped compose file carries no
# credential (issue #22, "no default creds").
#
# ── WHY THIS EXISTS ──────────────────────────────────────────────────────────
#
# docker-compose.yml used to read `POSTGRES_PASSWORD: postgres`, with the same value
# again inside APPROVAL_DATABASE_URL. That is the shipped file a self-hoster runs
# unmodified — the same standard the pinning work on #22 is held to — so it meant one
# identical database credential on every installation in the world. Postgres publishes
# no host port, so this was never a LAN-exposed database; what it cost was a constant
# shared by every deployment, and a finding in the security review this issue exists to
# pass (D54: it is the first thing they check).
#
# ── WHY GENERATE RATHER THAN DEMAND ──────────────────────────────────────────
#
# Making the variable simply required would have been the stronger posture and the
# wrong trade: docs/CONFIGURATION.md advertises "30 knobs, 0 required" and that the
# stack runs with nothing set, which is a real property worth keeping. Generating on
# first run keeps `sh scripts/dev.sh up` a single command while removing the shared
# constant. A fresh clone that never runs this gets compose's own error naming this
# script, not a silent default.
#
# ── THE EXISTING-VOLUME TRAP, HANDLED ────────────────────────────────────────
#
# Postgres applies POSTGRES_PASSWORD **only when it initialises an empty data
# directory**. Anyone with a pgdata volume from before this change has a database whose
# password is still the old literal, so handing it a freshly generated one produces
# `password authentication failed` and a confusing morning. When a pgdata volume is
# already present this script therefore writes the LEGACY value and says so, with the
# one command that rotates it properly. Detection is best-effort: if docker cannot be
# reached the script generates a fresh secret and prints the same warning, because
# guessing "there is no volume" is the answer that breaks people.
set -eu

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
ENV_FILE="${YJ_ENV_FILE:-$ROOT/.env}"
LEGACY_PASSWORD="postgres"

# The rotate hint has to name the file being written, not a fixed one: this script is
# also used for deploy/reference/.env via YJ_ENV_FILE, and telling that reader to delete
# the repo-root .env would destroy the wrong database. Default stays the documented
# `sh scripts/dev.sh env`; any other target quotes the invocation that produced it.
if [ "$ENV_FILE" = "$ROOT/.env" ]; then
  ROTATE_CMD="sh scripts/dev.sh env"
else
  ROTATE_CMD="YJ_ENV_FILE=$ENV_FILE sh scripts/gen-env.sh"
fi

if [ -f "$ENV_FILE" ]; then
  echo "gen-env: $ENV_FILE already exists — leaving it alone."
  echo "         To rotate: docker compose down -v && rm $ENV_FILE && $ROTATE_CMD"
  exit 0
fi

# A URL-safe secret: this value is interpolated into APPROVAL_DATABASE_URL, so anything
# needing percent-encoding would produce a DSN that parses wrong rather than a loud error.
random_password() {
  head -c 48 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | head -c 32
  echo
}

# volume_state -- "present" | "absent" | "unknown".
#
# THE THREE-WAY ANSWER IS LOAD-BEARING, AND THE TWO-WAY VERSION WAS WRONG. The first
# cut was `docker volume ls ... | grep -q`, which collapses "the daemon says there are
# no volumes" and "the daemon could not be asked" into the same non-zero exit. The
# header above promised a warning in the unreachable case and the code printed none.
#
# Measured 2026-09-12 with Docker Desktop stopped: `docker volume ls` exits 1, the else
# branch ran, and a fresh secret was written with a cheerful success message. Someone
# whose daemon happens to be down while they DO hold a pgdata volume gets exactly the
# `password authentication failed` morning the legacy branch exists to prevent -- and
# gets it silently, which is worse than not having the branch.
#
# Unknown is treated as "generate, but say so": guessing "there is no volume" is the
# answer that breaks people, and guessing "there is one" would hand a brand-new install
# the legacy literal, which is the defect this whole script removes.
# project_prefix -- the compose project this ENV_FILE belongs to, which is how its
# volumes are named. Compose derives the project from the directory holding the compose
# file, lowercased with anything outside [a-z0-9_-] dropped; COMPOSE_PROJECT_NAME wins
# when set.
project_prefix() {
  if [ -n "${COMPOSE_PROJECT_NAME:-}" ]; then
    printf '%s' "$COMPOSE_PROJECT_NAME"
    return
  fi
  basename "$(cd "$(dirname "$ENV_FILE")" && pwd)" | tr '[:upper:]' '[:lower:]' | tr -cd 'a-z0-9_-'
}

# volume_state -- "present" | "absent" | "unknown", FOR THIS PROJECT ONLY.
#
# Scoped, because the first cut matched any `*_pgdata` and that is wrong once more than
# one stack exists. MEASURED 2026-09-12: with only the main stack's `yellowjack_pgdata`
# present and no reference volume at all, generating deploy/reference/.env wrote the
# LEGACY literal `postgres` -- silently handing the example the one shared credential
# this whole change exists to remove, for a database that had not even been created yet.
#
# THE THREE-WAY ANSWER IS ALSO LOAD-BEARING. `docker volume ls` failing (daemon down, or
# Docker Desktop not started) is indistinguishable from it answering "no volumes" once
# both collapse to a non-zero exit. This file's header promised a warning in the
# unreachable case and the code printed none: measured with the daemon stopped, `docker
# volume ls` exits 1, the else branch ran, and a fresh secret was written with a cheerful
# success message. Someone whose daemon happens to be down while they DO hold a volume
# then gets exactly the `password authentication failed` morning the legacy branch exists
# to prevent, silently, which is worse than not having the branch.
#
# Unknown means "generate, but say so": guessing "there is no volume" breaks people who
# have one, and guessing "there is one" hands a brand-new install the legacy literal.
volume_state() {
  out=$(docker volume ls --format '{{.Name}}' 2>/dev/null) || { echo unknown; return; }
  if printf '%s
' "$out" | grep -qx "$(project_prefix)_pgdata"; then echo present; else echo absent; fi
}

unknown=0
case "$(volume_state)" in
  present) password="$LEGACY_PASSWORD"; legacy=1 ;;
  unknown) password="$(random_password)"; legacy=0; unknown=1 ;;
  *)       password="$(random_password)"; legacy=0 ;;
esac

umask 077
cat > "$ENV_FILE" <<EOF
# Generated by scripts/gen-env.sh. Git-ignored, local to this machine, not a template.
#
# POSTGRES_PASSWORD is consumed twice in docker-compose.yml: by the postgres service and
# inside APPROVAL_DATABASE_URL. Postgres only applies it when initialising an EMPTY data
# directory, so changing it here does nothing to an existing pgdata volume — rotate with
#   docker compose down -v && rm .env && sh scripts/dev.sh env
# which destroys the local database, including any audit trail it holds.
POSTGRES_PASSWORD=$password
EOF

if [ "$legacy" = "1" ]; then
  echo "gen-env: a pgdata volume already exists, so $ENV_FILE keeps the LEGACY password."
  echo "         A generated one would not match the database already initialised in that"
  echo "         volume, and you would get 'password authentication failed'."
  echo "         To move to a generated secret (DESTROYS the local database):"
  echo "           docker compose down -v && rm $ENV_FILE && $ROTATE_CMD"
else
  echo "gen-env: wrote $ENV_FILE with a generated POSTGRES_PASSWORD (32 chars, git-ignored)."
  if [ "$unknown" = "1" ]; then
    echo "gen-env: WARNING - could not reach docker, so it is unknown whether a pgdata volume"
    echo "         already exists. If one does, its database still has the OLD password and"
    echo "         you will get 'password authentication failed'. Then either restore the old"
    echo "         value in $ENV_FILE, or (DESTROYS the local database):"
    echo "           docker compose down -v && rm $ENV_FILE && $ROTATE_CMD"
  fi
fi
