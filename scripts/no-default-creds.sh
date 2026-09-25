#!/usr/bin/env sh
# The SHIPPED compose file carries no credential literal (issue #22, "no default creds").
#
# ── WHY ──────────────────────────────────────────────────────────────────────
#
# docker-compose.yml read `POSTGRES_PASSWORD: postgres`, with the same value again inside
# APPROVAL_DATABASE_URL: one identical database credential on every installation in the
# world, in the file a self-hoster runs unmodified. That is the same standard the pinning
# work on this issue is held to (Nexus #544: a customer who changed nothing), and it is
# the first thing a security review checks (D54).
#
# The fix is scripts/gen-env.sh — generated per machine into a git-ignored .env. This is
# the guard that keeps it fixed, because the way it comes back is not a decision anyone
# announces: it is one convenient default added during a debugging session.
#
# ── SCOPE, AND WHY THE RIG FILES ARE OUT OF IT ───────────────────────────────
#
# The files a person RUNS OR COPIES: docker-compose.yml, and the reference deployment
# under deploy/. docker-compose.e2e.yml, .asyncfake.yml, .verifyrepo.yml and
# .registryfront.yml carry deliberate FIXTURES — invented values living in throwaway
# stacks that the rigs tear down, granting nothing outside them — and
# docker-compose.e2e.yml already says so in its own comment. Demanding generation there
# would make the gate unsatisfiable, and an unsatisfiable gate gets weakened.
#
# The reference deployment was added to this list the day after it landed, and the
# reason is worth stating because it is the opposite of the rig argument: it exists to
# be COPIED. A shared credential in the shipped file is on every installation; a shared
# credential in the EXAMPLE is on every installation that started by copying the
# example, which is the path we actively recommend. It needs this rule at least as much
# as the shipped file, not less. Same widening, same reasoning, as
# scripts/exposed-ports.sh and scripts/pinned-images.sh took in !243.
#
# ── WHAT COUNTS AS A VIOLATION ───────────────────────────────────────────────
#
# A credential-shaped key (PASSWORD / SECRET / TOKEN / _KEY) whose value is a literal
# rather than a `${VAR}` interpolation, or a DSN carrying `user:secret@host`. An empty
# value is fine: that is the console's documented "no credential means read-only" shape.

set -u

: "${YJ_SHIPPED_COMPOSE:=docker-compose.yml deploy/reference/docker-compose.yml}"

# cred_violations FILE — print each offending line, one per line. Empty means clean.
cred_violations() {
  f="$1"
  # 1. KEY: value / KEY=value where KEY looks like a secret and value is a literal.
  #    `${...}` anywhere in the value means it is interpolated, which is the fix.
  grep -nE '^[[:space:]]*[A-Z_]*(PASSWORD|SECRET|TOKEN|_KEY)[A-Z_]*[[:space:]]*[:=]' "$f" 2>/dev/null \
    | tr -d '\r' \
    | while IFS= read -r line; do
        value=$(printf '%s' "$line" | sed 's/^[^:=]*[:=]//' | sed 's/^[[:space:]]*//; s/[[:space:]]*$//' | tr -d '"'"'"'')
        [ -z "$value" ] && continue                      # empty is the documented no-credential shape
        case "$value" in
          *'${'*) continue ;;                            # interpolated — this is the fix
          '#'*)   continue ;;                            # a comment, not a value
        esac
        printf '%s\n' "$line"
      done
  # 2. A DSN with an inline password, which hides a credential in a URL rather than a key.
  grep -nE '[a-z]+://[A-Za-z0-9_.-]+:[^@/$[:space:]]+@' "$f" 2>/dev/null | tr -d '\r'
}

check_no_default_creds() {
  rc=0
  files=0
  keys=0
  for f in $YJ_SHIPPED_COMPOSE; do
    [ -f "$f" ] || { printf 'no-default-creds: %s is missing — nothing was checked\n' "$f"; return 1; }
    files=$((files + 1))
    keys=$((keys + $(grep -cE '^[[:space:]]*[A-Z_]*(PASSWORD|SECRET|TOKEN|_KEY)[A-Z_]*[[:space:]]*[:=]' "$f" 2>/dev/null)))
    v=$(cred_violations "$f")
    if [ -n "$v" ]; then
      printf '%s: a credential is written literally in a compose file people run or copy:\n' "$f"
      printf '%s\n' "$v" | sed 's/^/    /'
      printf '    Every installation would share it. Interpolate it instead —\n'
      printf '      KEY: ${KEY:?not set - run `sh scripts/dev.sh env` to generate .env}\n'
      printf '    and let scripts/gen-env.sh mint a per-machine value (#22).\n'
      rc=1
    fi
  done
  # ANTI-VACUITY. Both assertions sit inside loops over a file list and a grep: a rename,
  # a moved key, or a broken pattern makes this print nothing and return 0, which reads
  # exactly like "no default credentials". EVERY file in the list has at least one
  # credential-shaped key by construction (POSTGRES_PASSWORD), so zero means the check
  # stopped matching rather than the files becoming clean. The per-file existence check
  # above is the other half: a RENAMED file must fail loudly, not silently shrink the
  # list — which is how a widened scope quietly narrows again.
  if [ "$files" -lt 1 ] || [ "$keys" -lt 1 ]; then
    printf 'no-default-creds: examined %s file(s) and found %s credential-shaped key(s).\n' "$files" "$keys"
    printf '    The check found nothing because it looked at nothing — a pattern or a path has drifted.\n'
    return 1
  fi
  [ "$rc" -eq 0 ] && printf 'no-default-creds: %s compose file(s) people run or copy, %s credential key(s), none literal\n' "$files" "$keys"
  return "$rc"
}
