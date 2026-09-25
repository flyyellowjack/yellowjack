#!/usr/bin/env bash
# The console demo: the real stack, real registries, real OpenSSF scores, and a small set
# of pulls that gives every console page something true to show. See docs/DEMO.md.
#
#   sh scripts/demo.sh up       build and start the stack, with demo lists and feed
#   sh scripts/demo.sh seed     pull a curated set of packages through the gate
#   sh scripts/demo.sh status   print the URLs and the console's sign-in
#   sh scripts/demo.sh down     stop the stack and delete ./.demo
#
# Nothing here is faked except the known-malware FEED, whose entries are marked DEMO-*:
# the verdicts, scores, queue and audit trail are the product's own, produced by the
# same pulls a developer's npm would make. Scores come from the public OpenSSF Scorecard
# API and change over time, so the seed prints what actually happened rather than
# assuming it.
set -euo pipefail
cd "$(dirname "$0")/.."

DEMO=.demo
PROJECT=yellowjack-demo
COMPOSE=(docker compose -p "$PROJECT" -f docker-compose.yml -f docker-compose.demo.yml)
GATE=http://127.0.0.1:8080
CONSOLE=http://127.0.0.1:8085
CONTROL=http://127.0.0.1:8090

say() { printf '\n== %s\n' "$*"; }

credentials() {
  if [ ! -f "$DEMO/credentials" ]; then
    # Generated per demo, never a default: scripts/no-default-creds.sh exists because a
    # shipped password is a password everyone has.
    rand() { head -c 18 /dev/urandom | base64 | tr -d '/+=' | head -c 20; }
    printf 'CONSOLE_AUTH_USER=admin\nCONSOLE_AUTH_PASS=%s\nPOSTGRES_PASSWORD=%s\n' "$(rand)" "$(rand)" > "$DEMO/credentials"
  fi
  # shellcheck disable=SC1091
  . "$DEMO/credentials"
  export CONSOLE_AUTH_USER CONSOLE_AUTH_PASS POSTGRES_PASSWORD
}

prepare() {
  mkdir -p "$DEMO/feed" "$DEMO/lists"
  # The known-malware feed. The IDs say DEMO because this file is invented for the demo;
  # the packages are real incidents, which is what makes the refusal worth showing.
  # ua-parser-js 0.7.29 was a hijacked release (October 2021): pinned to that version,
  # so the release is refused while the package's other versions are served.
  cat > "$DEMO/feed/malware.ndjson" <<'EOF'
{"id":"DEMO-0001","ecosystem":"npm","name":"crossenv"}
{"id":"DEMO-0002","ecosystem":"npm","name":"electorn"}
{"id":"DEMO-0003","ecosystem":"npm","name":"ua-parser-js","versions":["0.7.29"]}
{"id":"DEMO-0004","ecosystem":"npm","name":"coa","versions":["2.0.3"]}
EOF
  if [ ! -d "$DEMO/lists/.git" ]; then
    printf '# Packages this organisation allows without scoring.\nkind-of\n' > "$DEMO/lists/allow.txt"
    printf '# Packages this organisation refuses, whatever their score.\nevent-stream\ncolors\n' > "$DEMO/lists/deny.txt"
    git init -q -b main "$DEMO/lists"
    git init -q --bare -b main "$DEMO/lists-remote"
    git -C "$DEMO/lists-remote" config core.sharedRepository 0777
    git -C "$DEMO/lists" config user.name "demo setup"
    git -C "$DEMO/lists" config user.email "demo@yellowjack.invalid"
    git -C "$DEMO/lists" config commit.gpgsign false
    # The gate reads these files as written: no line-ending conversion on a Windows host.
    git -C "$DEMO/lists" config core.autocrlf false
    git -C "$DEMO/lists" add -A
    git -C "$DEMO/lists" commit -q -m "Start the demo lists: allow kind-of, block event-stream and colors"
    # The remote is the path INSIDE the console container. MSYS_NO_PATHCONV stops Git
    # Bash on Windows rewriting it into a host path; it is ignored everywhere else.
    MSYS_NO_PATHCONV=1 git -C "$DEMO/lists" remote add origin /srv/lists-remote
    git -C "$DEMO/lists" push -q "$(pwd)/$DEMO/lists-remote" main
  fi
  # The console runs as uid 65532 and the bind mounts carry host ownership, so it needs
  # to be told these repositories are safe, and needs to be able to write them.
  printf '[safe]\n\tdirectory = /srv/lists\n\tdirectory = /srv/lists-remote\n' > "$DEMO/gitconfig"
  chmod -R a+rwX "$DEMO/lists" "$DEMO/lists-remote"
  chmod a+r "$DEMO/gitconfig" "$DEMO/feed/malware.ndjson"
}

wait_for() {
  for _ in $(seq 1 90); do
    if curl -fsS -o /dev/null "$1"; then return 0; fi
    sleep 2
  done
  echo "timed out waiting for $1" >&2
  return 1
}

cmd_up() {
  prepare
  credentials
  say "building and starting the stack (first run builds every image; allow a few minutes)"
  "${COMPOSE[@]}" up -d --build
  wait_for "$CONTROL/healthz"
  wait_for "$CONSOLE/healthz"
  wait_for "$GATE/healthz"
  cmd_status
  echo
  echo "Next: sh scripts/demo.sh seed"
}

# Three workstations on the stack's network, so the audit log shows requests from more
# than one host, as it would in an office.
start_workstations() {
  # The network is whatever the gate is attached to: docker-compose.yml names it, so it
  # is not "<project>_default".
  NET="$(docker inspect -f '{{range $k, $v := .NetworkSettings.Networks}}{{$k}}{{end}}' \
    "$("${COMPOSE[@]}" ps -q firewall)")"
  for n in 1 2 3; do
    docker rm -f "yjdemo-dev-$n" >/dev/null 2>&1 || true
    docker run -d --rm --name "yjdemo-dev-$n" --network "$NET" curlimages/curl:8.10.1 sleep 900 >/dev/null
  done
}

stop_workstations() {
  for n in 1 2 3; do docker rm -f "yjdemo-dev-$n" >/dev/null 2>&1 || true; done
}

# pull <workstation> <path> <label>: one request through the gate, reported by outcome.
pull() {
  code="$(docker exec "yjdemo-dev-$1" curl -s -o /dev/null -w '%{http_code}' "http://firewall:8080/$2" || echo 000)"
  case "$code" in
    200) verdict="served" ;;
    403) verdict="refused" ;;
    404) verdict="not found upstream" ;;
    *) verdict="HTTP $code" ;;
  esac
  printf '  %-34s %s\n' "$3" "$verdict"
}

cmd_seed() {
  credentials
  wait_for "$GATE/healthz"
  start_workstations
  trap stop_workstations EXIT

  say "everyday packages (served when their OpenSSF score is 5.0 or better)"
  for p in lodash express react typescript uuid dotenv isarray ua-parser-js; do pull 1 "$p" "$p"; done
  say "downloads, so Capacity has bytes to show"
  pull 2 "lodash/-/lodash-4.17.21.tgz" "lodash 4.17.21 (tarball)"
  pull 2 "express/-/express-4.21.2.tgz" "express 4.21.2 (tarball)"
  pull 3 "ua-parser-js/-/ua-parser-js-0.7.28.tgz" "ua-parser-js 0.7.28 (tarball)"

  say "the known-malware list (refused on the gate, the registry is never asked)"
  pull 2 "crossenv" "crossenv"
  pull 3 "electorn" "electorn"
  pull 1 "ua-parser-js/-/ua-parser-js-0.7.29.tgz" "ua-parser-js 0.7.29 (hijacked release)"
  pull 3 "coa/-/coa-2.0.3.tgz" "coa 2.0.3 (hijacked release)"

  say "your block list"
  pull 2 "event-stream" "event-stream"
  pull 1 "colors" "colors"

  say "your allow list (served without scoring)"
  pull 3 "kind-of" "kind-of"

  say "low scores (refused, and sent to a person in Decisions)"
  for p in chalk left-pad is-odd; do pull 2 "$p" "$p"; done

  say "done"
  echo "  Open $CONSOLE and sign in (sh scripts/demo.sh status). The Overview shows"
  echo "  what just happened; Decisions has the packages waiting on a person."
}

cmd_status() {
  credentials
  cat <<EOF

  Console   $CONSOLE
            user     $CONSOLE_AUTH_USER
            password $CONSOLE_AUTH_PASS
  npm gate  $GATE   (npm install --registry $GATE <package>)
EOF
}

cmd_down() {
  stop_workstations
  # Compose interpolates the whole file even to stop it, so the password must be set; a
  # stack whose credentials are already gone gets a placeholder that is never used.
  if [ -f "$DEMO/credentials" ]; then credentials; else export POSTGRES_PASSWORD=unused; fi
  "${COMPOSE[@]}" down -v --remove-orphans
  rm -rf "$DEMO"
}

case "${1:-}" in
  up) cmd_up ;;
  seed) cmd_seed ;;
  status) cmd_status ;;
  down) cmd_down ;;
  *) sed -n '2,15p' "$0"; exit 2 ;;
esac
