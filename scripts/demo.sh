#!/usr/bin/env bash
# The console demo: the real stack, real registries, real OpenSSF scores, a real signed
# known-malware feed, and a small set of pulls that gives every console page something
# true to show. See docs/DEMO.md.
#
#   sh scripts/demo.sh up       build and start the stack, with demo lists and the feed
#   sh scripts/demo.sh seed     pull a curated set of packages through the gates
#   sh scripts/demo.sh feed     rebuild and re-sign the known-malware feed (the gate re-reads it)
#   sh scripts/demo.sh status   print the URLs and the console's sign-in
#   sh scripts/demo.sh down     stop the stack and delete ./.demo
#
# Nothing here is faked. The verdicts, scores, queue and audit trail are the product's own,
# produced by the same pulls a developer's npm or pip would make. The known-malware feed is
# built from OpenSSF's public malicious-packages data, plus the three GitHub advisories the
# demo's npm incidents carry, and is signed with a key made for this demo; every ID it
# quotes can be looked up. Only if the data cannot be downloaded does the demo fall back
# to a four-entry offline list, whose IDs say DEMO so nobody mistakes it for the real one.
# Scores come from the public OpenSSF Scorecard API and change over time, so the seed
# prints what actually happened rather than assuming it.
set -euo pipefail
cd "$(dirname "$0")/.."

DEMO=.demo
PROJECT=yellowjack-demo
COMPOSE=(docker compose -p "$PROJECT" -f docker-compose.yml -f docker-compose.demo.yml)
GATE=http://127.0.0.1:8080
PYPI_GATE=http://127.0.0.1:8082
CONSOLE=http://127.0.0.1:8085
CONTROL=http://127.0.0.1:8090

# The feed is built and signed in containers, so the demo host needs Docker and nothing
# else. Both images are the ones the repository already pins.
PY_IMAGE=python:3.12-alpine@sha256:c4634f578a412db396771b61b064c6e546c9d6414c7fb5b1b05d5871f1885f7b
GO_IMAGE=golang:1.26@sha256:9d2f36f06329b2a141b9db99ffa32765cf695ee57b813ca29e245e8670bcbfff
FEED_SOURCE=https://codeload.github.com/ossf/malicious-packages/tar.gz/main

say() { printf '\n== %s\n' "$*"; }

# docker run with the repository mounted at /src. MSYS_NO_PATHCONV stops Git Bash on
# Windows rewriting the container paths; it is ignored everywhere else.
in_container() {
  image="$1"; shift
  # As the host user, so what it writes into ./.demo is ours to move and chmod on Linux;
  # HOME and Go's caches then need a writable place.
  MSYS_NO_PATHCONV=1 docker run --rm -v "$(pwd):/src" -w /src --user "$(id -u):$(id -g)" \
    -e HOME=/tmp -e GOCACHE=/tmp/go-build -e GOPATH=/tmp/go -e GOFLAGS=-mod=mod "$image" "$@"
}

credentials() {
  if [ ! -f "$DEMO/credentials" ]; then
    # Generated per demo, never a default: scripts/no-default-creds.sh exists because a
    # shipped password is a password everyone has.
    rand() { head -c 18 /dev/urandom | base64 | tr -d '/+=' | head -c 20; }
    printf 'CONSOLE_AUTH_USER=admin\nCONSOLE_AUTH_PASS=%s\nPOSTGRES_PASSWORD=%s\n' "$(rand)" "$(rand)" > "$DEMO/credentials"
  fi
  # shellcheck disable=SC1091
  . "$DEMO/credentials"
  # The feed's public key, when the feed in force is the signed one. Empty means the
  # offline list, which the gate loads unverified and says so in its log.
  FW_MALWARE_FEED_KEY="$(cat "$DEMO/feed.pub" 2>/dev/null || true)"
  export CONSOLE_AUTH_USER CONSOLE_AUTH_PASS POSTGRES_PASSWORD FW_MALWARE_FEED_KEY
}

# The fallback when the public data cannot be fetched: four real incidents under IDs that
# say DEMO, unsigned. ua-parser-js 0.7.29 and coa 2.0.3 are pinned to the hijacked release,
# so the package's other versions are still served.
offline_feed() {
  rm -f "$DEMO/feed.pub" "$DEMO/feed/malware.ndjson.sig"
  cat > "$DEMO/feed/malware.ndjson" <<'EOF'
{"id":"DEMO-0001","ecosystem":"npm","name":"crossenv"}
{"id":"DEMO-0002","ecosystem":"npm","name":"electorn"}
{"id":"DEMO-0003","ecosystem":"npm","name":"ua-parser-js","versions":["0.7.29"]}
{"id":"DEMO-0004","ecosystem":"npm","name":"coa","versions":["2.0.3"]}
EOF
  chmod a+r "$DEMO/feed/malware.ndjson"
  echo "  in force: the four-entry OFFLINE list (IDs DEMO-0001..0004, unsigned)"
}

build_feed() {
  mkdir -p "$DEMO/cache" "$DEMO/feed"
  say "building the known-malware feed from OpenSSF's public malicious-packages data"
  if ! curl -fsSL -o "$DEMO/cache/malicious-packages.tar.gz" "$FEED_SOURCE"; then
    echo "  could not download $FEED_SOURCE"
    offline_feed
    return 0
  fi
  new="$DEMO/feed/malware.ndjson.new"
  if ! in_container "$PY_IMAGE" python3 scripts/build-malware-feed.py \
      --tarball "$DEMO/cache/malicious-packages.tar.gz" --out "$new"; then
    echo "  the feed did not build"
    rm -f "$new"
    offline_feed
    return 0
  fi
  # The demo's npm incidents predate OpenSSF's dataset. Their GitHub advisories are real,
  # and each ID below was checked against api.osv.dev for exactly this release.
  cat >> "$new" <<'EOF'
{"ecosystem":"npm","id":"GHSA-c2m4-w5hm-vqjw","name":"crossenv"}
{"ecosystem":"npm","id":"GHSA-pjwm-rvh2-c87w","name":"ua-parser-js","versions":["0.7.29"]}
{"ecosystem":"npm","id":"GHSA-73qr-pfmq-6rp8","name":"coa","versions":["2.0.3"]}
EOF
  # One key per demo directory. The private half stays in ./.demo, never in the repo or
  # on a gate; the gates get only the public half, as FW_MALWARE_FEED_KEY.
  if [ ! -f "$DEMO/feed.key" ] || [ ! -f "$DEMO/feed.pub" ]; then
    in_container "$GO_IMAGE" go run ./scripts/feedsign -gen > "$DEMO/feed.keys"
    sed -n 2p "$DEMO/feed.keys" > "$DEMO/feed.key"
    sed -n 4p "$DEMO/feed.keys" > "$DEMO/feed.pub"
    rm -f "$DEMO/feed.keys"
    chmod 600 "$DEMO/feed.key"
  fi
  # The serial must rise with every snapshot: a gate refuses one older than the feed in force.
  in_container "$GO_IMAGE" go run ./scripts/feedsign -key "$DEMO/feed.key" -in "$new" -serial "$(date +%s)"
  # Signature first, then the feed, each by rename: the gate re-reads within a minute and
  # keeps the last good snapshot if it ever reads a pair that does not verify.
  mv -f "$new.sig" "$DEMO/feed/malware.ndjson.sig"
  mv -f "$new" "$DEMO/feed/malware.ndjson"
  chmod a+r "$DEMO/feed/malware.ndjson" "$DEMO/feed/malware.ndjson.sig"
  rows="$(grep -vc '^#' "$DEMO/feed/malware.ndjson" || true)"
  echo "  in force: $rows advisories (OpenSSF malicious-packages + 3 GitHub advisories), signed"
}

prepare() {
  mkdir -p "$DEMO/feed" "$DEMO/lists"
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
  chmod a+r "$DEMO/gitconfig"
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
  if [ ! -f "$DEMO/feed/malware.ndjson" ]; then build_feed; fi
  credentials
  say "building and starting the stack (first run builds every image; allow a few minutes)"
  "${COMPOSE[@]}" up -d --build
  wait_for "$CONTROL/healthz"
  wait_for "$CONSOLE/healthz"
  wait_for "$GATE/healthz"
  wait_for "$PYPI_GATE/healthz"
  cmd_status
  echo
  echo "Next: sh scripts/demo.sh seed"
}

cmd_feed() {
  prepare
  build_feed
  echo "  The gates re-read the feed within a minute; no restart needed."
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

# pull <workstation> <gate host> <path> <label>: one request through a gate, by outcome.
pull_via() {
  code="$(docker exec "yjdemo-dev-$1" curl -s -o /dev/null -w '%{http_code}' "http://$2:8080/$3" || echo 000)"
  case "$code" in
    200) verdict="served" ;;
    403) verdict="refused" ;;
    404) verdict="not found upstream" ;;
    *) verdict="HTTP $code" ;;
  esac
  printf '  %-40s %s\n' "$4" "$verdict"
}
pull() { pull_via "$1" firewall "$2" "$3"; }

# pull_py <workstation> <project>: a PyPI index request, reported by what pip would find.
# The PyPI gate does not refuse the index page: it serves it with every refused release
# marked yanked, the reason as the yank reason (PEP 592), and refuses the file itself. So
# a 200 alone says nothing; count the releases left installable.
pull_py() {
  page="$(docker exec "yjdemo-dev-$1" curl -s -w '\n%{http_code}' "http://firewall-pypi:8080/simple/$2/" || echo 000)"
  code="$(printf '%s' "$page" | tail -n 1)"
  links="$(printf '%s' "$page" | grep -c '<a ' || true)"
  yanked="$(printf '%s' "$page" | grep -c 'data-yanked=' || true)"
  case "$code" in
    200) if [ "$links" -gt 0 ] && [ "$links" = "$yanked" ]; then verdict="every release withheld ($links, each with the reason)"
         else verdict="served ($((links - yanked)) of $links files installable)"; fi ;;
    403) verdict="refused" ;;
    404) verdict="gone from PyPI (removed upstream; the verdict is in the audit log)" ;;
    *) verdict="HTTP $code" ;;
  esac
  printf '  %-40s %s\n' "$2 (PyPI)" "$verdict"
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

  say "known malware (refused on the gate, the registry is never asked)"
  pull 2 "crossenv" "crossenv (typosquat of cross-env)"
  pull 3 "electorn" "electorn (typosquat of electron)"
  pull 1 "ua-parser-js/-/ua-parser-js-0.7.29.tgz" "ua-parser-js 0.7.29 (hijacked release)"
  pull 3 "coa/-/coa-2.0.3.tgz" "coa 2.0.3 (hijacked release)"

  say "your block list"
  pull 2 "event-stream" "event-stream"
  pull 1 "colors" "colors"

  say "your allow list (served without scoring)"
  pull 3 "kind-of" "kind-of"

  say "low scores (refused, and sent to a person in Decisions)"
  for p in chalk left-pad is-odd; do pull 2 "$p" "$p"; done

  say "Python, through the PyPI gate"
  for p in requests flask six; do pull_py 1 "$p"; done
  pull_py 2 coloramaa
  pull_py 3 num2words

  say "done"
  echo "  Open $CONSOLE and sign in (sh scripts/demo.sh status). The Overview shows"
  echo "  what just happened; Decisions has the packages waiting on a person."
}

cmd_status() {
  credentials
  if [ -n "$FW_MALWARE_FEED_KEY" ]; then feed="signed OpenSSF feed"; else feed="OFFLINE four-entry list"; fi
  cat <<EOF

  Console   $CONSOLE
            user     $CONSOLE_AUTH_USER
            password $CONSOLE_AUTH_PASS
  npm gate  $GATE   (npm install --registry $GATE <package>)
  PyPI gate $PYPI_GATE   (pip install --index-url $PYPI_GATE/simple <package>)
  malware   $feed
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
  feed) cmd_feed ;;
  status) cmd_status ;;
  down) cmd_down ;;
  *) sed -n '2,19p' "$0"; exit 2 ;;
esac
