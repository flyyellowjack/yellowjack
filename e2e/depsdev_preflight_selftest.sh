#!/usr/bin/env bash
# Self-test for e2e/depsdev_preflight.sh — the check that checks the checker.
#
# WHY THIS EXISTS. The preflight's whole job is to FAIL in specific ways: to tell a red
# pipeline apart from a rate-limited one, and both from stale test data. A preflight that
# has quietly become incapable of failing is worse than none — it converts an unknown into
# false confidence, and it would do so silently, because in the happy case its output is
# identical either way. CLAUDE.md's rule: prove a new assertion CAN fail before trusting
# it. This encodes that proof so it re-runs on every pipeline instead of being a thing
# somebody did once by hand.
#
# Fully OFFLINE and deterministic: every case runs against a local fake, so this never
# touches api.deps.dev and can never itself be flaky. (The live positive control is the
# real rig running immediately afterwards.)
#
# Run:  bash e2e/depsdev_preflight_selftest.sh
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
FAIL=0
PY="${PYTHON:-python3}"
command -v "$PY" >/dev/null 2>&1 || PY=python
command -v "$PY" >/dev/null 2>&1 || { echo "SKIP-IMPOSSIBLE: no python to run the fake deps.dev; refusing to report success"; exit 2; }

# Plain `mktemp`, no template: BusyBox (alpine, which the CI job runs) requires the X's at
# the END of a template, so the `ddfake.XXXXXX.py` form that works in Git Bash fails there
# with "mktemp: : Invalid argument". Python does not need a .py suffix to run a file.
FAKE="$(mktemp)" || { echo "SELF-TEST CANNOT RUN: mktemp failed; refusing to report success" >&2; exit 2; }
cat > "$FAKE" <<'PYEOF'
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
MODE, PORT = sys.argv[1], int(sys.argv[2])
CODES = {"ratelimit": 429, "missing": 404, "ghost": 200, "teapot": 418}
class H(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    def do_GET(self):
        self.send_response(CODES[MODE])
        self.send_header("Content-Length", "2"); self.end_headers(); self.wfile.write(b"{}")
    def log_message(self, *a): pass
ThreadingHTTPServer(("127.0.0.1", PORT), H).serve_forever()
PYEOF
trap 'rm -f "$FAKE"' EXIT

# case <mode> <port> <profile> <expected-exit> <expected-message-fragment> <description>
case_run() {
  local mode="$1" port="$2" profile="$3" want="$4" frag="$5" desc="$6" pid out got
  "$PY" "$FAKE" "$mode" "$port" >/dev/null 2>&1 &
  pid=$!
  # Wait for the fake, and if it never comes up say SO. Without this, a fake that failed
  # to start makes every case report "expected 3, got 5 (unreachable)" — six confusing
  # assertion failures pointing at the preflight, when the real fault is in this harness.
  # That is exactly how the first CI run of this file read before `mktemp` was fixed.
  local tries=0 ready=""
  while [ "$tries" -lt 100 ]; do
    if curl -s -o /dev/null "http://127.0.0.1:$port/ready" 2>/dev/null; then ready=1; break; fi
    tries=$((tries + 1)); sleep 0.1
  done
  if [ -z "$ready" ]; then
    kill "$pid" 2>/dev/null; wait "$pid" 2>/dev/null
    printf 'SELF-TEST HARNESS BROKEN: the fake deps.dev never came up on port %s (%s).\n' "$port" "$desc" >&2
    printf '  This is a fault in this self-test, NOT in depsdev_preflight.sh. Not reporting success.\n' >&2
    FAIL=1; return
  fi
  out="$(DEPSDEV_BASE="http://127.0.0.1:$port" bash e2e/depsdev_preflight.sh "$profile" 2>&1)"
  got=$?
  kill "$pid" 2>/dev/null; wait "$pid" 2>/dev/null
  if [ "$got" != "$want" ]; then
    printf 'FAIL: %s -> exit %s, want %s\n' "$desc" "$got" "$want"; FAIL=1; return
  fi
  case "$out" in
    *"$frag"*) printf 'PASS: %s -> exit %s, names it\n' "$desc" "$got" ;;
    *) printf 'FAIL: %s -> exit %s (right) but message never says %q\n' "$desc" "$got" "$frag"
       printf '%s\n' "$out" | tail -6; FAIL=1 ;;
  esac
}

echo "=== self-test: the preflight must FAIL, and fail distinguishably ==="

# The flake the whole thing exists for: deps.dev throttling a shared runner IP.
#
# The fragment names npm/lodash DELIBERATELY, not just "RATE LIMITING". The preflight has
# two independent loops (must-exist, must-not-exist) with their own 429 branches, and the
# first version of this self-test only asserted the exit code — so when the must-exist
# loop was sabotaged to wave 429 through, the run STILL exited 3, because the second loop
# caught it further down. The case passed while the branch it was meant to cover was
# broken. Pinning the first-checked package makes each loop's branch independently
# detectable. (Found by sabotaging the preflight and watching this case stay green.)
case_run ratelimit 9411 verifyrepo 3 "npm/lodash" "429 on the must-exist check is reported as rate-limiting (exit 3)"
case_run ratelimit 9412 async      3 "RATE LIMITING" "...and on the async profile too"
case_run ratelimit 9416 verifyrepo 3 "RATE LIMITING" "...and the message says rate-limiting, not just some failure"

# Premise drift, which unlike a 429 does NOT clear on a re-run.
case_run missing 9413 verifyrepo 4 "no longer has a record" "a package the legs need is gone from deps.dev (exit 4)"

# The subtle one: leg G proves a package with NO deps.dev record fails closed. If that
# name ever gets published, the leg still PASSES while testing something else entirely.
case_run ghost 9414 verifyrepo 4 "now HAS a deps.dev record" "leg G's never-published name now exists (exit 4)"

# An unexpected status must not be waved through as "fine".
case_run teapot 9415 verifyrepo 4 "unexpected HTTP 418" "an unexpected status is drift, not success (exit 4)"

# Nothing listening at all.
out="$(DEPSDEV_BASE="http://127.0.0.1:9" bash e2e/depsdev_preflight.sh verifyrepo 2>&1)"; got=$?
if [ "$got" = "5" ] && case "$out" in *"UNREACHABLE"*) true ;; *) false ;; esac; then
  echo "PASS: unreachable deps.dev is reported as unreachable (exit 5)"
else
  echo "FAIL: unreachable -> exit $got, want 5 with an UNREACHABLE message"; FAIL=1
fi

# A bad profile must not silently check nothing.
out="$(bash e2e/depsdev_preflight.sh not-a-profile 2>&1)"; got=$?
if [ "$got" = "2" ]; then echo "PASS: an unknown profile is rejected (exit 2)"
else echo "FAIL: unknown profile -> exit $got, want 2"; FAIL=1; fi

echo "=== RESULT ==="
if [ "$FAIL" = "0" ]; then
  echo "PREFLIGHT SELF-TEST: PASS — it still fails when it should"
else
  echo "PREFLIGHT SELF-TEST: FAIL — the preflight can no longer be trusted to catch what it claims"
fi
exit "$FAIL"
