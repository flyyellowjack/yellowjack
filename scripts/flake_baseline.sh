#!/usr/bin/env sh
# scripts/flake_baseline.sh — is this test failure MINE, or was it already there?
#
#   sh scripts/flake_baseline.sh <TestName> [runs] [--ref origin/main] [--pkg .] [--docker]
#
# Runs a test N times against a PRISTINE checkout of a baseline ref (default
# origin/main) in a throwaway worktree, and reports whether it fails there too.
#
#   exit 0 — it failed on the baseline as well → PRE-EXISTING, not your change
#   exit 1 — it passed every run on the baseline → your branch is implicated
#
# Why this exists
# ---------------
# The expensive mistake this prevents (2026-07-22): a Windows-only stress-test
# flake was reported as "main's CI is intermittently red" and a whole fix branch
# was built for it — while main had been green on Linux all along. The rule from
# that day is [[verify-flake-on-ci-platform]]: reproduce on the CI platform before
# escalating. This script is that rule, executable.
#
# --docker runs the baseline on LINUX (the golang image CI uses, same as race.sh).
# That matters: the async stress tests flake ~1-in-5 on the Windows host from an
# httptest accept-backlog overrun (GitLab issue #1) and are clean on Linux. Judging
# a flake by Windows behaviour alone is how you end up fixing a non-bug.
#
# The worktree is isolated on purpose: sibling sessions share this checkout and
# move HEAD around, so testing "the baseline" in place is not reproducible.
set -eu

ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
cd "$ROOT"

test_name=""
runs=10
ref="origin/main"
pkg="."
use_docker=0

while [ $# -gt 0 ]; do
  case "$1" in
    --ref)    ref="$2"; shift 2 ;;
    --pkg)    pkg="$2"; shift 2 ;;
    --docker) use_docker=1; shift ;;
    -h|--help) sed -n '2,28p' "$0"; exit 0 ;;
    *)
      if [ -z "$test_name" ]; then test_name="$1"
      else runs="$1"
      fi
      shift ;;
  esac
done

[ -n "$test_name" ] || { echo "usage: sh scripts/flake_baseline.sh <TestName> [runs] [--ref REF] [--pkg PKG] [--docker]" >&2; exit 2; }

git fetch origin --quiet 2>/dev/null || true
git rev-parse --verify "$ref" >/dev/null 2>&1 || { echo "unknown ref '$ref'" >&2; exit 2; }
base_sha="$(git rev-parse "$ref")"

# The baseline worktree sits NEXT TO the repo, not in $TMPDIR. On the Windows host
# `mktemp -d` yields an MSYS path (/tmp/…) that Docker Desktop resolves inside its
# own VM, so `-v` would mount an EMPTY directory — every run then "fails" with
# "go.mod file not found" and the script would report a pre-existing flake for a
# test it never ran. Caught while testing this script on 2026-07-26. A sibling of
# the repo root is a real filesystem path on both platforms.
wt="$ROOT/../.yj-flake-baseline-$$"
cleanup() {
  git worktree remove --force "$wt" >/dev/null 2>&1 || true
  rm -rf "$wt" 2>/dev/null || true
  # `remove` can fail (and its failure is deliberately swallowed so cleanup never
  # masks the test verdict), which leaves a registration pointing at a directory
  # we just deleted. Observed for real: two stale entries — one still holding a
  # FULL checkout — accumulated from this script's own test runs on 2026-07-26.
  # prune is idempotent and drops exactly those dangling entries.
  git worktree prune >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

# Also prune BEFORE we start: a previous run killed hard (SIGKILL, closed terminal)
# never got its trap, so its entry can still be here.
git worktree prune >/dev/null 2>&1 || true

echo "flake baseline"
echo "  test    : $test_name"
echo "  baseline: $ref ($base_sha)"
echo "  runs    : $runs"
echo "  platform: $([ "$use_docker" = "1" ] && echo 'linux (docker golang:1.26 — the CI platform)' || echo "$(uname -s) host")"
echo ""

git worktree add --detach --quiet "$wt" "$base_sha" || { echo "could not create baseline worktree" >&2; exit 2; }

# Docker needs the path as the HOST sees it (C:/... on Windows), not the MSYS view.
wt_mount="$(cd "$wt" && { pwd -W 2>/dev/null || pwd; })"

if [ "$use_docker" = "1" ]; then
  export MSYS_NO_PATHCONV=1
  # PREFLIGHT: prove the container can actually see the checkout before we start
  # counting failures. Without this, a bad mount reads as "the test fails on Linux"
  # — a wrong verdict delivered with total confidence, which is worse than no
  # script at all. This is the bug this script shipped with for ten minutes.
  if ! docker run --rm -v "$wt_mount:/src" -w /src golang:1.26 test -f go.mod 2>/dev/null; then
    echo "docker cannot see the baseline checkout at $wt_mount (no go.mod inside the container)." >&2
    echo "Refusing to report a verdict from runs that never compiled the code." >&2
    exit 2
  fi
fi

fails=0
i=1
while [ "$i" -le "$runs" ]; do
  if [ "$use_docker" = "1" ]; then
    export MSYS_NO_PATHCONV=1
    ok=0
    docker run --rm -v "$wt_mount:/src" -w /src -e GOFLAGS=-mod=readonly \
      golang:1.26 go test -run "^${test_name}\$" -count=1 "$pkg" >/dev/null 2>&1 || ok=1
  else
    ok=0
    ( cd "$wt" && go test -run "^${test_name}\$" -count=1 "$pkg" ) >/dev/null 2>&1 || ok=1
  fi
  if [ "$ok" = "1" ]; then
    fails=$((fails + 1))
    printf 'run %s/%s: FAIL\n' "$i" "$runs"
  else
    printf 'run %s/%s: pass\n' "$i" "$runs"
  fi
  i=$((i + 1))
done

echo ""
if [ "$fails" -gt 0 ]; then
  echo "VERDICT: PRE-EXISTING — '$test_name' failed $fails/$runs times on $ref itself."
  echo "Your branch did not cause it. Do not 'fix' it as part of your change;"
  echo "file or reference the existing issue instead."
  exit 0
fi

echo "VERDICT: NOT REPRODUCED on $ref — '$test_name' passed $runs/$runs there."
if [ "$use_docker" = "1" ]; then
  echo ""
  echo "That was the CI PLATFORM (Linux). If it fails on your Windows host but is"
  echo "clean here, it is a host-specific flake — NOT a CI problem and NOT evidence"
  echo "your change broke anything. Check for an existing issue before filing:"
  echo "the async stress tests are known to do exactly this (GitLab issue #1)."
else
  echo ""
  echo "The failure is likely yours — but re-run with --docker before concluding."
  echo "A test can be clean on this baseline and still be a host-only flake."
fi
echo ""
echo "Note that $runs runs cannot prove absence: for a ~1-in-5 flake, 10 clean runs"
echo "still leave a ~10% chance of missing it. Raise the run count when in doubt."
exit 1
