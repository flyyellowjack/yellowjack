#!/usr/bin/env sh
# scripts/staleness_test.sh — does the staleness classifier actually discriminate?
#
# Run by the vet gate. The important cases are not "does it notice 275 commits" (easy)
# but the two that manufacture false confidence:
#
#   1. a checkout that has never fetched reports ZERO commits behind, so "0" must not
#      mean "current" unless a fetch succeeded;
#   2. an unparseable count must not read as zero either.
#
# Both are asserted, and the NEGATIVE CONTROL at the end proves this file can go red —
# without it, a classifier that answered "fresh" to everything would pass the happy
# cases and the whole test would be decoration.
set -eu

ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
. "$ROOT/scripts/staleness.sh"

fails=0
check() {
  want="$1"; got="$2"; what="$3"
  if [ "$got" = "$want" ]; then
    echo "  ok   $what"
  else
    echo "  FAIL $what: got '$got', want '$want'"
    fails=$((fails + 1))
  fi
}

echo "staleness: a VERIFIED count is an answer"
check "fresh"          "$(classify_staleness ok 0 20)"    "a fetched checkout at origin/main is fresh"
check "behind:5"       "$(classify_staleness ok 5 20)"    "a small verified drift warns"
check "behind:19"      "$(classify_staleness ok 19 20)"   "just under the threshold still only warns"
check "far-behind:20"  "$(classify_staleness ok 20 20)"   "the threshold itself refuses"
check "far-behind:275" "$(classify_staleness ok 275 20)"  "the 2026-09-02 drift refuses"

echo "staleness: THE REGRESSION — an unfetched checkout is not a current one"
check "unverified" "$(classify_staleness fail 0 20)"   "0 behind WITHOUT a fetch is unverified, never fresh"
check "unverified" "$(classify_staleness fail 275 20)" "a large count without a fetch is still unverified"
check "unverified" "$(classify_staleness ok '' 20)"    "an empty count is unverified, not zero"
check "unverified" "$(classify_staleness ok 'abc' 20)" "a non-numeric count is unverified, not zero"

echo "staleness: every drift on the record would have been refused"
# The threshold was chosen from these numbers rather than picked round, so they are the
# test. If someone raises YJ_STALE_MAX, this is what should stop them doing it quietly.
for n in 22 162 227 275; do
  case "$(classify_staleness ok "$n")" in
    far-behind:*) echo "  ok   $n behind is refused at the default threshold" ;;
    *) echo "  FAIL $n behind is NOT refused at the default threshold — a drift that has already cost us a day would pass"
       fails=$((fails + 1)) ;;
  esac
done

echo "staleness: NEGATIVE CONTROL — the classifier must be able to disagree"
# Without this, a classifier that returned the same string for every input would satisfy
# any single assertion above that happened to expect that string. The property asserted
# is DISCRIMINATION: the four outcomes must be four, not one.
distinct="$(printf '%s\n%s\n%s\n%s\n' \
  "$(classify_staleness ok 0 20)" \
  "$(classify_staleness ok 5 20)" \
  "$(classify_staleness ok 99 20)" \
  "$(classify_staleness fail 0 20)" | sort -u | wc -l | tr -d ' ')"
check "4" "$distinct" "fresh / behind / far-behind / unverified are four distinct verdicts"

# And the message must actually change with the verdict, or an operator reads the same
# sentence whatever happened.
if [ "$(staleness_message fresh)" = "$(staleness_message unverified)" ]; then
  echo "  FAIL the message is identical for 'fresh' and 'unverified' — the distinction is invisible where it matters"
  fails=$((fails + 1))
else
  echo "  ok   the operator message distinguishes 'current' from 'could not tell'"
fi

if [ "$fails" -ne 0 ]; then
  echo "staleness: $fails check(s) FAILED" >&2
  exit 1
fi
echo "staleness: classifier checks passed (including the negative control)"

echo "staleness: the guard must NOT fire in CI"
# CI's vet job runs `dev.sh vet`, and on a runner "behind main" is the normal state of
# any branch -- plus the clone is shallow, so the count may be absent or wrong. Without
# the CI bypass this guard could redden a pipeline for a healthy branch, which is how a
# guard gets disabled wholesale.
#
# DRIVEN BY A STUB, and that is the point. The obvious test -- "call check_staleness with
# CI=true and assert silence" -- passes whether or not the bypass exists, because this
# worktree is current and a current tree is silent anyway. It would only discriminate on
# a machine that happened to be stale, i.e. never on the runner that checks it. So
# measure_staleness is replaced with one that always reports a large VERIFIED drift, and
# the two calls below then differ only in the bypass.
measure_staleness() { echo "ok 275"; }

# Same `set -e` care as the control below: if the bypass ever regresses this call
# starts returning non-zero, and a bare $? after the assignment would abort the
# script with no diagnostic -- red, but for an unreadable reason.
if ci_out="$(CI=true check_staleness 2>&1)"; then ci_rc=0; else ci_rc=$?; fi
check "0" "$ci_rc" "check_staleness succeeds under CI=true even at 275 behind"
if [ -n "$ci_out" ]; then
  echo "  FAIL the guard fired under CI=true: '$ci_out'"
  fails=$((fails + 1))
else
  echo "  ok   the guard is silent under CI=true"
fi

# THE CONTROL: the same stubbed drift, outside CI, must REFUSE. Without this the
# assertion above is satisfied by a check_staleness that does nothing at all.
# `set -e` would kill the script on this deliberately-failing call if its status were
# taken with a bare $? after the assignment, so the status is captured in the
# conditional itself. (Caught by running this file unpiped: `sh f | tail` reports
# TAIL's exit code, which is this project's own documented trap.)
if host_out="$(env -u CI -u GITLAB_CI sh -c ". \"$ROOT/scripts/staleness.sh\"; measure_staleness() { echo \"ok 275\"; }; check_staleness" 2>&1)"; then
  host_rc=0
else
  host_rc=$?
fi
if [ "$host_rc" -eq 0 ]; then
  echo "  FAIL the same 275-commit drift did NOT refuse outside CI, so the CI assertion proves nothing"
  fails=$((fails + 1))
else
  echo "  ok   the same drift refuses outside CI (rc=$host_rc)"
fi
case "$host_out" in
  *"275 commit"*) echo "  ok   the refusal names the actual drift" ;;
  *) echo "  FAIL the refusal does not name the drift: '$host_out'"; fails=$((fails + 1)) ;;
esac

if [ "$fails" -ne 0 ]; then
  echo "staleness: $fails check(s) FAILED" >&2
  exit 1
fi
echo "staleness: CI-bypass checks passed (including the control)"
