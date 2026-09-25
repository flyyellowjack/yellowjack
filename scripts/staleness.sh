#!/usr/bin/env sh
# scripts/staleness.sh — is this checkout current enough for its answer to mean anything?
#
# THE FAILURE THIS EXISTS FOR IS SILENT, which is why prose did not stop it happening
# five times. A stale checkout does not read as stale: it reads as a normal tree with
# edits in it, and it goes GREEN, because it is internally consistent. Recorded drift
# and what it cost:
#
#   2026-07-22   22 behind   rebuilt a feature that was already merged
#   2026-08-02  162 behind   fixed a function that had since been renamed
#   2026-08-19  227 behind   3 of 4 "ready to merge" claims wrong, one destructive
#   2026-08-23  275 behind   told the product owner two shipped features were unbuilt
#   2026-09-02  275 behind   ran `dev.sh vet` in it and read exit 0 as "the branch is clean"
#
# The last one is the reason this lives in the task runner rather than in a checklist.
# That tree predated most of the gate: its scripts/ held 9 files where the branch's held
# 19, so gofmt_check, pipeline_read and e2e_gate_check were not there to run. A stale
# tree does not FAIL the gate — it runs a smaller, older gate and PASSES it. The green
# was true and meaningless.
#
# 🚨 THE TRAP INSIDE THE OBVIOUS CHECK. `git rev-list --count HEAD..origin/main` reports
# ZERO for a checkout that has never fetched, because origin/main is then whatever it was
# when the clone happened — or absent. So the naive check reports "current" most
# confidently exactly when it knows least. That is why "fresh" is reachable ONLY through
# a fetch that actually succeeded, and why "we could not check" is its own outcome and
# never folds into "fine".
#
# Usage:
#   . scripts/staleness.sh          # then call classify_staleness / check_staleness
#   sh scripts/staleness.sh         # run the check standalone and print the verdict

# How far behind is too far. 20 sits just under the SMALLEST drift that has actually
# cost us anything (22, above) — chosen from the record rather than picked round, so
# every incident on that list would have been refused. Raise it only with a new row on
# that table justifying the raise.
: "${YJ_STALE_MAX:=20}"
# How long to let the freshness fetch take. Short on purpose: this runs before every
# task, and a task runner that can hang on the network is worse than one that
# occasionally cannot tell. On this host the credential manager alone can take ~45s
# (see the git-push-hang note), so a fetch that exceeds this is EXPECTED, not alarming.
: "${YJ_STALE_FETCH_TIMEOUT:=20}"

# classify_staleness <fetch_ok> <behind> [max]
#
# Pure: no git, no network, no filesystem — so the table test can drive every branch,
# including the ones a real repo cannot easily be put into.
#
# Outcomes, and why there are four rather than a boolean:
#   unverified    the freshness fetch did not succeed, so `behind` is a guess about a
#                 ref that may itself be old. WARN, never refuse: refusing on a network
#                 blip would be a worse failure than the one being prevented, and this
#                 host's network fails asymmetrically often enough to matter.
#   fresh         fetch succeeded AND behind == 0. The only outcome that means current.
#   behind:<n>    verified behind, but under the threshold. WARN.
#   far-behind:<n> verified behind past the threshold. REFUSE.
classify_staleness() {
  fetch_ok="$1"; behind="$2"; max="${3:-$YJ_STALE_MAX}"

  # A non-numeric count is a parse failure, not a zero. Reading it as zero is the same
  # class of mistake as the never-fetched case: it manufactures confidence.
  case "$behind" in
    ''|*[!0-9]*) echo "unverified"; return 0 ;;
  esac

  if [ "$fetch_ok" != "ok" ]; then
    echo "unverified"
    return 0
  fi
  if [ "$behind" -eq 0 ]; then
    echo "fresh"
  elif [ "$behind" -ge "$max" ]; then
    echo "far-behind:$behind"
  else
    echo "behind:$behind"
  fi
}

# staleness_message <verdict> — the operator-facing text. Separated from the classifier
# so the test can assert on the VERDICT (stable) rather than on wording (not).
staleness_message() {
  n="${1#*:}"
  case "$1" in
    fresh)      echo "checkout is current with origin/main" ;;
    unverified) echo "could not verify freshness against origin/main (fetch failed or timed out). \
Nothing below proves this tree is current — a never-fetched checkout reports 0 commits behind." ;;
    behind:*)   echo "checkout is $n commit(s) behind origin/main. Results here describe an older \
tree than the one you would merge into." ;;
    far-behind:*) echo "checkout is $n commit(s) behind origin/main — past the YJ_STALE_MAX=$YJ_STALE_MAX \
threshold. A tree this old runs an OLDER gate and passes it, so a green result here is true and \
meaningless. Rebase, or work in a worktree cut from origin/main. Set YJ_ALLOW_STALE=1 to proceed anyway." ;;
    *)          echo "unrecognised staleness verdict: $1" ;;
  esac
}

# measure_staleness — attempts the freshness fetch and prints "<fetch_ok> <behind>".
# Best-effort by construction: a failed fetch is reported, never fatal.
measure_staleness() {
  _ok=fail
  if timeout "$YJ_STALE_FETCH_TIMEOUT" git fetch --quiet origin main >/dev/null 2>&1; then
    _ok=ok
  fi
  # FETCH_HEAD rather than origin/main: `git fetch origin main` updates FETCH_HEAD on
  # every git version, whereas whether it also moves the remote-tracking ref has varied.
  # Falling back to origin/main keeps the count available when the fetch failed — and
  # that count is exactly what the "unverified" verdict exists to distrust.
  _ref=FETCH_HEAD
  if [ "$_ok" != "ok" ] || ! git rev-parse --verify --quiet FETCH_HEAD >/dev/null 2>&1; then
    _ref=origin/main
  fi
  _behind="$(git rev-list --count "HEAD..$_ref" 2>/dev/null || echo "")"
  echo "$_ok $_behind"
}

# check_staleness — the whole check. Prints a line, and exits 1 ONLY on a verified
# far-behind without an explicit override.
check_staleness() {
  # NOT IN CI, and this is a correctness requirement rather than a speed one.
  #
  # This guard asks "is the tree you are testing older than main?" — a question that is
  # meaningful for a long-lived developer checkout and MEANINGLESS on a runner, where the
  # checkout IS the thing under test and being behind main is the normal state of any
  # branch. Worse, GitLab clones shallowly, so the history needed to count commits may
  # simply not be present: the count would come out empty or wrong.
  #
  # CI's vet job invokes `dev.sh vet`, so without this the guard could fail the pipeline
  # for a branch that is perfectly fine — a self-inflicted red, and exactly the sort of
  # false alarm that gets a guard disabled wholesale.
  if [ -n "${CI:-}" ] || [ -n "${GITLAB_CI:-}" ]; then
    return 0
  fi
  set -- $(measure_staleness)
  _verdict="$(classify_staleness "${1:-fail}" "${2:-}")"
  case "$_verdict" in
    fresh) return 0 ;;
    far-behind:*)
      echo "dev.sh: STALE CHECKOUT — $(staleness_message "$_verdict")" >&2
      if [ "${YJ_ALLOW_STALE:-}" = "1" ]; then
        echo "dev.sh: proceeding anyway (YJ_ALLOW_STALE=1)" >&2
        return 0
      fi
      return 1 ;;
    *)
      echo "dev.sh: NOTE — $(staleness_message "$_verdict")" >&2
      return 0 ;;
  esac
}

# Standalone invocation, so the check is runnable and inspectable on its own.
case "${0##*/}" in
  staleness.sh)
    ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
    cd "$ROOT"
    check_staleness
    ;;
esac
