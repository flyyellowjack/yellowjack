#!/bin/sh
# pipefail-grep.sh — `grep -q` on the right of a pipe LIES in a script that sets
# `pipefail`, and every e2e rig sets it.
#
# ── WHY ──────────────────────────────────────────────────────────────────────
#
# `grep -q` exits at the FIRST match and closes the pipe. The producer's next write
# then gets EPIPE, and a Go program writing to stdout (docker, docker compose, glab,
# our own binaries) re-raises SIGPIPE and dies with status 141. `pipefail` makes the
# pipeline's status that of the failed producer rather than grep's — so the `if` takes
# the FALSE branch and a string that IS PRESENT reads as ABSENT.
#
# It is SIZE-DEPENDENT, which is what makes it a flake rather than a bug: when the
# producer finishes writing before grep exits, nothing is killed, the status is grep's,
# and the test is correct. Measured with a control, same shell, same grep:
#
#     one-line producer      | grep -q "known-malware feed"  ->  MATCHED
#     400,000-line producer  | grep -q "known-malware feed"  ->  NOT MATCHED (141)
#     either, captured first, matched with `case`            ->  MATCHED
#
# So a rig carries this for months and only starts failing once its logs grow. That is
# exactly what happened on 2026-09-22: `e2e-local-async` leg 21b reported *"the firewall
# did not report a known-malware feed at startup, so FW_MALWARE_LIST is not reaching
# it"* — while the next three assertions IN THE SAME LEG proved the feed was loaded,
# reloaded and enforced. The leg was reading `compose logs firewall | grep -q`, four
# minutes into a run whose firewall log grows every five seconds. Two other legs in the
# same run read the SAME log correctly, one by capturing it and one with `grep -c`.
#
# A rig that reports a product failure it did not observe is worse than one that misses
# a real defect: it spends an engineer's attention on a bug that does not exist, and it
# teaches everyone to re-run the pipeline instead of reading it.
#
# ── WHY A GUARD AND NOT A COMMENT ────────────────────────────────────────────
#
# Because the comment was already written. `e2e/ha_drill.sh` and `e2e/helm_list_drill.sh`
# each carry a note warning against this exact idiom — and it was then written three
# more times, in three other rigs, by people who had no reason to read those files. A
# lesson that lives in a comment protects the file it is in.
#
# ── THE RULE ─────────────────────────────────────────────────────────────────
#
# In a script that sets `pipefail`, never put `grep -q` (or `--quiet`) after a pipe.
# Both replacements read better than what they replace:
#
#     out=$(producer); case "$out" in *"needle"*) ... ;; esac   # no pipe at all
#     n=$(producer | grep -c PATTERN); [ "$n" -gt 0 ]           # grep -c reads to EOF
#
# `grep -q PATTERN file` is fine: nothing is upstream to kill. A script that does NOT
# set `pipefail` is fine too — the pipeline's status is grep's own, which is the answer
# being asked for. That precondition is the rule, not a detail of it, and the test
# proves the guard honours it.
#
# Sourced by scripts/dev.sh vet (offline, no network) and by its own test.

set -u

# THE CORPUS IS DERIVED, NOT LISTED. A hand-maintained list of rigs is bounded by
# whoever last remembered to edit it, and the failure mode is silent: a new rig is
# simply never examined. `git ls-files` asks the repo instead. YJ_SH_CORPUS exists for
# the test, which needs to point the same code at a scratch corpus.
: "${YJ_SH_CORPUS:=}"

# Anti-vacuity floors, measured on 2026-09-22: 47 tracked *.sh files, 11 of which set
# pipefail. Set below the measured counts so ordinary churn does not trip them, and
# above zero so a wrong working directory, a rename or a broken `git ls-files` fails
# LOUDLY instead of reporting a clean scan of nothing.
: "${YJ_SH_FLOOR:=40}"
: "${YJ_PIPEFAIL_FLOOR:=9}"

# sh_files — every tracked shell script, or the explicit corpus the test supplies.
sh_files() {
  if [ -n "$YJ_SH_CORPUS" ]; then
    # shellcheck disable=SC2086  # deliberate word splitting: a space-separated list
    printf '%s\n' $YJ_SH_CORPUS
    return 0
  fi
  git ls-files '*.sh' 2>/dev/null
}

# sets_pipefail FILE — does this script turn on pipefail? Covers `set -o pipefail`,
# `set -uo pipefail`, `set -euo pipefail`. Reads a FILE argument, so this grep has
# nothing upstream of it to kill.
sets_pipefail() {
  grep -qE '^[[:space:]]*set[[:space:]]+-[a-zA-Z]*o[[:space:]]+pipefail([[:space:]]|$)' "$1"
}

# quiet_greps FILE — every line putting a quiet grep after a pipe, as "line:text".
#
# Keyed on the SHAPE rather than on the literal "| grep -q": `-qi`, `-iq`, `-E -q` and
# `--quiet` are the same defect, and a recogniser that matched only the common spelling
# would report a smaller total while looking thorough.
#
# Full-line comments are excluded because two rigs document this very idiom in prose,
# and a guard that forced the warnings to be deleted would be trading a comment for a
# check rather than adding one.
#
# `|| true` because "this file is clean" is an ANSWER, not a failure, and grep says it
# with exit 1. dev.sh sources this under `set -eu`, where an unguarded non-zero kills
# the whole vet gate -- which is exactly what happened on this guard's first CI run,
# silently, before it printed a single line. See the `set -eu` legs in the test.
quiet_greps() {
  grep -nE '\|[[:space:]]*z?grep[[:space:]]+(-[a-zA-Z]+[[:space:]]+)*(-[a-zA-Z]*q[a-zA-Z]*|--quiet)([[:space:]]|$)' "$1" 2>/dev/null |
    grep -vE '^[0-9]+:[[:space:]]*#' || true
}

# check_pipefail_grep — the gate. Prints every violation, returns 1 if any.
check_pipefail_grep() {
  rc=0
  files=0
  pipefail_files=0
  hits=0
  for f in $(sh_files); do
    [ -f "$f" ] || continue
    files=$((files + 1))
    sets_pipefail "$f" || continue
    pipefail_files=$((pipefail_files + 1))
    found=$(quiet_greps "$f")
    if [ -n "$found" ]; then
      # `wc -l`, not `grep -c`: counting must not be able to fail. A counter whose exit
      # status can be 1 is how this guard killed its own gate the first time.
      printf '%s\n' "$found" | sed "s|^|$f:|"
      hits=$((hits + $(printf '%s\n' "$found" | wc -l)))
      rc=1
    fi
  done
  if [ "$rc" -ne 0 ]; then
    printf '\npipefail-grep: %s quiet grep(s) after a pipe, in scripts that set pipefail.\n' "$hits"
    printf '    grep -q exits at the first match; the producer is then killed by SIGPIPE, and\n'
    printf '    pipefail reports the PIPELINE as failed -- so a string that IS present reads as\n'
    printf '    ABSENT, but only once the producer grows big enough to still be writing. Use:\n'
    printf '        out=$(producer); case "$out" in *"needle"*) ... ;; esac\n'
    printf '        n=$(producer | grep -c PATTERN); [ "$n" -gt 0 ]\n'
  fi
  # ANTI-VACUITY. Every assertion above sits inside a loop over git-tracked files, so a
  # wrong working directory or a broken corpus prints nothing and returns 0 -- which
  # reads exactly like "no rig has this defect".
  if [ "$files" -lt "$YJ_SH_FLOOR" ]; then
    printf 'pipefail-grep: only %s shell scripts were examined, fewer than this repo has (floor %s).\n' "$files" "$YJ_SH_FLOOR"
    printf '    The check found nothing because it looked at nothing.\n'
    return 1
  fi
  # The second floor is the one that matters: the corpus could be complete while the
  # pipefail DETECTOR silently matches nothing, and then every file is skipped before
  # it is ever examined. That failure is invisible in the count above.
  if [ "$pipefail_files" -lt "$YJ_PIPEFAIL_FLOOR" ]; then
    printf 'pipefail-grep: only %s of %s scripts were seen to set pipefail (floor %s).\n' "$pipefail_files" "$files" "$YJ_PIPEFAIL_FLOOR"
    printf '    Either the rigs stopped setting it, or sets_pipefail no longer recognises how they do.\n'
    return 1
  fi
  if [ "$rc" -eq 0 ]; then
    printf 'pipefail-grep: %s shell scripts, %s set pipefail, no quiet grep after a pipe\n' "$files" "$pipefail_files"
  fi
  return "$rc"
}
