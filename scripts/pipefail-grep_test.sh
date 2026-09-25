#!/bin/sh
# Tests for scripts/pipefail-grep.sh.
#
# Two things have to be true for this guard to be worth its runtime, and they fail
# independently, so both are tested:
#
#   1. THE DEFECT IS REAL. Leg 0 reproduces it live — the same `grep -q`, in the same
#      shell, against a short and a long producer — rather than asserting the mechanism
#      from a comment. If that leg ever stops reproducing, the rule has outlived its
#      cause and this guard should be deleted, not weakened.
#   2. THE RECOGNISER IS HONEST. A guard that flagged everything, or that keyed on the
#      one spelling its author had in mind, would pass a review and report a smaller
#      total than the truth. So every refusal has a matching case that must stay GREEN:
#      the same grep without a pipe, the same pipe in a script that does not set
#      pipefail, and the prose that documents the idiom.
set -u

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
. "$ROOT/scripts/pipefail-grep.sh"

PASS=0
FAIL=0
ok()  { PASS=$((PASS + 1)); printf 'ok   %s\n' "$1"; }
bad() { FAIL=$((FAIL + 1)); printf 'FAIL %s\n' "$1"; }

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

# ── 0. THE MECHANISM, REPRODUCED ─────────────────────────────────────────────
#
# Needs a shell with pipefail, which `sh` is not required to have (dash does not).
# A missing bash is reported as NOT RUN rather than passed: a control that did not
# execute is not evidence, and silently counting it as green is the exact failure this
# whole guard exists to prevent.
NEEDLE="known-malware feed"
if command -v bash >/dev/null 2>&1; then
  # ⚠️ `"pipe""fail"` rather than the plain word, and it is not a loophole: bash sees
  # exactly `set -uo pipefail`. THIS FILE IS SCANNED BY THE GUARD IT TESTS, and the
  # fixture below IS the defect — a real piped `grep -q`. Written plainly, the guard
  # would read this test as a pipefail script full of violations and fail on its own
  # test. Disguising the line that turns the rule ON keeps the fixture honest while
  # leaving this file outside the rule's scope, which is where a fixture belongs.
  cat > "$TMP/mech.sh" <<'MECH'
set -uo "pipe""fail"
NEEDLE="known-malware feed"
short() { printf '%s\n' "$NEEDLE"; }
long()  { printf '%s\n' "$NEEDLE"; seq 1 200000; }
for p in short long; do
  if $p | grep -q "$NEEDLE"; then printf '%s pipe MATCHED\n' "$p"; else printf '%s pipe MISSED(%s)\n' "$p" "$?"; fi
  out=$($p)
  case "$out" in *"$NEEDLE"*) printf '%s capture MATCHED\n' "$p" ;; *) printf '%s capture MISSED\n' "$p" ;; esac
  n=$($p | grep -c "$NEEDLE")
  if [ "$n" -gt 0 ]; then printf '%s count MATCHED\n' "$p"; else printf '%s count MISSED\n' "$p"; fi
done
MECH
  bash "$TMP/mech.sh" > "$TMP/mech.out" 2>&1
  if grep -q '^short pipe MATCHED$' "$TMP/mech.out"; then
    ok "control: a SHORT producer piped into grep -q answers correctly (so the flake is size-dependent, not constant)"
  else
    bad "a short producer already missed — this test's own setup is wrong: $(cat "$TMP/mech.out")"
  fi
  if grep -q '^long pipe MISSED' "$TMP/mech.out"; then
    ok "THE DEFECT: a LONG producer piped into grep -q reports the needle ABSENT while it is present"
  else
    bad "the long producer MATCHED, so pipefail+SIGPIPE no longer breaks grep -q here; if that is true everywhere, delete this guard rather than relaxing it: $(cat "$TMP/mech.out")"
  fi
  if grep -q '^long capture MATCHED$' "$TMP/mech.out" && grep -q '^long count MATCHED$' "$TMP/mech.out"; then
    ok "BOTH REPLACEMENTS work on the same long producer (capture+case, and grep -c)"
  else
    bad "a replacement this guard recommends does not work: $(cat "$TMP/mech.out")"
  fi
else
  bad "NOT RUN: bash is unavailable, so the mechanism control did not execute and proves nothing"
fi

# ── scratch corpora ──────────────────────────────────────────────────────────
#
# write_script FILE PIPEFAIL BODY — a script that does or does not set pipefail.
write_script() {
  {
    printf '#!/usr/bin/env bash\n'
    [ "$2" = "yes" ] && printf 'set -uo pipefail\n'
    printf '%s\n' "$3"
  } > "$1"
}

# run_corpus FILES... — check_pipefail_grep over exactly these files, floors disabled.
run_corpus() {
  ( cd "$TMP" && YJ_SH_CORPUS="$*" YJ_SH_FLOOR=1 YJ_PIPEFAIL_FLOOR=1 \
      check_pipefail_grep > "$TMP/out" 2>&1; echo $? )
}

# ── 1. the clean shapes stay green ───────────────────────────────────────────
write_script "$TMP/clean1.sh" yes 'out=$(docker logs c); case "$out" in *"needle"*) echo yes ;; esac'
write_script "$TMP/clean2.sh" yes 'n=$(docker logs c | grep -c "needle"); [ "$n" -gt 0 ] && echo yes'
write_script "$TMP/clean3.sh" yes 'grep -q "needle" /var/log/thing && echo yes'
write_script "$TMP/clean4.sh" no  'docker logs c | grep -q "needle" && echo yes'
rc=$(run_corpus clean1.sh clean2.sh clean3.sh clean4.sh)
if [ "$rc" = "0" ]; then
  ok "clean: capture+case, grep -c, an unpiped grep -q, and a pipe in a NON-pipefail script all pass"
else
  bad "a clean shape was rejected: $(cat "$TMP/out")"
fi

# ── 2. ANTI-VACUITY FOR 1: the corpus was really read ────────────────────────
case "$(cat "$TMP/out")" in
  *"4 shell scripts"*) ok "the clean run examined all 4 files (it passed by reading, not by skipping)" ;;
  *) bad "the clean run did not report examining 4 files: $(cat "$TMP/out")" ;;
esac

# ── 3. the defect is refused, and located ────────────────────────────────────
write_script "$TMP/bad1.sh" yes 'docker logs c | grep -q "needle" && echo yes'
rc=$(run_corpus bad1.sh)
if [ "$rc" = "1" ] && grep -q '^bad1.sh:3:' "$TMP/out"; then
  ok "refused: a piped grep -q under pipefail, named by file and line"
else
  bad "a piped grep -q under pipefail was not refused at its line: rc=$rc $(cat "$TMP/out")"
fi

# ── 4. the spellings a narrow recogniser would miss ──────────────────────────
write_script "$TMP/bad2.sh" yes 'docker logs c | grep --quiet "needle"'
write_script "$TMP/bad3.sh" yes 'docker logs c | grep -qi "needle"'
write_script "$TMP/bad4.sh" yes 'docker logs c | grep -iq "needle"'
write_script "$TMP/bad5.sh" yes 'docker logs c | grep -E -q "a|b"'
write_script "$TMP/bad6.sh" yes 'zcat f.gz | zgrep -q "needle"'
for f in bad2 bad3 bad4 bad5 bad6; do
  rc=$(run_corpus "$f.sh")
  if [ "$rc" = "1" ]; then ok "refused: $(sed -n '3p' "$TMP/$f.sh")"
  else bad "NOT refused, so the recogniser reports a smaller total than the truth: $(sed -n '3p' "$TMP/$f.sh")"; fi
done

# ── 5. the precondition is real: no pipefail, no finding ─────────────────────
#
# The corpus carries a clean PIPEFAIL script beside it on purpose: a corpus with no
# pipefail script at all trips the detector floor instead, and would score this case
# red for a reason that has nothing to do with the precondition. (Measured — it did,
# the first time this test ran, which is the floor doing its job.)
write_script "$TMP/nopf.sh" no 'docker logs c | grep -qi "needle"'
rc=$(run_corpus clean1.sh nopf.sh)
if [ "$rc" = "0" ]; then
  ok "the same line in a script WITHOUT pipefail is not a finding (grep's own status is the answer there)"
else
  bad "flagged a pipeline in a script that does not set pipefail, so the rule is being applied for the wrong reason"
fi

# ── 6. prose about the idiom is not the idiom ────────────────────────────────
write_script "$TMP/prose.sh" yes '# never write: docker logs c | grep -q "needle"
echo fine'
rc=$(run_corpus prose.sh)
if [ "$rc" = "0" ]; then
  ok "a comment WARNING about the idiom is not itself a violation (two rigs carry exactly that comment)"
else
  bad "flagged a comment, which would force the existing warnings to be deleted to go green"
fi

# ── 7. the pipefail detector recognises how the rigs actually write it ───────
for form in 'set -o pipefail' 'set -uo pipefail' 'set -euo pipefail'; do
  printf '#!/usr/bin/env bash\n%s\ndocker logs c | grep -q x\n' "$form" > "$TMP/form.sh"
  rc=$(run_corpus form.sh)
  if [ "$rc" = "1" ]; then ok "detected pipefail written as \"$form\""
  else bad "\"$form\" was not recognised as pipefail, so every file writing it that way is skipped unexamined"; fi
done

# ── 8. the vacuity floors ────────────────────────────────────────────────────
rc=$( ( cd "$TMP" && YJ_SH_CORPUS="clean1.sh" check_pipefail_grep > "$TMP/out" 2>&1; echo $? ) )
if [ "$rc" = "1" ] && grep -q 'looked at nothing' "$TMP/out"; then
  ok "a corpus far smaller than the repo's fails loudly instead of reporting a clean scan"
else
  bad "the corpus floor did not fire: rc=$rc $(cat "$TMP/out")"
fi
i=0; files=""
while [ "$i" -lt 45 ]; do i=$((i + 1)); write_script "$TMP/n$i.sh" no 'echo hi'; files="$files n$i.sh"; done
rc=$( ( cd "$TMP" && YJ_SH_CORPUS="$files" YJ_PIPEFAIL_FLOOR=9 check_pipefail_grep > "$TMP/out" 2>&1; echo $? ) )
if [ "$rc" = "1" ] && grep -q 'set pipefail' "$TMP/out"; then
  ok "a full corpus in which NOTHING is seen to set pipefail fails too (the detector breaking is invisible in the file count)"
else
  bad "the pipefail-detector floor did not fire: rc=$rc $(cat "$TMP/out")"
fi

# ── 9. the replacements the rigs now carry ───────────────────────────────────
#
# `has`/`hasre` are DUPLICATED into every rig, because the rigs are standalone by
# design and share no library. Duplication's failure mode is drift: one copy is edited
# and the others quietly diverge. So the copies are compared to each other rather than
# to a remembered original, and then one of them is actually executed.
#
# The rig list is DERIVED (every tracked script defining the helper), not written here:
# a hand-listed corpus is bounded by whoever last remembered to update it, and a new
# rig would simply never be checked. That list includes THIS FILE, whose fixture below
# defines the helpers so it can execute them, and that is the point rather than an
# accident: the copy this test actually runs has to be the copy the rigs carry, or the
# behaviour proven here is the behaviour of something nothing ships.
RIGS=$(cd "$ROOT" && grep -l '^has()   {' $(git ls-files '*.sh') 2>/dev/null)
n_rigs=$(printf '%s\n' "$RIGS" | grep -c .)
if [ "$n_rigs" -ge 6 ]; then
  ok "$n_rigs rigs carry the replacement helpers"
else
  bad "only $n_rigs rigs define has(); the rewrite did not reach them all, or this leg is looking in the wrong place"
fi
first=""
same=yes
for r in $RIGS; do
  sed -n '/^has()   {/,/^hasre() {/p' "$ROOT/$r" | tr -d '\r' > "$TMP/defs.$$"
  if [ -z "$first" ]; then first="$TMP/defs.first"; cp "$TMP/defs.$$" "$first"
  elif ! cmp -s "$TMP/defs.$$" "$first"; then same=no; bad "$r's copy of has/hasre has drifted from the others"; fi
done
[ "$same" = "yes" ] && ok "every rig's copy of has/hasre is byte-identical"
cat > "$TMP/useh.sh" <<'USEH'
set -u
has()   { case "$1" in *"$2"*) return 0 ;; esac; return 1; }
hasre() { [ "$(printf '%s\n' "$1" | grep -ciE -- "$2")" -gt 0 ]; }
r=""
has "abcXdef" "X"      && r="$r found-substring"
has "abcdef"  "X"      || r="$r rejects-absent"
has 'a*b'     '*'      && r="$r literal-star"
has "x -- y"  "--"     && r="$r leading-dashes"
hasre "aXb"   'x'      && r="$r regex-caseless"
hasre "abc"   'z'      || r="$r regex-absent"
long=$(seq 1 200000)
hasre "$long" '^199999$' && r="$r long-input"
printf '%s\n' "$r"
USEH
got=$(sh "$TMP/useh.sh" 2>&1)
for want in found-substring rejects-absent literal-star leading-dashes regex-caseless regex-absent long-input; do
  case " $got " in
    *" $want "*) ok "helper behaviour: $want" ;;
    *) bad "helper behaviour FAILED: $want (got:$got)" ;;
  esac
done

# ── 10. THE WAY `vet` ACTUALLY CALLS IT: sourced, under `set -eu` ────────────
#
# Not paranoia. This guard's first CI run died here, silently, before printing a single
# line: `grep -c` exits 1 on a zero count, and `n=$(grep -c ...)` under `set -e` takes
# the whole vet gate down with it. Every leg above was green at the time, because they
# call check_pipefail_grep from a shell that does NOT set -e. A check tested differently
# from the way it is invoked has an untested call site, and this one failed there first.
rc=$( ( cd "$ROOT" && sh -c 'set -eu; . ./scripts/pipefail-grep.sh; check_pipefail_grep' > "$TMP/out" 2>&1; echo $? ) )
if [ "$rc" = "0" ] && grep -q 'no quiet grep after a pipe' "$TMP/out"; then
  ok "sourced and called under set -eu, exactly as dev.sh vet does, on a CLEAN repo"
else
  bad "died under set -eu, the way vet calls it (rc=$rc): $(cat "$TMP/out")"
fi
# And the violation path under the same conditions: the findings must be PRINTED before
# the non-zero return, or the gate goes red with nothing to act on.
rc=$( sh -c "set -eu; . '$ROOT/scripts/pipefail-grep.sh'; cd '$TMP'; YJ_SH_CORPUS=bad1.sh YJ_SH_FLOOR=1 YJ_PIPEFAIL_FLOOR=1 check_pipefail_grep" > "$TMP/out" 2>&1; echo $? )
if [ "$rc" = "1" ] && grep -q '^bad1.sh:3:' "$TMP/out"; then
  ok "under set -eu a violation is printed first, then returns non-zero"
else
  bad "under set -eu the violation path did not report before failing (rc=$rc): $(cat "$TMP/out")"
fi

# ── 11. the real repository ──────────────────────────────────────────────────
rc=$( ( cd "$ROOT" && check_pipefail_grep > "$TMP/out" 2>&1; echo $? ) )
if [ "$rc" = "0" ]; then
  ok "the repository is clean: $(cat "$TMP/out")"
else
  bad "$(cat "$TMP/out")"
fi

printf '\npipefail-grep tests: %s passed, %s failed\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
