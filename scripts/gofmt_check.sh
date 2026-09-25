#!/usr/bin/env sh
# scripts/gofmt_check.sh — is every COMMITTED Go blob gofmt-clean?
#
#   sh scripts/gofmt_check.sh           # check; exit 1 if anything is unformatted
#   sh scripts/gofmt_check.sh --fix     # rewrite the offenders (see the CRLF note)
#
# Why this exists, and why it does NOT just run `gofmt -l .`
# ---------------------------------------------------------
# Two CRLF traps cost real time on 2026-07-26 (MR !49, where eight files' blobs
# had silently drifted because nothing enforced formatting):
#
#   1. `gofmt -l .` on the Windows dev host flags ESSENTIALLY EVERY FILE. The
#      working tree is CRLF (core.autocrlf) and gofmt wants LF, so every line
#      reads as changed. That is a false alarm, and it trains you to ignore the
#      one real hit buried in it.
#   2. `gofmt -w` on a CRLF working-tree file SILENTLY FAILS to apply doc-comment
#      fixes. The trailing \r stops an indented block being recognised, so gofmt
#      exits 0 having changed nothing that matters — it reports success while
#      leaving the blob unformatted. Four of !49's eight files looked already-fixed
#      because of this.
#
# The escape from both: the working tree is not the artifact — the COMMITTED BLOB
# is. Blobs are always LF, on every platform, so checking them is unambiguous here
# and identical to what CI (Linux, LF checkout) sees. We extract each blob and run
# gofmt on that.
#
# Checks the index when a file is staged, else HEAD — so it gates what you are
# about to commit, not what you last committed.
set -eu

ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
cd "$ROOT"

FIX=0
[ "${1:-}" = "--fix" ] && FIX=1

command -v gofmt >/dev/null 2>&1 || { echo "gofmt not found in PATH" >&2; exit 2; }

tmp="$(mktemp -d)"
# shellcheck disable=SC2064
trap "rm -rf '$tmp'" EXIT INT TERM

bad=""
skipped=""
count=0

# reference/ is a vendored worked example we study but do not own — excluded so a
# third party's formatting never fails our gate.
for f in $(git ls-files '*.go' | grep -v '^reference/'); do
  count=$((count + 1))

  # Prefer the staged blob; fall back to HEAD for files with nothing staged.
  if ! git show ":$f" > "$tmp/blob.go" 2>/dev/null; then
    git show "HEAD:$f" > "$tmp/blob.go" 2>/dev/null || continue
  fi

  # gofmt -l prints the temp path, which tells the reader nothing. We only need
  # "is it clean", then report the REAL path ourselves.
  if [ -n "$(gofmt -l "$tmp/blob.go")" ]; then
    bad="$bad $f"
    if [ "$FIX" = "1" ]; then
      # Refuse to clobber unstaged edits: --fix writes the formatted BLOB over the
      # working-tree file, which would silently discard anything uncommitted.
      if ! git diff --quiet -- "$f"; then
        echo "SKIP $f — has unstaged changes; commit or stash them, then re-run --fix" >&2
        skipped="$skipped $f"
        continue
      fi
      gofmt "$tmp/blob.go" > "$tmp/fixed.go"
      cp "$tmp/fixed.go" "$f"
      echo "fixed $f"
    fi
  fi
done

# Enumerating NOTHING is not success. If `git ls-files` comes back empty — not a
# git checkout, a worktree whose .git pointer doesn't resolve (e.g. mounted into a
# container), a wrong CWD — then "all clean" would be a green light earned by
# checking zero files. Caught on 2026-07-26 running this very job in Docker against
# a worktree mount, where it printed "0 committed Go blobs, all clean" and exited 0.
if [ "$count" -eq 0 ]; then
  echo "gofmt_check: found NO Go files to check — refusing to report success." >&2
  echo "Is this a git checkout, and does its .git resolve here? (git ls-files returned nothing)" >&2
  exit 2
fi

if [ -z "$bad" ]; then
  echo "gofmt: $count committed Go blobs, all clean"
  # A clean result is only a statement about what is COMMITTED OR STAGED. Go files with
  # unstaged edits were never looked at -- this script deliberately reads blobs, not the
  # working tree (see the CRLF traps above) -- so "all clean" here says nothing whatever
  # about the code you are in the middle of writing.
  #
  # That is not hypothetical: on 2026-08-31 `sh scripts/dev.sh vet` was run with unstaged
  # edits, reported a clean gate, and the very next CI run failed on gofmt for one of the
  # files that had been edited. The gate was green about the previous commit.
  #
  # Reported as a NOTE and still exit 0: unstaged work is the normal state mid-task, and
  # failing here would make the gate unusable. But it must not be silent, because a green
  # that skipped your changes is exactly the false confidence this script exists to
  # prevent elsewhere.
  unchecked="$(git diff --name-only -- '*.go' | grep -v '^reference/' || true)"
  if [ -n "$unchecked" ]; then
    echo ""
    echo "NOTE: these Go files have UNSTAGED changes and were therefore NOT checked --"
    echo "the clean result above is about the committed blobs, not about your edits:"
    for f in $unchecked; do echo "  $f"; done
    echo "Stage them (git add) or commit, then re-run, or CI will be the first to know."
  fi
  exit 0
fi

if [ "$FIX" = "1" ]; then
  # Anything skipped means --fix did NOT do what was asked. Exiting 0 here would be
  # this script committing the very sin it exists to prevent: reporting success
  # while leaving the tree unformatted.
  if [ -n "$skipped" ]; then
    echo "" >&2
    echo "--fix left these unformatted (unstaged changes in the way):" >&2
    for f in $skipped; do echo "  $f" >&2; done
    exit 1
  fi
  echo ""
  echo "Rewrote the files above with LF endings (git normalises them back on commit)."
  echo "Re-run 'sh scripts/gofmt_check.sh' to confirm, then stage and commit."
  exit 0
fi

echo "gofmt: the following COMMITTED blobs are not gofmt-clean:" >&2
for f in $bad; do echo "  $f" >&2; done
echo "" >&2
echo "Fix with: sh scripts/gofmt_check.sh --fix" >&2
echo "(Do NOT just run 'gofmt -w' on the Windows host — on a CRLF working tree it" >&2
echo " silently does not apply doc-comment fixes. See the header of this script.)" >&2
exit 1
