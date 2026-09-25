#!/bin/sh
# mode-matrix.sh — run (or regenerate) the mode-coverage matrix.
#
# The matrix drives a real request through a real proxy for every reachable
# combination of ecosystem × request kind × scenario × byte gate × unscorable
# policy × unverified policy × scorecard mode × verify-repo, and compares what
# happened against the committed table in docs/mode-matrix.json.
#
#   sh scripts/mode-matrix.sh              # assert: fails on ANY divergence
#   sh scripts/mode-matrix.sh --update     # regenerate the table + docs/MODE_MATRIX.md
#
# --update is for when a behaviour change is INTENDED. It rewrites the expectation
# table from observed behaviour, so it will happily bless a regression: always read
# `git diff docs/mode-matrix.json` before committing. The table is the record of what
# the gate is worth, and a diff nobody read is worth nothing.
#
# There is no `make` on the Windows dev host — this script IS the target.
set -eu

cd "$(dirname "$0")/.."

if [ "${1:-}" = "--update" ]; then
  echo "regenerating the mode matrix (docs/mode-matrix.json, docs/mode-matrix-bypasses.json, docs/MODE_MATRIX.md)"
  go test -run TestModeMatrix -v . -args -update-matrix
  echo
  echo "REVIEW THE DIFF before committing:"
  echo "  git diff --stat docs/mode-matrix.json docs/mode-matrix-bypasses.json docs/MODE_MATRIX.md"
  exit 0
fi

# Assert mode. The -run pattern is an unanchored regex, so "TestModeMatrix" selects
# every check in the rig:
#
#   TestModeMatrix                  fails on divergence AND on any cell missing from
#                                   the table (an unrecorded cell is a failure — that
#                                   is what forces a human to look at a new mode).
#   TestModeMatrixBypasses          fails when the SET of ungated byte-path cells
#                                   changes, in either direction.
#   TestModeMatrixRoutesAreDetectable
#                                   fails if a byte route cannot report a fetch — the
#                                   rig's own negative control, so a route that was
#                                   added but never wired up cannot pass as coverage.
#   TestModeMatrixDocInSync         fails if docs/MODE_MATRIX.md is not the rendering
#                                   of docs/mode-matrix.json, so the human-readable
#                                   artifact cannot go stale behind green tests.
go test -run 'TestModeMatrix' -v .
