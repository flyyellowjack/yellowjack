#!/usr/bin/env sh
# check-doc-links.sh — do our markdown links still resolve for someone who only has
# what we PUBLISHED?
#
# WHY THIS EXISTS (codify, don't re-derive):
# README.md linked to CLAUDE.md. That file is deliberately untracked (.gitignore, 2026-08-05:
# "kept on each machine, never in the repo"). On every developer's disk the link works
# perfectly — the file is right there. In the published repository it is a 404, on the front
# page, in the first section a visitor reads.
#
# That is the exact shape CLAUDE.md says must become an assertion rather than a note: a defect
# that CANNOT be seen by looking, because the thing that hides it is the local filesystem. No
# amount of care while editing catches it; only asking git does.
#
# So the check is deliberately "is the target TRACKED?", not "does the target EXIST?". Those two
# questions agree on every machine we work on and disagree only in the one place that matters —
# which is precisely why the bug survived to within weeks of an open-source launch.
#
# Run:
#   sh scripts/check-doc-links.sh
#   sh scripts/check-doc-links.sh --selftest   # negative control: prove it CAN fail
#
# Exit 0 = every repo-relative link resolves to a tracked path. Exit 1 = at least one would 404.

set -eu

# Resolve targets by asking git from the LINKING FILE'S directory, so "../foo.md" and
# "docs/bar.md" both work without hand-rolling path normalisation — git already does it, and a
# reimplementation here would be one more thing to get subtly wrong.
check_tree() {
  root="$1"
  failed=0
  files=$(cd "$root" && git ls-files '*.md')
  [ -n "$files" ] || { echo "  (no tracked markdown files)"; return 0; }

  for f in $files; do
    dir=$(dirname "$f")
    # Pull out every ](target) — covers links and ![images] alike. Strip any "title",
    # then any #anchor. A bare "#anchor" link is in-page and has no file to resolve.
    targets=$(cd "$root" && sed -n 's/.*](\([^)]*\)).*/\1/p' "$f" \
              | sed 's/[[:space:]].*$//' | sed 's/#.*$//' | sed '/^$/d')
    for t in $targets; do
      case "$t" in
        http://*|https://*|mailto:*|\<*) continue ;;
      esac
      if ! (cd "$root/$dir" && git ls-files --error-unmatch -- "$t" >/dev/null 2>&1); then
        # A directory link is fine if anything tracked lives under it.
        if ! (cd "$root/$dir" && git ls-files -- "$t" 2>/dev/null | grep -q .); then
          printf '  BROKEN  %-28s -> %s\n' "$f" "$t"
          failed=1
        fi
      fi
    done
  done
  return "$failed"
}

if [ "${1:-}" = "--selftest" ]; then
  # NEGATIVE CONTROL. A link checker that cannot fail is worse than no link checker: it
  # converts "nobody has looked" into "we verified it", which is the trap CLAUDE.md names.
  #
  # The decisive case is the THIRD one: a file that exists on disk but is NOT tracked. That is
  # the real bug (CLAUDE.md), and a checker written against the filesystem passes it happily.
  tmp=$(mktemp -d)
  trap 'rm -rf "$tmp"' EXIT
  (
    cd "$tmp"
    git init -q .
    git config user.email t@t; git config user.name t
    mkdir -p docs
    echo 'tracked' > docs/real.md
    echo 'untracked but PRESENT on disk' > docs/local-only.md
    printf '[ok](docs/real.md)\n[dead](docs/missing.md)\n[ondisk](docs/local-only.md)\n[ext](https://example.com/x.md)\n[anchor](#section)\n' > README.md
    git add README.md docs/real.md
    git commit -qm x
  )
  out=$(check_tree "$tmp" 2>&1) && { echo "SELFTEST FAILED: broken links did not trip the check"; exit 1; }

  echo "$out" | grep -q 'docs/missing.md' || { echo "SELFTEST FAILED: a genuinely absent target was not reported"; exit 1; }
  echo "$out" | grep -q 'docs/local-only.md' || { echo "SELFTEST FAILED: an UNTRACKED-but-present file was not reported — the check is asking the filesystem, not git, which is the whole bug"; exit 1; }
  echo "$out" | grep -q 'docs/real.md'   && { echo "SELFTEST FAILED: a tracked target was wrongly reported"; exit 1; }
  echo "$out" | grep -q 'example.com'    && { echo "SELFTEST FAILED: an external URL was resolved as a path"; exit 1; }

  echo "selftest ok — flags missing AND untracked-but-present, passes tracked, ignores external"
  exit 0
fi

ROOT=$(cd "$(dirname "$0")/.." && pwd)
echo "Checking repo-relative markdown links against TRACKED paths in $ROOT"
if check_tree "$ROOT"; then
  echo "OK — every repo-relative link resolves to a tracked file"
else
  cat >&2 <<'EOF'

At least one link points at a path that is NOT in the repository. On your disk it may
resolve fine; for anyone who clones — or for the published repo — it is a 404.

Fix by one of:
  * committing the target, if it is meant to be public;
  * rewriting the link to describe the file instead of linking it, if the file is
    deliberately untracked (CLAUDE.md, docs/DECISIONS.md, docs/TODO.md are);
  * removing the link.
EOF
  exit 1
fi
