#!/usr/bin/env sh
# scripts/race.sh — run the Go race detector in Docker.
#
# The Windows dev host has no C toolchain, and -race (and any CGO) needs gcc. The
# golang image ships it, and it's the same image CI's race job uses, so a green
# local run matches CI. Go's caches stay INSIDE the container (default GOPATH/
# GOCACHE), so no root-owned files land in the repo mount.
#
# Usage:
#   sh scripts/race.sh                 # race-tests everything: ./... -count=1
#   sh scripts/race.sh ./firewall/...  # or pass your own go-test args
set -eu

IMAGE=golang:1.26
ARGS="$*"
[ -n "$ARGS" ] || ARGS="./... -count=1"

if ! docker version >/dev/null 2>&1; then
  echo "race.sh: Docker daemon not reachable — start Docker Desktop and retry." >&2
  exit 1
fi

# repo root = parent of scripts/
ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"

# Git Bash rewrites the -v/-w path args into C:\... — disable that.
export MSYS_NO_PATHCONV=1

echo "race.sh: go test -race $ARGS  (in $IMAGE)"
exec docker run --rm \
  -v "$ROOT:/src" -w /src \
  -e CGO_ENABLED=1 -e GOFLAGS=-mod=readonly \
  "$IMAGE" go test -race $ARGS
