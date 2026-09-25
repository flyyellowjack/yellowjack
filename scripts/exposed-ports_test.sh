#!/bin/sh
# Self-test for scripts/exposed-ports.sh.
#
# Every leg has a control. A checker of this kind fails in one direction silently --
# a parser that matches nothing reports "all clean" for a file full of exposed ports --
# so the cases below include both a file that MUST fail and a demonstration that the
# parser really extracts what it claims to.
set -u

ROOT=$(cd "$(dirname "$0")/.." && pwd)
. "$ROOT/scripts/exposed-ports.sh"

pass=0
fail=0
ok()  { pass=$((pass + 1)); echo "ok   $1"; }
bad() { fail=$((fail + 1)); echo "FAIL $1"; }

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

# ---------------------------------------------------------------- fixtures
cat >"$tmp/clean.yml" <<'YML'
services:
  approval:
    image: x
    ports:
      - "127.0.0.1:8090:8090"
  firewall:
    image: x
    ports:
      - "8080:8080"
  console:
    image: x
    environment:
      SOME_URL: "http://approval:8090"
    ports:
      - "127.0.0.1:8085:8085"

volumes:
  data:
YML

cat >"$tmp/leaky.yml" <<'YML'
services:
  approval:
    image: x
    ports:
      - "8090:8090"
  firewall:
    image: x
    ports:
      - "8080:8080"
YML

cat >"$tmp/wildcard.yml" <<'YML'
services:
  scheduler:
    image: x
    ports:
      - "0.0.0.0:8096:8096"
YML

cat >"$tmp/noports.yml" <<'YML'
services:
  approval:
    image: x
    environment:
      A: b
YML

# ------------------------------------------------------------------- legs
if check_exposed_ports "$tmp/clean.yml" >/dev/null 2>&1; then
	ok "a compose with control-plane ports on loopback passes"
else
	bad "the clean fixture was rejected"
fi

if check_exposed_ports "$tmp/leaky.yml" >/dev/null 2>&1; then
	bad "an unauthenticated service published on all interfaces was ACCEPTED"
else
	ok "a bare \"8090:8090\" on a non-front-door service is caught"
fi

# The message has to name the service, or an operator cannot act on it.
if check_exposed_ports "$tmp/leaky.yml" 2>&1 | grep -q "approval"; then
	ok "the failure names the offending service"
else
	bad "the failure does not name which service is exposed"
fi

# firewall is a declared front door and must NOT be reported, or the check would be
# telling us to break the product.
if check_exposed_ports "$tmp/leaky.yml" 2>&1 | grep -q "firewall publishes"; then
	bad "a declared front door was reported as an offender"
else
	ok "declared front doors are exempt (firewall on 8080 is not flagged)"
fi

if check_exposed_ports "$tmp/wildcard.yml" >/dev/null 2>&1; then
	bad "an explicit 0.0.0.0 binding was ACCEPTED"
else
	ok "an explicit 0.0.0.0 binding is caught, not just the bare form"
fi

# THE ANTI-VACUITY LEG. A file with no ports at all must FAIL rather than report a
# clean bill of health -- otherwise a parser that silently stops matching passes
# everything, which is the failure mode this whole file exists to prevent.
if check_exposed_ports "$tmp/noports.yml" >/dev/null 2>&1; then
	bad "a compose with ZERO parsed ports reported success"
else
	ok "zero parsed ports FAILS rather than passing vacuously"
fi

# The parser must really extract mappings, shown rather than asserted.
got=$(port_bindings_in "$tmp/clean.yml" | wc -l | tr -d ' ')
if [ "$got" = "3" ]; then
	ok "port_bindings_in really parses ports (got 3 mappings from the clean fixture)"
else
	bad "port_bindings_in extracted $got mappings, want 3"
fi

# A `ports:` key would be mistaken for a block if the indent were ignored; this pins
# that an environment value mentioning a port is not read as a binding.
if port_bindings_in "$tmp/clean.yml" | grep -q "SOME_URL"; then
	bad "an environment value was parsed as a port binding"
else
	ok "an environment value is not mistaken for a port binding"
fi

# The indirection legs. Compose interpolates ${VAR:-default}, so a checker that
# compares the raw string is blind to the value an operator actually gets. Both
# directions are pinned: a loopback default passes, and a wide-open default is still
# CAUGHT -- the second is the one that matters, because it is how this guard would
# quietly stop guarding.
cat >"$tmp/vardefault_ok.yml" <<'YML'
services:
  approval:
    image: x
    ports:
      - "${BIND:-127.0.0.1}:8090:8090"
YML

cat >"$tmp/vardefault_bad.yml" <<'YML'
services:
  approval:
    image: x
    ports:
      - "${BIND:-0.0.0.0}:8090:8090"
YML

if check_exposed_ports "$tmp/vardefault_ok.yml" >/dev/null 2>&1; then
	ok "a ${VAR:-127.0.0.1} default is read as loopback"
else
	bad "a loopback default behind a variable was rejected"
fi

if check_exposed_ports "$tmp/vardefault_bad.yml" >/dev/null 2>&1; then
	bad "a ${VAR:-0.0.0.0} default was ACCEPTED -- the guard is blind to interpolation"
else
	ok "a wide-open default behind a variable is still caught"
fi

# ------------------------------------------------------- the real repo file
if check_exposed_ports "$ROOT/docker-compose.yml" >/dev/null 2>&1; then
	ok "this repo passes: $(check_exposed_ports "$ROOT/docker-compose.yml" 2>&1)"
else
	bad "docker-compose.yml exposes a control-plane port: $(check_exposed_ports "$ROOT/docker-compose.yml" 2>&1 | head -3)"
fi

echo
echo "$pass passed, $fail failed"
[ "$fail" -eq 0 ]
