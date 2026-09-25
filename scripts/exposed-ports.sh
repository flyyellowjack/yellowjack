#!/bin/sh
# Which services may be published on ALL interfaces, and which must stay on loopback.
#
# The rule is inverted on purpose. A denylist of "internal services" would have to be
# extended every time a service is added, and the failure of forgetting is SILENT: a
# new control-plane port reachable from the LAN, which is exactly the state this check
# was written after finding.
#
# So: every published port must bind 127.0.0.1, EXCEPT the services named below. That
# list IS the entire fail-open surface -- keep it short enough to review at a glance.
# Same shape as the control-plane path enumeration in !86: prefer leaving something
# out, because a missing entry breaks a client loudly and is fixed by adding one line,
# while a spurious entry is a silent hole.
#
# WHY THIS EXISTS. Found 2026-09-08 while answering "why can't I share the console?".
# docker-compose.yml published the APPROVAL control plane on 0.0.0.0:8090 and the
# scheduler on 0.0.0.0:8096. Neither takes any credential (#13 item 2, awaiting a project decision on
# D31 Q3), and GET /v1/decisions returned 200 with no credentials -- the same surface
# the console POSTs approvals to. Meanwhile the CONSOLE, the one service that does
# have authentication, was correctly bound to 127.0.0.1. The protection was inverted.
#
# Nothing needed those host ports: every service reaches approval at
# http://approval:8090 and the scheduler at http://scheduler:8096 over the compose
# network, and the launched scanner container joins that network via
# SCHEDULER_DOCKER_NETWORK. The mappings existed for human debugging.
#
# SCOPE: the files an OPERATOR DEPLOYS -- docker-compose.yml and the reference
# deployment under deploy/. The e2e rigs (docker-compose.e2e.yml and friends)
# publish broadly on purpose so client containers can reach the stack through
# host.docker.internal, and holding them to a deployment rule would be a false claim
# about a test harness.
#
# The reference deployment was added to this list the day it was written, and the
# reason is worth stating: it exists to be COPIED. An example that publishes a
# control plane on 0.0.0.0 does not stay an example -- it becomes somebody's
# deployment, with the inverted protection this check was written after finding.
# A file people are invited to copy needs the rule MORE than the one they edit.

# Services whose ports are MEANT to be reachable from outside the host. These are the
# product's front doors: a developer's npm/pip/docker client points at them, which is
# the entire point of the firewall.
: "${EXPOSED_PORTS_PUBLIC_SERVICES:=firewall firewall-pypi firewall-oci cache}"

# The compose files this rule is about, space separated. Every one of them is a file
# an operator runs or copies; nothing here is a test rig.
: "${EXPOSED_PORTS_FILE:=docker-compose.yml deploy/reference/docker-compose.yml}"

# port_bindings_in FILE
#
# Prints "service<TAB>mapping" for every published port. Tracks the service by the
# 2-space indent compose uses under `services:`, and a `ports:` block by the 4-space
# indent under a service, so a `ports:` key nested anywhere else cannot be mistaken
# for one.
port_bindings_in() {
	awk '
		/^  [A-Za-z0-9_-]+:[[:space:]]*$/ {
			svc = $1; sub(/:$/, "", svc); in_ports = 0; next
		}
		/^    ports:[[:space:]]*$/ { in_ports = 1; next }
		/^    [A-Za-z0-9_-]+:/     { in_ports = 0 }
		in_ports && /^      - / {
			line = $0
			sub(/^      - /, "", line)
			gsub(/"/, "", line)
			gsub(/\r/, "", line)
			if (line != "" && svc != "") print svc "\t" line
		}
	' "$1"
}

# resolve_compose_default MAPPING
#
# Compose interpolates ${VAR:-default} at up time. The guard must read through that
# indirection or it is decoration: a mapping written ${BIND:-0.0.0.0}:8090:8090 would
# otherwise sail past every check while publishing to the world by default.
#
# It checks the DEFAULT, which is what an operator who sets nothing actually gets.
# Someone who deliberately exports the variable has made a choice; someone who runs
# `docker compose up` has not.
resolve_compose_default() {
	printf '%s' "$1" | sed 's/[$][{][A-Za-z_][A-Za-z0-9_]*:-\([^}]*\)[}]/\1/g'
}

# binds_all_interfaces MAPPING
#
# True when the mapping publishes on every interface: either no host IP at all
# ("8090:8090") or an explicit wildcard ("0.0.0.0:8090:8090", "[::]:8090:8090").
binds_all_interfaces() {
	case "$(resolve_compose_default "$1")" in
	127.0.0.1:* | localhost:*) return 1 ;;
	0.0.0.0:* | \[::\]:* | ::*) return 0 ;;
	*:*:*) return 1 ;; # some other explicit host IP -- a deliberate choice, not a default
	*) return 0 ;;     # "8090:8090" -- docker's default is every interface
	esac
}

is_public_service() {
	for s in $EXPOSED_PORTS_PUBLIC_SERVICES; do
		[ "$s" = "$1" ] && return 0
	done
	return 1
}

# check_exposed_ports [FILE...]
#
# Exits non-zero, naming every offender, when a service outside the public list
# publishes a port on all interfaces. With no argument it checks every file in
# EXPOSED_PORTS_FILE; with arguments it checks exactly those, which is how the
# selftest points it at fixtures.
#
# EVERY file is checked before returning, rather than stopping at the first bad one:
# an operator fixing two files wants both names in one run, and a loop that exits
# early would report the second only after the first is fixed.
check_exposed_ports() {
	files="$*"
	[ -z "$files" ] && files="$EXPOSED_PORTS_FILE"
	rc=0
	for f in $files; do
		check_one_compose_file "$f" || rc=1
	done
	return $rc
}

# check_one_compose_file FILE — the rule, applied to exactly one file.
check_one_compose_file() {
	file="$1"
	if [ ! -f "$file" ]; then
		echo "exposed-ports: $file not found" >&2
		return 1
	fi

	total=0
	bad=0
	# Anti-vacuity: a parser that silently matches nothing would report a clean bill
	# of health for a file full of exposed ports. Counting is what makes the pass mean
	# something.
	while IFS="$(printf '\t')" read -r svc mapping; do
		[ -z "$svc" ] && continue
		total=$((total + 1))
		if binds_all_interfaces "$mapping" && ! is_public_service "$svc"; then
			echo "exposed-ports: $svc publishes $mapping on ALL interfaces" >&2
			echo "  $svc is not a front door. Bind it to loopback: \"127.0.0.1:$mapping\"" >&2
			echo "  (or add it to EXPOSED_PORTS_PUBLIC_SERVICES, which is the fail-open surface)" >&2
			bad=$((bad + 1))
		fi
	done <<EOF
$(port_bindings_in "$file")
EOF

	if [ "$total" -eq 0 ]; then
		echo "exposed-ports: parsed ZERO port mappings from $file -- the check cannot pass vacuously" >&2
		return 1
	fi
	if [ "$bad" -gt 0 ]; then
		echo "exposed-ports: $bad of $total published port(s) reachable from outside the host" >&2
		return 1
	fi
	echo "exposed-ports: $total published ports, all loopback except the declared front doors ($EXPOSED_PORTS_PUBLIC_SERVICES)"
	return 0
}
