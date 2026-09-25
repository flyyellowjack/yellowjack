# syntax=docker/dockerfile:1

# The DNS sinkhole for the zero-egress assertion (issue #27).
#
# It records every name the firewall container tries to resolve. The e2e leg points the
# firewall's --dns at this container and configures every LEGITIMATE destination as an
# explicit IP, so a clean run produces an EMPTY query log: nothing the firewall needs
# requires a lookup, therefore any lookup at all is unexplained egress.
#
# See main.go for why DNS is the right observation point (it catches what the in-process
# dialler check structurally cannot) and for what it deliberately does not catch.
#
# Build from the repo ROOT:
#   docker build -f e2e/fakedns/Dockerfile -t yellowjack-fakedns:e2e .
# TestFirewallMakesNoUnconfiguredEgress does this for you.

# Built standalone with its own throwaway module: the fixture is stdlib-only and
# deliberately NOT part of the main module's dependency graph — the same rule as
# e2e/fakescanner, and doubly so here, since TestFirewallBinaryLinksOnlyStdlib asserts
# the firewall module stays dependency-free.
FROM golang:1.26@sha256:9d2f36f06329b2a141b9db99ffa32765cf695ee57b813ca29e245e8670bcbfff AS build
WORKDIR /src
COPY e2e/fakedns/main.go ./main.go
RUN go mod init fakedns && CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /fakedns .

# scratch, not alpine: the sinkhole must itself have nothing that could make a network
# call, or the rig would be explaining its own noise.
FROM scratch
COPY --from=build /fakedns /fakedns
EXPOSE 53/udp
ENTRYPOINT ["/fakedns"]
