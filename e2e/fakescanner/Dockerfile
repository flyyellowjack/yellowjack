# syntax=docker/dockerfile:1

# The DETERMINISTIC scanner image for the async local-mode e2e (issue #55).
#
# It is the real run-once scanner image with ONE thing swapped: the third-party
# `scorecard` binary is replaced by e2e/fakescanner, which reports a score chosen at
# build time. Everything the rig is actually testing stays real — the scheduler, the
# docker-run/docker-api launchers, the container lifecycle, the result sink and its
# capability token, the approval Postgres L2, and the firewall's async decision path.
#
# Build from the repo ROOT, after the base scanner image exists:
#   docker build -f scanner/Dockerfile -t yellowjack-scanner:dev .
#   docker build -f e2e/fakescanner/Dockerfile -t yellowjack-scanner-fake:e2e .
# e2e/async_local.sh does both for you.

# ---- Stage 1: build the fake scorecard binary -------------------------------
# Built standalone with its own throwaway module: the fixture is stdlib-only and
# deliberately NOT part of the main module's dependency graph.
FROM golang:1.26@sha256:9d2f36f06329b2a141b9db99ffa32765cf695ee57b813ca29e245e8670bcbfff AS build
WORKDIR /src
COPY e2e/fakescanner/main.go ./main.go
RUN go mod init fakescorecard && CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /fake-scorecard .

# ---- Stage 2: the real scanner image, with scorecard swapped ----------------
# FROM the real image on purpose rather than rebuilding the scanner from source:
# the binary under test must be byte-identical to the one production runs, or the
# rig would be testing a different scanner than the one that ships.
FROM yellowjack-scanner:dev
COPY --from=build /fake-scorecard /usr/local/bin/fake-scorecard

# Point the run-once scanner at the fake instead of the real /usr/local/bin/scorecard.
# The real binary is left in the image untouched, so `docker run --entrypoint` can
# still reach it if someone wants to compare against a live scan.
ENV SCANNER_SCORECARD_BIN=/usr/local/bin/fake-scorecard

# The fixture's behavior, baked in — the scheduler's launchers forward only a fixed
# env set to the scanner container, so per-scan configuration is not possible.
#
# FAKE_SCORE: the aggregate score reported for every repo that is not matched below.
#   Default 9.0, comfortably ABOVE the rig's FW_SCORE_THRESHOLD of 5.0, so the async
#   pipeline's success path ends in a real ALLOW driven by a real number.
#   The rig's negative control rebuilds this image with FAKE_SCORE=1.0 and requires
#   the allow assertion to then FAIL — see e2e/fakescanner/README.md.
# FAKE_UNSCORABLE_SUBSTR: any repo whose path contains this substring exits non-zero,
#   reproducing "Scorecard ran but could not score this repo" so the durable NEGATIVE
#   MARKER path is exercised too. Defaults to the express repo, which the rig pulls
#   as its second package precisely to reach this branch.
ARG FAKE_SCORE=9.0
# Widened from "expressjs/express" to the ORG PREFIX on 2026-09-05 (D193, leg 21).
# express still matches, so every leg that relied on it is unchanged -- but the rig now
# has MORE THAN ONE default-blocked package, which leg 21 needs: it has to allow-list
# something that would otherwise be refused, and express is already consumed by leg 19
# (the console approves it, so allow-listing it afterwards would prove nothing).
ARG FAKE_UNSCORABLE_SUBSTR=expressjs/
# PARTIAL reports (#133, D271): the shape the real scorecard produces when checks hit
# runtime errors -- a complete report with the named checks at -1, and exit status 1.
# Two repos, one per side of the required-check floor: the first errors only LOW-weight
# checks (must be ACCEPTED as a score), the second errors a REQUIRED one (must be
# UNSCORABLE, naming the check). Leg 29 of e2e/async_local.sh pulls both.
ARG FAKE_PARTIAL_SUBSTR=chalk/chalk
ARG FAKE_PARTIAL_ERRORED=License,CI-Tests,Contributors
ARG FAKE_PARTIAL2_SUBSTR=debug-js/debug
ARG FAKE_PARTIAL2_ERRORED=Dangerous-Workflow,License
ENV FAKE_SCORECARD_SCORE=${FAKE_SCORE}
ENV FAKE_SCORECARD_UNSCORABLE_SUBSTR=${FAKE_UNSCORABLE_SUBSTR}
ENV FAKE_SCORECARD_PARTIAL_SUBSTR=${FAKE_PARTIAL_SUBSTR}
ENV FAKE_SCORECARD_PARTIAL_ERRORED=${FAKE_PARTIAL_ERRORED}
ENV FAKE_SCORECARD_PARTIAL2_SUBSTR=${FAKE_PARTIAL2_SUBSTR}
ENV FAKE_SCORECARD_PARTIAL2_ERRORED=${FAKE_PARTIAL2_ERRORED}

# ENTRYPOINT/USER inherited from the base image: still the run-once /scanner as nonroot.
