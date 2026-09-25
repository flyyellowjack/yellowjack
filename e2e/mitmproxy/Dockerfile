# syntax=docker/dockerfile:1

# The TLS-interception rig for the #39 class-5 measurement (D200).
#
# Built from the repo ROOT:
#   docker build -f e2e/mitmproxy/Dockerfile -t yellowjack-mitmproxy:e2e .
# e2e/mitm.go does this for you.
#
# WHY A CONTAINER: under docker-in-docker the daemon is a SEPARATE container, so a
# client container's `host.docker.internal` reaches the dind daemon's gateway and never
# a listener in the job container. This repo has already paid for that lesson twice —
# see .gitlab-ci.yml on the firewall and e2e/harness.go on the approval stub.

# Built standalone with its own throwaway module: the fixture is stdlib-only and
# deliberately NOT part of the main module's dependency graph, so it can never
# contribute a dependency to the shipped binaries.
FROM golang:1.26@sha256:9d2f36f06329b2a141b9db99ffa32765cf695ee57b813ca29e245e8670bcbfff AS build
WORKDIR /src
COPY e2e/mitmproxy/main.go ./main.go
RUN go mod init mitmproxy && CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /mitmproxy .

# The same final base as every shipped service, so the fixture pulls no image the rig
# does not already need. :nonroot brings the unprivileged user; 8888/8889 are
# unprivileged ports so nothing needs capability to bind them. distroless/static also
# carries the CA bundle this needs to verify the REAL registry on the upstream leg —
# the rig terminates the client's TLS, it does not weaken its own.
FROM gcr.io/distroless/static:nonroot@sha256:1c2c046bc09ed40fad370b599a0b1ae7987f55b01e247cf27a7c27cd97e5bbc7
COPY --from=build /mitmproxy /mitmproxy
EXPOSE 8888 8889
ENTRYPOINT ["/mitmproxy"]
