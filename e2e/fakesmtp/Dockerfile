# syntax=docker/dockerfile:1

# The SMTP sink for the alert-email e2e leg (#32 Phase C / C4c).
#
# Built from the repo ROOT:
#   docker build -f e2e/fakesmtp/Dockerfile -t yellowjack-fakesmtp:e2e .
# e2e/async_local.sh does this for you.

# Built standalone with its own throwaway module: the fixture is stdlib-only and
# deliberately NOT part of the main module's dependency graph, so it can never
# contribute a dependency to the shipped binaries.
FROM golang:1.26@sha256:9d2f36f06329b2a141b9db99ffa32765cf695ee57b813ca29e245e8670bcbfff AS build
WORKDIR /src
COPY e2e/fakesmtp/main.go ./main.go
RUN go mod init fakesmtp && CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /fakesmtp .

# The same final base as every shipped service, so the fixture pulls no image the rig
# does not already need. :nonroot brings the unprivileged user with it — the ports here
# are 1025/1080 rather than 25/80 precisely so nothing needs privilege to bind them.
FROM gcr.io/distroless/static:nonroot@sha256:1c2c046bc09ed40fad370b599a0b1ae7987f55b01e247cf27a7c27cd97e5bbc7
COPY --from=build /fakesmtp /fakesmtp
EXPOSE 1025 1080
ENTRYPOINT ["/fakesmtp"]
