# syntax=docker/dockerfile:1

# The recording upstream registry for the credential-rotation e2e leg (#53, D177, !148).
#
# Built from the repo ROOT:
#   docker build -f e2e/credupstream/Dockerfile -t yellowjack-credupstream:e2e .
# e2e/upstreamcred_test.go does this for you (buildCredUpstream).

# Built standalone with its own throwaway module: the fixture is stdlib-only and
# deliberately NOT part of the main module's dependency graph, so it can never
# contribute a dependency to the shipped binaries.
FROM golang:1.26@sha256:9d2f36f06329b2a141b9db99ffa32765cf695ee57b813ca29e245e8670bcbfff AS build
WORKDIR /src
COPY e2e/credupstream/main.go ./main.go
RUN go mod init credupstream && CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /credupstream .

# ── the credential WRITER, built as its own target ───────────────────────────
#
#   docker build -f e2e/credupstream/Dockerfile --target credwriter -t yellowjack-credwriter:e2e .
#
# The leg has to rewrite the credential file while the firewall runs, and it must do it
# by TEMP FILE AND RENAME, because that is what every real refresher does (a reader must
# never see a half-written secret) and it is the shape that exposes an inode-pinning
# mount. Our own images are distroless and have no shell, so the write needs a container
# that does.
#
# It lives HERE, in a Dockerfile, rather than as a string in the Go test, for one
# specific reason: scripts/pinned-images.sh walks Dockerfile FROM lines and compose
# `image:` lines, and NOTHING ELSE. An image reference written in a .go file is outside
# every pin check we have — it would be pinned only for as long as whoever wrote it
# remembered to, which is the state issue #22 exists to end.
FROM alpine:3.22@sha256:14358309a308569c32bdc37e2e0e9694be33a9d99e68afb0f5ff33cc1f695dce AS credwriter
ENTRYPOINT ["/bin/sh"]

# The same final base as every shipped service, so the fixture pulls no image the rig
# does not already need. :nonroot brings the unprivileged user with it, and the port is
# 8080 rather than 80 precisely so nothing needs privilege to bind it.
FROM gcr.io/distroless/static:nonroot@sha256:1c2c046bc09ed40fad370b599a0b1ae7987f55b01e247cf27a7c27cd97e5bbc7
COPY --from=build /credupstream /credupstream
EXPOSE 8080
ENTRYPOINT ["/credupstream"]
