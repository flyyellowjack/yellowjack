# syntax=docker/dockerfile:1

# ---- Stage 1: build ----------------------------------------------------------
# Builds the console GUI service. Context is the repo ROOT (so go.mod/go.sum and
# the console/ package are both visible); build this image with:
#   docker build -f console/Dockerfile -t yellowjack-console:dev .
# The build stage runs on the BUILDER's platform and cross-compiles for the target, so a
# multi-arch release (scripts/release.sh) builds linux/arm64 without emulation. A plain
# `docker build` is unchanged: both variables then name the host. The default covers the
# legacy (non-BuildKit) builder, which does not set BUILDPLATFORM; CI's amd64 e2e jobs use it.
FROM --platform=${BUILDPLATFORM:-linux/amd64} golang:1.26@sha256:9d2f36f06329b2a141b9db99ffa32765cf695ee57b813ca29e245e8670bcbfff AS build
ARG TARGETOS TARGETARCH

WORKDIR /src

# Resolve dependencies as a cached layer (shared go.mod; the console itself adds
# none — it is stdlib-only).
COPY go.mod go.sum ./
RUN go mod download

# Copy the console package's source, INCLUDING templates/ — the queue page is
# embedded into the binary via //go:embed, so the template must be present at
# build time.
COPY console/ ./console/
# The one-line FIPS banner every service prints (D374); shared, so the six stay identical.
COPY fipsmode/ ./fipsmode/

# Static, CGO-free binary for a minimal runtime image (same rationale as the
# approval/firewall images).
# FIPS 140-3 (D374): build against the certified Go Cryptographic Module. Setting it also
# makes the binary start in FIPS mode (GODEBUG fips140=on). The startup banner says which.
# Build with --build-arg GOFIPS140=off only to compare; the published images keep it on.
ARG GOFIPS140=v1.0.0
RUN GOFIPS140=$GOFIPS140 CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=$TARGETARCH go build -ldflags="-s -w" -o /console ./console

# ---- Stage 2a: git-capable runtime (OPT-IN) ----------------------------------
# Built only when asked for:  docker build --target console-git ...
#
# WHY THIS IS A SEPARATE, OPT-IN IMAGE AND NOT THE DEFAULT.
#
# D193 has the console EDIT the operator's allow/deny lists, and the mechanism chosen
# (D193 option (c)) is "console commits to git, replicas read the file" -- which needs a
# git binary. distroless/static has none, and that is the point of distroless.
#
# Putting git into the default console image would add a large, historically
# CVE-prone binary, plus a shell, to the one service that holds the operator credential
# and owns the only write path -- on a product whose stated differentiator is a small
# self-hosted footprint. That is a real cost, and it should be paid only by deployers who
# turn list editing on.
#
# So: the default image below is unchanged and has no git, CONSOLE_LIST_REPO is unset by
# default, and a console without git reports list editing as DISABLED at startup with the
# reason (see newGitListStore). A deployer who wants D193's editable whitelist builds
# this target instead. ⚠️ If that trade is the wrong one for the product, this is the
# decision to revisit -- it is flagged rather than settled here.
#
# openssh-client is NOT installed: a push over ssh would need it, but it is another
# surface, and https with a credential helper covers the common case. Add it in your own
# derived image if your remote is ssh.
FROM alpine:3.22@sha256:14358309a308569c32bdc37e2e0e9694be33a9d99e68afb0f5ff33cc1f695dce AS console-git

RUN apk add --no-cache git ca-certificates

COPY --from=build /console /console

# A non-root user, matching the distroless image's posture. The uid is fixed so a
# deployer can chown the list repo to it on the host side of the bind mount.
RUN adduser -D -u 65532 -h /home/nonroot nonroot
USER 65532:65532
ENV HOME=/home/nonroot

EXPOSE 8085
ENTRYPOINT ["/console"]

# ---- Stage 2: runtime --------------------------------------------------------
# distroless/static:nonroot — the console needs no docker socket and owns no
# state, so it runs fully unprivileged (unlike the scheduler, which needs root
# for the daemon socket). Smallest attack surface, matching the approval image.
FROM gcr.io/distroless/static:nonroot@sha256:1c2c046bc09ed40fad370b599a0b1ae7987f55b01e247cf27a7c27cd97e5bbc7

COPY --from=build /console /console

EXPOSE 8085
USER nonroot:nonroot
ENTRYPOINT ["/console"]
