# syntax=docker/dockerfile:1

# ---- Stage 1: build ----------------------------------------------------------
# Builds the approval service. Context is the repo ROOT (so go.mod/go.sum and the
# approval/ package are both visible); build this image with:
#   docker build -f approval/Dockerfile -t yellowjack-approval:dev .
# The build stage runs on the BUILDER's platform and cross-compiles for the target, so a
# multi-arch release (scripts/release.sh) builds linux/arm64 without emulation. A plain
# `docker build` is unchanged: both variables then name the host. The default covers the
# legacy (non-BuildKit) builder, which does not set BUILDPLATFORM; CI's amd64 e2e jobs use it.
FROM --platform=${BUILDPLATFORM:-linux/amd64} golang:1.26@sha256:9d2f36f06329b2a141b9db99ffa32765cf695ee57b813ca29e245e8670bcbfff AS build
ARG TARGETOS TARGETARCH

WORKDIR /src

# Resolve dependencies as a cached layer (pgx etc. live in the shared go.mod).
COPY go.mod go.sum ./
RUN go mod download

# Copy only the approval package's source — it doesn't import the firewall code.
COPY approval/ ./approval/
# The one-line FIPS banner every service prints (D374); shared, so the six stay identical.
COPY fipsmode/ ./fipsmode/

# Static, CGO-free binary for a minimal runtime image (same rationale as the
# firewall image). Build the ./approval package specifically.
# FIPS 140-3 (D374): build against the certified Go Cryptographic Module. Setting it also
# makes the binary start in FIPS mode (GODEBUG fips140=on). The startup banner says which.
# Build with --build-arg GOFIPS140=off only to compare; the published images keep it on.
ARG GOFIPS140=v1.0.0
RUN GOFIPS140=$GOFIPS140 CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=$TARGETARCH go build -ldflags="-s -w" -o /approvald ./approval

# ---- Stage 2: runtime --------------------------------------------------------
# distroless/static provides CA certs (the service has no outbound TLS today, but
# this keeps parity with the firewall image) and a tiny attack surface. :nonroot
# runs as an unprivileged user.
FROM gcr.io/distroless/static:nonroot@sha256:1c2c046bc09ed40fad370b599a0b1ae7987f55b01e247cf27a7c27cd97e5bbc7

COPY --from=build /approvald /approvald

EXPOSE 8090
USER nonroot:nonroot
ENTRYPOINT ["/approvald"]
