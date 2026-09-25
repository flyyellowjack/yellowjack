# syntax=docker/dockerfile:1

# BASE IMAGES ARE PINNED BY DIGEST, HERE AND IN EVERY OTHER Dockerfile (issue #22).
# A tag is a mutable pointer: `golang:1.26` is republished, so the same Dockerfile
# builds different bytes on different days. Nexus bug #544 is what that costs — a
# newer `:latest` triggered an unintended database migration on somebody who had
# changed nothing. The digest is what makes a build reproducible and an incident
# explainable, and for the self-hoster D54 says we are building for, "I can explain
# exactly what changed" is the product.
#
# The tag is kept alongside the digest on purpose: the digest makes it reproducible,
# the tag makes it reviewable. `scripts/pinned-images.sh` enforces both.
#
# To move a version — do NOT hand-copy a digest out of `imagetools inspect`, which
# prints a per-platform digest for each of 8 platforms next to the index digest:
#   sh scripts/dev.sh resolve golang:1.27

# ---- Stage 1: build ----------------------------------------------------------
# The builder stage has the full Go toolchain. Nothing from this stage ends up
# in the final image except the one binary we copy out — so the toolchain,
# source, and build cache never ship to production.
FROM golang:1.26@sha256:9d2f36f06329b2a141b9db99ffa32765cf695ee57b813ca29e245e8670bcbfff AS build

WORKDIR /src

# Copy module files first and resolve dependencies as their own layer. Docker
# caches layers, so as long as go.mod/go.sum don't change, this expensive step
# is reused across builds even when only source files change. (We currently have
# no third-party deps, so this is mostly establishing the pattern.)
COPY go.mod go.sum ./
RUN go mod download

# Now copy the actual source and compile.
COPY *.go ./

# CGO_ENABLED=0 -> a fully static binary with no libc dependency, so it can run
# on a near-empty base image. GOOS=linux because the container runs Linux even
# though we build on Windows. -ldflags "-s -w" strips debug info to shrink the
# binary. The result is a single self-contained executable.
#
# GO_TAGS selects optional build variants. Empty (the default) is the open-source gate;
# GO_TAGS=intercept adds TLS-interception mode where its source is present.
ARG GO_TAGS=""
RUN CGO_ENABLED=0 GOOS=linux go build -tags "$GO_TAGS" -ldflags="-s -w" -o /yellowjack .

# ---- Stage 2: runtime --------------------------------------------------------
# distroless/static is a minimal base: it contains CA certificates (required for
# our outbound HTTPS calls to npm and deps.dev) and not much else — no shell, no
# package manager, no OS userland. That tiny surface is deliberate for security
# software. The :nonroot tag makes the default user unprivileged.
FROM gcr.io/distroless/static:nonroot@sha256:1c2c046bc09ed40fad370b599a0b1ae7987f55b01e247cf27a7c27cd97e5bbc7

# Copy just the compiled binary from the build stage.
COPY --from=build /yellowjack /yellowjack

# Document the port the service listens on. This is informational; the actual
# port still comes from FW_LISTEN_ADDR at runtime.
EXPOSE 8080

# Run as the built-in non-root user provided by the :nonroot base.
USER nonroot:nonroot

# The binary is the entrypoint. All configuration is injected at runtime via
# environment variables (-e FW_...), so this same image runs anywhere unchanged.
ENTRYPOINT ["/yellowjack"]
