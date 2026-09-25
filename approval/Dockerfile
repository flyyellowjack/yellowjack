# syntax=docker/dockerfile:1

# ---- Stage 1: build ----------------------------------------------------------
# Builds the approval service. Context is the repo ROOT (so go.mod/go.sum and the
# approval/ package are both visible); build this image with:
#   docker build -f approval/Dockerfile -t yellowjack-approval:dev .
FROM golang:1.26@sha256:9d2f36f06329b2a141b9db99ffa32765cf695ee57b813ca29e245e8670bcbfff AS build

WORKDIR /src

# Resolve dependencies as a cached layer (pgx etc. live in the shared go.mod).
COPY go.mod go.sum ./
RUN go mod download

# Copy only the approval package's source — it doesn't import the firewall code.
COPY approval/ ./approval/

# Static, CGO-free binary for a minimal runtime image (same rationale as the
# firewall image). Build the ./approval package specifically.
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /approvald ./approval

# ---- Stage 2: runtime --------------------------------------------------------
# distroless/static provides CA certs (the service has no outbound TLS today, but
# this keeps parity with the firewall image) and a tiny attack surface. :nonroot
# runs as an unprivileged user.
FROM gcr.io/distroless/static:nonroot@sha256:1c2c046bc09ed40fad370b599a0b1ae7987f55b01e247cf27a7c27cd97e5bbc7

COPY --from=build /approvald /approvald

EXPOSE 8090
USER nonroot:nonroot
ENTRYPOINT ["/approvald"]
