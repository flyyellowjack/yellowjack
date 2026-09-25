# syntax=docker/dockerfile:1

# ---- Stage 1: build ----------------------------------------------------------
# Builds the cache service. Context is the repo ROOT (so go.mod/go.sum and the
# cache/ package are both visible); build this image with:
#   docker build -f cache/Dockerfile -t yellowjack-cache:dev .
FROM golang:1.26@sha256:9d2f36f06329b2a141b9db99ffa32765cf695ee57b813ca29e245e8670bcbfff AS build

WORKDIR /src

# Resolve dependencies as a cached layer (shared go.mod).
COPY go.mod go.sum ./
RUN go mod download

# Copy only the cache package's source — it doesn't import the firewall code.
COPY cache/ ./cache/

# Static, CGO-free binary for a minimal runtime image (same rationale as the
# firewall and approval images). Build the ./cache package specifically.
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /cache ./cache

# ---- Stage 2: runtime --------------------------------------------------------
# distroless/static for CA certs and a tiny attack surface; :nonroot drops privileges.
FROM gcr.io/distroless/static:nonroot@sha256:1c2c046bc09ed40fad370b599a0b1ae7987f55b01e247cf27a7c27cd97e5bbc7

COPY --from=build /cache /cache

EXPOSE 8070
USER nonroot:nonroot
ENTRYPOINT ["/cache"]
