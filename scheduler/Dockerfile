# syntax=docker/dockerfile:1

# The scheduler launches run-once scanner containers. Its docker-run launcher
# shells out to `docker`, so the runtime image needs the docker CLI — but only the
# CLI (a static binary), not a whole docker/alpine base. We copy just that binary
# into distroless to keep the attack surface small, matching the other services.
#
# Security tradeoff to be honest about (this is security software): the docker-run
# launcher requires the docker CLI AND a mounted docker daemon socket, and the
# process must run as root to use that socket — a powerful grant. The planned
# raw-Docker-Engine-API launcher removes the CLI (still needs the socket); a
# Kubernetes-Job launcher removes the socket entirely (D16). This image is the
# pragmatic first step, not the end state.

# ---- Stage 1: build the scheduler binary ------------------------------------
FROM golang:1.26@sha256:9d2f36f06329b2a141b9db99ffa32765cf695ee57b813ca29e245e8670bcbfff AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
# Only the scheduler package — it's standalone (imports no firewall code).
COPY scheduler/ ./scheduler/
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /scheduler ./scheduler

# ---- Stage 2: source the docker CLI binary ----------------------------------
# The official docker image ships a static `docker` client at /usr/local/bin/docker.
# Pin by digest in production so the exact bytes can't change under the tag.
FROM docker:cli@sha256:3f4743208d2338c934d7b8bcfbe1bb54c0b2355c510ad5e0f31c0c4a54bd704e AS dockercli

# ---- Stage 3: runtime -------------------------------------------------------
# distroless/static (root variant, NOT :nonroot) so the process can access the
# mounted /var/run/docker.sock. CA certs come with distroless/static.
FROM gcr.io/distroless/static:latest@sha256:f2ea2709ac8db56323cbd7d014277f32cb572d9ea124b0076f7aafe5980678fe
COPY --from=build /scheduler /scheduler
COPY --from=dockercli /usr/local/bin/docker /usr/local/bin/docker
EXPOSE 8096
ENTRYPOINT ["/scheduler"]
