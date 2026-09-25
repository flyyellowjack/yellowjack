# The scanner is a RUN-ONCE container: `docker run` it with the target repo, a
# GitHub token, and a results-sink URL in the environment; it runs OpenSSF
# Scorecard once, POSTs the result to the sink, and exits. There is no server and
# no port. A separate scheduler launches one of these per scan (see DECISIONS.md
# D16). This image is destined to be published as its own public repo (the
# scorecard-container); for now it lives here so the reshape stays self-contained.

# ---- Base images: pinned here, mirrored in CI (issue #106) -------------------
# Every external base is named ONCE, as a build ARG whose default is the upstream
# reference pinned by digest. A developer's plain `docker build` uses these
# defaults and pulls from upstream, as it always did. The e2e gate does not:
# scripts/mirror-bases.sh copies each digest into the project's own container
# registry the first time a pipeline sees it, builds with
# `--build-arg NAME=<mirror>@<the same digest>`, and refuses if the build resolved
# a base anywhere else. The digest is the identity in both worlds.
#
# Why: on 2026-08-31 gcr.io withdrew anonymous pull from the scorecard base and
# the merge gate went red on every open MR with nothing changed here. Pinning by
# digest fixed the BYTES; this fixes the DEPENDENCY. To move a version: resolve
# the new digest with `sh scripts/dev.sh resolve <image:tag>`, paste it here, and
# the next pipeline mirrors it — that is the only moment upstream is contacted.
#
# No `# syntax=` directive, on purpose: it makes BuildKit pull the
# docker/dockerfile frontend image from Docker Hub at build time — one more
# anonymous third-party pull — and nothing in this file needs it.
#
# The Go toolchain is the declared exception (`# mirror: upstream` on the line
# above its ARG, which is what the script reads). golang:1.26's index spans 16
# manifests including two Windows variants — about 6.5 GB — and a registry
# refuses a sparse copy (measured: registry:2 answers MANIFEST_BLOB_UNKNOWN for
# every child left out of a pushed index), so a digest-faithful mirror would
# cost the whole index per Go version. It stays on Docker Hub, and CI PREFLIGHTS
# it instead: an unreachable or revoked registry fails in a step that names
# Docker Hub, not somewhere inside the build. GitLab's Dependency Proxy is the
# cheap route for Docker Hub images if this ever bites.
# mirror: upstream — 6.5 GB multi-platform index; preflighted, not copied (see above)
ARG GOLANG_BASE=golang:1.26@sha256:9d2f36f06329b2a141b9db99ffa32765cf695ee57b813ca29e245e8670bcbfff
# single-platform: upstream publishes no index
ARG SCORECARD_BASE=ghcr.io/ossf/scorecard:v5.2.1@sha256:f326f06a6d3e09f9528da5a1610dd176c000a2840532a0982f6a7eb7b389c305
ARG DISTROLESS_BASE=gcr.io/distroless/static:nonroot@sha256:1c2c046bc09ed40fad370b599a0b1ae7987f55b01e247cf27a7c27cd97e5bbc7

# ---- Stage 1: build our run-once scanner binary -----------------------------
# Same pattern as the other services: the full Go toolchain lives here and never
# ships. Build from the repo ROOT so go.mod/go.sum and scanner/ are both visible:
#   docker build -f scanner/Dockerfile -t yellowjack-scanner:dev .
FROM ${GOLANG_BASE} AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
# Only the scanner package's source — it doesn't import the firewall code.
COPY scanner/ ./scanner/
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /scanner ./scanner

# ---- Stage 2: source the scorecard binary -----------------------------------
# The scanner shells out to the OpenSSF `scorecard` binary, so the runtime image
# must contain it. We copy it from OpenSSF's own published image rather than
# downloading a release tarball ourselves: the image is the upstream's own
# artifact. This is the single trusted external binary in our stack.
#
# 🚨 SOURCE CHANGED 2026-08-31 (issue #106): this was
# `gcr.io/openssf/scorecard:v5.2.1`, which now returns **403 Forbidden** to
# anonymous token requests and broke the e2e gate for every MR at once.
#
# It is NOT an outage and retrying does not help — measured, because "wait for the
# registry to come back" was the obvious wrong response:
#
#   gcr.io/openssf/scorecard        -> 403     <- only this repository
#   gcr.io/distroless/static        -> 200     <- still used below, still fine
#   gcr.io/google-containers/pause  -> 200
#   gcr.io/kaniko-project/executor  -> 200
#
# So gcr.io is healthy and anonymous pull was withdrawn from this repo specifically.
# `ghcr.io/ossf/scorecard` is the SAME upstream publishing the same artifact, which
# keeps the "upstream's own artifact" property the paragraph above is about.
#
# NOW PINNED BY DIGEST, as the previous comment said production should be. That is
# not cosmetic here: a tag whose registry can revoke access is exactly the kind of
# reference that changes underneath you, and the digest is what makes the bytes
# reproducible. Verified before switching (over the registry API, since Docker does
# not run on the dev host): linux/amd64, and Entrypoint `/scorecard` — so the
# `COPY --from=scorecard /scorecard` below still finds the binary at that path.
#
# To move version: resolve the new digest with
#   sh scripts/dev.sh resolve ghcr.io/ossf/scorecard:<tag>
# and paste it into SCORECARD_BASE at the top of this file; the next pipeline
# mirrors it. ghcr.io/ossf/scorecard:v5.2.1 is a bare linux/amd64 manifest, not a
# manifest list, so this pin is faithful to the tag rather than a narrowing of it.
# The `single-platform:` marker above that ARG is what `sh scripts/dev.sh pins`
# reads: an UNDECLARED single-arch pin fails there, because that is the silent way
# an arm64 build gets broken.
FROM ${SCORECARD_BASE} AS scorecard

# ---- Stage 3: runtime -------------------------------------------------------
# distroless/static:nonroot for CA certs (Scorecard calls the GitHub API over
# HTTPS) and a tiny attack surface, matching the other Yellow Jack services.
# scorecard is a static Go binary that uses the GitHub API (not a local git
# clone), so it needs no extra libraries or tools here.
FROM ${DISTROLESS_BASE}
COPY --from=build /scanner /scanner
COPY --from=scorecard /scorecard /usr/local/bin/scorecard

# distroless has no PATH-search niceties, so point the run-once binary at the
# absolute path rather than relying on the code's bare-"scorecard" default.
ENV SCANNER_SCORECARD_BIN=/usr/local/bin/scorecard

# No EXPOSE: this container serves nothing. It runs to completion and exits.
# Inputs arrive at `docker run` time, e.g.:
#   docker run --rm \
#     -e SCANNER_REPO=github.com/lodash/lodash \
#     -e SCANNER_SINK_URL=http://scheduler:8096/results/<id> \
#     -e GITHUB_TOKEN=$GITHUB_TOKEN \
#     yellowjack-scanner:dev
USER nonroot:nonroot
ENTRYPOINT ["/scanner"]
