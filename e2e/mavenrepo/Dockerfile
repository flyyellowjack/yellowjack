# syntax=docker/dockerfile:1

# The one-artifact Maven repository for the strict-checksum e2e leg (#147).
#
# Built from the repo ROOT:
#   docker build -f e2e/mavenrepo/Dockerfile -t yellowjack-mavenrepo:e2e .
# e2e/maven_checksum_test.go does this for you (buildMavenRepo).
#
# A CONTAINER rather than an httptest server inside the test, because under docker:dind
# the gate is a container and cannot reach a listener in the test process.

# Built standalone with its own throwaway module: the fixture is stdlib-only and
# deliberately NOT part of the main module's dependency graph.
FROM golang:1.26@sha256:9d2f36f06329b2a141b9db99ffa32765cf695ee57b813ca29e245e8670bcbfff AS build
WORKDIR /src
COPY e2e/mavenrepo/main.go ./main.go
RUN go mod init mavenrepo && CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /mavenrepo .

# ── the Maven CLIENT, as its own target ──────────────────────────────────────
#
#   docker build -f e2e/mavenrepo/Dockerfile --target mvnclient -t yellowjack-mvnclient:e2e .
#
# Declared HERE rather than as a string in the Go test for the reason credupstream's
# Dockerfile records: scripts/pinned-images.sh walks Dockerfile FROM lines and compose
# `image:` lines and nothing else, so an image named in a .go file is outside every pin
# check. This leg's result depends on the client's checksum behaviour, which is exactly
# the kind of thing a floating tag changes underneath you.
FROM maven:3.9-eclipse-temurin-21@sha256:c2a2c58516d160f43b50f12baa427ca86989e0bc942609e04aff61da5d9a7d74 AS mvnclient
# PRE-WARM mvn's own plugin tree into the image. Measured on the first run of this leg:
# 207s / 262s / 112s for the three legs, almost all of it mvn downloading the dependency
# plugin's ~200 artifacts from Central into a cold local repository, three times over.
# Resolving it once here costs one of those downloads per image build and makes each leg a
# few seconds.
#
# It does NOT weaken the measurement, and the reason is checkable rather than assumed: the
# fixture artifact exists in no public repository, so it can never be in this cache, and
# every leg REQUIRES the fixture repository to have served it (the contact check). `help`
# is used because it resolves the plugin's whole realm without needing any artifact.
RUN printf '<settings/>' > /tmp/warm-settings.xml  && mvn -B -gs /tmp/warm-settings.xml org.apache.maven.plugins:maven-dependency-plugin:3.6.1:help > /dev/null  && rm /tmp/warm-settings.xml

# The same final base as every shipped service, so the fixture pulls no image the rig
# does not already need.
FROM gcr.io/distroless/static:nonroot@sha256:1c2c046bc09ed40fad370b599a0b1ae7987f55b01e247cf27a7c27cd97e5bbc7
COPY --from=build /mavenrepo /mavenrepo
EXPOSE 8080
ENTRYPOINT ["/mavenrepo"]
