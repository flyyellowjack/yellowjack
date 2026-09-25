# syntax=docker/dockerfile:1

# The tampering hop for e2e/registry_front.sh leg 11 (#147). Built by compose from the repo
# ROOT (docker-compose.registryfront.yml names this file); same two-stage shape and the same
# pinned bases as e2e/fakesmtp. A rig fixture: it reaches no deployment.
FROM golang:1.26@sha256:9d2f36f06329b2a141b9db99ffa32765cf695ee57b813ca29e245e8670bcbfff AS build
WORKDIR /src
COPY e2e/tamperfront/main.go ./main.go
RUN go mod init tamperfront && CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /tamperfront .

FROM gcr.io/distroless/static:nonroot@sha256:1c2c046bc09ed40fad370b599a0b1ae7987f55b01e247cf27a7c27cd97e5bbc7
COPY --from=build /tamperfront /tamperfront
EXPOSE 8080
ENTRYPOINT ["/tamperfront"]
