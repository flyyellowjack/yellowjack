# syntax=docker/dockerfile:1

# The stub OpenID Provider for the console's OIDC sign-in legs (#149, legs 24-27).
#
# Built from the repo ROOT:
#   docker build -f e2e/oidcstub/Dockerfile -t yellowjack-oidcstub:e2e .
# e2e/async_local.sh does this for you, next to yellowjack-fakesmtp:e2e.
#
# Why an image rather than a host process: under dind the compose stack runs inside a
# daemon container, so a process on the job's host is not what "host.docker.internal"
# reaches, and the job cannot reach the stack by "localhost" either. A service in the
# stack is reachable from both sides by construction -- the console dials oidcstub:9000,
# the rig's curl dials the published port. Same reasoning as e2e/fakesmtp.
#
# Pinned by digest like every other image in the tree (the vet gate refuses a bare tag;
# re-resolve with `sh scripts/dev.sh resolve python:3.12-alpine`).
FROM python:3.12-alpine@sha256:c4634f578a412db396771b61b064c6e546c9d6414c7fb5b1b05d5871f1885f7b

# Unprivileged, on the same uid the shipped distroless images use, so a bind mount
# added later would not need a different owner. Port 9000 needs no privilege.
RUN adduser -D -u 65532 -h /home/idp idp
COPY e2e/oidcstub/idp.py /idp.py
USER idp
EXPOSE 9000
ENV IDP_STATE=/tmp/oidcstub-state.json

# console-oidc waits on this (depends_on: service_healthy). !330 makes a configured but
# unreachable IdP FATAL at console startup -- the right call for a console, and the
# reason ordering by "started" is not enough here: the stub must be LISTENING first.
HEALTHCHECK --interval=2s --timeout=2s --retries=15 \
  CMD wget -qO- http://127.0.0.1:9000/_hits >/dev/null || exit 1

CMD ["python", "-u", "/idp.py", "9000"]
