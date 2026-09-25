# `mitmproxy` — the TLS-interception rig

A forward proxy that **terminates** the client's TLS on `CONNECT` rather than tunnelling
it, re-originates to the real origin, and can alter a response body in flight. It is the
instrument behind the #39 failure-class measurements, and the corporate TLS-inspecting
proxy the `FW_UPSTREAM_CA_BUNDLE` tests traverse.

It is a **test fixture**. Nothing here ships, nothing here is imported by the firewall,
and the CA private key is supplied per run and dies with the container.

## Why it is a container

It began as a listener inside the test binary, and that is the shape this repo has
already removed twice. Under docker-in-docker the daemon is a **separate container**, so
a client container's `host.docker.internal` resolves to the dind daemon's gateway and
never reaches a process in the job container. `.gitlab-ci.yml` records the lesson about
the firewall itself — *"used to run as a host PROCESS that dind can't route to"* — and
`e2e/harness.go` records it about the approval stub. A container with a published port
works on a laptop and on a shared runner alike.

## Interface

| | |
|---|---|
| `:8888` | the proxy. Clients set `HTTPS_PROXY=http://<host>:<published 8888>`. |
| `:8889` | control plane. `GET /requests` returns everything that crossed the interception point, plus the mutation counters. `GET /healthz` for readiness. |

Two ports because a client must never be able to reach the control plane by asking the
proxy for it.

## Configuration

| Variable | Meaning |
|---|---|
| `YJ_MITM_CA_CERT` / `YJ_MITM_CA_KEY` | the CA, PEM. **Required.** Supplied by the test so the certificate handed to clients is the one the test owns, and the container holds no state the test cannot see. |
| `YJ_MITM_MUTATE` | `none` (default, relay verbatim — the class-5 measurement), `swap` (serve the FIRST artifact's bytes for every later artifact — the integrity control), `forge` (rewrite the packument's hashes *and* serve substituted bytes — the npm adversarial leg), `corrupt` (append a byte to any artifact whose path ends with the configured suffix — for formats whose integrity is over the raw octets), `zipinject` (add a file INSIDE the archive — the tamper a Go module's hash actually covers), `corruptsha1` (tamper an artifact *and* forge the `x-checksum-sha1`/`x-checksum-md5` header and `.sha1` sidecar that travel with it — the Maven leg), `ociswap` (return a substitute manifest for any `/manifests/` request and forge `Docker-Content-Digest` — the OCI leg; a digest pull rejects it, a tag pull accepts it). |
| `YJ_MITM_FORGE_PKG`, `YJ_MITM_FORGE_INTEGRITY`, `YJ_MITM_FORGE_SHASUM`, `YJ_MITM_FORGE_BODY_B64` | `forge` mode only. |
| `YJ_MITM_CORRUPT_SUFFIX` | `corrupt` / `zipinject` / `corruptsha1` modes: which artifact suffix to tamper. |
| `YJ_MITM_OCI_SUB_MANIFEST_B64` | `ociswap` mode only: base64 of the substitute manifest to serve. |
| `HTTPS_PROXY` / `https_proxy` (set on the RIG) | class 7: route the rig's OWN upstream leg through another proxy — a corporate MITM stand-in, e.g. a second rig. Unset = dial the registry direct, as every other leg does. |
| `YJ_MITM_UPSTREAM_CA` | class 7: an extra root (PEM) APPENDED to the system roots for the upstream leg — the shape a product upstream CA bundle would take. Appended, not substituted, so a direct path keeps working. |
| `YJ_MITM_PROXY_AUTH` (`user:pass`) | class 7 (6b): the rig as an AUTHENTICATING corporate proxy — a CONNECT without matching `Proxy-Authorization: Basic …` is answered `407` and closed before any TLS; challenges are counted on the control plane. |
| `YJ_MITM_INTERMEDIATE=1` | class 7 (6b): sign leaves with an intermediate CA minted under the loaded root, not with the root; `GET /intermediate` on the control port returns its PEM. |
| `YJ_MITM_SERVE_INTERMEDIATE=0` | class 7 (6b): withhold that intermediate from the handshake — the common corporate misconfiguration, where a root-only bundle fails and only a full-chain bundle survives. Default `1` (served). |

The modes are **named and mutually exclusive on purpose**: the rig can relay faithfully
or do one specific, stated thing, so a leg cannot quietly be measuring a different attack
than the one it claims.

## Local-only: the real Docker daemon leg (increment 5b)

The e2e OCI leg (`tls_trust_oci_test.go`) drives **crane**, a Go client, so it measures the
Go trust path — not the Docker **daemon's** own `/etc/docker/certs.d` store. That was closed
by a local measurement, kept out of the CI e2e gate because it needs privileged
dind-in-dind. It is reproducible on a host with Docker; the finding is that **one
`certs.d/<registry>/ca.crt` file carries the whole pull** — registry, token server and blob
CDN alike — so the OCI operator instruction is a single per-registry file, not a system-store
change.

```sh
# 1. an ECDSA P-256 CA (the rig signs leaves with it)
openssl ecparam -name prime256v1 -genkey -noout -out ca.key
openssl req -x509 -new -key ca.key -sha256 -days 2 -subj "/CN=YJ MITM Test CA" \
  -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" -out ca.crt

# 2. the rig, faithful mode, published on the host
docker build -q -f e2e/mitmproxy/Dockerfile -t yellowjack-mitmproxy:e2e .
docker run -d --name yj-mitm -p 18888:8888 -p 18889:8889 \
  -e "YJ_MITM_CA_CERT=$(cat ca.crt)" -e "YJ_MITM_CA_KEY=$(cat ca.key)" -e YJ_MITM_MUTATE=none \
  yellowjack-mitmproxy:e2e

# 3. a real dockerd in dind, CA in certs.d ONLY (system store left untouched), routed through the rig
docker run -d --privileged --name yj-dind --add-host host.docker.internal:host-gateway \
  -e HTTP_PROXY=http://host.docker.internal:18888 -e HTTPS_PROXY=http://host.docker.internal:18888 \
  -e NO_PROXY=localhost,127.0.0.1 -e "YJ_CA_PEM=$(cat ca.crt)" --entrypoint sh docker:dind \
  -c 'mkdir -p /etc/docker/certs.d/registry-1.docker.io && printf "%s" "$YJ_CA_PEM" > /etc/docker/certs.d/registry-1.docker.io/ca.crt && exec dockerd-entrypoint.sh'

# 4. pull by digest; expect success + "Digest: sha256:c64c687…" verified
docker exec yj-dind docker pull \
  registry-1.docker.io/library/alpine@sha256:c64c687cbea9300178b30c95835354e34c4e4febc4badfe27102879de0483b5e

# 5. the rig's control plane shows registry + auth.docker.io/token + the CDN blob host all crossed it
curl -s http://localhost:18889/requests
```

On Git Bash / MSYS, prefix the `docker exec` calls that name absolute container paths with
`MSYS_NO_PATHCONV=1` so `/etc/...` is not rewritten to a Windows path.
