# SETUP.md — Yellow Jack

How to build, run, test, and operate Yellow Jack, plus the one-time onboarding +
push checklist. For *why* the code is shaped as it is, see `BUILD_LOG.md`; for
the project constitution, `../CLAUDE.md`.

---

> **The bounded claim, in the words to use.** With an operator allow list in play, *"we block known
> malware"* is not accurate on its own. The honest form is: **"we block known malware, unless an
> administrator has explicitly allowed that release."** That is D312's ruling — the administrator has
> the last word about an artifact they judged — and every override is on the audit record, so the
> narrower claim is checkable rather than merely stated. Write the narrow one; the broad one invites
> exactly the inspection it cannot survive.

## Prerequisites

- **Go 1.26+** — `go version`
- **Git 2.34+** (for SSH commit signing) — `git --version`
- **Docker Desktop** (for the container stack) — `docker version`

On Windows, after installing any of these, fully restart the terminal/VS Code so
`PATH` refreshes.

---

## Build & run (local, no containers)

Three binaries, one Go module:

```
go build -o yellowjack.exe .          # the firewall/proxy
go build -o approvald.exe ./approval  # the approval (control-plane) service
go build -o cache.exe ./cache         # the optional cache front door
```

Run the firewall (npm by default):

```
./yellowjack.exe
# then, in another shell:
curl http://localhost:8080/healthz          # -> ok
curl http://localhost:8080/lodash           # allowed/blocked per score
```

Switch ecosystem with `FW_ECOSYSTEM` (npm | pypi | oci); the upstream defaults to
match. Examples:
- PyPI: `FW_ECOSYSTEM=pypi ./yellowjack.exe`, then `GET /simple/requests/`
- OCI:  `FW_ECOSYSTEM=oci ./yellowjack.exe`, then `GET /v2/library/nginx/manifests/latest`

### Configuration (environment variables)

**Firewall**
| Var | Default | Meaning |
|-----|---------|---------|
| `FW_LISTEN_ADDR` | `:8080` | listen address |
| `FW_ECOSYSTEM` | `npm` | `npm` \| `pypi` \| `oci` |
| `FW_UPSTREAM` | per-ecosystem | real registry to proxy to |
| `FW_UPSTREAM_CA_BUNDLE` | _(empty)_ | absolute path to a PEM bundle **appended** to the system roots for the firewall's own outbound TLS. Set it when an enterprise TLS-inspecting proxy sits in front of the registry, or every upstream handshake fails `x509: certificate signed by unknown authority`. The public roots stay, so a host reached directly still verifies. The proxy ADDRESS is not a `FW_` variable: use `HTTPS_PROXY`/`NO_PROXY`. |
| `FW_SCORECARD_MODE` | `stub` | `off` (no scoring: lists + release-age window + feed decide; the supported no-scanner posture) \| `stub` (dev fixture: fixed 7.5, reports **not ready**) \| `api` (deps.dev) \| `local` (your own scanner via the scheduler) — full semantics in `docs/CONFIGURATION.md` |
| `FW_VERIFY_REPO` | `true` | api/local mode: cross-check the self-declared repo against deps.dev's own record, closing the "borrow-a-score" bypass. `false` restores the old score-the-claimed-repo behavior |
| `FW_UNVERIFIED_POLICY` | `closed` | what happens when that cross-check can't confirm the link. `closed` = blocked (and queued for review if `FW_APPROVAL_URL` is set — with no approval service there is no way to approve, so the flag below is the only lever), independent of `FW_UNSCORABLE_POLICY`; `open-with-visibility` = proceed on the self-declared repo, logged `unverified`. Applies only to **durable** answers (deps.dev has no mapping, or contradicts the claim) — a deps.dev **outage** is never a verdict: since D102 it is a 403 whose explanation says the firewall *could not verify* the package, distinct from the *blocked by firewall* wording a real denial carries (it was a retryable 503 before that ruling). No effect unless the cross-check actually runs (`FW_VERIFY_REPO=true` **and** `FW_SCORECARD_MODE` of `api`/`local`; the startup banner reports the effective posture). **OCI fails closed under the default**: deps.dev has no container index, so every image that declares a source repo is refused until this is set to `open-with-visibility` (D48, #33) — the banner says so in capitals. **Maven, with scanning on, refuses part of its own toolchain under the default**: deps.dev lists no source repository for many Maven artifacts (measured in !47: `commons-lang3`, and Maven's own dependency plugin), so they are unverifiable. The default stays `closed` (D141), and the fix is one line on the Maven instance only — `FW_UNVERIFIED_POLICY=open-with-visibility` — since each instance fronts one ecosystem, npm and PyPI instances keep `closed` (#95) |
| `FW_SCORE_THRESHOLD` | `5.0` | min Scorecard score to allow |
| `FW_UNSCORABLE_POLICY` | `block` | `block` (fail-closed) \| `allow` (fail-open) |
| `FW_APPROVAL_URL` | _(empty)_ | approval service base URL; empty disables it |
| `FW_TRUSTED_PROXIES` | _(empty)_ | comma-separated reverse-proxy/LB addresses (CIDR `10.0.0.0/8` or bare IP) whose `X-Forwarded-For` the firewall will believe when recording a pull's **source IP** (#41). Empty = trust none, so the source IP is always the raw connecting peer — correct for the default cooperative setup where clients reach the firewall directly. Set it **only** when the firewall genuinely sits behind a proxy you control: an untrusted client's `X-Forwarded-For` is attacker-controlled and is ignored. The recorded IP is the observed connecting host (may be a shared NAT/CI egress), **not** a developer identity, and is treated as personal data |
| `FW_MAX_CONNS_PER_HOST` | `64` | ceiling on simultaneous TCP connections the firewall opens to any **one** host it calls (upstream registry, deps.dev, approval/L2, scheduler). Beyond the ceiling, requests wait for a free connection instead of dialing a new socket — which is what stops a cold resolve burst from stampeding your own approval service with connection setup (issue #1). Raise it if your L2 is beefy and you see requests queueing; a **negative** value disables the ceiling entirely (connections still pooled and reused). Does **not** apply to the proxy's client-facing relay path, which is uncapped on purpose so large parallel artifact downloads are never throttled |
| `FW_BYTE_GATE` | `allow-but-log` | **npm only.** Whether tarball (artifact) fetches are gated, not just metadata — `npm ci` fetches tarballs straight from lockfile URLs and never asks for metadata. `allow-but-log` = evaluate every fetch; **refuse it if the package was denied on a positive finding** (score below threshold, or human-denied), serve-and-log if it was merely unscorable/unverifiable. `enforce` = refuse those too, plus the retryable pending/unavailable outcomes. `off` = no evaluation and no artifact-URL rewriting (the pre-#11 passthrough) — the only setting that serves a blocked package's bytes. An unrecognized value reads as `allow-but-log` |
| `FW_URL_SIGNING_KEY` | _(empty)_ | **Opt-in.** Turns on **signed artifact URLs** (#72). When set, every artifact URL the firewall mints carries an HMAC binding the package name in the URL to that URL's object path, and a byte fetch whose two halves were not minted together is refused. This closes the confused deputy in #67: without it, a client can pair an **allowed** package's URL prefix with a **blocked** package's object path and be handed the blocked bytes under a verdict about something else. Applies to the two routes the firewall mints — npm's `/_tarball/` and PyPI's `/_files/`. npm's own `/<pkg>/-/<file>.tgz` shape is unaffected (its identity comes from the same path it forwards), as are Maven and OCI. Minimum 16 bytes; the process refuses to start on a shorter one. All replicas must be given the **same** key, or one replica cannot verify a URL another minted |
| `FW_URL_SIGNING_KEY_PREVIOUS` | _(empty)_ | Accepted for **verification only**, never for minting. Rotation needs it: signed URLs are recorded in lockfiles and replayed later by `npm ci`, so without a grace window every in-flight lockfile would break the instant you rotated. Rotate by moving the old key here, then drop it once those lockfiles have aged out |

> **Signed artifact URLs are a *binding*, not a permission slip.** The signature says the
> firewall minted this package/path pair; it says nothing about the verdict, which is still
> re-evaluated on **every** byte fetch. That is deliberate and is why the URLs carry **no
> expiry**: replaying an old lockfile URL earns a fresh evaluation, so a package blocked
> since the URL was minted is still refused, and revocation keeps working. An expiry would
> buy nothing while breaking `npm ci` on any lockfile older than the window.
>
> **Turning it on invalidates `/_tarball/` and `/_files/` URLs minted while it was off**, so
> budget one round of lockfile regeneration. Lockfiles recording npm's native
> `/<pkg>/-/<file>.tgz` URLs — most of what is already in the wild — are unaffected.

> **`FW_BYTE_GATE` splits enforcement by *why* a package was denied.** The gate's main
> control point is the *metadata* request, but `npm ci` (and pnpm/yarn installing from a
> lockfile) fetch tarballs **directly** by their recorded `resolved` URL and never request
> metadata. So the byte path has to make its own decision, and the default draws the line
> at the kind of denial:
>
> - **Denied on a positive finding** — it scored below the threshold, or a human denied
>   it. **Refused, in every mode except `off`.** Serving those bytes was never the intent,
>   and allowing it means the same package installs or fails depending only on whether the
>   developer ran `npm install` or `npm ci`.
> - **Denied for an absence of trust** — unscorable, or its repo could not be verified.
>   **Served and logged** (`SERVING BYTES ANYWAY`) under the default. This fires on plenty
>   of legitimate packages with thin metadata, so blocking it by default would break CI
>   builds for a reason that is about *our* coverage, not the package. Set
>   `FW_BYTE_GATE=enforce` to refuse these as well — grep your logs for
>   `SERVING BYTES ANYWAY` first to see exactly what that would have blocked.
>
> PyPI has gated artifact bytes since D22 and needs no knob. OCI blob fetches are not
> gated; unlike `npm ci`, no ordinary OCI client fetches blobs without first fetching
> the manifest, which *is* gated (see `docs/BUILD_LOG.md`).

**Approval service**
| Var | Default | Meaning |
|-----|---------|---------|
| `APPROVAL_LISTEN_ADDR` | `:8090` | listen address |
| `APPROVAL_DATABASE_URL` | _(empty)_ | Postgres DSN; empty = in-memory (non-durable) |

**Cache**
| Var | Default | Meaning |
|-----|---------|---------|
| `CACHE_LISTEN_ADDR` | `:8070` | listen address |
| `CACHE_UPSTREAM` | `http://localhost:8080` | upstream to forward to (the firewall) |

---

### What a refusal carries

Every refusal is a `403` whose explanation travels twice: as prose for the developer and as
**machine-readable fields** for a log scraper, a ticket, or an audit (D182, #20):

| Where | Fields |
|---|---|
| Headers | `X-Yellowjack-Reason` (prose), `X-Yellowjack-Next-Step` (what happens now), `X-Yellowjack-Kind`, `X-Yellowjack-Rule`, `X-Yellowjack-Source` |
| Body (npm, Maven, PyPI byte path) | `error`, `reason`, `nextStep`, `kind`, `rule`, `source` |
| Body (OCI, distribution-spec shape) | the same fields inside `errors[0].detail` |

`kind` is the denial kind (`known-malware`, `operator-denied`, `score-below-threshold`, `unscorable`,
`unverified`, `human-denied`, `release-window`, `integrity`, or the two non-verdicts `pending` and
`unavailable`). `rule` is the identifier of what fired — an advisory ID such as `MAL-2026-1234`, a
deny-list entry (`deny-list:<package>`), a **policy rule by position** (`verdict#4`,
`classification#2`: the same numbering the policy view lists each chain in, the implicit terminal
last — positional rather than named, because rule names carry knob values and must not reach a
client), `release-window`, or the integrity check (`artifact-binding`, `artifact-filename-binding`,
`url-signature`, `tarball-version`, `wheel-version`). `source` is where that rule lives — `known-malware feed`
(`FW_MALWARE_LIST`), `operator deny list` (`FW_DENY_LIST`), `policy <digest>` (the same digest the
audit record and the startup line carry), `approval service` (`FW_APPROVAL_URL`), `release window`
(`FW_MIN_RELEASE_AGE_DAYS` / `FW_MAX_RELEASE_AGE_DAYS`), or `byte integrity`. The knob names appear
here and in the log, never on the wire. The audit record carries the same three (`deny_kind`, `rule`, `source`), plus
`taken` and `mode`: under `FW_MODE=report` a refused verdict is relayed anyway, and the record
reads `action: block`, `taken: allow`, `mode: report` — distinguishable from a real block without
reading a log line (#114).

One exception, by protocol: a PyPI refusal is a PEP 592 **yank** inside a `200` index, because pip
backtracks around a 403 but reads a yank reason out loud (D22). The index format has no field for a
rule identifier, so only the prose reason travels on that route.

## Run the full stack (containers)

```
sh scripts/dev.sh up
```

Brings up Postgres + approval + firewall (npm, :8080) + firewall-oci (:8081) +
cache (:8071), wired by injected service URLs. `docker compose down` to stop
(`down -v` also wipes the `pgdata` volume).

**Why the wrapper rather than `docker compose up --build` directly.** The shipped compose
file carries **no database credential** (#22) — a default there would be one identical
password on every installation of the product. `dev.sh up` first runs `scripts/gen-env.sh`,
which mints a per-machine `POSTGRES_PASSWORD` into a git-ignored `.env` that compose loads
automatically; after that, plain `docker compose` commands work normally in this directory.
Run bare and with no `.env`, compose stops with an error naming that command rather than
starting on a shared secret.

⚠️ Postgres applies `POSTGRES_PASSWORD` **only when initialising an empty data
directory**. If you already have a `pgdata` volume from an earlier version, the generator
keeps the legacy password rather than locking you out of it, and says so. Rotating means
`docker compose down -v`, which destroys the local database and any audit trail in it.

### ⚠️ Deployment assumption: these services trust the network between them (D77)

**Yellow Jack assumes its own services run on a private network, and it does not
authenticate them to each other.** The firewall, scheduler, approval service and console
talk over plain HTTP using the injected service URLs above, and the approval control
plane's mutating routes — `PUT /v1/decisions`, `PUT`/`DELETE /v1/scores`,
`POST /v1/events` — take **no credential**. That is a deliberate design decision, not an
oversight: Kubernetes and Docker networks are private by default, and inter-service
transport security is delivered by the deployment (a service mesh such as Istio, or a
network policy), which is the **deployer's responsibility** rather than something Yellow
Jack builds into the application.

**What this means in practice.** Do not publish the approval service's port
(`APPROVAL_LISTEN_ADDR`, default `:8090`) beyond the network its own services sit on.
Anything that can reach that socket can write verdicts and scores. The listen address is
**not** an authorization boundary — binding to loopback protects a single-host deployment
only, and one port mapping or debug tunnel removes even that.

**Two things that are authenticated, because the network cannot cover them:**

- **The scan-result callback.** A scanner reports its score to a per-scan URL carrying a
  `crypto/rand` capability token, compared in constant time, so a forged verdict cannot be
  injected regardless of network posture (issue #13).
- **The console's write actions.** Approving or denying a queued package sits behind basic
  gateway auth, and with no credential configured the override endpoint is disabled rather
  than left open.

If your estate requires mutual TLS between services — some enterprise and public-sector
environments do — provide it through your mesh. Yellow Jack neither requires nor supplies
it, and adding an application-level shared secret would duplicate the boundary your
infrastructure already owns.

### ⚠️ The scheduler holds the Docker socket, and that is root on your host (#80, D133)

**One service in this stack is root-equivalent on the machine it runs on.** The scheduler
launches a run-once scanner container per scan, and to do that it mounts the host's Docker
daemon socket:

```yaml
scheduler:
  volumes:
    - /var/run/docker.sock:/var/run/docker.sock
```

Anything that can reach that socket can **start a privileged container, bind-mount your host
filesystem, and compromise sibling containers — including the firewall itself**. This is true
*regardless of the user the container runs as*: the socket is owned `root:docker` on a normal
host, so talking to it is equivalent to being root on the host, and running the scheduler as a
non-root uid would buy appearance rather than safety. That is why the scheduler is the one
service deliberately excluded from the non-root assertion in `e2e/hardening.sh`, where it is
recorded as `ROOT_BY_DESIGN`.

**You only carry this risk if you opt into local scanning.** The scheduler exists solely to
serve `FW_SCORECARD_MODE=local`. Under `off` — the no-scanner posture the reference deployment
and the Helm chart both ship — and under `api`, the gate never calls a scanner, so you do not
run the scheduler and **no Docker socket is mounted anywhere**. Everything below applies from
the moment you turn local scans on, and not before.

**Which services have it.** Only the scheduler. The firewall, firewall-oci and cache — the
services that terminate traffic from developer machines — do **not** mount the socket, and a
test (`dockersocket_test.go`) fails if that ever changes, so the blast radius cannot widen in
a one-line compose edit without somebody deciding to.

**This is your deployment's risk to manage, not something Yellow Jack engineers away** (D133:
deployment security is the deployer's; ours is the Dockerfile, the HA behaviour and the Helm
chart). What follows is what is actually available today, stated precisely, because a
mitigation that does not exist is worse than none.

**Option 1 — point the launcher at a remote daemon (no socket mount). This is the recommended
production deployment.** The `docker-run`
launcher shells out to the `docker` CLI and does not override the process environment, so the
CLI honours `DOCKER_HOST`. Setting it — with `DOCKER_TLS_VERIFY=1` and `DOCKER_CERT_PATH` for
mutual TLS — sends container launches to a daemon on another host, and the socket mount can be
removed entirely:

```yaml
scheduler:
  environment:
    SCHEDULER_LAUNCHER: "docker-run"
    DOCKER_HOST: "tcp://scanner-host:2376"
    DOCKER_TLS_VERIFY: "1"
    DOCKER_CERT_PATH: "/certs/client"
  # and no /var/run/docker.sock volume
```

The daemon that runs scans is then a machine you can treat as expendable, rather than the one
running your gate.

**This path is now run, not merely reasoned about.** `sh scripts/dev.sh remotedaemon` starts a
second daemon with its own image store, points a scheduler at it over **mutual TLS with no
socket mounted anywhere**, and drives a real scan: the run-once container is created on that
daemon, reports back through the capability-token sink, and `/scan` answers with the score. The
drill reads which daemon created the container from the daemons' own event streams rather than
inferring it from the scan succeeding, and it carries two controls — remove `DOCKER_HOST` and
the scan must fail, and the `docker-api` launcher pointed at the same `tcp://` address must
fail. What it still does not cover is a second *host*: the "remote" daemon is a container on one
machine, so the network between two machines remains yours (D133).

⚠️ **The first thing you will hit is the certificate's name.** A daemon's server certificate
covers the names it was generated for, and `DOCKER_HOST` must use one of them or the CLI refuses
before it sends anything:

```
error during connect: Get "https://scanner-host:2376/_ping": tls: failed to verify certificate:
  x509: certificate is valid for 8a3bb4900fd5, docker, localhost, not scanner-host
```

That is a **client-side** refusal, so nothing reaches the remote daemon and its logs are empty —
look at the scheduler's `/scan` response, not the daemon. Either reach the host by a name its
certificate carries, or issue the certificate for the name you intend to use.

**The two facts this rests on are pinned in CI**, so the deployment cannot be broken by an
unrelated change: `scheduler/launcher_env_test.go` measures that the launcher hands its
environment to the CLI (using the test binary itself as a stand-in `docker` and reading back
what the child was given), and that the `docker-api` launcher cannot reach a `tcp://` address.

**Why this one is recommended, and what the recommendation does not cover.** It is the only
option that removes the socket mount rather than narrowing it, and it is the only one we have
run end to end. Option 2 still mounts a socket, so it bounds what can be asked, not who can
ask. The recommendation rests on the single-machine drill above, so the network between the
scheduler and a daemon on another host, and the daemon host's own hardening, remain yours
(D133). Keep that host running nothing but scans.

**Option 2 — a filtering socket proxy.** The `docker-api` launcher dials whatever unix socket
path `SCHEDULER_DOCKER_SOCKET` names, so you can mount a proxy's socket instead of the real
one and allow only the container create/start/remove calls the scheduler needs. This keeps the
mount but narrows what it can ask for.

**What is NOT available, so you do not go looking for it:** the `docker-api` launcher cannot be
pointed at a remote endpoint. Its transport dials a **unix socket** unconditionally, ignoring
the request host, so a `tcp://` value in `SCHEDULER_DOCKER_SOCKET` is treated as a filename and
fails. Use option 1 for a remote daemon. A launcher that needs no Docker socket at all (ECS
RunTask / Kubernetes Job, D24) is designed but **not built**.

**If you keep the socket mount**, treat it as the simple-deployment convenience it is: keep the
scheduler on a host that runs nothing else you care about, do not publish its port
(`127.0.0.1:8096` by default) beyond the network its own services sit on, and remember that
anything able to reach the approval control plane can trigger scans (see the previous section
and issue #13).

### Serving the gate over HTTPS: terminate TLS in front of it

**The gate speaks plain HTTP, on purpose, and has no `FW_TLS_*` setting.** To give
developers an `https://` address, put the TLS terminator you already run in front of it —
an ingress controller, a load balancer, nginx. This is the same line drawn for traffic
between our own services (see the deployment assumption above): certificates, renewal and
cipher policy belong to the platform you already operate them on, not to a second
implementation inside the gate.

This is separate from **TLS-interception mode** (`FW_INTERCEPT_LISTEN`), which is an
optional second listener for clients you cannot configure. What is described here is the
ordinary front door.

The configuration below is the one `e2e/ingress_tls_test.go` runs on every pipeline, with
real `npm` and `pip` installing through it; a test fails if this page and that file drift
apart.

```nginx
# TLS termination in front of a Yellow Jack gate (docs/SETUP.md, "Serving the gate over HTTPS").
#
# This file is the one e2e/ingress_tls_test.go runs, with yellowjack:8080 replaced by the gate's
# address, and the one docs/SETUP.md prints: ingressdoc_test.go fails if they drift apart.
# Every directive below is here for a stated reason; none is decoration.
server {
    listen 443 ssl;

    # Your certificate, for the name developers will put in their client config. The
    # gate never sees it: TLS ends here.
    ssl_certificate     /etc/nginx/tls/tls.crt;
    ssl_certificate_key /etc/nginx/tls/tls.key;

    # Artifacts are large and the gate streams them. Buffering them to disk here would
    # add a copy and a size limit the gate itself does not have.
    client_max_body_size    0;
    proxy_buffering         off;
    proxy_request_buffering off;

    location / {
        proxy_pass http://yellowjack:8080;

        # The gate records the puller's address. Behind a proxy that is this proxy's
        # address unless you pass the real one on AND list this proxy in
        # FW_TRUSTED_PROXIES; the header alone is ignored, by design.
        proxy_set_header X-Forwarded-For $remote_addr;
        proxy_set_header Host            $http_host;
    }
}
```

**Behind a terminator, `FW_PUBLIC_URL` is required, not recommended.** Set it to the
`https://` address developers use:

```
FW_PUBLIC_URL=https://yellowjack.internal.example.com
```

The gate rewrites artifact links to point back at itself. With `FW_PUBLIC_URL` unset it
builds them as `http://` plus the request's `Host` — and behind a terminator that is the
right host with the wrong scheme. Measured: `npm install` fetches the package metadata,
is then sent to speak plain HTTP to the TLS port, the terminator answers `400`, and the
install fails. The gate does not read `X-Forwarded-Proto`; the setting is the only source
of the scheme.

**What HTTPS changes for developers — and what was never our requirement.** Two of the
steps people meet when pointing a client at a plain-HTTP gate are the *client* refusing
plain HTTP, not the gate asking for anything:

| client | over plain HTTP | over HTTPS (measured through the config above) |
|---|---|---|
| npm | `registry=` | `registry=` — unchanged |
| pip | `index-url` **and** `trusted-host`; pip refuses a plain-HTTP index without it | `index-url` only |
| Maven (3.8.1+) | blocks plain-HTTP repositories outright, so a `settings.xml` mirror is needed | a `settings.xml` mirror with `<mirrorOf>*</mirrorOf>` — **still required**, now for a different reason (below) |

**Maven: a repository flag is not a mirror, over HTTPS or otherwise.** It is tempting to read the
plain-HTTP blocker as the only reason Maven needs a settings file, and to expect
`-DremoteRepositories=https://…` to be enough once the gate is on
HTTPS. Measured, it is not: that *adds* a repository, Maven still asks Maven Central first, Central
has the artifact, and the gate is **never contacted** — the install succeeds against a gate
configured to block it, and the gate has no log line to show for it. Only a mirror with
`<mirrorOf>*</mirrorOf>` replaces Central; with it, the same blocking gate fails the install and
logs why. The JVM must also trust the terminator's certificate (`keytool -importcert -cacerts` for a
private CA). Measured on Maven 3.9 with Temurin 21 in a Linux container.

**The same holds for a repository the project declares, and for Gradle.** Measured against a gate
configured to block the artifact:

| how the gate was added | is the gate asked? | does the block stop the install? |
|---|---|---|
| Maven `-DremoteRepositories` flag | no — Central is asked first | no |
| Maven `<repositories>` in the POM | yes, before Central | **no** — Maven reads the refusal as "not here" and fetches from Central |
| Gradle, the gate declared before `mavenCentral()` | yes | **no** — Gradle 8.14 was answered `403` and resolved from `mavenCentral()` |
| Gradle, `mavenCentral()` declared first | no | no |
| Maven `settings.xml` mirror with `<mirrorOf>*</mirrorOf>` | yes | **yes** |
| Gradle with the gate as the **only** repository | yes | **yes** |

The rule the table reduces to: a gate added *beside* another repository gives you, at best, a log
line. It enforces only when the client has nowhere else to go. Client configuration cannot stop a
project from declaring Central again; if that matters to you, it is a network control (no direct
route from build machines to public registries), not a setting on this page. Measured on Maven 3.9
and Gradle 8.14 in Linux containers; Gradle plugin resolution and Maven 4 are not measured.

One caveat, so the table is not over-read: a client must trust the certificate the
terminator presents. If it chains to a CA your machines already trust — a public CA, or a
corporate root your device management distributes — that costs nothing. If it is a private
CA nobody has distributed, each tool needs to be told about it (`cafile` for npm,
`PIP_CERT` or `cert` for pip), and that is per tool, not per machine. Verified on Linux
containers (node 22, python 3.12); other platforms are not yet measured.

### Set `FW_PUBLIC_URL` wherever lockfiles are committed

**If developers commit `package-lock.json`, set `FW_PUBLIC_URL` to one stable URL for the
whole team.** Not optional guidance — it decides whether your lockfiles are portable.

We rewrite npm's `dist.tarball` to point at ourselves, which is what stops a client fetching
tarballs straight from npm and bypassing the gate. That rewritten URL is what npm records as
`resolved` in the lockfile, and the lockfile gets **committed**. `FW_PUBLIC_URL` is what we
put there.

When it is unset we fall back to the request's `Host` header, so `resolved` encodes whatever
address that particular developer reached us on:

```
# FW_PUBLIC_URL unset — the lockfile records the address THIS client used
"resolved": "http://localhost:8080/_tarball/ms/ms/-/ms-2.1.3.tgz"
```

Commit that and `npm ci` in CI tries to fetch from `localhost:8080`, which is not the
firewall there. Set it once and every deployment writes the same line:

```
FW_PUBLIC_URL=https://yellowjack.internal.example.com
```

`dist.integrity` is never touched — it stays byte-identical to what the public registry
publishes, so the client's own end-to-end check on the tarball still works. Both properties
are asserted by `TestNpmLockfileResolvedIsStableAndIntegrityUntouched` (issue #20).

---

## Test, vet, scan

```
go vet ./...
go test ./... -count=1
go install golang.org/x/vuln/cmd/govulncheck@v1.4.0 && govulncheck ./...
```

These are exactly what `.gitlab-ci.yml` runs (build → test → scan).

---

## Where things are

- Source: `*.go` (firewall), `approval/`, `cache/`. Reference impl: `reference/`.
- CI: `.gitlab-ci.yml`. Containers: `Dockerfile`, `approval/Dockerfile`,
  `cache/Dockerfile`, `docker-compose.yml`.
- Docs: `BUILD_LOG.md` (design log), `BUILD_PLAN.md` (plan).
