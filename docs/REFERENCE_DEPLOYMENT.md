# Reference deployment — watch the whole product work, end to end

[QUICKSTART.md](../QUICKSTART.md) shows one binary refusing one package in about a
minute. This is the other thing an evaluator needs: **the real shape of a deployment**
— a gate in front of a package registry, a control plane, and a console — so you can
watch a refusal happen to a real `npm install`, `pip install` and `docker pull` and then
go read that decision in a UI.

It exists because a prospect who does not already run Artifactory had no way to see
any of that.

> **This is an example, not a product component.** The registry in it stands in for
> **your** registry, which you already run and already patch. We ship a reference
> deployment that *includes* a registry; we do not ship a registry *as* our component.
> One value needs changing before this is anything but a laptop demo, and it is marked
> `⚠️ CHANGE THIS` in the compose file: `FW_UPSTREAM`, pointing at your own registry.
> The database password is not one of them — it is generated per machine in step 1 and
> never written into the file.

## The topology is the point

```
developer ──▶ Yellow Jack ──▶ your registry ──▶ the public registry
```

This example puts Yellow Jack **in front of** your registry. That is why the registry
service publishes **no host port** here: there is no route to it that does not pass the
gate.

The example runs that topology **three times over**, one gate per ecosystem, each in
front of its own stand-in for your registry: npm on `:8080`, PyPI on `:8081`, Docker on
`:8082`. Steps 2-7 walk the npm one; steps 8 and 9 show the other two doing the same
thing, because an evaluator with a Python or container shop could not use this page
when it was npm-only. None of the three registry stand-ins publishes a host port.

### In front or behind: the two positions stop different things

| position | path | what it stops | what it cannot do |
|---|---|---|---|
| **In front** (this example) | developer → Yellow Jack → your registry | **the install**, including a pull your registry would serve from its own cache; a cached package can still be withdrawn | stop a package entering your registry by another route |
| **Behind** | developer → your registry → Yellow Jack → public registry | **ingest**: a refused package never enters your registry at all | see a cache hit, so it cannot withdraw what your registry already holds |

Behind needs **no change on any developer machine**: the only client is your registry,
and pointing its upstream at the gate is one line of its own configuration. In front
needs clients to reach the gate instead of the registry, which this example arranges
by publishing no other route.

Neither position covers a developer who pulls straight from the public internet;
that is what egress controls are for, alongside either one. Both positions are
exercised on every pipeline by `e2e/registry_front.sh` — legs 4, 7 and 9 for in front,
leg 10 for behind, with leg 9's control showing what behind cannot do.

## 1. Start it

Generate this machine's database password once. **No credential is written in the compose
file** — an example exists to be copied, and a literal in it would be one shared password
on every deployment that started from this page (#22).

```bash
YJ_ENV_FILE=deploy/reference/.env sh scripts/gen-env.sh
docker compose -f deploy/reference/docker-compose.yml up --build -d
```

The generated value lands in `deploy/reference/.env`, which is git-ignored and which
compose reads automatically because it sits beside the compose file. Skip that first
command and the second one refuses to start, naming it:

```
error while interpolating services.postgres.environment.POSTGRES_PASSWORD:
  required variable POSTGRES_PASSWORD is missing a value:
  not set - run `YJ_ENV_FILE=deploy/reference/.env sh scripts/gen-env.sh` to generate it
```

The gate states what it is enforcing before it serves anything:

```
operator allow-list "/lists/allow.txt": 0 package(s) allowed without scoring [npm], re-read every 5s
operator deny-list "/lists/deny.txt": 1 package(s) blocked outright [npm], re-read every 5s
Yellow Jack starting on :8080
  ecosystem:         npm
  upstream:          http://custreg:4873
  public URL:        http://localhost:8080
  score threshold:   0.0
  scorecard mode:    off
```

**Which signal is deciding here:** the operator lists and the release-age floor. Both
are local, and neither needs an account, a scanner or a network call of ours.
`scorecard mode: off` means exactly what it says: the gate never resolves a source
repository and never asks for a score, so the threshold line above is inert in this
deployment. An allowed package's audit reason reads *"served: scoring is disabled
(FW_SCORECARD_MODE=off), and it is on neither operator list nor in the known-malware
feed"* — the gate telling you it **did not ask**, which is a different statement from
*"it asked and the package passed"*.

*(Until `off` existed this walkthrough ran `stub` with a threshold of `0.0`, and audit
reasons read `score 7.5 >= threshold 0.0`. That was never the same thing: `stub`
fabricates a flat 7.5 for every repository, and it now reports **not ready** so it cannot
reach a deployment someone copies. If your own stack still shows that banner line, switch
it to `off`.)*

## 2. Watch it refuse a package

```bash
curl -i http://localhost:8080/left-pad
```

```
HTTP/1.1 403 Forbidden
X-Yellowjack-Kind: operator-denied
X-Yellowjack-Rule: deny-list:left-pad
X-Yellowjack-Source: operator deny list
X-Yellowjack-Reason: package "left-pad" is on this organisation's deny list; refused
  without contacting upstream. This is a local policy decision, not a published malware
  advisory -- ask whoever maintains the firewall's deny list
X-Yellowjack-Next-Step: ... Waiting will not clear it and neither will re-running; it is
  reversible by whoever maintains this firewall's deny list
```

Four headers, and each answers a different question a developer actually asks: **what
kind** of refusal, **which rule** fired, **who** decided, and **what to do now**.

## 3. Watch it allow one — and prove where it came from

```bash
curl -o /dev/null -w '%{http_code}\n' http://localhost:8080/is-number
```

```
200
```

A gate that blocks everything is not a gate, so this step is what makes step 2 mean
something. Now the part worth doing, which shows the topology rather than asserting it:

```bash
docker compose -f deploy/reference/docker-compose.yml exec custreg ls /verdaccio/storage
```

```
is-number
```

**`is-number` is in your registry's own storage. `left-pad` is not.** The allowed pull
went through and was cached; the refused one never reached your registry at all.

## 4. Point a real client at it

On this machine:

```bash
npm --registry http://localhost:8080 install is-number
```

```
added 1 package in 3s
```

The refused package fails the way a developer will actually meet it:

```
npm error code E403
npm error 403 Forbidden - GET http://localhost:8080/left-pad - blocked by firewall:
  package "left-pad" is on this organisation's deny list; refused without contacting
  upstream. This is a local policy decision, not a published malware advisory ...
```

**Running the client in a container instead?** Set the address the client will use, or
the install fails with `ECONNREFUSED` on a URL that looks perfectly correct:

```bash
YJ_PUBLIC_URL=http://firewall:8080 docker compose -f deploy/reference/docker-compose.yml up -d
docker run --rm --network reference_default -e npm_config_registry=http://firewall:8080 \
  node:22-alpine sh -c 'cd /tmp && npm init -y >/dev/null && npm install is-number'
```

```
added 1 package in 3s
```

The gate mints artifact URLs from `FW_PUBLIC_URL`, so it has to be reachable **from
where the client runs**, not from where the gate runs. A container resolves
`localhost` to itself. This is the single most likely thing to trip you up, which is
why it is a setting here rather than a fixed value.

## 5. Read the decisions in the console

```bash
open http://localhost:8085/audit      # loopback only, on purpose
```

Both pulls are there — the refusal with its reason, the allow with its score. The
console is published on `127.0.0.1` and so is the control plane behind it; the only
service reachable from the network is the gate itself, because it is the only one a
developer's client has to reach.

To enable the write path (approve, deny, edit the lists), set both credentials:

```bash
CONSOLE_AUTH_USER=admin CONSOLE_AUTH_PASS=... \
  docker compose -f deploy/reference/docker-compose.yml up -d console
```

With them unset the console runs **read-only**, which is the right default while you
are evaluating.

**What a ruling reaches.** *Approve* lets through a package the gate's policy would
have refused. *Deny* refuses it on **every** path — including a package the policy
would allow on its own (D272, 2026-09-19, reversing that half of D11). The console
states this at the moment you record a ruling.

**The one limit.** A human ruling lives in the approval service, and a gate that
cannot reach that service falls back to policy — so a deny recorded here is not in
force during an approval outage. A deny-list entry is: the `deny.txt` this example
mounts, or `/lists` on the console image that can edit it. Use the list for a block
that must hold regardless.

*History, not current behaviour:* until D272 a deny reached only the refuse path, so
a deny on a package the policy allowed was recorded, displayed, and never enforced.
`#132` is the measured trace of that, and it is why the reach is spelled out here.

## 6. Try it in front of your build system without blocking anything

```bash
YJ_MODE=report docker compose -f deploy/reference/docker-compose.yml up -d firewall
```

```
MODE:  *** REPORT ONLY — NOTHING IS BLOCKED *** verdicts are computed and logged
```

The same denied package now returns **200 with 31,412 bytes**, and the log carries what
would have happened instead:

```
REPORT MODE: WOULD HAVE REFUSED left-pad -> package "left-pad" is on this organisation's
  deny list ... (relayed anyway; set FW_MODE=enforce to refuse)
```

This is the honest way to meet the biggest objection to a blocking gate, which is that
nobody switches one on in front of a working build system cold. Run it in report mode,
read a week of logs, then decide.

## 7. The time gate, and watch it hold a release back

The lists above are your own policy. The **release-age floor** is the other half, and it
needs no list at all: it refuses versions that are too new to have been looked at by
anyone. **It is on by default, at 14 days** (`YJ_MIN_RELEASE_AGE_DAYS=0` turns it off). The
measurement below was taken with it set to 7:

```bash
YJ_MIN_RELEASE_AGE_DAYS=7 docker compose -f deploy/reference/docker-compose.yml up -d firewall
```

**What you will see is not a 403**, and that is the design. The package still resolves;
the versions younger than the floor are simply absent from what we hand the client, so
`npm install react` quietly gets the newest release that has had seven days of daylight
instead of failing the build. Measured on this stack against the live registry:

| | versions offered | newest version dated |
|---|---|---|
| through Yellow Jack, floor at 7 days | 2,934 | 2026-09-04 |
| straight from the registry | 2,945 | 2026-09-11 |

**11 versions withheld, and the newest one we serve is exactly seven days older than the
newest one upstream.** That is the whole control: an attacker who publishes a poisoned
release has to keep it undetected for a week before any of your builds can reach it.

A refusal would have been the easier thing to build and the wrong one. A gate that fails
the build gets removed; a gate that steers resolution to a slightly older release gets
kept.

## 8. The same topology, for PyPI

The PyPI gate listens on `:8081`, in front of a stand-in for your PyPI registry — a
caching proxy of the public `/simple/` index, which is the shape a Nexus or Artifactory
*remote* repository takes. Its deny list has one entry, `requests`. Point pip at it:

```bash
pip install --index-url http://localhost:8081/simple/ six
pip install --index-url http://localhost:8081/simple/ requests
```

```
Successfully installed six-1.16.0
```

```
ERROR: Ignored the following yanked versions: 0.2.0, 0.2.1, ... 2.32.5
ERROR: Could not find a version that satisfies the requirement requests (from versions: none)
ERROR: No matching distribution found for requests
```

**A PyPI refusal does not look like an npm one, on purpose.** A `403` on the index makes
pip route around it and silently *backtrack other packages* to older, often CVE-laden
versions. So the gate serves the real index with every release marked **yanked** (PEP
592) and the reason attached to each — the "protect and inform" posture (D22). Read it
with curl and the reason is right there in the page, not just in a header:

```bash
curl -s http://localhost:8081/simple/requests/ | grep -o 'data-yanked="[^"]*"' | head -1
```

```
data-yanked="package "requests" is on this organisation's deny list; the index was
  fetched to list the releases to yank, and no artifact bytes were. This is a local
  policy decision, not a published malware advisory -- ask whoever maintains the
  firewall's deny list"
```

Two things pip's output above does *not* say, and this page should. First, pip drops
the reason on this path and prints "No matching distribution found" instead — a
developer reads that as *the package does not exist* (#79, measured; no wording of ours
changes it). Second, notice what the reason says about upstream contact: **the index
was fetched, the bytes were not.** That is exactly what happened, and it is a different
claim from the npm one in step 3. Yanking every release needs the real release list, so
the refused package's `/simple/` page *does* reach your registry's cache; its wheel
never does. Prove both halves:

```bash
docker compose -f deploy/reference/docker-compose.yml exec custreg-pypi \
  sh -c 'grep -rl "simple/six/" /var/cache/nginx | wc -l; grep -rl "simple/requests/" /var/cache/nginx | wc -l'
docker compose -f deploy/reference/docker-compose.yml logs firewall-pypi | grep -c '_files/requests'
```

```
1
1
0
```

Both index pages are cached; zero artifact fetches for the refused one. And an exact pin
does not get around it — the bytes are gated at the fetch:

```bash
pip install --index-url http://localhost:8081/simple/ 'requests==2.31.0'
```

```
ERROR: 403 Client Error: Forbidden for url: http://localhost:8081/_files/requests/packages/...
```

**Where the bytes come from.** The stand-in proxies the *index*; wheel links inside it
still point at PyPI's CDN, and the gate relays those through its own `/_files/` path.
So artifact bytes are gated but do not pass through this stand-in. If your registry also
mirrors the files, point `FW_FILES_UPSTREAM` at it.

## 9. The same topology, for Docker

The OCI gate listens on `:8082`, in front of a `registry:2` **pull-through cache** of
Docker Hub — the shape Harbor's and Nexus's proxies take. Its deny list has one entry,
`library/busybox`, which applies to **every tag** of that repository (#128).

**The address is `localhost` on purpose, and it is not a placeholder for a hostname.**
Docker treats a *loopback* registry (`localhost`, `127.0.0.1`) as plain HTTP
automatically; any other hostname or IP needs `--insecure-registry` in every developer's
daemon configuration before a pull will even start. A real deployment terminates TLS at
the gate and the question disappears, so the demo stays on loopback rather than teaching
you a flag you should not need.

```bash
docker pull localhost:8082/library/alpine:3.20
docker pull localhost:8082/library/busybox:latest
```

```
Status: Downloaded newer image for localhost:8082/library/alpine:3.20
```

```
Error response from daemon: unknown: failed to resolve reference
  "localhost:8082/library/busybox:latest": unexpected status from HEAD request to
  http://localhost:8082/v2/library/busybox/manifests/latest: 403 Forbidden
```

That is what a daemon on the **containerd image store** prints (Docker Desktop, and new
Docker Engine installations): it resolves a tag with a `HEAD`, which has no body, so the
reason travels only in headers, and `docker` does not print them. A daemon on the older
**graphdriver store** (`docker info` shows `overlay2` and no `driver-type` row; Docker
Engine 27 as installed by most distributions) fetches the manifest with a `GET` and does
print the body — the whole reason — but leads with a guess of its own:

```
Error response from daemon: pull access denied for localhost:8082/library/busybox,
  repository does not exist or may require 'docker login': denied: blocked by firewall:
  package "library/busybox:latest" is on this organisation's deny list; refused ...
```

Neither half of that preamble is true, and it is printed before the text that corrects it.
Both renderings are measured and pinned by `e2e/blockreason_test.go`, one leg per store.
On either store the headers carry the verdict; ask for them:

```bash
curl -I http://localhost:8082/v2/library/busybox/manifests/latest
```

```
HTTP/1.1 403 Forbidden
X-Yellowjack-Kind: operator-denied
X-Yellowjack-Rule: deny-list:library/busybox:latest
X-Yellowjack-Reason: package "library/busybox:latest" is on this organisation's deny
  list; refused without contacting upstream. ...
```

Here the npm claim from step 3 holds exactly, and the registry proves it:

```bash
docker compose -f deploy/reference/docker-compose.yml exec custreg-oci \
  ls /var/lib/registry/docker/registry/v2/repositories/library/
```

```
alpine
```

**`alpine` is in your registry. `busybox` never reached it.** And the pull that
succeeded went *through* the gate, not around it — its log carries the verdict for the
tag and then for the digest the tag resolved to:

```
HEAD [verdict-allowed] library/alpine:3.20 -> allowed=true score=7.5 hasScore=true
GET  [verdict-allowed] library/alpine@sha256:6243dec9... -> allowed=true ...
```

### Two things about image policy that differ from npm, on purpose

**An operator-list entry covers the whole repository — every tag.** `library/busybox`
and `library/busybox:1.36` are enforced identically: both refuse every tag. An advisory
condemns a repository, not whichever tag was asked for, so the match strips the tag — but
the second line does not look like it says that, so the gate says so when it loads one.
Append `library/nginx:1.27-alpine` to `deploy/reference/lists/oci/deny.txt`; the next
pull at least five seconds later re-reads the file (the reload is checked on lookup, not
on a timer), refuses `library/nginx` at *every* tag, and the `firewall-oci` log says:

```
operator deny-list line 37: "library/nginx:1.27-alpine" names a tag or digest, but an
entry here applies to the WHOLE repository "library/nginx" — every tag of it, not just
the one written. It is enforced that way, and this is not an error. Write
"library/nginx" if that is what you meant, and note that per-tag entries are not
supported.
```

The **allow** list has one exception, since #155: an entry may name exactly one image by
**digest** (`library/nginx@sha256:…`), and that one is exact rather than widened. A tag
still cannot, because a tag is mutable — "allow whatever this tag points at next" is not
a decision anyone made. So the same warning on the allow list ends by showing the digest
form instead of saying exact entries are unsupported.

**There is no release-age floor for images, and that is a measurement, not a gap.**
Step 7's time gate needs a publication time the publisher does not control. A container
registry offers none: a manifest response carries no `Last-Modified`, and the only date
in the pull path is `created` in the image's own config, written by whoever built it. Of
7 real images sampled on #127, 4 report `1970-01-01T00:00:00Z` — every distroless one,
because reproducible builds zero it on purpose. A window keyed on that field would read
those as decades old and would clear any cooldown the moment a publisher edited one
string. So the gate does not apply the window to OCI at all, `firewall-oci` sets no
`FW_MIN_RELEASE_AGE_DAYS`, and `referencedeploy_test.go` fails if the example gains the
knob before #127 closes.

## Changing policy without a restart

Both lists are re-read every five seconds, and the check happens on **lookup**: a gate
that receives no traffic re-reads on its next request, not on a timer. Append a name to
`deploy/reference/lists/npm/deny.txt`, wait, and the next pull is refused; delete it and
service resumes. A failed read keeps the **last good** list rather than failing open,
which matters because a blanked deny list that fails open denies nothing.

Measured across replicas (`e2e/ha_drill.sh` leg 9, #131): three gates sharing one list
directory, one entry added the way the console adds it (a temp file, then a rename),
every replica touched just before the edit so its last check is the worst case. Every
replica enforced the edit **4.7 s** after it, within one poll sample of each other; a
replica restarted in the same instant came up on the new list in **0.5 to 2.1 s**; a replica
mounting a copy nobody edited never changed, and the drill reports it rather than
averaging it away. That is the compose shape. On Kubernetes the list is a ConfigMap and
`helm upgrade` is the edit, so the kubelet's own sync period sits in front of the same
five seconds. Measured on a three-node kind cluster with one gate pod per node
(`e2e/helm_list_drill.sh`, #131): the pods enforced the edit **50 to 76 s** after the
upgrade, each on its own node's schedule, so for **10 to 20 s** two replicas of one
deployment answered the same request differently; a pod that mounted the list through
`subPath` never saw the edit at all, which is why the chart mounts the directory; a pod
created after the edit was refusing 9 s after its predecessor was deleted.

Two behaviours worth knowing, both measured rather than assumed:

- **The deny list beats the allow list, and the gate says so.** A name on both is
  refused with rule `deny-list:<name>`, and the log names the override:
  `POLICY "<name>" is on BOTH operator lists -- REFUSED: the deny list outranks the
  allow list.` Until #124 that override was silent and the rule name was the only clue.
- **Neither list beats a published malware advisory.** An operator who allow-listed
  something later reported as malware is told that, not handed the package.

## What is deliberately not turned on

| | how to turn it on |
|---|---|
| known-malware feed from public OSV data | build it with `sh scripts/dev.sh malwarefeed`, then set `FW_MALWARE_LIST` |
| real OpenSSF Scorecard scoring | `FW_SCORECARD_MODE=api` or `local`, and raise `FW_SCORE_THRESHOLD` |
| refuse the *bytes* of an unscorable package, not just its metadata | `FW_BYTE_GATE=enforce` |

The malware feed is off because it needs a data file you generate; the rest is off so
the walkthrough above behaves the same way every time you run it. The time gate in step 7
is the exception: it ships **on**, at 14 days, because it is the only control here that
needs neither a list you maintain nor a scanner, and it only holds back versions younger
than the window, so every step above still resolves. Every setting in the product is
listed in **[CONFIGURATION.md](CONFIGURATION.md)**.

## Tear it down

```bash
docker compose -f deploy/reference/docker-compose.yml down -v
```

`-v` also drops the database volume, so the next run starts with an empty audit trail.
