# Egress guarantee — exactly what the firewall connects to

This document is the deliverable of issue #27. It is the list an operator uses to configure
their **own** firewall, and the statement our zero-egress claim is allowed to make.

It is kept honest by tests, not by review: see [Assertions](#assertions).

---

## The claim, worded exactly

> **Zero egress** means *no telemetry to us, and no vendor meter on your traffic.*

It does **not** mean "no outbound connections at all." The gate fetches metadata from the
registry you configure and scores from the scorer you configure, and the cacheless MVP adds
one upstream fetch per pull. Overclaiming this is how a strong, checkable argument gets
discredited by the first competent reader (D65).

The precise, checkable form is:

> **Every address the firewall dials comes from operator-supplied configuration.**
> There is no host literal in the egress path, and in particular none of them is ours.

That is a stronger statement than it looks. Every comparable product studied (2026-07-26)
needs the vendor's cloud reachable **on the request path** to render a verdict — which is
*why* they must fail open when it is unreachable. We can default fail-closed because there
is nothing of ours to be unreachable.

---

## The list

Every entry is a `Config` field. Nothing here is a default that points at us.

| Destination | Env var | When it is dialled | Required? |
|---|---|---|---|
| Upstream registry | `FW_UPSTREAM` | Every metadata request; npm/Maven/OCI artifact bytes | **Yes** |
| PyPI files host | `FW_FILES_UPSTREAM` | PyPI artifact bytes (a different host from the index) | PyPI only |
| deps.dev | `FW_DEPSDEV_BASE` | `api`-mode scoring, and repo verification (D33) | Unless `stub`/`local` mode **and** `FW_VERIFY_REPO=false` |
| Scheduler | `FW_SCANNER_URL` | `local`/async scoring only — to launch a scan | `local` mode only |
| Approval service | `FW_APPROVAL_URL` | L2 score lookups, approval verdicts, and the capacity/health heartbeat | Optional |
| Known-malware snapshot | `FW_MALWARE_FEED_URL` | Hourly, in the background, never on the request path; once at startup only if no snapshot exists yet (#157) | Optional, **empty by default** |
| DNS resolver | *(host resolver)* | To resolve any of the above that is named rather than addressed | If you use hostnames |

**Not dialled, despite looking like it:**

- `FW_LISTEN_ADDR` — inbound.
- `FW_PUBLIC_URL` — never connected to. It is only woven into the artifact URLs we mint, so
  the client's *next* request comes back to us.

**Behind a corporate forward proxy, this whole list collapses to one destination.** Set
`HTTPS_PROXY` (and `NO_PROXY` for anything that must stay direct) and every entry above is
reached *through* it: the container needs outbound access to the proxy and to nothing else.
The claim at the top of this file is unchanged — the proxy address is operator configuration
like every other address here, and nothing new is dialled. If that proxy terminates TLS with
a corporate CA, it also needs `FW_UPSTREAM_CA_BUNDLE` (`docs/CONFIGURATION.md`), or every
upstream handshake fails `x509: certificate signed by unknown authority`. Measured against a
real chained proxy in `docs/TLS_INTERCEPTION.md` increment 15.

**The heartbeat is not telemetry to us.** `FW_APPROVAL_URL` is *your* approval service, on
your network. If you do not set it, no heartbeat is emitted at all.

---

## What an operator must allow through their own firewall

Allow outbound from the firewall container to:

1. your registry (and, for PyPI, the files host),
2. `api.deps.dev:443` — **only** if you use `api` mode or leave `FW_VERIFY_REPO` on,
3. your scheduler and approval service, if configured,
4. your DNS resolver.

Deny everything else. The firewall is designed to run in exactly that posture, and the
container-level test below runs it that way on every pipeline.

To run with **no internet at all**: `FW_SCORECARD_MODE=local` (or `stub`),
`FW_VERIFY_REPO=false`, and an upstream on your own network.

---

## Denying your clients a route around the proxy (deployment hardening, D170)

Everything above is about **our** outbound connections. This section is the mirror image and
the only part of this document about **your clients'** outbound connections.

In the cooperative mode we ship today, a client reaches the gate because it was *configured*
to — an `.npmrc`, a `settings.xml`, a `pip.conf`. Nothing stops a developer or a CI job from
pointing at the public registry instead, and the gate never sees the pull. Blocking direct
registry egress at the network layer removes that choice: a client that **cannot** reach
`registry.npmjs.org` has to come through us.

⚠️ **This is hardening, not a substitute for interception (D170).** It makes bypass
inconvenient; it does not make the gate unavoidable, and it must never be described as doing
so. Interception is what closes the bypass properly, because it depends on neither the
client's cooperation nor on your enumerating every destination. See `docs/TLS_INTERCEPTION.md`.

### Deny by default, allow the proxy — do not blocklist registries

Write the rule as **default-deny egress plus an allowance for the gate and DNS**, never as a
list of registry hostnames to block. A blocklist is an open set and loses: PyPI serves
artifacts from a different host than its index, container registries redirect blob downloads
to a CDN, and npm and Maven front their traffic the same way. Miss one and the bypass is
silent — the same shape as an extension allowlist, which this repository has already been
bitten by twice.

**Kubernetes** — default-deny egress for a build namespace, allowing only DNS and the gate
(requires a CNI that enforces NetworkPolicy, such as Calico or Cilium; without one the object
is accepted and does nothing):

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: builds-egress-through-yellowjack
  namespace: builds
spec:
  podSelector: {}                 # every pod in the namespace
  policyTypes: [Egress]           # with Egress listed, anything not matched below is denied
  egress:
    - to:
        - namespaceSelector: {}
          podSelector:
            matchLabels:
              k8s-app: kube-dns
      ports:
        - { protocol: UDP, port: 53 }
        - { protocol: TCP, port: 53 }
    - to:
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: yellowjack
          podSelector:
            matchLabels:
              app: yellowjack-firewall
      ports:
        - { protocol: TCP, port: 8080 }
```

**A build host, scoped to the account that runs builds** — host rules are per host, so this
is only as good as your coverage of the fleet:

```sh
iptables -A OUTPUT -m owner --uid-owner build -d "$GATE_IP" -p tcp --dport 8080 -j ACCEPT
iptables -A OUTPUT -m owner --uid-owner build -p udp --dport 53 -j ACCEPT
iptables -A OUTPUT -m owner --uid-owner build -j REJECT
```

### What it does not guarantee

- **It is a network control, not an identity one.** Anything with its own path out escapes
  it: a laptop off the VPN, a self-hosted runner outside the policy, a container on host
  networking, a developer's phone hotspot.
- **It is only as complete as the boundary you drew.** Default-deny fixes the open-set
  problem *within* the namespace or host you applied it to, and says nothing about the ones
  you did not.
- **It does not police an allowed destination.** Most estates must permit their source-code
  host; dependencies fetched straight from release URLs or a git reference are then outside
  the package-manager path the gate inspects, and the network rule cannot tell them apart.
- **It does not survive a client that is configured to use us and then fetches elsewhere** —
  a postinstall script with its own HTTP client, for example — unless that traffic is also
  inside the deny.

Each of those is closed by the client being unable to talk to anything *unintercepted*, which
is the interception mode's property, not this one's.

---

## Assertions

The property is enforced by four tests, because it has four independent ways to break.
Each carries a negative control — an egress check that has only ever printed green is worse
than no check, since it converts an unknown into false confidence.

| Test | Layer | Catches |
|---|---|---|
| `TestFirewallDialsOnlyConfiguredDestinations` | in-process dialler | a connection to any address no `Config` field names |
| `TestEveryOutboundClientIsObservable` | source (AST) | an `http.Client` with no `Transport`, which uses `http.DefaultTransport` and is **invisible** to the layer above |
| `TestFirewallBinaryLinksOnlyStdlib` | dependency graph | a third-party package, which can dial without passing through our transport |
| `TestFirewallMakesNoUnconfiguredEgress` (e2e) | container | any **name** the process resolves, including from code that never touches our transport |

Both are gated already: the first three run in `unit-tests` (`go test ./...`), the fourth in
one of the three sharded e2e jobs.

> The argument here used to be *"`make e2e ECOSYSTEM=all` applies no `-run` filter, so
> everything runs"*. Since #140 each shard DOES apply one, so that reasoning no longer holds
> and the assurance comes from a different place: `TestEveryE2ETestIsInExactlyOneShard`
> derives every test in the package from the source and asserts the shards partition it, so a
> test cannot fall out of the gate unnoticed. Recorded rather than quietly reworded, because
> "no filter" was the whole of the old argument.

### The two layers are complementary, not redundant

- The **in-process** check sees `host:port` for every dial through `pooledTransport`. It
  cannot see DNS (resolution happens inside the dialer, before the connect it wraps), and it
  cannot see a dialer it does not own.
- The **container** check sees every name resolved, by anything in the process. It cannot
  see egress to a hard-coded **IP literal**, which needs no lookup.

Each covers the other's blind spot. Retiring either one silently reopens a spelling.

---

## Known gaps

- **TLS-interception mode (npm, increment 7) is covered, and by construction.** The
  interception listener (`intercept.go`, `FW_INTERCEPT_LISTEN`) never dials the host a
  client names. It terminates TLS **only** for the hostname of `FW_UPSTREAM`, refuses
  `CONNECT` to any other host with a 403 and no dial, and hands the intercepted request to
  the same `ServeHTTP` the cooperative path uses — so its one upstream is
  `cfg.UpstreamRegistry`, which is already in `egressDestinations()`. No new destination,
  no new dialler. Asserted, not claimed: `TestInterceptDialsOnlyTheConfiguredUpstream`
  observes every dial the intercepted path makes through the same observer this document
  describes, and checks that a refused `CONNECT` dialled nothing. D65's extension of the
  guarantee to this mode is therefore met for the host set the mode terminates today —
  the registry host, plus `FW_FILES_UPSTREAM`'s host for PyPI (increment 8), both of them
  configured destinations already. OCI (increment 11, below) and Maven (increment 12) added
  no host, and any host ever added must already be a configured upstream.

  Under `FW_ECOSYSTEM=oci` (increment 11) one more thing is relayed, and it is not a new
  destination: a registry that wants a token names a realm in its 401 challenge, and the
  intercepted client is pointed at `/_token` on the registry host instead, from where the
  exchange is relayed to the realm the registry actually named. That realm is already a
  host this binary dials for its own scoring (`ociEcosystem.ociToken`), so the set of
  hosts the gate talks to is unchanged, and the client is never handed a host the
  operator did not configure. `TestInterceptedOciPullStaysOnTheRegistryHost` asserts a
  CONNECT to the realm host is still refused.

  Under `FW_ECOSYSTEM=maven` (increment 12) the listener does one thing *less* than relay:
  an intercepted client names Central's repository path (`/maven2`, the path in
  `FW_UPSTREAM`) in front of every request, and the listener strips it so the gate sees the
  path it gates cooperatively. A request on the registry host *outside* that path is
  refused with no dial — the gate relays one repository and does not construct a URL for
  anything else — so the mode's only upstream is still `cfg.UpstreamRegistry`, path
  included. `TestInterceptedRequestOutsideTheRepositoryIsRefusedUndialled` asserts the
  refusal dialled nothing.

  *(Earlier versions of this bullet recorded the mode as a deliberate gap while only the
  e2e measurement rig existed — `e2e/mitmproxy`, a throwaway container the firewall
  cannot import. That rig is still the instrument for the failure classes; the product
  path above is what closed the gap.)*
- **The container leg does not use an `--internal` network**, so it proves "nothing was
  resolved", not "nothing could have left." Port publishing and an internal network do not
  compose cleanly; the DNS observation was chosen because it *records the attempt*, whereas
  an internal network only makes attempts fail silently — and a silent failure is precisely
  how a best-effort telemetry call would behave.
