# Failure modes

**What breaks your pipeline when something around the gate breaks, what the developer
reads when it does, and the test that keeps each answer true.**

Yellow Jack is, by construction, one more thing in the pull path that can fail. The
people it is built for already carry scar tissue about that: an r/devops thread with 111
comments has as its central complaint *"a dozen services which could block our ability to
deploy code if they failed"*, with npm outages and a registry "in a confused state"
as the lived examples (#24). So this page does not argue that the gate is reliable. It
enumerates every way the gate, or something it depends on, can fail, states what the
pipeline sees, and names the test that pins that behaviour so it cannot drift quietly.

Two rulings shape every row:

- **A failure to decide is not a decision (D17).** *Not found*, *unavailable* and
  *unscorable* are three different events and are never collapsed into one another. An
  outage on our side is never reported as a fact about your dependency.
- **Outcomes that are not verdicts are still refusals (D102).** *Pending* ("a scan is
  running") and *unavailable* ("we could not reach what we need to decide") are `403`s
  with their own explanation, not `503`s. The price, accepted deliberately, is that
  **nothing retries on its own**: the developer re-runs the install. A genuine
  infrastructure failure (the relay breaking mid-stream, an unreadable body) stays a
  `5xx`, because a status code should say what actually happened.

Every refusal carries the verdict on the wire (`X-Yellowjack-Kind`, `-Reason`,
`-Next-Step`, D182) and in the body shape the client's own tooling reads. The seven
**verdict** kinds are `score-below-threshold`, `human-denied`, `unscorable`, `unverified`,
`known-malware`, `operator-denied` and `release-window`. The two **non-verdict** kinds
are `pending` and `unavailable`, and both are sent with `Cache-Control: no-store` so an
intermediary cannot remember a state that is about to change. Which clients actually
show the developer any of that text is measured separately, per client, in
`e2e/blockreason_test.go` (#79).

## The table

| What fails | What the developer gets | What the pipeline does | Knob |
|---|---|---|---|
| [The gate itself is down](#1-the-gate-itself-is-down) | a connection error from their own package manager; nothing of ours answers | fails at the first pull, for as long as no replica answers | run replicas; `/healthz` is liveness |
| [The gate is being upgraded or rolled back](#2-the-gate-is-being-upgraded-or-rolled-back) | nothing; measured zero failed requests through a rollover | keeps pulling | none needed |
| [The gate is slow](#3-the-gate-is-slow) | nothing on a warm path; one cold hit per package | first sight of a package costs 1&ndash;2 s, once, however many clients ask | `FW_SCORE_CACHE_TTL` |
| [The upstream registry is unreachable or slow](#4-the-upstream-registry-is-unreachable-or-slow) | `403`, kind `unavailable`: *"this is not a verdict about the package"* | every pull that needs the registry fails for the duration; nothing retries | registry-in-front topology keeps already-held packages installable |
| [The upstream stalls or truncates mid-download](#5-the-upstream-stalls-or-truncates-mid-download) | a short transfer is refused as short, never delivered as complete | the download fails; a stall waits as long as the client does | none |
| [The score source is down or rate-limiting](#6-the-score-source-is-down-or-rate-limiting) | `403 unavailable`, the reason names rate limiting when that is the cause | first-seen packages fail for the backoff window; decided packages keep their score | `FW_ALLOW_LIST` needs no score; credentials raise the ceiling |
| [First pull of a package nobody has scanned (local mode)](#7-first-pull-of-a-package-nobody-has-scanned-local-mode) | `403`, kind `pending`: *"try again in about 60 seconds"* | the first pull of each new package fails once and is re-run; one scan, however many clients | `FW_PENDING_RETRY_AFTER` |
| [The approval service or its database is unreachable](#8-the-approval-service-or-its-database-is-unreachable) | the policy verdict, within the 10 s client timeout, never a hang | human rulings are not consulted until it is back — **including a deny on a package the policy allows** | `FW_APPROVAL_URL`, and the deny list for a block that survives this |
| [A package that cannot be scored](#9-a-package-that-cannot-be-scored) | `403 unscorable` (default), queued for a person if approval is configured | packages with no resolvable source repo fail until approved | `FW_UNSCORABLE_POLICY`, `FW_UNVERIFIED_POLICY` |
| [A client that would wait forever](#10-a-client-that-would-wait-forever) | its connection is released by a bound; a well-behaved client is served after it | cannot happen at our listener; the one unbounded wait is a stalled upstream body | none |
| [Turning enforcement off without removing the gate](#11-turning-enforcement-off-without-removing-the-gate) | everything it would have refused, with the refusal logged beside it | nothing blocked on day one | `FW_MODE=report` |

The verdicts themselves (a low score, a human denial, a deny-list hit, a known-malware
advisory, a release window) are not failures and are not in this table; they are what the
gate is for. `docs/MODE_MATRIX.md` records the verdict every posture produces for every
request shape, including an upstream-outage scenario, across 3,072 cells.

## 1. The gate itself is down

A crashed process, a lost node, a network partition between the client and the gate.
**The developer** sees their package manager's own connection error: nothing of ours is
in the path to explain anything. **The pipeline** fails at its first pull and stays failed
until a replica answers.

The posture is the same as for the registry being down: run more than one. The gates
share nothing (`e2e/ha_drill.sh` leg 3) and give identical verdicts with no coordination
between them (leg 4), so a load balancer in front of two or more replicas is the whole
answer; the Helm chart spreads them one per node.

`/healthz` answers `200` whenever the process is serving, **and only says that**: it
never varies with upstream reachability and never contacts an upstream (D163, pinned by
`TestHealthzDoesNotVaryWithUpstreamReachability` and `TestHealthzNeverContactsUpstream`).
A liveness check that depended on npm being up would restart healthy gates during an
npm outage, which is the failure it is meant to detect. Readiness is liveness today: a
gate that boots in `stub` scoring mode reports itself ready, and whether that should
need an explicit opt-in is the one open box on #19.

## 2. The gate is being upgraded or rolled back

Every replica is replaced while a client keeps pulling through the load balancer, and
**zero requests fail** (`e2e/ha_drill.sh` leg 5, measured on every CI run). Rolling
back is a redeploy of the previous image, not a restore (leg 6): there is no durable
state in the gate to migrate. On Kubernetes an operator-list edit rolls nothing, because
the pod template hashes only the environment.

Run it yourself: `sh scripts/dev.sh ha`.

## 3. The gate is slow

Measured, not estimated (`docs/FOOTPRINT.md`): on a warm, already-decided path the gate
adds **&minus;1 to &minus;2 ms** at p50 through p99 against pulling direct from the
registry, and not because it caches (76 upstream fetches for 76 verdicts in that run).
The **cold path**, the first time a package is ever seen, costs 1.2&ndash;2.4 s for
repository resolution, the deps.dev cross-check and the score; a refusal afterwards
costs 5&ndash;22 ms and touches no upstream. `latencybudget_test.go` asserts the delta
in the ordinary unit suite: median added latency under 5 ms, p99 under 250 ms.

A cold fleet does not multiply the cold path. Concurrent pulls of the same package
collapse into one upstream lookup (`TestEvaluateCoalescesColdLookups`,
`TestNpmCoalescesConcurrentSameKeyLookups`; through real `npm` clients,
`TestNpmCoalescesUpstreamScoringCalls` measured 210 decisions against 67 score calls),
and in local mode into one scan (`TestLocalConcurrentColdPullsStillScanOnce`). Distinct
packages are deliberately not coalesced (`TestEvaluateDoesNotCoalesceDistinctPackages`).

## 4. The upstream registry is unreachable or slow

The gate did not evaluate, and it says so. **The developer** gets a `403` with kind
`unavailable` and the reason *"This is not a verdict about the package -- the firewall
could not reach the sources it needs to evaluate it. That is an outage on our side, not a
finding about your dependency, and it clears when those sources are reachable again"*,
sent `no-store`. It is never a `5xx` (`TestUpstreamOutageIsForbiddenNotServerError`) and
never *unscorable* (`TestOciFailedConnectionIsUnavailableNotUnscorable`,
`TestMavenTransientErrorsAreUnavailable`, `TestMavenAgeProbeOutageIsNotAPolicyRefusal`,
`TestVerifyRepoOutageIsRetryableNotBlocked`), and a client can tell it from a real
block on the wire (`TestD102BlockAndUnavailableAreDistinguishableOverHTTP`).

**The bytes are withheld too.** Under the shipped default the byte gate serves an
*absence of trust* with a log line, but an outage is not an absence of trust: an
artifact fetch during one is refused rather than delivered (the #60 fix,
`TestNpmTarballGateUnavailableIsForbidden`, `TestPypiFilesFetchUnavailable`). A
release window with no publish dates to judge by refuses rather than waves the package
through (D100, `TestPypiAgeFloorFailsClosedWhenUploadTimesUnavailable`).

**Bounds.** Metadata probes give up after 10 s; the relay waits 30 s for the upstream's
response headers; transient upstream errors on idempotent fetches are retried within a
bound (!30); a package that just answered `429` is not asked again for a short backoff
window. Every path ends in a status the client understands.

**Blast radius.** Every pull that needs the registry fails for the duration, and nothing
retries on its own (D102 gave up the automatic `503` retry on purpose). The gate holds
no artifacts, so it does not serve stale. What survives an outage is the customer's own
registry: with the gate **in front of** it, a package the registry already holds keeps
installing while the public registry is unreachable, and the gate still sees and counts
the pull; an uncached package fails (`e2e/registry_front.sh` legs 3&ndash;5,
`sh scripts/dev.sh regfront`). The optional `cache/` service serves its hits from memory
and forwards misses to the gate, so a miss during an outage gets this row's `403`.

## 5. The upstream stalls or truncates mid-download

The relay has **no whole-request timeout, on purpose** (`TestProxyClientHasNoWholeRequestTimeout`):
a 30 s one truncated large images, and a real 450 MB pull streams for minutes. So an
upstream that stops sending in the middle of a body holds the client for as long as the
client itself is prepared to wait. This is the one unbounded wait in the table, and it
is a bound on the upstream, not on the gate. The upstream fetch carries the client's
request context (`proxy.go`, `openUpstream`), so a client that gives up releases the
upstream connection with it.

A transfer that ends early is detected and logged, never presented to the client as
complete (`TestShortGetIsStillTreatedAsTruncated`); a `HEAD`, which has no body, is not
mistaken for one (`TestHeadIsNotTreatedAsATruncatedTransfer`).

## 6. The score source is down or rate-limiting

deps.dev answering `429` was hit in the first week (D25). It classifies as
*unavailable*, and the reason **names rate limiting** rather than a generic outage
(`TestEvaluate429ReasonNamesRateLimit`, `TestClassifyStatusRateLimited`). A short-TTL
backoff then stops the gate re-storming the source on every request
(`TestEvaluateRateLimitBackoffSkipsUpstream`, `TestVerifyRepo429IsRetryableAndArmsBackoff`,
`TestBackoffCacheExpiryAndNilSafety`).

In local mode the scheduler's own failures are kept apart by status (!96): *at capacity*
and *failed to launch* are ours and read *unavailable*
(`TestGetScoreSchedulerAtCapacityIsTransient`, `TestGetScoreSchedulerPrepareFailureIsTransient`);
a scan that ran and could not score the repository is a fact about the package and
reads *unscorable* (`TestGetScoreScannerBadGatewayStaysUnscorable`). Collapsing those
would either serve a package because our launcher was down, or retry a hopeless one
forever.

**Blast radius.** Packages seen for the first time read `403 unavailable` until the
backoff window passes or the source recovers; packages already decided keep their
cached score for the score cache TTL and, in local mode, durably in the approval
database. Three things need no score call at all and keep working through it: an entry
on `FW_ALLOW_LIST`, an entry on `FW_DENY_LIST`, and a package named by `FW_MALWARE_LIST`.
Credentials on the gate's own probes raise the rate ceiling (!38).

## 7. First pull of a package nobody has scanned (local mode)

With `FW_SCORECARD_MODE=local` the first pull of a never-scanned package is quarantined
while one background scan runs (D18). **The developer** gets a `403` with kind `pending`
and a reason ending *"(a background scan is running; try again in about 60 seconds)"*;
the number is `FW_PENDING_RETRY_AFTER`. It is sent `no-store`
(`TestD102PendingIsNotCacheable`) so a corporate proxy cannot remember "denied" for a
package that was only mid-scan.

**One scan, however many clients.** N concurrent cold pulls launch exactly one scan
(`TestLocalConcurrentColdPullsStillScanOnce`; `e2e/async_local.sh` asserts *exactly 1
background scan* with real containers on every CI run). The score lands in the durable
L2 cache in the approval database, so a gate restart is **not** a cold cache
(`TestAsyncColdThenCached`); only a package no replica has ever scanned is cold. A
scan that fails transiently is not pinned as a verdict (`TestAsyncTransientDoesNotPin`).

**Blast radius.** The first pull of every new package fails **once** and has to be
re-run by hand. That was a `503` the client retried on its own until D102 ruled the
taxonomy wrong; the cost was named and accepted, and a way to request a scan without
failing an install was named as the follow-up. It is not built.

## 8. The approval service or its database is unreachable

The gate does not need the approval service to decide; it needs it to *overrule*. With
the database gone, the gate stays healthy, the verdict falls back to policy, and the log
says exactly that: `approval lookup failed: ... (falling back to policy)`
(`e2e/ha_drill.sh` leg 7, on every CI run). The wait is bounded by the same 10 s client
timeout the probes use: a dead service at a live address is refused in under 3 s, a
vanished DNS name within the timeout, never a hang. Redeploying the service from an
empty database needs no restore ritual, and the gate never restarts.

The service's own boot retries the first database connection for
`APPROVAL_DB_CONNECT_TIMEOUT` (default 60 s) and then **exits with the error** rather
than coming up wrong (`TestStartupRetriesAnUnreachableDatabaseThenGivesUp`); 80
replicas bootstrapping the same empty database at once no longer race (leg 8). Audit
events are emitted without blocking the pull and are dropped and counted when the
buffer fills (`TestAuditEmitterDropsWhenFull`).

**Blast radius.** Human rulings are not consulted while it is down, so a package a
person approved reads as its policy verdict again (`403 unscorable` under the default)
until the service is back. Audit events lost in that window are counted, not silently
absent — whether the service could not be reached at all
(`TestAnUndeliverableAuditEventIsCountedAsDropped`) or was reachable and **refused** the
record, which is what a control plane whose database is down does
(`TestARefusedAuditEventIsCountedAsDropped`). The count travels in each heartbeat as
`audit_dropped`, and the gate logs the loss once when it starts and once when it clears,
not once per pull. *(Before `#153` this sentence was true only of a full local buffer:
an undeliverable event was logged but not counted, and a refused one was neither.)*

⚠️ **Since D272 (2026-09-19) this cuts both ways, and the second direction is the
one that fails OPEN.** A human *deny* now outranks a passing score (`#132`), so a deny is
one of the rulings that stops being consulted here: a package whose score clears the
threshold is **served** for the duration of the outage even though a person blocked it.
That is a deliberate trade — failing closed on the allow path would refuse every install
whenever this service blinked — but it means a human deny is not the mechanism to reach
for when a block must hold regardless. **The operator deny list is**: it is read from a
file on the gate itself and does not depend on this service at all.
`TestAnUnreachableApprovalStillServesAnAllowedPackage` pins the behaviour so the trade
cannot be reversed by accident, and the console says the same thing at the moment a deny
is recorded.

## 9. A package that cannot be scored

No repository link, a repository that does not exist, a scan that could not score it:
the common messy-metadata case, and the one `FW_UNSCORABLE_POLICY` decides. Under the
default `block` the pull is refused (`403`, kind `unscorable`) and, if `FW_APPROVAL_URL`
is set, queued for a person; under `allow` it is served with the decision logged
(`TestUnscorableMatchesLegacyPolicy`, `TestBelowThresholdOverride`,
`TestVerifyRepoNoRepoDeclaredAndNoMappingStaysUnscorable`). Under the byte gate's
permissive default the artifact of an unscorable package is served with visibility,
because unscorable is an absence of trust rather than a finding (D72,
`TestNpmTarballGateDefaultServesUnscorable`); set `FW_BYTE_GATE=enforce` to withhold it.

**Which deployments this protects, with a real sample.** A Lazarus Group npm typosquat
(`react-html2pdf.js`, first-hand incident writeup in #24) had no lifecycle hook and a
payload padded off-screen; a human reading the package page would have approved it.
Traced through the gate, both of its metadata shapes end at a knob: no `repository`
field is *unscorable*, and a `repository` spoofed to the legitimate project is caught
by the deps.dev cross-check and is *unverified* (`FW_UNVERIFIED_POLICY`, default
`closed`). Only a deployment running both `FW_UNSCORABLE_POLICY=allow` **and**
`FW_UNVERIFIED_POLICY=open-with-visibility` lets it through. The defaults are the control.

**Blast radius.** Under the defaults, every package with no resolvable source repository
fails until a person approves it, and on a fresh deployment that is a real day-one
volume (accepted in D36/D42). deps.dev's Maven coverage is patchier than npm's, so the
cost lands unevenly by ecosystem.

## 10. A client that would wait forever

A failure other package tools' trackers report often: a transient error mid-install
and *"pnpm will just hang forever"*, surviving even a cancelled CI job (#24). The
listener is bounded so that cannot happen at the gate:

| listener | headers | request body | idle | other |
|---|---|---|---|---|
| cooperative (`FW_LISTEN_ADDR`) | 15 s | 90 s between bytes, extended as bytes arrive | 90 s | |

Each stalled shape releases its slot and a well-behaved client is served afterwards
(`TestCooperativeSilentClientIsReleasedByTheHeaderTimeout`,
`TestCooperativeStalledRequestBodyIsReleasedByTheReadTimeout`), and the body bound is a
bound on a **stall**, not on an upload: a slow honest upload completes
(`TestCooperativeTrickledUploadIsNotCutByTheReadTimeout`). Cancelling is honoured: the
upstream fetch shares the client's request context (row 5). The one wait the gate does
not bound is an upstream that stalls mid-body, described in row 5.

## 11. Turning enforcement off without removing the gate

`FW_MODE=report` computes every verdict, logs what it would have done, and refuses
nothing (`TestReportModeRelaysWhatEnforceWouldRefuse`), so the gate can sit in the pull
path with none of the rows above blocking a build while its verdicts are read. Two
things it deliberately keeps: request-integrity refusals, which report mode would
otherwise turn into a bypass enforce does not have
(`TestReportModeStillRefusesAnIntegrityMismatch`), and an audit record that says a
block was *reported*, not made (`TestAuditRecordDistinguishesReportModeFromARealBlock`).

## What this page does not claim

- **Serve-stale.** The gate holds no artifacts and never will; surviving a registry
  outage is the customer's registry's job, with the gate in front of it (row 4).
- **More available than the upstream.** Not claimed until it is measured on a real
  deployment, which no drill here is.
- **Readiness.** `/healthz` is liveness. A gate whose scoring mode is `stub` reports
  ready (#19).
- **A scan-request path.** Row 7's first-pull failure is the accepted cost of D102; the
  replacement was named there and is not built.

## How this page is kept true

`failuremodes_test.go` runs in the ordinary unit suite. It refuses to pass if a test
named on this page no longer exists, if a drill leg cited by number is not in the
script it is attributed to, or if a load-bearing sentence (the `no-store` on deferred
outcomes, the *falling back to policy* line, the pending wait knob) disappears. Its
own negative control proves each check can fail.
