# Customer-shaped E2E Testing — practices & lessons

This doc captures how we test Yellow Jack **the way a customer actually uses it**
(a real package manager, in a throwaway container, pointed at a live firewall),
and the lessons that changed our practices along the way. Read it before adding a
new ecosystem or a feature that touches the request path — it exists so we don't
re-learn the same things.

The real-client harness lives in `./e2e` (build tag `e2e`). It needs Docker +
network and is kept out of the default `go test ./...` so unit runs stay fast and
offline. There is one scenario file per ecosystem — `npm_test.go`, `pypi_test.go`,
`oci_test.go`, `maven_test.go` — each a `TestXxxEndToEnd` running the real client
under a permissive and a fail-closed policy.

Run it with the make target (defaults to all four ecosystems):

```
make e2e                 # every ecosystem
make e2e ECOSYSTEM=npm   # just one: npm | pypi | oci | maven
```

which wraps `go test -tags e2e -run TestXxxEndToEnd ./e2e/...`. In CI the e2e
jobs (`.gitlab-ci.yml`) run the full matrix **nightly on the default branch** (D336),
and a red nightly fails that pipeline and emails the schedule's owner. On a merge
request they are **manual**: run them by hand on a change you think a real client
could see. A manually-run e2e job that fails blocks the merge. A merge is otherwise
gated on the fast jobs (build, vet, unit, race, chart, scans). While the latest nightly
is red, `waitci` prints a warning on every merge. The jobs run
on GitLab's shared runners via **`docker:dind`**: the harness (`e2e/harness.go`)
builds the firewall image and runs it as a **container** with a published port, and
the client containers reach it via `host.docker.internal`, which resolves to the
docker host on both a dev laptop and a dind daemon. Locally the harness reaches the
firewall at `127.0.0.1`; in CI it uses the dind service host (`E2E_FW_HOST=docker`).

> **History:** this job used to require a self-hosted `docker-host` shell runner,
> because the firewall ran as a host *process* that `docker:dind` couldn't route a
> client container to. Running the firewall as a container removed that constraint
> (MR `!35`, 2026-07-22), so the gate moved to GitLab's own runners and the
> self-hosted WSL2 runner was retired.

> **Async local-mode e2e (D18/MR-D) — now covered.** `bash e2e/async_local.sh`
> (compose overrides `docker-compose.e2e.yml` + `docker-compose.asyncfake.yml`) drives
> the REAL pipeline — firewall(`local`) → scheduler → `docker run` scanner container →
> results → approval **Postgres** L2 → firewall — and asserts the async contract: cold
> pull → **403 "still scanning"** (D102; was `503 + Retry-After 60`); ONE background scan
> writes L2 **carrying the exact score**; the next pull is **decisive**; and **no re-scan** (the
> durable row prevents it). The rig builds both images itself, so there is no prereq
> step to forget. Verified 2026-07-17 on Docker 29.5.3; reworked and re-verified
> 2026-07-26 (18 legs green **with and without** `GITHUB_TOKEN`, plus a negative
> control — see the warning below).
>
> **⚠️ The trap this rig fell into, and the rule it produced (issue #55).** The rig
> used to obtain its decisive answer from the real `scorecard` binary **failing
> authentication**, because no `GITHUB_TOKEN` is set anywhere in `.gitlab-ci.yml`. The
> `403` it asserted was produced by *scanning being broken*. That is not a smaller
> version of the right test — it is an **inverted gate**: it could not tell "the
> pipeline works" from "every scan fails", it **FAILED 3 legs when run with a working
> token** (the healthy configuration was the red one), and it would have gone red the
> day someone fixed scanning. It was documented at the time as a known coverage *gap*;
> the lesson is that **a gap whose workaround supplies the assertion's answer is not a
> gap, it is a false pass.**
>
> The fix is `e2e/fakescanner` (+ `docker-compose.asyncfake.yml`): the scheduler
> launches a deterministic fixture image whose score is chosen at build time, so the
> gate depends on no token and no GitHub. Everything else stays real. The rig now
> asserts **both** terminal outcomes on purpose — `lodash` scores 9.0 → the L2 row
> carries that exact number → **200 allowed** (which proves a real score traversed
> scanner → sink → scheduler → L2 → firewall → `decideByScore`, something the old
> negative-marker leg proved *nothing* about), and `express` is refused by the fixture
> → durable negative marker → **403**. Closing the old "successful-score → allow gap"
> came free with removing the false pass.
>
> **Prove it can fail before trusting it:** `FAKE_SCORE=1.0 bash e2e/async_local.sh`
> must fail the allow leg (`FAIL: post-scan lodash pull code=403 …`). See
> `e2e/fakescanner/README.md`.
>
> This is a script-driven e2e, not part of the tagged Go `TestXxxEndToEnd` matrix,
> because it needs the multi-service compose stack (scheduler + scanner container +
> DB) the subprocess harness doesn't stand up.
>
> **Both scanner launchers, one driver.** The scheduler can spawn each run-once
> scanner via `docker-run` (CLI shell-out) or `docker-api` (raw Engine API, D16 /
> "Reshape L5"). The driver is parameterized: `SCHEDULER_LAUNCHER=docker-api bash
> e2e/async_local.sh` runs the *same* async pipeline over the API launcher, and a
> fifth assertion checks the scheduler actually logged `launcher: docker-api` (so it
> can't silently fall back). This is the durable closure of the docker-api
> real-score gap: the launch + fail-fast path was already proven (unit + a DooD e2e
> → 502), but a *successful* real-score customer flow was proven live only on
> `docker-run`; a launcher-parameterized run of this suite closes that as a
> **dimension of the existing e2e, not a bespoke one-off**. Default stays
> `docker-run`, so committed behavior is unchanged. _(docker-api parity run **verified
> 2026-07-17** on Docker 29.5.3 — all five assertions green, incl. `launcher:
> docker-api` with no silent fallback; AutoRemove left zero leftover scanner
> containers. See BUILD_LOG "Reshape Layer 5".)_

> **Local-mode borrow-a-score e2e (D39) — `bash e2e/verify_repo_local.sh`.** Drives the
> same real local stack (firewall(`local`) → scheduler → run-once scanner → approval L2)
> with a **real client per ecosystem** and proves the D33/D39 cross-check where it
> matters: a package that **borrows another project's repo is refused BEFORE a scan is
> launched**. Seven legs — npm borrow (`lodash` claiming `expressjs/express`) → 403 +
> mismatch logged + **zero** scans; npm honest (`left-pad`) → 403 pending + a scan on the
> right repo; **npm durably-unverified (leg G, D36)** — `yj-unverifiable-d36`, a name
> published **nowhere** so live deps.dev genuinely 404s it, claiming lodash's repo → 403
> **carrying the verdict explanation** ("deps.dev has no record" is a durable answer, so
> it is a verdict, not a "we could not look") + zero scans; the same borrow/honest pair for pypi (`six` claiming
> `pallets/flask`, `certifi`); maven borrow (guava's POM claiming `junit-team/junit5`); and OCI
> (`library/traefik`, which declares a source label) asserting the **fail-closed** path
> — refused as unverified, no scan launched — since deps.dev has no package index for OCI
> and D48 (#33) reversed the degrade-open it used to assert. Compose override: `docker-compose.verifyrepo.yml` (ports **818x**, clear
> of a local Artifactory test rig on 8081-8082; a preflight names a clash instead
> of letting `compose up` fail cryptically).
>
> **The rig's key idea — craft the half the attacker controls, keep the other half real.**
> Borrow-a-score is a *publisher-controlled metadata lie*, so the **upstream registry** is
> faked (`e2e/fakeupstream/`, a static tree served by `python -m http.server`) while
> verification runs against the **live api.deps.dev**. Faking deps.dev instead would test
> our own mock rather than the cross-check, and we obviously can't publish malware to
> npmjs.org. The trick is to reuse names deps.dev *already* has a `SOURCE_REPO` record
> for, then have the crafted upstream claim a different repo — so the contradiction is
> real. Only the paths the **firewall itself** fetches need to exist (npm
> `/{pkg}/latest`, pypi `/pypi/{pkg}/json`, maven metadata+POM): the client's request is
> answered by the firewall with a 403 and never proxied upstream, so no tarballs,
> wheels, or jars are needed.
>
> Three traps this leg walked into, recorded so the next person doesn't:
> - **In local mode, maven cannot bootstrap through the gate at all** — so the api-mode
>   maven recipe (`<mirrorOf>*</mirrorOf>`) produces a leg that "fails" while proving
>   nothing. The star mirror is mandatory to reach a plain-HTTP proxy, but it also routes
>   maven's own plugin tree (dependency, clean, install, deploy, site, …) through the
>   firewall; tokenless local mode resolves each of those to unscorable → 403, so `mvn`
>   dies on `maven-dependency-plugin` long before the artifact under test. Pre-warming a
>   shared local repo from real Central does **not** fix it: maven re-validates plugin
>   POMs, and its `_remote.repositories` origin tracking re-resolves anything whose repo
>   id changed. **What works:** drop the mirror entirely and use `-gs` (which replaces
>   maven's global settings, removing the `external:http:*` blocker — the only reason
>   plain-http is reachable) to override the `central` **repository** to the firewall while
>   pointing the `central` **pluginRepository** at real Central. Artifacts cross the gate;
>   the toolchain doesn't. Assert this from the **firewall's own decision log** (it saw
>   `com.google.guava:guava`, and never saw `org.apache.maven.plugins`), not by grepping
>   mvn's output — mvn names plugins in incidental warnings and a substring match
>   false-fails.
> - **`alpine` is the wrong image for the OCI leg.** The "unverified: not indexed by
>   deps.dev" line is only logged when the image actually *declares* a repo; alpine
>   declares no `org.opencontainers.image.source`, so it takes the unscorable path and
>   logs nothing — the assertion would have gone green for the wrong reason. Use an image
>   that carries the label (`library/traefik`).
> - **The scanner+scorecard stack needs `GITHUB_TOKEN` to reach "allow".** Tokenless, an
>   honest package's scan fails auth → negative marker → block (the pre-existing gap
>   noted above). So the local-mode honest leg asserts *verification passed and the right
>   repo was scanned*, and the "a legit package still installs" proof comes from the
>   api-mode matrix, which does real installs.

---

## Cross-cutting lessons (apply to every ecosystem and feature)

1. **Per-branch e2e is a category error.** The harness waits on the firewall's
   `/healthz` and reads its `allowed=…` decision log — both are *foundation*
   features. A feature branch based on plain `main` (e.g. the maven branch) has
   no `/healthz`, so the harness can't even start it. **Real, customer-shaped e2e
   only exists on the *integrated* tree.** Practice: unit-test each feature branch
   in isolation; run the real-client e2e on the assembled stack (foundation +
   features), or stack the feature on the foundation so it's e2e-able.

2. **`api`-mode + permissive policy does NOT test scoring.** With
   `FW_SCORE_THRESHOLD=0`, `FW_UNSCORABLE_POLICY=allow` and (since D36)
   `FW_UNVERIFIED_POLICY=open-with-visibility` — a permissive leg must relax **all
   three** knobs now that unverified is its own fail-closed posture — the
   install/resolve succeeds *regardless* of whether scoring worked. So a
   green permissive run proves the **proxy / parsing / rewrite / allow-block
   plumbing**, not the **scoring decision**. To exercise scoring you need `local`
   mode (scanner stack) or a stub that returns a *controlled* score, and you must
   assert on the score-driven outcome, not just the client's exit code.

3. **A clean git auto-merge is not proof of correctness.** Reconciling D17 onto
   the foundation, git auto-merged `ecosystem.go` with *no conflict markers* but
   silently dropped the all-shapes `repository` parser in favour of an older
   object-only struct. Only a shape-covering test caught it. Practice: after any
   cross-branch reconcile/cherry-pick, diff the semantic core against the
   source-of-truth commit, and lean on tests that cover **real-world input
   shapes**, not just the happy path.

4. **Assertions must be drift-robust.** Package scores and dependency trees change
   over time. Assert on *exit code* + *presence of allow/block decisions*, never a
   specific dependency's score. For a guaranteed block, use an unreachable
   threshold (`9.9`) rather than betting a particular artifact scores low.

5. **Real registries rate-limit — space out real-registry runs.** Maven Central
   returns `429` after back-to-back resolves (both the `maven-metadata` API and
   the POM CDN). `429` is already mapped to `errUpstreamUnavailable` (→ a client-facing
   403 explaining we could not verify, since D102; it was a retryable 503 before) in
   `classifyStatus`. For isolation checks, **pin the version** to
   skip the rate-limited metadata endpoint, and add backoff.
   > **Not every maven 429 is rate-limiting — check the User-Agent first.** A
   > *deterministic* `429` on the very first maven fetch was a firewall bug, not
   > load: Maven Central (Fastly) 429s Go's default `Go-http-client/1.1` UA
   > outright (custom/empty/absent UA → 200). Fixed 2026-07-18 — the firewall now
   > sends a real `User-Agent` on all its own fetches (`useragent.go`). So: a 429
   > that reproduces on the *first* request is a UA/identity problem; a 429 that
   > appears only after many rapid resolves is genuine rate-limiting (this lesson).
   > Distinguish them with a direct `curl -A '<ua>' <central>/…/maven-metadata.xml`.

6. **Running the code is not measuring it — and a single `npm install` is not a
   thundering herd.** The e2e suite exercised request coalescing (issue #16) from the
   day it shipped and asserted *nothing* about it: deleting the flight groups entirely
   would have left every leg green. Two lessons came out of closing that
   (`e2e/coalesce_test.go`, MR !53):
   - **To measure what the firewall asks upstream, you need a seam.** An e2e firewall
     is a *container*; its only interface is the environment. `FW_DEPSDEV_BASE` exists
     so a counting stand-in can be dropped between the firewall and deps.dev. Reach for
     the same pattern for any "how many upstream calls did we make?" claim.
   - **The herd comes from concurrent CLIENTS, not from one client.** The first version
     of that test ran one `npm install` and its own anti-vacuity guard failed it: npm
     fetches each packument exactly once, so 132 upstream calls landed on 132 distinct
     paths and no two same-key lookups ever competed. Contention appears only with
     several clients pulling overlapping trees through **one shared firewall** — which
     is the real deployment shape (a team or CI fleet behind one instance). Measured:
     3 concurrent `npm install express` → 210 firewall decisions but **67** upstream
     score calls; with coalescing removed, 209 → 209 and four simultaneous lookups of
     one key.
   > Corollary, and the reason both numbers are asserted: **turn the L1 caches off
   > (`FW_SCORE_CACHE_TTL=0`) when measuring coalescing.** With caching on, "one call
   > per package" is what a *cache* produces, and the test passes identically with the
   > coalescing deleted — measuring the wrong mechanism and reporting it as proof of
   > this one.

7. **In the shell rigs, never `producer | grep -q PAT` under `set -o pipefail`.** `grep -q`
   exits at the **first** match, the still-writing producer is killed by SIGPIPE (141),
   and `pipefail` makes the whole pipeline report failure **even though the pattern was
   found**. Use the `logmatch` helper in `verify_repo_local.sh` (read into a variable,
   match with `case`) — no pipe, nothing to SIGPIPE. `grep -c` is safe: it reads to EOF.
   > Repro: `set -o pipefail; yes X | grep -q X` → exit 141.
   > This was real, not theoretical: leg A reported "no mismatch log line" in CI while
   > that exact line was in the same job output. It hid for a long time because it
   > depends on **where in the log the match falls** — an early match leaves more still
   > to write, so it is likelier — which is why other legs passed with the same helper
   > and why the rig always passed on a laptop with smaller logs. It produced false
   > FAILURES, never false passes.

8. **If a required gate depends on an external service, preflight it — don't write a note
   asking someone to watch for it.** The local-mode rigs verify against the real
   api.deps.dev on purpose, so two things fail the gate while meaning "the firewall is
   fine": deps.dev rate-limiting the runner, and deps.dev's own data drifting away from
   what the legs assume. `e2e/depsdev_preflight.sh` runs first and exits **3**
   (rate-limited, re-run later), **4** (premise drift, a re-run will NOT help), or **5**
   (unreachable) — so nobody has to infer that from a failed security assertion.
   > **Assert the ABSENCE too.** Leg G proves a package with *no* deps.dev record fails
   > closed; its subject is a name published nowhere. If someone publishes it, the leg
   > keeps **passing** while testing something else. The preflight asserts the name is
   > still unknown — when a test's meaning depends on external data being absent, assert
   > the absence.
   > **Don't re-assert the thing under test.** The preflight checks known/unknown, not the
   > package->repo mapping — that mapping is what the rigs assert, and duplicating it in
   > the preflight would let the preflight mask the failure it exists to explain.
   > **Its negative controls are committed** (`e2e/depsdev_preflight_selftest.sh`, offline,
   > run in CI before either rig): a preflight that has silently lost the ability to fail
   > is worse than none, and looks identical in the happy path.

9. **A "known-good" manual rig moved into CI is not bookkeeping.** Both shell rigs had
   been run by hand many times and passed. Putting `verify_repo_local.sh` into CI failed
   it on the first run and exposed the defect above — in the *test*, not the product —
   which no amount of re-running it locally would have surfaced. Expect the environment
   change (bigger logs, different host, colder caches) to find something.
   > Related asymmetry, and the reason `local` mode went untested for so long: a **Go
   > test** under `e2e/` automatically joins the required gate (the job runs the package
   > with no `-run` filter), but a **shell rig needs its own CI job**. Prefer a Go test
   > when the choice exists.

10. **An anti-vacuity guard must measure the precondition the claim actually rests on —
    not a nearby quantity that correlates with it on a quiet laptop.** Lesson 6's test
    guarded itself with "did the *fake* ever see two upstream calls in flight at once?"
    (`max_concurrent > 1`). That is overlap between calls the firewall had **already
    decided to make**, across *unrelated* keys. Coalescing is about several clients
    converging on the **same** key, which is a different event. On a loaded shared runner
    the firewall issued its lookups one at a time, the guard tripped, and a green
    firewall was reported red on an unrelated MR (issue #44) — while the very same run
    collapsed **198 client requests into 66 upstream calls**, a textbook 3:1 coalesce.
    Two practices came out of it (`e2e/coalesce_test.go`, MR for issue #44):
    - **Measure the precondition at the component that owns it.** Client-side contention
      is visible at the *firewall* (`decisions - scoreCalls` with caching off: a request
      that produced no upstream call is by definition one that met a flight in progress),
      and client concurrency is visible in the *test* (`maxOverlap` over each client's
      start/end). Neither needs to ask the fake how busy it looked.
    - **Separate "the code is broken" from "the environment didn't cooperate", and say
      which.** With no coalescing observed *and* no client overlap, the run is unusable →
      skip loudly. With no coalescing observed *and* demonstrable overlap, it is the
      firewall → fail. Collapsing those two into one verdict is what made #44 a
      misdiagnosis rather than a retry.
    > **A timing-dependent guarantee deserves a second, deterministic leg.** The realistic
    > leg (real npm clients, real trees) inherently lets the runner decide whether its
    > clients ever meet. `TestNpmCoalescesConcurrentSameKeyLookups` fires N goroutines at
    > **one** package through the container while the fake holds each call for 5s — skew
    > of microseconds against a ~10s window — so N→1 is a property of the code, not of the
    > scheduler. Keep both: the realistic leg for shape, the deterministic leg for the
    > guarantee. Verified by negative control (flight groups nil → 1 upstream call becomes
    > 12, both assertions fire, preconditions still hold).
    > **Don't reach for a barrier in the fake.** The obvious fix — hold the first N
    > arrivals until all N are present — cannot work here: if coalescing *works*, only one
    > call per key is ever issued, so a same-key barrier never fills and the test hangs;
    > and a barrier across distinct keys makes `max_concurrent > 1` true **by
    > construction**, converting the guard into a tautology. Forcing overlap downstream
    > cannot manufacture the upstream contention that is the thing under test.

11. **Honest-client e2e cannot find a bypass — you have to attack the thing.** Every leg
    in this suite drove the firewall the way a *customer* does, and all of them were
    green while a blocked package could be pulled in full by rewriting the request path.
    An honest npm client never sends `//lodash`, so no honest-client test can tell you
    what happens when someone does (issue #59, `e2e/adversarial_test.go`).
    - **The bug class: the identity we GATE vs the identity the upstream RESOLVES.** We
      parsed the package out of the request path, then forwarded that path verbatim to a
      CDN that normalizes `//`, `..` and percent-escapes differently than we do. Measured
      at `FW_BYTE_GATE=enforce` + `FW_UNSCORABLE_POLICY=block`: `/lodash` → 403, while
      `//lodash` returned the real 247KB packument and `/lodash/%2d/lodash-4.17.21.tgz`
      returned the real 318KB tarball **with no decision line logged at all**.
    - **Two parsers reading two views of one request is the smell.** The metadata gate
      read `r.URL.Path` (decoded), the byte gate read `r.URL.EscapedPath()` (encoded);
      each skipped the tarball case believing the other handled it. `%2d` fell in the gap.
    - **Fix at ONE choke point, before ecosystem dispatch.** npm and PyPI leaked through
      *different* shapes, so four parsers would each have to stay right forever. See
      `pathguard.go`.
    - **Whitelist, don't normalize.** Normalizing hostile input safely requires predicting
      every CDN's normalization — the assumption that failed. Require the path to be
      unambiguous already and refuse it otherwise; real clients only emit canonical paths.
    > **Write the attack onto the socket by hand.** `http.Client` is entitled to normalize
    > what it sends, and would have quietly repaired the attack before it left the test and
    > reported a pass. `rawGet` opens a socket and writes the request line verbatim.
    > **Assert on CONTENT, not status.** The bypass returned a perfectly ordinary `200`;
    > only "does this body contain a packument or a gzip magic number" catches it.
    > **A refusal is not automatically a defence.** "No package content came back" is also
    > what a broken firewall produces, so the same evasions run a second time against an
    > **allow-everything** firewall whose honest path demonstrably serves real bytes. A 400
    > there cannot be a block verdict — it can only be the guard. That is the discriminator.
    > **Pin the compatibility surface too.** The cheapest way to a green adversarial suite
    > is to break the product, so scoped names (`/@babel%2fcore`), our own
    > `/_tarball/@scope%2fname/…` rewrite, npm's `/-/` control plane and PEP 503 names with
    > dots are all asserted to still pass — in the unit table *and* through the container.

12. **Defence in depth hides broken defences: assert WHICH layer refused, not that
    something did** (issue #77, `e2e/adversarial_pypi_signed_test.go`). PyPI's byte route
    has two independent guards on the same question — the signed binding (`#72`) and the
    filename grammar `pypiFilenameBindsToPackage` (`D101`). An adversarial leg that only
    asserts "no bytes came back" is satisfied by *either*, so a leg written to measure the
    signature passes just as happily when the signature is gone.
    - **Measured, not theorised.** With signature verification stubbed out (`return true`),
      five of seven legs went red — but both cross-package legs stayed **green**, refused
      by the grammar with `"artifact filename does not belong to the requested package"`.
      Two legs would have certified a defence that was not running.
    - **The fix is one line of assertion**: check `X-Yellowjack-Reason` names the layer
      under test. With that in, the same mutation fails all seven.
    - **Generalise it:** any surface with a backstop needs this. The backstop is worth
      having — it is why the cross-package attack fails twice over — but it must not be
      allowed to *stand in for* the guard a test claims to measure.
    > **A relaxation of a security binding earns its own attacker leg.** `!114` let one
    > signature cover two object paths (`X` and `X.metadata`) so PEP 658 could work. That is
    > correct and necessary, and it is also the only place the binding is deliberately not
    > exact — so the legs that matter attack the **approved** package, where grammar and
    > verdict both pass and the signature is the only thing left that can refuse. Attacking
    > a blocked package proves less: three guards fire at once and you cannot tell which.
    > **Anti-vacuity has to be in the same run.** An honestly signed `.metadata` fetch must
    > SUCCEED alongside the refusals, or a firewall that refuses everything scores a clean
    > sweep. Discover the artifact from an anchor advertising `data-core-metadata` — PyPI
    > only has a `.metadata` sibling for those, and a control built on any other file 404s
    > and gets misread as the binding working.

### A shared compose override is SHARED — check every rig that layers it

**2026-09-05, cost: one red CI pipeline and a confused half hour.** The operator
allow/deny fixtures (D193) went into `docker-compose.e2e.yml` because that is where the
async rig's firewall settings live. `e2e-local-verifyrepo` then failed on leg B, *"cold
pull of a verified package is not pending"*.

`verify_repo_local.sh` layers **the same file**:

```sh
COMPOSE=(docker compose -f docker-compose.yml -f docker-compose.e2e.yml -f docker-compose.verifyrepo.yml)
```

and it uses `left-pad` as its **verified** package — the one that must reach the scanner.
Our deny fixture blocked it before any scan could launch, so a rig testing repo
verification failed on a policy it never opted into.

**I did check for a name collision — but only inside `async_local.sh`, the rig I was
adding to.** That is the mistake worth remembering: the *fixture* was fine, the *file I
put it in* was shared.

**The rule:** anything that changes a **verdict** belongs in the override that only one
rig layers (`docker-compose.asyncfake.yml` for the async rig), never in
`docker-compose.e2e.yml`, which is shared plumbing — ports, timeouts, intervals.

**Verify both directions afterwards, because one is not enough:**

```sh
# must be 0 — the rigs that must not see it
docker compose -f docker-compose.yml -f docker-compose.e2e.yml -f docker-compose.verifyrepo.yml config | grep -c operator-allow
# must be > 0 — the rig that must
docker compose -f docker-compose.yml -f docker-compose.e2e.yml -f docker-compose.asyncfake.yml config | grep -c operator-allow
```

### In the async rig, a *fresh* package name is not a neutral baseline

Leg 22 needed a package whose verdict would visibly change. Its first draft used a new
name, and the leg's own baseline guard refused to run: **every unseen package is 403 in
the async rig** — the cold-scan *pending* state, not a denial. A leg asserting "it is now
403" would have passed with the feature doing nothing.

Use a package the rig has already **warmed and served** (`$PKG`), and keep a baseline
assertion that fails loudly when the "before" state is not what the leg assumes. Same
family as the 403-impostor guard in leg 21: *the status code alone cannot tell a verdict
from a pending scan.*


---

## Per-package-manager cheatsheet (coding + testing)

| PM | Coding gotchas (what the firewall must handle) | Real-client e2e setup |
|----|-----------------------------------------------|-----------------------|
| **npm** | `repository` field comes as object **/ bare string / array** — parse all shapes, never fail the packument on an unexpected one. Scoped packages arrive `%2f`-encoded (`@babel%2fcore`) — preserve `EscapedPath`, don't decode. Packuments run to tens of MB — fetch `/{pkg}/latest`, cap bytes. Rewrite `dist.tarball` URLs in **metadata** bodies to route back through the proxy (now through `/_tarball/<pkg>/`, so the byte fetch re-gates on the resolved identity); never rewrite tarball **bodies** — that corrupts them and fails `dist.integrity`. `/-/` control-plane paths (`/-/npm/v1/…`, ping, whoami — i.e. an **empty** prefix before `/-/`) pass ungated. **`npm ci` never requests metadata**: it fetches each tarball by its lockfile `resolved` URL, so a metadata-only gate is bypassable — see the lockfile leg below. | `node:22-alpine`, `npm install --no-save <pkg>`, isolated cache, `npm_config_registry` → firewall. |
| **PyPI** | Gate only `/simple/` (PEP 503) paths. Source repo is inconsistent — check `project_urls` under several keys (`Source`, `Repository`, `Homepage`, …) then `home_page`. **PEP 658/714:** pip fetches a wheel's METADATA without the wheel by appending `.metadata` to the distribution URL — to the **whole URL, query included** — so anything you put in the query gets that suffix glued onto it. The `#sha256=` fragment must survive any rewrite untouched, and a query you add has to go **before** it (a fragment is never sent to a server). | `python:3.12-slim` (glibc, for manylinux wheels), `pip install`, `PIP_TRUSTED_HOST` set (proxy is plain-http). |
| **OCI** | Manifest gating; registry is `registry-1.docker.io`. Many base images (alpine) have **no Scorecard repo** — deliberately exercises the unscorable/fail-open branch. | `crane pull library/alpine --insecure` (plain-http). |
| **Maven** | SCM is frequently **inherited from a parent POM** (Guava, Maven core plugins) — walk the `<parent>` chain (bounded depth) when the artifact's own POM has no `<scm>`. Maven **3.8.1+ blocks `external:http:*` mirrors** — a plain-http proxy is only reachable via an on-the-fly `settings.xml` mirror passed with `-gs`. `maven-metadata.xml` rate-limits hard. | `maven:3.9-eclipse-temurin-21`, `mvn dependency:get`, `-gs <settings.xml>` mirror → firewall. |

> Maven trap learned the hard way: a manual `mvn -DremoteRepositories=…http://…`
> silently hit the `external:http:*` blocker and **never reached the firewall**
> (empty decision log). Always route maven through the `-gs` settings.xml mirror.

> **PyPI trap learned the hard way (#72): pip appends `.metadata` to the URL you
> minted, query and all.** Signed artifact URLs (`?_yjsig=…`) shipped with unit tests
> and an adversarial test but **no real-client leg** — and `pip install` failed
> outright the first time one was written. Under PEP 658 pip requests
> `…/six-1.17.0-py2.py3-none-any.whl?_yjsig=bOEs..dQ.metadata`: the suffix lands on the
> **signature**, not on the path, so the signature stops verifying and the object pip
> wants (`.whl.metadata`) is one that was never signed. Every fetch 403'd.
>
> Two lessons, and the second is the general one:
>
> - **Anything appended to a PyPI artifact URL must tolerate a `.metadata` suffix
>   arriving at the very end of the string** — after the query, not after the path.
> - **A unit test cannot find this class of bug**, because it builds the URL the way
>   *we imagine* the client builds it. npm passed every test; pip did not. Whenever a
>   feature changes a URL a real client constructs or replays, the customer-shaped leg
>   is not optional coverage — it is the only thing testing the actual contract.

---

## Per-feature testing guidance (pick the right kind of test)

- **Feature changes the proxy / parsing / rewrite path** (e.g. D17 npm-reality):
  shape **table tests** for every input form + an **api-mode permissive** real
  client run is sufficient (it exercises the whole path end to end).
- **Feature changes the scoring path**: api-mode permissive will *not* catch it —
  use **`local` mode / controlled stub** and assert on the score-driven decision.
- **Feature changes repo resolution** (e.g. maven parent-POM chain): pick a **real
  artifact that exhibits the exact case** (Guava for inherited SCM) and assert the
  **resolved repo is non-empty** — not just that a permissive install succeeds
  (which would pass even if resolution silently failed).
- **Feature based on `main` (not the foundation)**: it **cannot** be e2e-tested
  standalone — integrate it onto the foundation stack (even temporarily) to run a
  real client against it.

---

## Lockfile installs (`npm ci`) — a second client behaviour, not a variant of the first

`TestNpmLockfileByteGate` exists because **`npm install` and `npm ci` exercise
different code paths in the firewall**, and only the first one was ever tested. An
`npm install` asks for metadata and then bytes; an `npm ci` asks for **bytes only**,
straight from the lockfile's `resolved` URL. A gate that watches metadata therefore
looks fully effective under every `npm install` test while being completely bypassed
by `npm ci` (issue #11). Assume the same split exists for any ecosystem with a
lockfile — pnpm, yarn, `poetry.lock`, `Cargo.lock`.

Three traps this leg hit, all of which would have produced a **green test that proved
nothing**:

1. **The lockfile records the firewall's ADDRESS**, so replaying it against a
   differently-configured firewall means restarting on the **same published port**
   (`startFirewallOnPort` + `fw.stop()`). A new port silently sends the client to a
   dead address, and the install fails for the wrong reason.
2. **The workspace must be a named docker volume, never a host bind mount.** On dind
   the daemon is a separate service, so a host path from the job container is
   meaningless to it — the bind mount yields an empty directory on CI while working
   perfectly on a laptop.
3. **The npm cache must be empty for every step.** A warm cache lets `npm ci` satisfy
   itself locally and never touch the byte path under test.

The leg asserts the lockfile actually resolves through the firewall before trusting
anything downstream — if it doesn't, the client is talking to the public registry and
every later assertion is vacuous. It also keeps a deliberate **negative control**: the
same `npm ci` under the default `allow-but-log` must SUCCEED, demonstrating the
side-door is real and that the enforcing leg's failure is caused by the gate rather
than by a broken fixture.

---

## OCI: `crane` is distroless — and the trap it sets for byte-count assertions

Added while settling the OCI blob deferral (issue #57, D79).

**`gcr.io/go-containerregistry/crane:latest` contains no shell.** Its entrypoint *is*
`crane`. So the natural way to count bytes fetched —

```sh
docker run --entrypoint sh crane:latest -c "crane blob --insecure $REF | wc -c"
```

— dies with `exec: "sh": executable file not found in $PATH`, docker exits non-zero,
**stdout is empty, and the byte count is 0.**

That is the dangerous part. A test asserting "no bytes came through" reads that zero as
**"the gate held"** and passes. On the first run of `e2e/oci_blob_test.go` it did
exactly that: reported green over a bypass that had already been reproduced by hand.

**Rules this produced:**

- Do **not** override the entrypoint. Pass `blob --insecure <ref>` as arguments and read
  crane's stdout on the host (`cmd.Output()`); a few MB buffered is fine.
- **A zero-byte result is only meaningful if you can prove the client ran.**
  `assertClientRan` fails loudly on `executable file not found`,
  `Error response from daemon`, `failed to create task` and `Unable to find image`,
  naming it as a broken harness rather than a security result.
- More generally: **any e2e assertion whose "safe" outcome is an absence** (no bytes, no
  request, no log line) needs a positive proof that the client executed. Absence is what
  a broken harness produces too.

**Also useful:** `crane blob` fetches a blob with **no manifest request at all**, which
is precisely why it settled the deferral. `crane manifest <ref>` is the way to re-derive
the pinned digests in that test when they drift.

---

## Driving a service that shells out to `git` (leg 23, #58 increment 3b)

Leg 23 is the first leg that exercises a **write** crossing the console/firewall boundary: an
operator POSTs to the console, the console commits to git and pushes, the firewall re-reads the
file, and a real pull is refused. Four traps cost a run each, and none of them is about the product.

**1. Git Bash rewrites leading-slash arguments into Windows paths.** On a Windows host,

```sh
git -C "$LIST_DIR" remote add origin /srv/lists-remote      # stores C:/Program Files/Git/srv/lists-remote
```

The stored URL then contains a colon, so git reads it as an **SCP-style address** and tries SSH:
`error: cannot run ssh: No such file or directory`. The symptom appears at *push* time, far from
the cause. Prefix the one command with `MSYS_NO_PATHCONV=1`; the variable is unset and harmless on
Linux. **The same applies to `docker run -e VAR=/abs/path`** — but *not* to paths inside a
compose YAML file, which the shell never sees.

**2. A bind-mounted repo is owned by another uid, so git refuses everything.** `detected dubious
ownership in repository at '/srv/lists'` — an error that names neither mounts nor users, and which
makes the feature look broken rather than misconfigured. The store declares **its own** repo safe
per invocation (`git -c safe.directory=…`), which is scoped and correct: the operator named that
repo. A **local-path remote is a second repository**, and a process should not vouch for one it
was never pointed at, so the *deployer* declares it — in the rig, a `.gitconfig` mounted at the
container's `HOME`. That is also what a real operator with a local-path remote must do.

**3. `git init --bare` without `-b main` makes the remote's `HEAD` useless.** It symrefs to
`refs/heads/master` while the console pushes `refs/heads/main`, so `git rev-parse HEAD` on the
remote resolves to nothing. Leg 23 reported *"the commit did not reach the remote"* while the push
had in fact landed. **Assert on the ref you pushed** (`refs/heads/main`), not on `HEAD` — the same
family as trusting an exit code: a plausible-looking handle that is not the one carrying the answer.

**4. Seed line endings deliberately.** `core.autocrlf=true` on a Windows host checks the committed
fixture out as CRLF; the containers that consume it are Linux, and one of them (the console)
commits it back. Seeding CRLF made a one-entry add report **+13/-11** — the host had stored LF, the
container stored what it found, and every line differed. Strip CR on copy *and* set
`core.autocrlf false` in the throwaway repo, so the bytes are identical on every host and the
audit-diff assertion means the same thing anywhere.

**Two rig properties worth keeping:**

- **The list files are a run-scoped copy, not the committed fixture.** Leg 22 used to edit
  `e2e/operator-lists/deny.txt` in place and restore it in a trap, so a failure at the wrong moment
  left the repo dirty. `.e2e-lists/` is built from the fixture and deleted on the way out — there is
  nothing to put back. It has to be a git repo anyway, because leg 23's console commits into it.
- **A count is not evidence.** `+2/-1` and `+13/-11` are different failures with different fixes
  (a missing trailing newline versus a line-ending flip), and the assertion could not tell them
  apart. It now prints the diff and the previous blob's trailing bytes when it fails.

⚠️ **A file-backed store commits what is IN THE FILE.** Leg 22 appends to the deny list on the host
and does not commit; the console's next write sweeps that pending edit into *its* commit, so the
one-line-diff assertion was measuring two changes. Leg 23 commits any pending work first. This is
real behaviour rather than a rig artifact — worth knowing when reading history, because a commit
subject can understate what its commit contains.

**The console image needs git, and the default one does not have it.** `console/Dockerfile` ships
`distroless/static`. The rig builds the opt-in `console-git` target (`build.target` in
`docker-compose.asyncfake.yml`); without it the console reports list editing DISABLED and the whole
leg degrades into "the page rendered" — which is why leg 23's first assertion is that editing is
actually *on*, before anything else is measured.

### Addendum 3 — the one that would have shipped: an atomic write is invisible through a FILE bind mount

The most valuable thing CI found, and the only one of the increment's defects that would have
reached a customer.

**The symptom.** Leg 23 passed every step — the console accepted the edit, committed it (`+1/-0`),
attributed it to the operator, pushed it to the remote — and then the gate went on serving the
package it had just been told to deny. "The write landed in git but never reached the gate."

**The cause is the interaction of two individually-correct decisions.** `writeFileAtomic` writes a
temp file and `rename`s it over the target, because `os.WriteFile` truncates first and a truncated
deny list is a window during which blocked packages are served. A rename replaces the directory
entry, so the path now points at a **new inode**. Meanwhile the compose file mounted the two list
**files** into the gate — and a file bind mount pins *that inode* into the container's mount table.
The gate re-read its path faithfully every 5 seconds and got the old inode every time.

So the atomicity that protects the file from a partial write is exactly what makes the update
invisible. Neither half is wrong; the combination is.

**Why it is the worst shape of failure.** Everything an operator can see says it worked. The console
reports "committed and pushed". `git log -p` is perfect and shows the entry. The audit trail — the
whole justification for D193 option (c) — is complete and correct. Only the enforcement is missing,
which is the one part nobody looks at until it matters.

**Why local runs could not find it.** Docker Desktop resolves file bind mounts by path rather than
pinning the inode, so the console's rename *is* visible there. Six consecutive local runs passed.
Linux pins, and Linux is what this deploys onto. This is the "reproduce on the CI platform" rule
with its usual sting: platform-only is not the same as not-a-bug — here the platform that behaved
"correctly" was the one that does not matter.

**Why leg 22 had missed it for two runs.** Leg 22 edits the list with `printf >> file`, which writes
**in place** and keeps the inode. A file mount sees that fine. The console is the only writer that
replaces the file, so only a leg driving the console could expose it — which is precisely the gap
tier 2 exists to cover, and an argument for driving the real writer rather than simulating its
effect.

**The fix is a deployment requirement, not a code change:** mount the list files' **directory** into
the gate, never the individual files. Then the gate re-resolves the name on each reload and picks up
the new inode. `docker-compose.asyncfake.yml` now mounts `./.e2e-lists` at
`/etc/yellowjack/lists` (still `:ro` — the gate reads, it never writes), and
`docs/CONFIGURATION.md` carries the requirement on the `FW_ALLOW_LIST` / `FW_DENY_LIST` rows where
a deployer will actually meet it.

**The general form, worth more than the instance:** *an atomic write and a file-level mount are
incompatible, and neither side reports the conflict.* Anything that replaces a file by rename —
config reloaders, secret rotators, certificate renewal — is invisible to a consumer holding a file
bind mount. `FW_UPSTREAM_AUTH_FILE` (`!148`) is re-read on a timer and has exactly the same shape;
**Addendum 4 below closes it**, with a rotation leg against a real container and a platform-independent structural guard on the mount shape.

### Addendum 4 — closing the same hazard on `FW_UPSTREAM_AUTH_FILE`, and why the e2e leg alone was not enough

Addendum 3 ended by noting that `FW_UPSTREAM_AUTH_FILE` (`!148`) has the identical shape and that it
was "worth checking how any deployment mounts it". This is that check, and the answer needed two
tests rather than one.

**The gap.** `grep -rn FW_UPSTREAM_AUTH e2e/ docker-compose*.yml` returned nothing. The credential
source was thoroughly unit-tested — rotation, the trailing-newline trim, the last-good retention —
and had never been run inside a container at all. That matters more here than for the lists, because
the consequence is worse in the direction that hides: the credential does not vanish, it goes
**stale**, so the gate keeps presenting an expired token and the upstream's refusals get attributed
to the registry rather than to us. And the safer the refresher, the more certainly it breaks — every
mechanism `!148` names as its interop point (Kubernetes projected tokens, Vault agent, a cron running
the AWS CLI) writes by temp-file-and-rename, precisely so a reader never sees a half-written secret.

**The behavioural half: `TestUpstreamCredentialRotation` (`e2e/upstreamcred_test.go`).** A recording
npm-shaped upstream (`e2e/credupstream/`) captures the `Authorization` header of every metadata probe
and serves it back on `/_seen`. The leg then asserts three things against a real container: the
credential reaches upstream at all (anti-vacuity — without it, the rotation step could pass on a
fixture that only ever saw one value); a credential rotated **by rename** reaches upstream with no
restart; and a **blanked** file does not degrade the gate to anonymous, which is `!148`'s security
property asserted end to end for the first time.

Three fixture decisions are load-bearing:

- **The upstream records, it does not enforce.** An upstream that 401s on the wrong token cannot
  distinguish "sent the old token" from "sent no token at all" — one 401 collapses stale rotation
  and silent degrade-to-anonymous into the same observation, and those are the two different
  failures the leg exists to tell apart.
- **`/_seen` is excluded from its own recording.** The test host polls it without a credential;
  counting those would inject phantom anonymous observations into the signal being asserted on.
- **A distinct package name per phase.** The firewall caches repo lookups, so re-pulling one name is
  served from cache and never reaches upstream — the leg would then assert on a probe that never
  happened and pass while measuring nothing.

**Why that leg is not sufficient on its own, and what the second test is.** The bug is
**platform-masked**: Docker Desktop resolves file bind mounts by path, Linux pins the inode. A leg
that mounted the file would therefore go green on the dev host — reproducing the mask instead of
catching it. So the mount shape is asserted **structurally** by
`TestReReadFilesAreMountedAsDirectories` (`mountshape_test.go`), which reads the compose text and
needs no daemon, no platform and no luck: it fails if any compose file mounts something *at* a path
it also uses as a re-read config value. It ships with three guards of its own — an anti-vacuity check
that reports how many volume entries and re-read paths it actually compared (a hand parser that
matched nothing would otherwise report a clean corpus), a permanent negative control that runs the
checker over the real broken document and fails if it stays quiet, and
`TestReReadPathVarsMatchTheCode`, which fails if someone makes another config file reloadable without
adding it — the one-line change that is obviously correct on its own and silently invalidates a
mount three files away.

**Two traps this cost, both worth recognising on sight:**

1. **A negative control can "pass" because the test never ran.** Sabotaging `fileCredentialEvery` to
   capture-once and re-running produced `PASS` — with an elapsed time *identical to the previous run
   down to the hundredth of a second*, which is the tell. `go test` had served a cached result: its
   cache key covers the `e2e` package's own sources, and the thing actually under test is a **Docker
   image built out of band**, which the cache knows nothing about. **Always `-count=1` when sabotaging
   an e2e leg**, or the control proves nothing and says so convincingly.
2. **`gofmt -l` exits 0 whether or not it lists a file.** `gofmt -l x.go && echo bad || echo fine`
   prints `bad` unconditionally. Use `gofmt -d` and read the diff — same family as the `waitci`
   pipe trap: a coarse signal shared by the pass and the impostor.

**And one scope hole worth remembering:** `scripts/pinned-images.sh` walks Dockerfile `FROM` lines
and compose `image:` lines, and nothing else. The first draft of this leg held its helper image as a
string constant in a `.go` file, where it was pinned only for as long as whoever wrote it remembered
to — outside every pin check the repo has. It is now a named `credwriter` target in
`e2e/credupstream/Dockerfile` (declared **before** the runtime stage, so an unqualified
`docker build` still produces the fixture), which puts it back under the #22 gate.

### Addendum 5 — a test helper that WAS the attack: forged approval records

Found 2026-09-07 while acting on a note left in memory during a compaction pass, not by a failing
test — nothing was failing, which is the point.

**The defect.** `lookupApproval` asked the approval service *"has a human ruled on X?"* and applied
whatever record came back **without checking it was about X**. The query string said what was
*asked*; nothing said what came *back*. So anything able to answer that request — a compromised or
misconfigured control plane, a mis-keyed cache or proxy in front of it, a replaced implementation —
could hand back a single approval and have it apply to **every package the firewall asked about**.
`lookupScore` had the identical hole, where the consequence is borrow-a-score (#10/D33) arriving
through our own control plane instead of through publisher metadata.

**Measured, not argued:** with the check removed, a stub answering every query with an approval for
`some-other-package` caused `GET /lodash` to return **248,354 bytes of the real packument** at
`FW_SCORE_THRESHOLD=8.0` with `FW_UNSCORABLE_POLICY=block` — a posture in which policy blocks
everything and only a human override can produce a 200.

**Why it survived so long: our own test fixture was the attack.** `startApprovalStub` in
`e2e/harness.go` replied with one fixed body to *every* `/v1/decisions` query. Any leg using it got
the whole world approved, so the missing check could never surface — the fixture and the defect
cancelled out. A real service cannot behave that way (both stores key on an exact-match
`TEXT PRIMARY KEY` and return that stored key), so the stub was not a simplification of the service,
it was a different and more permissive thing.

**The generalisable rule: a stub that is more permissive than the real service can hide a defect in
the code that consumes it, and the more convenient the stub, the more legs inherit the blind spot.**
Ask of every fixture: *what does the real thing refuse that this one accepts?* Here the answer was
"records about other packages", which was precisely the untested contract.

**What shipped:**

- Identity checks in both `lookupApproval` and `lookupScore`. They cannot break a correct service —
  the invariant already holds by construction — and a mismatch returns an error, which the callers
  already handle (`applyHumanRuling` falls back to policy; `resolveCachedScore` treats it as cold),
  so the blast radius equals an approval-service outage. Strict about the empty case too: an absent
  `package` field is not evidence the record is ours, the same reasoning as `!91`'s empty deny kind.
- `startApprovalStub` now answers **only** for the package it was started with and 404s otherwise,
  which is what the real service does. Use `startSelectiveApprovalStub` for mixed verdicts.
- A tier-3 leg (`TestAdversarialForgedApprovalCannotOpenTheGate`) that keeps the old fixed-body stub
  **as the adversary**, with a discriminator leg proving an honest approval for the same package
  still opens the gate — without which "blocked" is also just what an unreachable approval service
  produces.
