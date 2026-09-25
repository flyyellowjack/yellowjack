# `fakeupstream` — a crafted registry that tells a lie (D39 e2e)

This is a static file tree served by `python -m http.server` (see
`docker-compose.verifyrepo.yml`) and used as the firewall's **upstream registry** in
the local-mode borrow-a-score e2e (`e2e/verify_repo_local.sh`).

## Why a fake upstream, and why this is the *faithful* rig

The borrow-a-score attack is a **publisher-controlled metadata lie**: an attacker
publishes a package whose `repository` / `project_urls` / `<scm>` points at a healthy,
high-scoring project it does not own, so the firewall scores that project instead of
the attacker's. The attacker controls **the package metadata**, not deps.dev's own
package→project record — which is exactly the asymmetry D33/D39 exploits to catch them.

So the rig crafts the side the attacker controls (this tree) and leaves the other side
**real**: the firewall verifies against the live `api.deps.dev`. We cannot publish a
malicious package to npmjs.org to test this, and a fake deps.dev would test our own
mock instead of the actual cross-check.

The trick is to reuse names deps.dev **already has a `SOURCE_REPO` record for**, then
have this tree claim a *different* repo. Confirmed live records (2026-07-25):

| ecosystem | package | deps.dev SOURCE_REPO | what this tree claims | expected |
|---|---|---|---|---|
| npm | `lodash` | `github.com/lodash/lodash` | `github.com/expressjs/express` | **mismatch → blocked, no scan** |
| npm | `left-pad` | `github.com/stevemao/left-pad` | `github.com/stevemao/left-pad` | match → scan launched |
| pypi | `six` | `github.com/benjaminp/six` | `github.com/pallets/flask` | **mismatch → blocked, no scan** |
| pypi | `certifi` | `github.com/certifi/python-certifi` | `github.com/certifi/python-certifi` | match → scan launched |
| maven | `com.google.guava:guava` | `github.com/google/guava` | `github.com/junit-team/junit5` | **mismatch → blocked, no scan** |

## The second fixture shape: no record at all (D36, issue #18)

The table above all relies on deps.dev holding a record to **contradict**. The other —
and much more common — case is the claim deps.dev can neither confirm nor contradict,
because it has never heard of the package. That is the fresh-typosquat profile, and up
to D36 it degraded open: nothing contradicted the claim, so the claimed repo was scored.

`yj-unverifiable-d36` covers it, and inverts the trick above: the name is deliberately
published **nowhere**, so live deps.dev genuinely 404s it — no mock required.

| ecosystem | package | deps.dev record | what this tree claims | expected |
|---|---|---|---|---|
| npm | `yj-unverifiable-d36` | *none (404)* | `github.com/lodash/lodash` | **durably unverified → blocked, no scan** |

Keep this name unpublished. If someone ever publishes it to npmjs.org and deps.dev
ingests it, the fixture silently stops testing the no-record path.

## Why the tree is so small

Only the paths the **firewall itself** fetches to resolve a source repo need to exist:

- npm → `/{pkg}/latest`
- pypi → `/pypi/{pkg}/json`
- maven → `/{group}/{artifact}/maven-metadata.xml` + the release POM

The *client's* request (`npm install`, `pip install`, `mvn dependency:get`) is answered
by the **firewall** with a 403 block or a 503 pending and is never proxied upstream, so
no tarballs, wheels, or jars are needed. If you ever make one of these packages
allowable, you will need to add the artifact bodies too.

## Defanging convention (#46)

Every host a fixture in this tree names is either **unresolvable by construction** —
`.invalid`, `.example`, `.test`, an RFC 5737 address, a single-label compose service name
such as `fakeupstream` — or **listed with a reason** in [`e2e/fixture-hosts.txt`](../fixture-hosts.txt).
This tree's claims name real GitHub repos on purpose: the borrow-a-score check is only a
check because deps.dev's record of the *real* repo contradicts the lie, and a claim of
`example.invalid` would test our own mock instead. Those names are the documented sentinels;
nothing here fetches them. `sh scripts/dev.sh vet` runs `scripts/fixture-hygiene.sh`, which
fails on any other host, on an allowlist entry without a reason, and on an entry no fixture
uses. The shipped images are asserted fixture-free by `e2e/hardening.sh` leg 1b.
