# The three-tier test structure (mandatory for every feature)

Standing convention. **Every feature is tested at all three tiers before
it is called done.** The tiers are not degrees of thoroughness you stop at when tired —
they answer three different questions, and a green tier says nothing about the other two.

The structure combines three framings at once, because each catches what the others miss:

- **scope** — how much of the system is really running
- **audience** — who is driving it
- **behaviour** — what you throw at it

| | Tier 1 | Tier 2 | Tier 3 |
|---|---|---|---|
| **Scope** | in-process, mocked deps | the real container + real deps | the real container + real upstreams |
| **Audience** | developer | **customer** | **attacker** |
| **Behaviour** | happy path + edge cases | an honest, real workflow | evasion, malformed input, abuse |
| **Where** | `*_test.go` | `e2e/*_test.go`, `e2e/*.sh` rigs | `e2e/adversarial_test.go`, `mutation_test.go` |
| **Cost** | milliseconds, offline | minutes, needs Docker + network | minutes, needs Docker + network |
| **Answers** | "is the logic right?" | "does it work the way it's sold?" | "can someone defeat it?" |

The behavioural progression **happy path → edge cases → adversarial** runs *inside* each
tier as well as across them. The emphasis shifts (tier 1 is mostly happy/edge, tier 3 is
all adversarial), but no tier is exempt: a parser's unit test should still be fed hostile
input, and an e2e leg should still cover the boring install.

---

## Tier 1 — unit / in-process

Fast, offline, mocked dependencies. Runs on every `go test ./...`.

- Cover the happy path, then the **edge cases**: empty, huge, malformed, duplicated,
  concurrent, unicode, missing fields, partial failure — every shape the real input
  actually takes. (`repoField` exists because npm's `repository` field has four.)
- Assert on **absence** as well as presence when the meaning depends on it.
- **Every non-trivial check needs a negative control.** A check that can only print green
  converts an unknown into false confidence.

Tier 1 runs against mocks, so it proves the logic you wrote matches the logic you meant —
and nothing whatsoever about the deployed system.

## Tier 2 — customer-shaped e2e

Drive it **exactly how a customer would**: a real package manager (`npm`/`pip`/`docker`/
`mvn`) in a throwaway container, pointed at the firewall running as a container, doing an
honest install. `docs/E2E_TESTING.md` holds the accumulated traps — read it before
touching the request path or adding an ecosystem.

- Real clients, not synthetic HTTP: the client's own behaviour is part of the test
  (`npm ci` reads `resolved` URLs; pip needs `PIP_TRUSTED_HOST`; maven needs a mirror in
  `settings.xml`; `crane blob` skips the manifest entirely).
- Assertions must be **drift-robust** — exit code plus the presence of allow/block
  decisions, never a specific dependency's score.
- Make sure the leg exercises what it claims: `api` mode with a permissive policy proves
  plumbing, *not* scoring.

**Tier 2 structurally cannot find a bypass.** An honest client never sends a hostile
request, so no amount of customer-shaped testing answers the attacker question. That is a
gap in the *question*, not in the tests.

## Tier 3 — adversarial

Drive it **the way an attacker would**. For a security product this is the tier that
tests the actual promise, so it is not optional and not a nice-to-have.

> **Rule: anything found here is fixed immediately, or filed as a GitLab issue, before
> moving on.** A known bypass is never left undocumented.

Method — each of these was learned by getting it wrong:

- **Write the attack onto the socket by hand.** An HTTP client library is entitled to
  normalize what it sends; a normalizing client will quietly repair your attack and then
  report a pass. Use the raw `net.Dial` helper (`rawGet`), not `http.Client`.
- **Assert on content, not status.** Real bypasses return a perfectly ordinary `200`.
  Check for the payload itself — packument markers, gzip magic, installable links, byte
  counts.
- **Check WHO refused, not just that something did.** An upstream rejects a hand-written
  request for its own reasons — Docker Hub answers an unauthenticated blob GET with 401
  and an unknown path with 404 — and a relayed-then-rejected request is indistinguishable
  from a gated one on status and body alone. Assert on something only *we* emit
  (`X-Yellowjack-Reason`, a decision line in the log). Without it, the suite scores the
  registry's auth challenge as its own success while the request was never gated at all.
  Learned on #57, where every OCI evasion "passed" before this assertion existed.
- **Use a real client for the compatibility leg.** Hand-written sockets are right for the
  attack legs, where client normalization would repair the attack — and *wrong* for the
  leg that proves honest traffic still flows, where not doing the client's auth dance
  produces a false failure that invites someone to "fix" a working firewall.
- **Add a discriminator.** "Nothing came back" is also what a *broken* system produces,
  so a refusal is not by itself a defence. Re-run the same attacks against a deliberately
  **permissive** config whose honest path demonstrably serves real bytes: a refusal there
  can only be the guard you just added.
- **Pin the compatibility surface.** The cheapest route to a green adversarial suite is
  to break the product — so assert that real client traffic still flows, in the unit
  table *and* through the container.
- **Negative control, always.** Short-circuit the defence, rebuild, re-run, and confirm
  the suite fails with the real payload.
- **Test at the strictest supported configuration.** If the attack still works there,
  say so loudly — that is the headline, not a footnote.

### Attack catalogue — start here, extend as we learn

| Class | Concretely | Seen in |
|---|---|---|
| **Identity divergence** | the identity *we* parse vs the one the *upstream* resolves | #59 |
| Path normalization | `//pkg`, `/a/../pkg`, trailing `//`, `.` segments | #59 |
| Encoding | `%2e%2e`, `%2f`, `%2d` to hide a structural marker, mixed case (`%2D`) | #59 |
| **Case-folded structural tokens** | `/V2/`, `/Blobs/` — the *protocol* keywords, not the encoding. A parser matching them case-sensitively stops recognising the request, and an unrecognised request is relayed **ungated** | #57 |
| Confused deputy | gate on an **allowed** decoy; upstream serves the **blocked** target | #59 |
| **Alternate route to the same bytes** | metadata gated but artifact not; index gated but blob not; lockfile `resolved` URLs | #11, #57 |
| Allowlist-shaped gates | the gate keys on extension/suffix, so other artifact types walk past | #56 |
| **Inference from an attacker-chosen name** | the gate decides *what a path is* from the filename — "extensions are alphabetic" (`.tar.bz2`), "a digit-initial name is a version dir" (`2FA.jar`), "a trailing slash means a directory" (`foo.jar/`), a prefix match (`maven-metadata.xml.evil.jar`). The publisher picks the name, so it is never evidence | #56 |
| Verdict downgrade | mangle the name until it is *unknown*, so a **hard** deny softens to a policy default | #59 |
| Audit evasion | does the bypass appear in the decision log at all? A silent bypass is worse than a loud one | #59 |
| Resource abuse | unbounded connections, cache blowup, huge or slow responses | #1, #15 |

### The threat model

The cooperative-client model **does not assume the client is honest**. The realistic
attackers are:

1. **A poisoned or compromised dependency** — `npm ci` fetches exactly the `resolved` URL
   recorded in the lockfile, so a transitive dep can carry any request shape it likes.
2. **A postinstall script** fetching from the configured registry.
3. **An insider** deliberately evading policy.

"You would have to craft that request by hand" is **not** a mitigation — a lockfile
crafts it for you.

---

## Why this is written down

Issue #59 was found the first time anyone drove the firewall as an attacker. Every tier-2
leg was green, and had been for months, while a blocked package could be pulled **in
full** — the real packument and the real tarball — by respelling the URL, at the
strictest configuration we ship. The tests were not failing. They were never asked the
question.

Related: `docs/E2E_TESTING.md` (tier-2 traps, per-ecosystem lessons), `CLAUDE.md`
("codify, don't re-derive").