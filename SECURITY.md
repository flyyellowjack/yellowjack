# Security Policy

Yellow Jack is a package firewall: a gate that decides whether an open-source package
reaches a developer. A defect here does not just affect this program — it can let
through the thing it was installed to stop. We would rather hear about that from you
than from an incident.

## Reporting a vulnerability

**Report it privately through GitHub:** the repository's **Security** tab ->
**Report a vulnerability** (https://github.com/flyyellowjack/yellowjack/security/advisories/new). The report is
visible only to the maintainers, so details stay private while we work.

Do not put the details in a public issue, a pull request, or a commit message.

Please include whatever you have: what you did, what happened, what you expected, and
the configuration (the `FW_*` environment variables, ecosystem, and mode). A proof of
concept helps enormously and does not need to be polished — a `curl` invocation that
returns bytes it should not is a complete report.

## What we will do, honestly stated

This project currently has **one maintainer**, so these are the intentions of a small
team and not a contractual commitment:

| | Target |
|---|---|
| We acknowledge your report | within **3 business days** |
| We tell you whether we can reproduce it | within **10 business days** |
| We agree a disclosure timeline with you | once it is confirmed |

We would rather publish a real number we can meet than a fast one we cannot. If we are
going to miss one of these, we will say so rather than go quiet.

There is **no bug bounty** and no payment. We will credit you by whatever name you
choose in the fix's pull request and changelog, unless you would rather not be named.

## Disclosure

We ask for **coordinated disclosure**: give us 90 days from acknowledgement before
publishing, or less if we ship a fix sooner. If we disagree with your severity
assessment, we will say so plainly and you remain free to publish — this is a request,
not a condition, and we will not use legal threats against someone who reported a real
problem in good faith.

## What is in scope

The threat model is narrower than "anything bad that could happen". In scope:

- **Any way to get a blocked package's bytes delivered.** This is the most severe class
  by a distance. It includes reaching the artifact by a second route (a lockfile URL, a
  blob digest, an alternate object path), getting one package's verdict applied to a
  different package, and getting a verdict for one *version* applied to another.
- **Anything that turns a refusal into a delivery** — an unavailable scoring source, a
  malformed response, a truncated body, or a transient upstream error resolving toward
  allow.
- **Confidentiality of what passes through** — credentials, tokens, or package names
  leaking into logs, error text, or an outbound request.
- **Anything that lets a caller who is not an administrator cause work or change
  policy** on the control plane.
- Ordinary application vulnerabilities: injection, path traversal, SSRF from a
  registry-supplied value, denial of service through unbounded memory or connections.

## What is out of scope

Not because these do not matter, but because they are someone else's to fix and telling
you now saves you the effort:

- **A malicious administrator, or anyone who already holds privileged access to the
  deployment.** The gate is not designed to defend against the operator who runs it.
- **How the operator deployed it** — an exposed port, a permissive network policy, an
  unpatched host, a secret in their orchestration. The hardened configuration is
  documented; running a different one is the deployer's decision.
- **Findings in the tools we integrate** rather than in our use of them — OpenSSF
  Scorecard, deps.dev, OSV, the registries themselves. Report those to their
  maintainers; if our *use* of one is unsafe, that is in scope and we want it.
- **A package that scored well and was malicious anyway.** A score is a signal, not a
  guarantee, and disagreeing with it is a detection question, not a vulnerability. Open
  an ordinary issue — we do want those, just not privately.
- Missing hardening headers, version-disclosure banners, and similar scanner output,
  unless you can show how one leads to something in the list above.

## Supported versions

Pre-1.0 and under active development. Only the current `main` is supported; there are
no backports. When there are releases, this section will say which ones are maintained.
