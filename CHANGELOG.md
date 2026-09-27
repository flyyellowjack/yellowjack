# Changelog

All notable changes to Yellow Jack are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html). [docs/RELEASING.md](docs/RELEASING.md)
says what a patch release may change and what each release publishes.

> This is kept honest by test, not by intention: `changelog_test.go` fails if this
> file claims a version that has no tag behind it, fails if a tag exists with no
> section here, and fails if a package ecosystem the firewall gates goes unmentioned.
> 0.1.0 is the first release; nothing earlier was back-filled.

---

## [Unreleased]

## [0.1.0] - 2026-09-27

The first release. It publishes the gate, the control plane and the console as
`ghcr.io/flyyellowjack/yellowjack-{firewall,approval,console}:0.1.0`, each built for
linux/amd64 and linux/arm64 against Go's certified FIPS 140-3 module, and the Helm chart as
`oci://ghcr.io/flyyellowjack/charts/yellowjack` at 0.1.0, pinned to those images by digest:

```
helm install yellowjack oci://ghcr.io/flyyellowjack/charts/yellowjack --version 0.1.0
```

**Read this if you ran an earlier build from `main`:** a bare package name on the allow list
outranks a known-malware advisory for every release of that package (D367). Builds before
this release honoured only a pinned release (`name@version`) over an advisory. Every such
pull is logged as `[administrator-override]` and carries an `override` field in the audit
record, and the operator's deny list still wins. If you mean one release, pin it.

The gate is built and runs. What follows is grouped by what an operator or a
developer would notice, not by merge order.

### Added

- **A package firewall for four ecosystems — npm, PyPI, Maven and OCI.** The client
  points at Yellow Jack (one `.npmrc`/`pip.conf`/`settings.xml`/registry line), and
  each fetched package is allowed through to the real registry or refused with a
  reason. Transitive dependencies are covered for free: they pass the same boundary.
- **Known-malware refusal (layer 1).** An operator-supplied advisory feed is checked
  *before* anything else and needs **no network at all**, so it keeps enforcing
  through an upstream outage, a rate limit, or in an air-gapped deployment.
  Version-specific advisories are enforced for PyPI, OCI and Maven.
- **OpenSSF Scorecard as the scoring gate**, with the score cached in two tiers and a
  configurable freshness bound so a stale score cannot be served indefinitely.
- **Artifact byte gating.** Refusing a package's *metadata* is not enough — a
  lockfile install, a `crane` blob pull or a chosen filename can fetch the bytes
  directly. Those routes are gated too, per ecosystem.
- **Quarantine and human review.** Packages that cannot be scored are held rather
  than guessed at, with an approval queue an operator works through.
- **A release cooldown.** A release younger than `FW_MIN_RELEASE_AGE_DAYS` is held
  back and the resolver is steered to the newest release old enough; on by default
  for npm, PyPI and Maven. The gate's log names every release it held, one line per
  release, on npm and PyPI alike.
- **Operator allow and block lists**, by package or by exact release, re-read while
  the gate runs and editable from the console.
- **Report mode** (`FW_MODE=report`): every verdict computed and logged, nothing refused.
- **An operator console**: an overview of what the gate is doing, the approval queue,
  every refusal explained, the policy in force in plain words, a per-package lookup,
  request and download volumes, and an audit view of every verdict. Sign-in with OIDC
  or a single shared credential.
- **Deployment**: a Helm chart, a Docker Compose stack, and a reference deployment
  with a package registry in front.
- **A structured, exportable decision record** (NDJSON), carrying not just the verdict
  but the inputs that produced it — the score, the threshold it was weighed against,
  and a fingerprint of the policy in force — so a verdict is reproducible by someone
  who was not there. Where the request named a release, the record names it too
  (`version`), so "which releases of this package did we refuse" is a query, not a
  text search.
- **An ordered, first-match-wins policy engine** whose default is to reject, reported
  back to the console by the engine itself rather than described separately.

### Security

- Every base image is pinned by digest, and a gate fails the build if one is not.
- Services run as a non-root user on a read-only root filesystem, under an
  unmapped UID, and require no writable host directory. Asserted, not assumed.
- The scheduler's result sink takes a per-scan capability token, so a forged score
  cannot be posted into a live scan.
- Every image is built against the certified FIPS 140-3 Go Cryptographic Module and starts
  in FIPS mode. Each service prints whether it is on at startup (`docs/SETUP.md`, "FIPS 140-3
  mode", which also lists what is not covered).

### Known limitations

Stated here rather than discovered later:

- **The approval service has no authentication.** Its mutating endpoints are open to
  anyone who can reach the port, and it binds every interface by default. The
  mechanism is an open architecture decision; the exposure is enumerated in
  `approval/exposure_test.go` and in `docs/CONFIGURATION.md`.
- **Scorecard scores the source repository, not the published artifact**, so a
  poisoned tarball from a healthy repo is not caught by the score alone.
- **Enforcement is cooperative.** A developer who removes the registry line is not
  gated. Closing that takes network egress rules; TLS interception is not part of
  this edition.
- **No released version.** Nothing here has been through a release process, and the
  configuration surface may still change.

[Unreleased]: https://github.com/flyyellowjack/yellowjack/commits/main
