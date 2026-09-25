# Yellow Jack

**A package firewall you run yourself.** Yellow Jack sits between your developers and the
public package registries (npm, PyPI, Maven Central, Docker/OCI) and decides, at the moment
a package is pulled, whether it is allowed in. Every decision is recorded with its reason,
and a refused developer is told why and what happens next.

> *"Your firewall stops at the package manager. Yellow Jack starts there."*

The name is the maritime **yellow jack**: the quarantine flag a ship flies so its cargo is
held and inspected before it may enter port.

## What it does

- **Known-malware list.** Packages and individual releases named in a malware advisory are
  refused before the registry is contacted. Build the list from the public OpenSSF Malicious
  Packages data with `scripts/build-malware-feed.py`.
- **Release cooldown.** A release younger than a configured age is held back, and the
  resolver is steered to the newest release old enough to trust. On by default for npm,
  PyPI and Maven (`FW_MIN_RELEASE_AGE_DAYS`).
- **Allow and block lists.** Your organisation's own decisions, by package or by exact
  release, re-read while the gate runs, and editable from the console.
- **OpenSSF Scorecard (optional).** Score each package's source repository on demand, on
  your own infrastructure, and hold packages below a threshold for a person to review.
  `FW_SCORECARD_MODE=off` turns scoring off entirely.
- **Decisions, recorded.** An append-only audit log of every allow and refusal, with the rule
  that fired, searchable in the console and exportable as NDJSON.
- **A console.** An overview of what the gate is doing, a queue of packages waiting for a
  person, every refusal explained, the policy in plain words, package lookup, request and
  download volumes, and sign-in with OIDC.
- **Report mode.** `FW_MODE=report` computes every verdict and refuses nothing, so the gate
  can be introduced without breaking a single build.
- **Zero egress to us.** The gate talks only to the registries you configure. No telemetry,
  no licence server, no call home. [docs/EGRESS.md](docs/EGRESS.md) says how to verify it.

**How clients reach it.** Package managers are configured to use Yellow Jack as their
registry (for example `npm config set registry http://yellowjack:8080`). It is a gate for
clients that use it: a client pointed straight at the public registry does not pass through
it, so pair it with egress rules if that must not happen.

## Quick start

**See it refuse something in about a minute:** [QUICKSTART.md](QUICKSTART.md). One binary, one
deny list, no account and no database.

**Run the whole thing, with the console:** [docs/REFERENCE_DEPLOYMENT.md](docs/REFERENCE_DEPLOYMENT.md)
puts the gate in front of a package registry with the console to read its decisions, and
[docs/DEMO.md](docs/DEMO.md) seeds a local stack with real packages so every console page has
something true to show.

```bash
go build -o yellowjack .    # the gate
./yellowjack                # an npm gate on :8080; FW_ECOSYSTEM=npm|pypi|oci|maven
```

## Documentation

- **[docs/SETUP.md](docs/SETUP.md)**: build, run and test; the container stack; serving the gate over HTTPS.
- **[docs/CONFIGURATION.md](docs/CONFIGURATION.md)**: every setting, with its default.
- **[docs/REFERENCE_DEPLOYMENT.md](docs/REFERENCE_DEPLOYMENT.md)**: a deployment you can run end to end.
- **[docs/FAILURE_MODES.md](docs/FAILURE_MODES.md)**: every way the gate can fail, what the developer sees, and the test that keeps each row true.
- **[docs/EGRESS.md](docs/EGRESS.md)**: exactly what the gate connects out to.
- **[docs/CONFIG_SURFACE.md](docs/CONFIG_SURFACE.md)**: where settings come from, and what can never influence them.
- **[docs/MODE_MATRIX.md](docs/MODE_MATRIX.md)**: what each combination of modes does.
- **[docs/CLIENT_TRUST.md](docs/CLIENT_TRUST.md)**: making clients trust a private CA.
- **[docs/TEST_TIERS.md](docs/TEST_TIERS.md)** and **[docs/E2E_TESTING.md](docs/E2E_TESTING.md)**: how the tests are organised and run.
- **[SECURITY.md](SECURITY.md)**: how to report a vulnerability.
- **[CHANGELOG.md](CHANGELOG.md)**: what has shipped.

## Repository layout

```
*.go                 the gate (proxy, decision engine, one Ecosystem per registry type)
approval/            control plane: approval queue, audit log, scores (Postgres)
console/             the web console
scheduler/ scanner/  on-demand OpenSSF Scorecard scans, one short-lived container each
cache/               optional caching front door
deploy/              Helm chart and the reference deployment
e2e/                 end-to-end tests with real package managers
docs/                operator and contributor documentation
```

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Every change is tested at three tiers (unit, a real
client, and an attacker's view); [docs/TEST_TIERS.md](docs/TEST_TIERS.md) explains what that means.

## License

**GNU Affero General Public License v3.0** (see [LICENSE](LICENSE)). AGPLv3 also covers
networked use, so modifications stay open when someone runs Yellow Jack as a hosted service,
not only when they distribute the binary. © 2026 Yellow Jack.
