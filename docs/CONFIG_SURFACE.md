# Config surface — where settings come from, and where they can never come from

This document is the deliverable of issue #38. It states what a deployer can rely on about
how Yellow Jack is configured, and — more importantly — what cannot influence it.

It is kept honest by tests, not by review: see [Assertions](#assertions).

---

## The invariant, worded exactly

> **Yellow Jack reads configuration from the process environment only.** It does not read,
> discover, or execute any file from the current working directory, the request path, or any
> location influenced by a client or by inspected content.

Two consequences a deployer can rely on:

- **The directory you start the process in does not matter.** Nothing is discovered there. A
  repository being scanned cannot carry a file that changes how it is judged.
- **A package we inspect cannot reach our configuration.** Package names, versions, repo URLs
  and artifact contents are data. None of them is ever turned into a path we open.

## Why this is written down rather than assumed

**CVE-2025-64726** — a competing package firewall (`sfw`, before 0.15.5) shipped arbitrary
code execution by exactly this route:

> An attacker places a malicious `.sfw.config` in a project directory. Running the tool there
> loads that file and populates environment variables directly into the Node.js process — so
> `NODE_OPTIONS=--require …` executes attacker-controlled code **before the tool's security
> controls activate**, bypassing its malicious-package detection entirely.

Read the ordering: the payload ran *first*. The gate could not have caught it, because the
gate was not up yet. **A firewall that can be disarmed by the thing it is inspecting is worse
than no firewall, because it is trusted.**

Yellow Jack's architecture is on the right side of this by construction — env-only config, no
durable state, and a *server that is pointed at* rather than a wrapper that runs inside a
developer's working directory. But "we happen to be built that way" is not a guarantee.
Someone adding a convenience `.yellowjack.yml` loader would get a green test suite, and it
would look like a feature.

## What the process actually reads

Audited 2026-08-08, across all production (non-test, non-`reference/`) code:

| Source | Count | Notes |
|---|---|---|
| Runtime file reads | **0** | no `os.Open`/`os.ReadFile`/`ReadDir`/`ParseFiles` anywhere in shipped code |
| `//go:embed` templates | 5 | console HTML, resolved at **compile** time against the source tree — never from the runtime cwd |
| Environment variables | ~30 `FW_*` | the entire config surface; see [SETUP.md](SETUP.md) |
| Subprocess launches | 2 | `scheduler/launcher.go` (docker), `scanner/scorecard.go` (scorecard binary) |

### Subprocess environments

This is the CVE's actual mechanism, so it is stated separately.

- **`scheduler/launcher.go` passes an explicit allowlist** — `SCANNER_REPO`,
  `SCANNER_SINK_URL`, `GITHUB_TOKEN`, `SCANNER_SCAN_TIMEOUT_SECS` — as individual `-e` flags.
  It does **not** forward its own environment. Values are passed as `argv`, never through a
  shell, so a hostile repo URL is one env var's *value* and cannot become a new variable.
- **`scanner/scorecard.go` inherits its environment** (`append(os.Environ(), …)`). That is the
  one place, and it is allowlisted with its reason: the scanner runs inside its own run-once
  container, whose environment *is* the explicit list above. It inherits a controlled env, not
  the firewall's and not anything a client set.

Any **new** inheritance fails the build.

## If we ever want file-based config

A plausible future request. The safe shape is decided here, in advance, so it is not decided
under deadline:

- an explicit `--config /absolute/path` **given by the operator**
- never discovery, never a relative path, never a location influenced by inspected content
- and the loader must not populate the process environment — the CVE's payload rode in on
  exactly that step

## Assertions

In `configsurface_test.go`:

| Test | What it pins |
|---|---|
| `TestConfigIgnoresWorkingDirectory` | starts in a directory seeded with `.sfw.config`, `.yellowjack.yml`, `.env`, `config.json` … and proves the loaded `Config` — and whether loading errors at all — is identical to an empty directory |
| `TestNoRuntimeFileAccessInProductionCode` | no runtime file read in shipped code; no `os.Environ()` forwarding outside the one allowlisted file |
| `TestEnvInheritAllowlistIsHonest` | the allowlist cannot outlive its subject — an entry naming a file that no longer inherits is itself a failure |

**Negative controls** (a check that has only ever passed proves nothing — all three were run,
observed red, and reverted):

| Perturbation | Result |
|---|---|
| add a `.yellowjack.yml` cwd loader to `loadConfig` | **red** — both the behavioural test and the source check |
| add `os.Environ()` to `proxy.go` | **red** — names the file and the line |
| make `scanner/scorecard.go` stop inheriting | **red** — the stale allowlist entry is reported |

The first control also improved the test: its first run failed with `"is not a number"` rather
than naming the invariant, because the seeded load aborted inside a helper. The comparison now
covers the *error* as well as the value, and loads the clean directory **first** — a
CVE-shaped loader sets environment variables process-wide, which would otherwise contaminate
the baseline and make the two directories agree for the worst possible reason.

### The source scan's scope, and how we learned it

The first CI run of `TestNoRuntimeFileAccessInProductionCode` **failed**, reporting `os.Open`
in `pgx`, `x/mod` and `x/telemetry`. CI points `GOMODCACHE` at `.gocache/` **inside the repo**,
so walking from `.` descended into every vendored dependency's source. It passed locally only
because that directory does not exist here.

The walk now skips **any dot-directory** and **any directory carrying its own `go.mod`** (a
different module is not our source, whatever it is called). Verified by reproducing CI's exact
condition locally — a fake cached module under `.gocache/pkg/mod/` — and confirming it trips
the check with *both* guards removed and passes with either.

That failure is also why the test asserts `scanned >= 20` and that specific files were
reachable. **A security check that silently scans nothing reports green forever**, and skip
rules broad enough to exclude a module cache make that a live risk rather than a theoretical
one. Proven able to fail by making the walk read no files at all.

## Related

- [EGRESS.md](EGRESS.md) — the sibling invariant (#27): what we connect *out* to.
- Issue #19 — startup config validation; this is the security half of the same surface.
- Issue #51 — the config-surface *budget*: ~30 knobs is a number to defend, not to grow.
