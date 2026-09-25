# `fakescanner` — a deterministic `scorecard` for the async e2e (issue #55)

This fixture replaces the third-party OpenSSF `scorecard` binary inside the run-once
scanner container with a tiny stdlib-only Go program that reports a score **chosen at
image build time**. It exists to fix a gate that was green for the wrong reason.

## The bug it fixes

`e2e/async_local.sh` asserts the D18 async contract: cold pull → `503` pending → one
background scan → durable L2 write → the next pull is *decisive*. Until now it got its
decisive answer like this — quoting the rig's own header:

> 2. ONE background scan runs and writes L2 (here: the negative marker, **because
>    scorecard has no token and fails auth** → "unscorable")

That was deliberate, and it is the problem. `GITHUB_TOKEN` appears **nowhere** in
`.gitlab-ci.yml`, so the required `e2e-local-async` job always ran tokenless, the real
`scorecard` binary always failed authentication, and leg 3's `403` was produced by
**scanning being broken**. Three consequences:

- The gate could not distinguish "the async pipeline works" from "every scan fails".
- Running the rig **with** a real `GITHUB_TOKEN` made it **FAIL** 3 legs — the healthy
  configuration was the red one.
- The day someone fixed scanning in CI, a required gate would have gone red for a
  correct change.

This is the CLAUDE.md anti-pattern verbatim — *"watch out, X silently passes for the
wrong reason"* — sitting in the async workstream's own verification rig.

## Why fake the scorecard binary and nothing else

The async contract is a claim about **our wiring**: firewall → scheduler → launched
container → result sink (+ its capability token) → approval Postgres L2 → firewall →
verdict. It is not a claim about Scorecard's scoring, which is a third-party tool with
its own tests. So the fixture makes the one component we neither own nor need to test
deterministic, and leaves **everything else real** — including the real scanner binary,
which this image inherits `FROM yellowjack-scanner:dev` rather than rebuilding, so the
code under test is byte-identical to what ships.

It also removes the rig's dependence on GitHub availability and rate limits, which a
required gate should never have had.

## What it makes possible that the old rig could not prove

Because the score is now a **chosen number** rather than an accident, the rig asserts
the pipeline end-to-end in the *positive* direction:

- `lodash` scores **9.0** → the L2 row contains that exact score → the next pull is
  `200 allowed`. This proves a real numeric score traversed scanner → sink → scheduler
  → L2 → firewall → `decideByScore`. **The old negative-marker leg proved none of
  that** — a marker only records that *something* failed.
- `express` matches `FAKE_UNSCORABLE_SUBSTR` → the fake exits non-zero → the durable
  **negative marker** path is exercised → `403` under fail-closed. This keeps the
  coverage the old rig had, but now reached on purpose instead of by auth failure.

## Negative control (run this before trusting the rig)

A rig that can only print PASS is worse than doing it by hand. Prove it can fail:

```sh
FAKE_SCORE=1.0 bash e2e/async_local.sh
```

`1.0` is below the rig's `FW_SCORE_THRESHOLD=5.0`, so the allow leg **must** fail. The
verified output (exit status `1`):

```
FAIL: post-scan lodash pull code=403 (want 200 allowed at score 1.0)
FAIL: post-clear pull code=403 (want 200: L1 should still mask the cleared L2 row)
ASYNC E2E: FAIL
```

The first line is the control's target. The second is a cascade — leg 7a re-pulls the
same package and inherits the same `403` — and is expected; it is not a second defect.

If that command **passes**, the allow assertion is not testing what it claims and the
rig is lying. The verified result is recorded in `docs/BUILD_LOG.md`.

## Configuration

Baked into the image as build args, because the scheduler's launchers forward only a
fixed env set (`SCANNER_REPO`, `SCANNER_SINK_URL`, `GITHUB_TOKEN`, the timeout) to the
scanner container — per-scan configuration is not available. **The image is the test
configuration.**

| Build arg | Default | Meaning |
|---|---|---|
| `FAKE_SCORE` | `9.0` | aggregate score reported for any repo not matched below. Default is above the rig's `5.0` threshold so the success path ends in a real allow |
| `FAKE_UNSCORABLE_SUBSTR` | `expressjs/` | any repo path containing this exits non-zero, reproducing "Scorecard ran but could not score this repo" |
| `FAKE_PARTIAL_SUBSTR` / `FAKE_PARTIAL_ERRORED` | `chalk/chalk` / `License,CI-Tests,Contributors` | a PARTIAL report (#133, D271): all 18 documented checks, the named ones at `-1`, **and exit status 1**, exactly as the real binary behaves when a check hits a runtime error. Low-weight checks only, so the firewall's required-check floor must ACCEPT it (leg 29, half 1) |
| `FAKE_PARTIAL2_SUBSTR` / `FAKE_PARTIAL2_ERRORED` | `debug-js/debug` / `Dangerous-Workflow,License` | the same shape with a REQUIRED check errored, so the floor must refuse it and name the check (leg 29, half 2). Same 15-of-18 count as the first: the two halves exist because a count cannot tell them apart |

The fake exits `2` on an invocation it does not model (missing `--repo`, a `--format`
other than `json`, an unparseable `FAKE_SCORE`) rather than guessing. If
`scanner/scorecard.go` ever changes how it invokes the binary, this fixture fails loudly
instead of quietly testing something else.

## What this fixture does NOT cover

Scorecard's own behavior — that a real scan of a real repo produces a sensible number,
and that our parser handles the real output shape. That belongs to `scanner`'s unit
tests (which feed recorded Scorecard JSON through `scan()`), not to a pipeline gate.
If you want a live end-to-end sanity check, run the rig with `SCHEDULER_SCANNER_IMAGE`
left at `yellowjack-scanner:dev` and a real `GITHUB_TOKEN` — but do not make that a
required gate, for all the reasons above.
