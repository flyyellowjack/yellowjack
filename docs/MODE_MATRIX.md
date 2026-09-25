# Mode coverage matrix

**Generated — do not edit by hand.** Regenerate with `sh scripts/mode-matrix.sh --update`.

Every row is a real request driven through a real proxy against the committed
fake upstreams, not a reasoned expectation. `artifact_fetched` records whether the
UPSTREAM was asked for the artifact — a denial with `artifact_fetched=true` means the
bytes left the upstream regardless of what the client was told.

Cells: **3840**.

## What each ecosystem does per request kind

| ecosystem | request kind | verdicts observed | bytes ever delivered while ungated |
|---|---|---|---|
| npm | metadata | allowed×135, hard-deny×24, soft-deny×81 | — |
| npm | bytes | allowed×101, hard-deny×16, soft-deny×43, ungated×80 | **80** |
| npm | bytes-alt | allowed×101, hard-deny×16, soft-deny×43, ungated×80 | **80** |
| npm | infra | ungated×240 | — |
| pypi | metadata | allowed×135, hard-deny-via-yank×24, soft-deny-via-yank×33, soft-deny×48 | — |
| pypi | bytes | allowed×135, hard-deny×24, soft-deny×81 | — |
| pypi | bytes-alt | allowed×135, hard-deny×24, soft-deny×81 | — |
| pypi | infra | ungated×240 | — |
| oci | metadata | allowed×132, hard-deny×18, soft-deny×90 | — |
| oci | bytes | allowed×102, hard-deny×12, soft-deny×46, ungated×80 | **80** |
| oci | bytes-alt | allowed×102, hard-deny×12, soft-deny×46, unavailable×16, ungated×64 | **64** |
| oci | infra | ungated×240 | — |
| maven | metadata | unavailable×48, ungated×192 | — |
| maven | bytes | allowed×135, hard-deny×24, soft-deny×81 | — |
| maven | bytes-alt | allowed×135, hard-deny×24, soft-deny×81 | — |
| maven | infra | ungated×240 | — |

## Deliberately not covered

- **FW_MALWARE_LIST** — D172 layer 1 short-circuits Evaluate AHEAD of every mode-sensitive step (backoff, repo resolution, scoring), so its verdict cannot vary across the axes this matrix drives -- adding a 2x axis would double the committed cells to prove the same block 3,840 times. That is a claim, so it is RUN: TestKnownMalwareVerdictIsIndependentOfEveryMode sweeps unscorable x unverified x byte-gate x threshold and asserts one verdict throughout. If that test ever fails, this exclusion is void and the axis belongs in the matrix.
- **FW_MAX_RELEASE_AGE_DAYS** — an independent PyPI-only policy axis (D22) that does not interact with the verdict classes here; covered by its own unit tests.
- **FW_MIN_RELEASE_AGE_DAYS** — the cooldown (#26) -- the same PyPI-only index-filtering axis as FW_MAX_RELEASE_AGE_DAYS and its inverse; it yanks entries rather than changing a verdict class, so it does not move a matrix cell. Covered by its own unit tests, including a negative control and the both-bounds-at-once case.
- **mode=local** — local mode scores via the scheduler, which launches a run-once scorecard CONTAINER per scan; it cannot run in-process. Covered instead by e2e/async_local.sh + docker-compose.e2e.yml, which exercise pending/cold-scan.
- **real clients** — npm/pip/docker/mvn behaviour (lockfile replay, resume, cached manifests) cannot be proven by an in-process request. Covered by the live matrix in e2e/ — notably e2e/oci_blob_test.go and e2e/npm_test.go.
- **third and further artifact routes** — each ecosystem drives TWO byte routes (issue #63), not every one. Maven alone has ten alternate packagings that bypassed the pre-#56 gate; the matrix drives .jar and .module. Two routes make the CLASS measurable — a gate that holds on one route and not another — which one route could not; enumerating every filename is the unit twins' job (bytegate_test.go, maven_bytegate_test.go, oci_bytegate_test.go), where a case costs one line instead of 192 committed cells.
