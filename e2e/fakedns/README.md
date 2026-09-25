# fakedns — the DNS sinkhole for the zero-egress assertion (#27)

A ~150-line UDP DNS server that answers every A query with a fixed address and prints one
line per query:

```
QUERY <name>
```

That log line is the entire point. `TestFirewallMakesNoUnconfiguredEgress` asserts it is
**empty**.

## Why this exists rather than a simpler check

The obvious way to test "the firewall does not phone home" is to run it on a network with no
route out and check that it still works. That proves the firewall does not *depend* on
egress. It does **not** prove the firewall does not *attempt* it — and a telemetry call is
best-effort by nature, so it would fail silently and the test would stay green. **The
attempt is the thing worth observing, not its outcome.**

A DNS sinkhole records attempts. Every legitimate destination in the rig is configured as an
explicit **IP**, so a correct run needs no resolution at all; therefore *any* query is a
name the binary wanted that nobody configured.

## Why not just use the in-process dialler check

There is one (`egress.go`), and it is faster. But it wraps *our* transport, so it cannot see:

- **DNS** — resolution happens inside the dialer, before the connect it wraps;
- **anything that dials without our transport** — a future dependency, cgo, the Go runtime.

Both are exactly what a phone-home would use. This fixture watches from outside, where both
are visible.

## What it deliberately does not catch

Egress to a **hard-coded IP literal**, which needs no lookup. That spelling is what the
in-process dialler check *does* see. The two legs are complementary; neither alone is
sufficient. Do not retire one believing the other covers it.

## Design notes

- **stdlib only, and its own throwaway Go module.** The fixture must not enter the main
  module's dependency graph — doubly so here, since `TestFirewallBinaryLinksOnlyStdlib`
  asserts the firewall module stays dependency-free. Pulling in a DNS library to test that
  we have no dependencies would be self-defeating.
- **`FROM scratch`.** The sinkhole must have nothing in it that could itself make a network
  call, or the rig would spend its time explaining its own noise.
- **Malformed packets are dropped, never guessed at.** A sinkhole that invented a name would
  write a false entry into the log the assertion reads.
- **Compression pointers in the question section are refused.** They are illegal there, and
  following one is a classic parser-loop bug.

## Build

From the repo root (the test does this for you):

```sh
docker build -f e2e/fakedns/Dockerfile -t yellowjack-fakedns:e2e .
```

## Proving it can fail

The test's negative control reconfigures the firewall with a **named** upstream instead of
an addressed one and requires the recorder to report it. If that leg ever passes while the
main assertion is clean, the resolver is not ours and the clean result means nothing.
