package main

import (
	"encoding/json"
	"os"
	"testing"
)

// TestSchedulerReadsTheSameCoverageTheScannerWrote is the scheduler's end of the
// cross-boundary agreement on #133's two coverage fields.
//
// THE RISK. `scoredChecks`/`totalChecks` cross two HTTP boundaries into three
// independently-owned DTOs, and each service owns its own (the same rule as the
// firewall<->approval boundary). "Total" is exactly the kind of denominator that
// changes meaning in transit without anything failing: a hop that re-derived it
// from len(Checks), or renamed the field, would keep compiling and keep answering.
// A ratio whose denominator is computed in another component is a ratio nobody can
// defend, so the hops are pinned against ONE artifact instead of three lookalike
// literals.
//
// Siblings: TestTheWireShapeMatchesTheFixtureEveryHopReads (scanner, which PRODUCES
// this shape) and TestFirewallReadsTheSameCoverageTheScannerWrote (root package).
func TestSchedulerReadsTheSameCoverageTheScannerWrote(t *testing.T) {
	raw, err := os.ReadFile("../testdata/scanresult_partial_wire.json")
	if err != nil {
		t.Fatalf("reading the shared fixture: %v", err)
	}
	var got scanResult
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("the scheduler cannot decode the scanner's wire shape: %v", err)
	}
	if got.ScoredChecks != 11 || got.TotalChecks != 18 {
		t.Fatalf("coverage decoded as %d of %d, want 11 of 18 — the scheduler and the scanner disagree "+
			"about the fields, so the firewall is reading numbers nobody produced",
			got.ScoredChecks, got.TotalChecks)
	}
	if got.Score != 4.8 || len(got.Checks) != 18 {
		t.Errorf("score/checks = %v/%d, want 4.8/18", got.Score, len(got.Checks))
	}

	// The scheduler is TRANSPORT for these numbers and must not recompute them. It
	// could: len(Checks) is right here and would look correct forever, until the day
	// the scanner's definition of "scored" changes and only one of the two follows.
	// Re-encoding must give the fixture's numbers back byte-for-byte in meaning.
	out, err := json.Marshal(got)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var round map[string]any
	if err := json.Unmarshal(out, &round); err != nil {
		t.Fatalf("unmarshal round-trip: %v", err)
	}
	if round["scoredChecks"] != float64(11) || round["totalChecks"] != float64(18) {
		t.Errorf("the scheduler altered the coverage in transit: re-encoded as %v of %v",
			round["scoredChecks"], round["totalChecks"])
	}
}
