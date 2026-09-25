package main

import (
	"net/http"
	"strings"
	"testing"
)

// e2e/async_local.sh leg 20 flaked: "a byte total rendered as '0 B' after real traffic",
// twice in about six runs (one seen by a sibling session, one in the run that was gating
// the leg-28 branch). It passes on re-run with nothing changed.
//
// The leg's COMMENT says it watches the totals tile -- `<div class="v">0 B</div>`, the
// signature of a JSON tag renamed on one side of the console/approval seam, which zeroes
// the summary without erroring. Its PATTERN was `>0 B<` anywhere on the page, and the
// per-package table renders a byte cell the same way. So the pattern also fires on a
// package ROW whose bytes are zero while the totals are healthy.
//
// Such a row is a legitimate state, not a wiring fault. The gate counts a relay's REQUEST
// when the upstream opens (proxy.go, recordRelay) and its BYTES only once the stream
// finishes (recordRelayBytes), so a package whose only traffic so far is in flight, was a
// HEAD, or drew an empty upstream answer has requests and no bytes. Whether one is on the
// page when leg 20 renders it depends on which five-second flush has landed.
//
// WHAT IS PROVEN HERE: that the old pattern fires on a healthy page (this test), so it
// could not distinguish the fault it names from an ordinary row. WHAT IS NOT: which row
// tripped it in the failing runs -- the page was not captured. The leg now prints the
// offending fragment, so the next occurrence documents itself.
func TestAZeroByteRowIsNotTheTotalsTileReadingZero(t *testing.T) {
	f := &fakeApproval{
		flowSum: flowSummary{Requests: 12, BytesUpstream: 5_000_000, BytesClient: 5_000_000, Packages: 2},
		flowPkgs: []flowPackage{
			{Package: "lodash", Ecosystem: "npm", Requests: 11, BytesUpstream: 5_000_000, BytesClient: 5_000_000},
			// requests counted, bytes not yet: in flight, a HEAD, or an empty upstream answer
			{Package: "express", Ecosystem: "npm", Requests: 1},
		},
	}
	rec := getCapacity(t, f, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /capacity = %d", rec.Code)
	}
	page := rec.Body.String()

	const oldRigPattern = ">0 B<"        // what leg 20 matched
	const tilePattern = `class="v">0 B<` // what its comment said it matched
	if !strings.Contains(page, oldRigPattern) {
		t.Fatal("the fixture does not reproduce a zero-byte cell, so it proves nothing about the rig's pattern")
	}
	if strings.Contains(page, tilePattern) {
		t.Fatalf("the TOTALS tile reads 0 B with a 5 MB summary; that would be the real wiring fault")
	}

	// And the fault the leg exists for must still be visible to the narrowed pattern: a
	// summary that decoded to zero puts 0 B in the tile.
	zeroed := getCapacity(t, &fakeApproval{
		flowSum:  flowSummary{Requests: 12, Packages: 1},
		flowPkgs: []flowPackage{{Package: "lodash", Ecosystem: "npm", Requests: 12}},
	}, "").Body.String()
	if !strings.Contains(zeroed, tilePattern) {
		t.Fatal("a summary whose byte fields are zero does not render the tile pattern, so narrowing the " +
			"rig's check to the tile would stop it catching the tag-mismatch it was written for")
	}
}
