package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

// #133, the firewall's end: a PARTIAL scanner report must not become a score.
//
// Before the salvage fix a non-zero scorecard exit reached the firewall as a 502
// and landed on "couldn't get a score" — unscorable, and from there the
// human-ruling path. Salvaging the report is an availability fix, but it puts a
// SCORE on the wire where there was previously an error, and that score is computed
// over only the checks that succeeded. Scorecard EXCLUDES an errored check from its
// aggregate rather than zeroing it, so 4.8-over-11-of-18 and 4.8-over-18 are
// different measurements. Letting the first clear FW_SCORE_THRESHOLD would buy
// availability with soundness — the trade this project has refused before (#94,
// #60), and the one #133 filed rather than patched.
//
// D271 then ruled the floor (scorecardfloor.go): a partial report is a score if and
// only if every REQUIRED check scored. This file keeps the pre-floor guarantees, and
// the reply below carries counts but no check names, which is the one partial shape
// the floor cannot evaluate and must still refuse. scorecardfloor_test.go covers the
// floor itself.

func startFakeScanner(t *testing.T, reply string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, reply)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestAPartialScannerReportIsNotAScore(t *testing.T) {
	// The measured shape from #14/#133: the real gitlab.com/gitlab-org/gitlab-runner
	// with no credential — 18 checks, 7 errored on HTTP 401, aggregate 4.8 over the
	// other 11. The host is defanged in the literal (#46); nothing here resolves it.
	srv := startFakeScanner(t, `{"repo":"gitlab.example/gitlab-org/gitlab-runner","score":4.8,"scoredChecks":11,"totalChecks":18}`)
	f := &Firewall{cfg: Config{ScannerURL: srv.URL, ScoreThreshold: 5.0}, scannerClient: srv.Client()}

	score, err := f.getScoreFromScanner("gitlab.example/gitlab-org/gitlab-runner")
	if err == nil {
		t.Fatalf("a score computed over 11 of 18 checks was returned as a SCORE (%.1f). It would be compared "+
			"to FW_SCORE_THRESHOLD as though it were a full measurement, which is the soundness bug #133 "+
			"exists to avoid trading for the availability fix", score)
	}
	// An operator has to be able to tell this from "the scanner is down". Both are
	// errors; only one is a statement about coverage, and only one is fixed by
	// supplying a credential.
	for _, want := range []string{"partial", "11 of 18", "4.8", "#133"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal does not mention %q, so the log cannot distinguish a coverage shortfall "+
				"from an outage: %v", want, err)
		}
	}
}

func TestACompleteReportIsStillAScore(t *testing.T) {
	// THE DISCRIMINATOR. Everything above is also true of a firewall that rejects
	// every scanner reply. The same shape with full coverage must come back as a
	// plain score — including from a run that exited non-zero, which is the case
	// where the salvage genuinely changes the verdict for the better and is sound
	// precisely because nothing was excluded from the aggregate.
	srv := startFakeScanner(t, `{"repo":"github.com/a/b","score":7.5,"scoredChecks":18,"totalChecks":18}`)
	f := &Firewall{cfg: Config{ScannerURL: srv.URL, ScoreThreshold: 5.0}, scannerClient: srv.Client()}

	score, err := f.getScoreFromScanner("github.com/a/b")
	if err != nil {
		t.Fatalf("a report where all 18 checks scored is a full measurement and must be usable; got %v", err)
	}
	if score != 7.5 {
		t.Errorf("score = %v, want 7.5", score)
	}
}

func TestAReplyWithNoCoverageFieldsIsStillAScore(t *testing.T) {
	// ROLLING DEPLOY. A scanner or scheduler that predates #133 sends no coverage
	// fields, which decode as 0/0. Treating "no information" as "bad coverage" would
	// make the firewall refuse every score the moment one replica lagged a release —
	// turning a visibility improvement into an outage. Absent is not partial.
	srv := startFakeScanner(t, `{"repo":"github.com/a/b","score":7.5}`)
	f := &Firewall{cfg: Config{ScannerURL: srv.URL, ScoreThreshold: 5.0}, scannerClient: srv.Client()}

	score, err := f.getScoreFromScanner("github.com/a/b")
	if err != nil {
		t.Fatalf("a pre-#133 reply carries no coverage fields and must keep working; got %v", err)
	}
	if score != 7.5 {
		t.Errorf("score = %v, want 7.5", score)
	}
}

// TestFirewallReadsTheSameCoverageTheScannerWrote is the third and last end of the
// cross-boundary agreement (siblings in scanner/ and scheduler/). The two counts
// cross two HTTP hops into three independently-owned DTOs; "total" is exactly the
// denominator that changes meaning in transit while everything still compiles. All
// three hops are pinned against ONE fixture, so a rename or a re-derivation on any
// of them fails somebody's test rather than silently producing a ratio nobody can
// defend.
func TestFirewallReadsTheSameCoverageTheScannerWrote(t *testing.T) {
	raw, err := os.ReadFile("testdata/scanresult_partial_wire.json")
	if err != nil {
		t.Fatalf("reading the shared fixture: %v", err)
	}
	var got scannerResponse
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("the firewall cannot decode the scanner's wire shape: %v", err)
	}
	if got.ScoredChecks != 11 || got.TotalChecks != 18 {
		t.Fatalf("coverage decoded as %d of %d, want 11 of 18 — the firewall is reading different numbers "+
			"than the scanner wrote", got.ScoredChecks, got.TotalChecks)
	}
	if !got.Partial() {
		t.Error("scannerResponse.Partial and ScanResult.Partial are restated per service rather than shared; " +
			"they must agree on the same bytes, and here they do not")
	}
	if got.Score != 4.8 {
		t.Errorf("score = %v, want 4.8", got.Score)
	}
}
