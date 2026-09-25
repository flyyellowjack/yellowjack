package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"
)

// The console's scoreRecord is the console's copy of the approval service's ScoreRecord,
// and until 2026-09-22 it named `hasScore` and `scoredAt` -- keys the approval service
// has never sent (it sends a nullable `score` and `updatedAt`). encoding/json dropped
// the number on decode with no error, so the lookup page showed no score and a zero
// time for EVERY scored package, and nothing was red: the fake approval in the tests
// hands the handler a struct, so no test ever decoded the real wire. Same class as the
// five audit fields (#142); same fix: hold the two types together by their keys, and
// decode the real shape once.

func f64(v float64) *float64 { return &v }

func TestEveryStoredScoreFieldReachesTheConsole(t *testing.T) {
	stored := approvalStructJSONKeys(t, "ScoreRecord", 3)
	shown := jsonKeySet(reflect.TypeOf(scoreRecord{}))
	var missing []string
	for _, k := range stored {
		if !shown[k] {
			missing = append(missing, k)
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Errorf("the approval service sends score fields the console's scoreRecord does not name: %v. "+
			"They are dropped on decode, so the lookup page can never show them.", missing)
	}
}

// TestTheScoreWireGuardCanFail: the pre-fix console type, run through the same
// comparison, must be flagged on both of its invented keys -- and the real approval
// keys must be what it is compared against, or the guard above proves nothing.
func TestTheScoreWireGuardCanFail(t *testing.T) {
	type preFix struct {
		Repo     string    `json:"repo"`
		Score    float64   `json:"score"`
		HasScore bool      `json:"hasScore"`
		ScoredAt time.Time `json:"scoredAt"`
	}
	stored := approvalStructJSONKeys(t, "ScoreRecord", 3)
	shown := jsonKeySet(reflect.TypeOf(preFix{}))
	var missing []string
	for _, k := range stored {
		if !shown[k] {
			missing = append(missing, k)
		}
	}
	if len(missing) == 0 {
		t.Fatal("the pre-fix scoreRecord passed the key comparison, so the guard cannot see the defect it was written for")
	}
	for _, must := range []string{"updatedAt"} {
		found := false
		for _, k := range missing {
			found = found || k == must
		}
		if !found {
			t.Errorf("the comparison did not flag %q, which the pre-fix type spelled differently: %v", must, missing)
		}
	}
}

// TestTheLookupPageShowsTheScoreTheApprovalServiceActuallySends decodes the approval
// service's OWN JSON shape through the real client, then renders it. The literal is
// hand-written; the key guard above is what keeps it the approval service's shape.
func TestTheLookupPageShowsTheScoreTheApprovalServiceActuallySends(t *testing.T) {
	const wire = `{"package":"lodash","decisionGranularity":"package",` +
		`"score":{"repo":"github.com/lodash/lodash","score":7.5,"updatedAt":"2026-09-22T10:00:00Z"},` +
		`"scoreAvailability":"present","upstreamMetadata":"not-collected-by-this-service","cacheStatus":"not-implemented"}`
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, wire)
	}))
	defer up.Close()

	c := &approvalHTTPClient{baseURL: up.URL, http: up.Client()}
	st, found, err := c.PackageStatus("lodash", "")
	if err != nil || !found {
		t.Fatalf("PackageStatus = (found=%v, err=%v)", found, err)
	}
	if st.Score == nil || !st.Score.HasScore() || st.Score.Value() != 7.5 {
		t.Fatalf("the score the approval service sent did not survive decode: %+v", st.Score)
	}
	if st.Score.UpdatedAt.IsZero() {
		t.Error("updatedAt did not survive decode; the page would show a zero time")
	}
	if st.Score.Partial() {
		t.Error("a record with no coverage fields decoded as PARTIAL; zero counts must read as unknown")
	}

	page := lookupGet(t, newTestServer(&fakeApproval{statusOK: true, status: st}), "?package=lodash").Body.String()
	if !strings.Contains(page, "7.5") {
		t.Error("the lookup page does not show the score the approval service sent")
	}
	if !strings.Contains(page, "2026-09-22") {
		t.Error("the lookup page does not show when the score was recorded")
	}
	if strings.Contains(page, "partial score") || strings.Contains(page, "Coverage") {
		t.Error("a full score is labelled as partial")
	}
}

// TestAPartialScoreIsLabelledOnTheLookupPage: a score that passed the D271 floor is a
// score, and the page must still say what it was computed over and without. The control
// is the same record at full coverage, which must carry no such label.
// TestTheLookupPageRendersTimesForAPerson pins how the lookup page prints a time.
//
// It printed four of them with Go's default String(), so an operator read
// "2026-09-22 14:34:26.2 -0400 EDT" (and in tests "... m=+0.004"), every other console
// page printing a formatted UTC time beside it. It was noticed only because a substring
// in another test matched the fractional seconds. And the pages that DID format a time
// labelled it "UTC" without converting it first, which is right only while every
// upstream happens to send UTC.
func TestTheLookupPageRendersTimesForAPerson(t *testing.T) {
	// A non-UTC input on purpose: the rendering must CONVERT, not merely append a label.
	edt := time.FixedZone("EDT", -4*3600)
	at := time.Date(2026, 9, 22, 14, 34, 26, 200000000, edt) // 18:34:26.2 UTC
	rec := &scoreRecord{Repo: "gitlab.example/org/repo", Score: f64(6.2), UpdatedAt: at}
	ev := event{Package: "p", Action: "block", Reason: "r", At: at}
	st := packageStatus{Package: "p", ScoreAvailability: "present", Score: rec,
		LastObserved: &ev, RecentEvents: []event{ev}}
	page := lookupGet(t, newTestServer(&fakeApproval{statusOK: true, status: st}), "?package=p").Body.String()

	// Three renders carry this instant: the score, the last observed decision, and the
	// recent-events row. Counted rather than merely found, so one of them reverting to
	// the raw form cannot hide behind the other two.
	if n := strings.Count(page, "2026-09-22 18:34:26 UTC"); n != 3 {
		t.Errorf("%d of the 3 times on the page render as a converted UTC time", n)
	}
	for _, leak := range []string{"26.2", "EDT", "-0400", "m=+"} {
		if strings.Contains(page, leak) {
			t.Errorf("the page leaks Go's default time rendering (%q)", leak)
		}
	}
}

func TestAPartialScoreIsLabelledOnTheLookupPage(t *testing.T) {
	// A FIXED time, and deliberately this one. The last assertion below looks for "6.2"
	// on the page, and the page used to print this timestamp with Go's default String()
	// -- "…18:34:26.2 +0000 UTC" -- so a clock reading of x6.2 seconds satisfied it.
	// With time.Now() that failed about one run in eighteen. Pinned to the colliding
	// value, the test now fails EVERY time if the raw rendering comes back.
	rec := &scoreRecord{Repo: "gitlab.example/org/repo", Score: f64(6.2), UpdatedAt: time.Date(2026, 9, 22, 18, 34, 26, 200000000, time.UTC),
		ScoredChecks: 15, TotalChecks: 18, ComputedWithout: []string{"CI-Tests", "Contributors", "License"}}
	st := packageStatus{Package: "partial-pkg", ScoreAvailability: "present", Score: rec}

	page := lookupGet(t, newTestServer(&fakeApproval{statusOK: true, status: st}), "?package=partial-pkg").Body.String()
	for _, want := range []string{"6.2", "15 of 18 checks", "partial score", "CI-Tests, Contributors, License"} {
		if !strings.Contains(page, want) {
			t.Errorf("a partial score rendered without %q, so a reader cannot tell it from a full measurement", want)
		}
	}

	// Control: full coverage, no label.
	rec.ScoredChecks, rec.ComputedWithout = 18, nil
	page = lookupGet(t, newTestServer(&fakeApproval{statusOK: true, status: st}), "?package=partial-pkg").Body.String()
	if strings.Contains(page, "partial score") || strings.Contains(page, "Coverage") {
		t.Error("a full-coverage score is labelled as partial")
	}
	if !strings.Contains(page, "6.2") {
		t.Error("the control lost the score itself")
	}

	// A row that predates the coverage fields (zeros) is unknown, not partial.
	rec.ScoredChecks, rec.TotalChecks = 0, 0
	page = lookupGet(t, newTestServer(&fakeApproval{statusOK: true, status: st}), "?package=partial-pkg").Body.String()
	if strings.Contains(page, "partial score") {
		t.Error("a record with no coverage information is labelled as partial")
	}

	// The negative marker: scanned, no score. No number, no label.
	rec.Score = nil
	page = lookupGet(t, newTestServer(&fakeApproval{statusOK: true, status: st}), "?package=partial-pkg").Body.String()
	if strings.Contains(page, "6.2") || strings.Contains(page, "partial score") {
		t.Error("an unscorable record rendered a number or a coverage label")
	}
}
