package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// getStatus drives the real router (not the handler directly), so route registration
// and the method guard are covered too — a handler that works but is unreachable is
// the kind of thing a direct-call test happily reports as green.
func getStatus(t *testing.T, srv *server, query string) (int, packageStatus) {
	t.Helper()
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v1/packages?"+query, nil))
	var st packageStatus
	if rec.Code == http.StatusOK {
		if err := json.Unmarshal(rec.Body.Bytes(), &st); err != nil {
			t.Fatalf("response is not valid packageStatus JSON: %v\nbody: %s", err, rec.Body)
		}
	}
	return rec.Code, st
}

func newStatusServer(t *testing.T) *server {
	t.Helper()
	return &server{store: newMemStore()}
}

// TestPackageStatusUnknownPackageIs200NotFound pins the D102/D139 decision that an
// unseen package is a 200 describing our ignorance, not a 404. The caller is typically
// someone whose install just failed; answering "not found" reproduces the exact
// misreading (#79) that the pip block already suffers from.
func TestPackageStatusUnknownPackageIs200NotFound(t *testing.T) {
	srv := newStatusServer(t)

	code, st := getStatus(t, srv, "package=never-seen-before")
	if code != http.StatusOK {
		t.Fatalf("unknown package returned %d, want 200 — a 404 reads as 'no such package'", code)
	}
	if st.Package != "never-seen-before" {
		t.Errorf("package echoed as %q", st.Package)
	}
	if st.LastObserved != nil {
		t.Errorf("LastObserved should be nil for a package never requested, got %+v", st.LastObserved)
	}
	// The availability markers must be PRESENT and must say "we did not look".
	// An omitted field would read as "nothing to worry about".
	if st.ScoreAvailability != availNoRepoKnown {
		t.Errorf("ScoreAvailability = %q, want %q", st.ScoreAvailability, availNoRepoKnown)
	}
	if st.Upstream != availNotCollected || st.Cache != availNotImplemented {
		t.Errorf("seam markers not stated: upstream=%q cache=%q", st.Upstream, st.Cache)
	}
	if st.DecisionGranularity != granularityPackageOnly {
		t.Errorf("DecisionGranularity = %q, want the package-only disclosure", st.DecisionGranularity)
	}
}

// TestPackageStatusReportsWhatActuallyHappened is the anti-vacuity twin of the test
// above. Without it, a handler that ALWAYS returned "we know nothing" would pass the
// unknown-package test and look correct while reporting nothing at all.
func TestPackageStatusReportsWhatActuallyHappened(t *testing.T) {
	srv := newStatusServer(t)

	older := AuditEvent{Package: "lodash", Ecosystem: "npm", Action: ActionAllow, Reason: "score 8.1", At: time.Now().Add(-time.Hour)}
	newer := AuditEvent{Package: "lodash", Ecosystem: "npm", Action: ActionBlock, Reason: "score 3.2 below threshold", At: time.Now()}
	for _, e := range []AuditEvent{older, newer} {
		if _, err := srv.store.AppendEvent(e); err != nil {
			t.Fatalf("seeding audit event: %v", err)
		}
	}

	code, st := getStatus(t, srv, "package=lodash&ecosystem=npm")
	if code != http.StatusOK {
		t.Fatalf("status = %d", code)
	}
	if st.LastObserved == nil {
		t.Fatal("LastObserved is nil after two real events were recorded — the endpoint is reporting nothing")
	}
	// Newest-first: the block is what a developer is currently hitting. Reporting the
	// hour-old allow would actively mislead them.
	if st.LastObserved.Action != ActionBlock {
		t.Errorf("LastObserved.Action = %q, want the NEWEST event (block); newest-first ordering is broken",
			st.LastObserved.Action)
	}
	if st.LastObserved.Reason == "" {
		t.Error("LastObserved.Reason is empty — the reason is the whole point of the view")
	}
	if len(st.RecentEvents) != 2 {
		t.Errorf("RecentEvents has %d entries, want both", len(st.RecentEvents))
	}
}

// TestPackageStatusDoesNotLeakNeighbouringPackages is a real defect guard, not a
// formality. EventFilter.Package is a SUBSTRING match by design (store.go documents
// this), so asking about "lodash" would otherwise return "lodash-es" events and tell a
// developer their package was blocked when it was not.
func TestPackageStatusDoesNotLeakNeighbouringPackages(t *testing.T) {
	srv := newStatusServer(t)

	if _, err := srv.store.AppendEvent(AuditEvent{
		Package: "lodash-es", Ecosystem: "npm", Action: ActionBlock, Reason: "a DIFFERENT package", At: time.Now(),
	}); err != nil {
		t.Fatalf("seeding: %v", err)
	}

	code, st := getStatus(t, srv, "package=lodash&ecosystem=npm")
	if code != http.StatusOK {
		t.Fatalf("status = %d", code)
	}
	if st.LastObserved != nil {
		t.Errorf("substring leak: asking about %q returned an event for %q (%q). A developer would "+
			"conclude their package was blocked when it was not.",
			"lodash", st.LastObserved.Package, st.LastObserved.Reason)
	}
	if len(st.RecentEvents) != 0 {
		t.Errorf("substring leak: %d neighbouring events returned", len(st.RecentEvents))
	}
}

// TestPackageStatusSubstringGuardCanFail is the negative control for the test above.
// It proves the guard is doing the work rather than the store happening to be exact:
// the UNFILTERED store query really does return the neighbour, so removing the
// EqualFold check in the handler would turn the previous test red.
func TestPackageStatusSubstringGuardCanFail(t *testing.T) {
	srv := newStatusServer(t)
	if _, err := srv.store.AppendEvent(AuditEvent{
		Package: "lodash-es", Ecosystem: "npm", Action: ActionBlock, At: time.Now(),
	}); err != nil {
		t.Fatalf("seeding: %v", err)
	}

	raw, err := srv.store.ListEvents(EventFilter{Ecosystem: "npm", Package: "lodash"})
	if err != nil {
		t.Fatalf("ListEvents: %v", err)
	}
	if len(raw) == 0 {
		t.Skip("store no longer substring-matches; the handler's guard may now be redundant — " +
			"re-check store.go's EventFilter contract before deleting it")
	}
	if raw[0].Package != "lodash-es" {
		t.Fatalf("control broken: expected the store to return the neighbour, got %q", raw[0].Package)
	}
}

// TestPackageStatusSurfacesTheHumanDecisionAndScore covers the two things this service
// genuinely owns, and the score path specifically — which is only reachable when a
// decision carries a RepoURL, because decisions are package-keyed and scores are
// repo-keyed.
func TestPackageStatusSurfacesTheHumanDecisionAndScore(t *testing.T) {
	srv := newStatusServer(t)
	const repo = "github.com/lodash/lodash"

	if _, err := srv.store.Put(Decision{Package: "lodash", Verdict: VerdictApproved, RepoURL: repo, DecidedBy: "admin"}); err != nil {
		t.Fatalf("seeding decision: %v", err)
	}
	score := 8.4
	if _, err := srv.store.PutScore(ScoreRecord{Repo: repo, Score: &score}); err != nil {
		t.Fatalf("seeding score: %v", err)
	}

	code, st := getStatus(t, srv, "package=lodash")
	if code != http.StatusOK {
		t.Fatalf("status = %d", code)
	}
	if st.Decision == nil || st.Decision.Verdict != VerdictApproved {
		t.Fatalf("human decision not surfaced: %+v", st.Decision)
	}
	if st.ScoreAvailability != availPresent {
		t.Errorf("ScoreAvailability = %q, want %q", st.ScoreAvailability, availPresent)
	}
	if st.Score == nil || st.Score.Score == nil || *st.Score.Score != score {
		t.Errorf("score not surfaced: %+v", st.Score)
	}
}

// TestPackageStatusDistinguishesUnscorableFromNeverScanned pins the difference a
// boolean would erase. ScoreRecord.Score is a pointer precisely so "we scanned it and
// could not score it" survives as a durable negative; flattening that into "no score"
// would hide a package we know we cannot evaluate.
func TestPackageStatusDistinguishesUnscorableFromNeverScanned(t *testing.T) {
	const repo = "github.com/example/unscorable"
	srv := newStatusServer(t)
	if _, err := srv.store.Put(Decision{Package: "mystery", RepoURL: repo}); err != nil {
		t.Fatalf("seeding decision: %v", err)
	}

	// No score row yet.
	if _, st := getStatus(t, srv, "package=mystery"); st.ScoreAvailability != availNeverScanned {
		t.Errorf("with no score row: got %q, want %q", st.ScoreAvailability, availNeverScanned)
	}

	// A durable negative: scanned, could not be scored.
	if _, err := srv.store.PutScore(ScoreRecord{Repo: repo, Score: nil}); err != nil {
		t.Fatalf("seeding negative score: %v", err)
	}
	_, st := getStatus(t, srv, "package=mystery")
	if st.ScoreAvailability != availScoredNegative {
		t.Errorf("with a negative score row: got %q, want %q — 'never scanned' and 'cannot be scored' "+
			"are opposite operational situations", st.ScoreAvailability, availScoredNegative)
	}
}

// TestPackageStatusRejectsMissingPackageAndWrites verifies the two guards on the route:
// a missing query parameter is a 400 rather than a listing, and every non-GET method is
// refused. The method guard is D140 — an unauthenticated caller must not be able to
// reach anything that could start work.
func TestPackageStatusRejectsMissingPackageAndWrites(t *testing.T) {
	srv := newStatusServer(t)

	if code, _ := getStatus(t, srv, ""); code != http.StatusBadRequest {
		t.Errorf("missing 'package' returned %d, want 400", code)
	}
	for _, m := range []string{http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodPatch} {
		rec := httptest.NewRecorder()
		srv.ServeHTTP(rec, httptest.NewRequest(m, "/v1/packages?package=lodash", nil))
		if rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("%s /v1/packages returned %d, want 405 — this route must stay read-only (D140)", m, rec.Code)
		}
	}
}
