package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// The L2 score cache must distinguish three states, because the firewall drives a
// different outcome from each: no row (cold -> launch a scan), a present score
// (decide on it), and a NULL score (the negative "scanned-but-unscorable" marker
// -> route to the unscorable path, do NOT re-scan).
func TestMemStoreScore(t *testing.T) {
	s := newMemStore()

	// Cold: never scanned.
	if _, ok, err := s.GetScore("github.com/a/b"); err != nil || ok {
		t.Fatalf("cold GetScore = (ok=%v, err=%v), want (false, nil)", ok, err)
	}

	// Positive: a real numeric score round-trips.
	score := 7.5
	if _, err := s.PutScore(ScoreRecord{Repo: "github.com/a/b", Score: &score}); err != nil {
		t.Fatalf("PutScore positive: %v", err)
	}
	rec, ok, err := s.GetScore("github.com/a/b")
	if err != nil || !ok || rec.Score == nil || *rec.Score != 7.5 {
		t.Fatalf("positive GetScore = (%+v, ok=%v, err=%v), want score 7.5", rec, ok, err)
	}
	if rec.UpdatedAt.IsZero() {
		t.Error("PutScore should stamp UpdatedAt")
	}

	// Negative marker: a nil score is stored and read back as present-but-nil,
	// which is distinct from a cold miss.
	if _, err := s.PutScore(ScoreRecord{Repo: "github.com/x/y", Score: nil}); err != nil {
		t.Fatalf("PutScore negative: %v", err)
	}
	rec, ok, err = s.GetScore("github.com/x/y")
	if err != nil || !ok {
		t.Fatalf("negative GetScore = (ok=%v, err=%v), want present", ok, err)
	}
	if rec.Score != nil {
		t.Errorf("negative marker Score = %v, want nil", *rec.Score)
	}
}

// TestMemStoreDeleteScore covers the operator re-scan primitive (issue #12): deleting
// a present row reports existed=true and leaves the repo cold, while deleting an
// absent row reports existed=false (so the handler can 404 a no-op).
func TestMemStoreDeleteScore(t *testing.T) {
	s := newMemStore()
	score := 7.5
	if _, err := s.PutScore(ScoreRecord{Repo: "github.com/a/b", Score: &score}); err != nil {
		t.Fatalf("PutScore: %v", err)
	}

	existed, err := s.DeleteScore("github.com/a/b")
	if err != nil || !existed {
		t.Fatalf("DeleteScore present = (existed=%v, err=%v), want (true, nil)", existed, err)
	}
	// The row is gone -> the next lookup is a cold miss, which re-triggers a scan.
	if _, ok, _ := s.GetScore("github.com/a/b"); ok {
		t.Fatal("GetScore after delete should be cold (ok=false)")
	}

	existed, err = s.DeleteScore("github.com/never/scanned")
	if err != nil || existed {
		t.Fatalf("DeleteScore absent = (existed=%v, err=%v), want (false, nil)", existed, err)
	}
}

// TestDeleteScoreHandler covers the DELETE /v1/scores route: 204 when a row is
// cleared, 404 when there is nothing to clear, 400 without a repo.
func TestDeleteScoreHandler(t *testing.T) {
	st := newMemStore()
	score := 7.5
	st.PutScore(ScoreRecord{Repo: "github.com/a/b", Score: &score})
	srv := &server{store: st}

	do := func(target string) int {
		req := httptest.NewRequest(http.MethodDelete, target, nil)
		rec := httptest.NewRecorder()
		srv.ServeHTTP(rec, req)
		return rec.Code
	}

	if code := do("/v1/scores?repo=github.com/a/b"); code != http.StatusNoContent {
		t.Fatalf("delete present: status = %d, want 204", code)
	}
	if code := do("/v1/scores?repo=github.com/a/b"); code != http.StatusNotFound {
		t.Fatalf("delete already-gone: status = %d, want 404", code)
	}
	if code := do("/v1/scores"); code != http.StatusBadRequest {
		t.Fatalf("delete without repo: status = %d, want 400", code)
	}
}
