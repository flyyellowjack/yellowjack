package main

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"
)

// summaryFixture is one of every shape SummarizeEvents has to tell apart, plus one event
// outside the window. Returned with the window start so each test asks the same question.
func summaryFixture(t *testing.T, s Store) time.Time {
	t.Helper()
	now := time.Now().UTC()
	since := now.Add(-24 * time.Hour)
	for _, e := range []AuditEvent{
		// Outside the window: must not count anywhere, including Sources.
		{Package: "old", Ecosystem: "npm", Action: ActionAllow, SourceIP: "10.0.0.9", At: now.Add(-25 * time.Hour)},
		{Package: "a", Ecosystem: "npm", Action: ActionAllow, SourceIP: "10.0.0.1", At: now.Add(-3 * time.Hour)},
		{Package: "b", Ecosystem: "npm", Action: ActionAllow, SourceIP: "10.0.0.1", At: now.Add(-2 * time.Hour)},
		{Package: "evil", Ecosystem: "npm", Action: ActionBlock, Taken: "block", DenyKind: "known-malware", SourceIP: "10.0.0.2", At: now.Add(-90 * time.Minute)},
		{Package: "weak", Ecosystem: "npm", Action: ActionBlock, Taken: "block", DenyKind: "score-below-threshold", At: now.Add(-80 * time.Minute)},
		// A block recorded before the control plane kept deny_kind (#142): its own bucket.
		{Package: "legacy", Ecosystem: "npm", Action: ActionBlock, At: now.Add(-70 * time.Minute)},
		// Report mode (#114): the verdict was block, the package was DELIVERED.
		{Package: "served", Ecosystem: "npm", Action: ActionBlock, Taken: "allow", DenyKind: "score-below-threshold", SourceIP: "10.0.0.3", At: now.Add(-60 * time.Minute)},
	} {
		if _, err := s.AppendEvent(e); err != nil {
			t.Fatalf("AppendEvent %s: %v", e.Package, err)
		}
	}
	return since
}

// The tally has to be right on BOTH backends: the Postgres path is a GROUP BY folded
// through the same add(), and a column slip there is invisible to the memStore run.
func TestSummarizeEventsEveryBackend(t *testing.T) {
	for name, store := range eventStores(t) {
		t.Run(name, func(t *testing.T) {
			since := summaryFixture(t, store)
			got, err := store.SummarizeEvents(since)
			if err != nil {
				t.Fatalf("SummarizeEvents: %v", err)
			}
			if got.Allowed != 2 {
				t.Errorf("Allowed = %d, want 2 (the 25h-old allow is outside the window)", got.Allowed)
			}
			if got.Blocked != 3 {
				t.Errorf("Blocked = %d, want 3 refused -- the served block must not be counted as stopped", got.Blocked)
			}
			if got.BlockedServed != 1 {
				t.Errorf("BlockedServed = %d, want 1", got.BlockedServed)
			}
			want := map[string]int{"known-malware": 1, "score-below-threshold": 1, "": 1}
			for k, n := range want {
				if got.ByDenyKind[k] != n {
					t.Errorf("ByDenyKind[%q] = %d, want %d (all: %v)", k, got.ByDenyKind[k], n, got.ByDenyKind)
				}
			}
			sum := 0
			for _, n := range got.ByDenyKind {
				sum += n
			}
			if sum != got.Blocked {
				t.Errorf("ByDenyKind sums to %d, Blocked is %d -- the parts must add up", sum, got.Blocked)
			}
			// 10.0.0.1 twice, .2 and .3 once; the unobserved block and the out-of-window .9
			// are not sources.
			if got.Sources != 3 {
				t.Errorf("Sources = %d, want 3", got.Sources)
			}
		})
	}
}

// A window that starts after every event is an honest zero, not an error and not the
// default window.
func TestSummarizeEventsEmptyWindow(t *testing.T) {
	for name, store := range eventStores(t) {
		t.Run(name, func(t *testing.T) {
			summaryFixture(t, store)
			got, err := store.SummarizeEvents(time.Now().UTC().Add(time.Hour))
			if err != nil {
				t.Fatalf("SummarizeEvents: %v", err)
			}
			if got.Allowed+got.Blocked+got.BlockedServed+got.Sources != 0 {
				t.Errorf("future window = %+v, want all zero", got)
			}
		})
	}
}

func TestSummarizeEventsHTTP(t *testing.T) {
	srv := &server{store: newMemStore()}
	summaryFixture(t, srv.store)

	// No ?since= is the last 24 hours.
	rec := do(t, srv, http.MethodGet, "/v1/events/summary", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("summary = %d, want 200", rec.Code)
	}
	var got EventSummary
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v; body=%s", err, rec.Body.String())
	}
	if got.Allowed != 2 || got.Blocked != 3 || got.BlockedServed != 1 {
		t.Errorf("default window = %+v, want 2 allowed / 3 blocked / 1 served", got)
	}
	if age := time.Since(got.Since); age < 23*time.Hour || age > 25*time.Hour {
		t.Errorf("default since is %s ago, want about 24h", age)
	}

	// An explicit since narrows it: only the served block and nothing else is this recent.
	since := time.Now().UTC().Add(-65 * time.Minute).Format(time.RFC3339)
	rec = do(t, srv, http.MethodGet, "/v1/events/summary?since="+since, "")
	json.Unmarshal(rec.Body.Bytes(), &got)
	if got.Allowed != 0 || got.Blocked != 0 || got.BlockedServed != 1 {
		t.Errorf("since=%s gave %+v, want only the served block", since, got)
	}

	// A malformed since is a 400, not a silent fall back to the default window.
	if r := do(t, srv, http.MethodGet, "/v1/events/summary?since=yesterday", ""); r.Code != http.StatusBadRequest {
		t.Errorf("?since=yesterday = %d, want 400", r.Code)
	}
	if r := do(t, srv, http.MethodPost, "/v1/events/summary", ""); r.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST summary = %d, want 405", r.Code)
	}
}

// The console decodes this over REST with its own struct, so the key names are the
// contract. Pinned here as literal strings, and on the console side against the same.
func TestEventSummaryWireKeys(t *testing.T) {
	b, err := json.Marshal(EventSummary{ByDenyKind: map[string]int{}})
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	json.Unmarshal(b, &m)
	for _, k := range []string{"since", "allowed", "blocked", "blocked_served", "by_deny_kind", "sources"} {
		if _, ok := m[k]; !ok {
			t.Errorf("wire form %s has no %q key", b, k)
		}
	}
}
