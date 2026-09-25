package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// eachHealthStore runs fn over every backend available, reusing the flow suite's
// flowStores helper (memStore always; pgStore when APPROVAL_TEST_DSN is set). Shared
// deliberately: replace-vs-add is expressed as a Go map assignment on one side and
// ON CONFLICT DO UPDATE on the other, and a divergence between them would surface only
// as different numbers depending on how the operator deployed us.
func eachHealthStore(t *testing.T, fn func(t *testing.T, s Store)) {
	t.Helper()
	for name, s := range flowStores(t) {
		t.Run(name, func(t *testing.T) { fn(t, s) })
	}
}

// NEGATIVE CONTROL for replace-vs-add.
//
// AuditDropped/FlowDropped are the firewall's PROCESS-LIFETIME totals, re-sent unchanged
// on every heartbeat. The flow buckets next door are additive because they are
// per-interval deltas — so the obvious "make it consistent with the flow upsert" change
// is exactly the bug: accumulating a standing count of 3 dropped batches would reach the
// hundreds within an hour and raise a data-loss alarm about losses that never happened.
func TestInstanceHealthReplacesRatherThanAccumulates(t *testing.T) {
	eachHealthStore(t, func(t *testing.T, s Store) {
		h := InstanceHealth{
			Instance: "fw-1", Ecosystem: "npm",
			ReportedAt: time.Now().UTC(), AuditDropped: 3, FlowDropped: 2,
		}
		// The same reading, reported five times — as a real firewall would while the
		// underlying counters stayed put.
		for i := 0; i < 5; i++ {
			if err := s.UpsertInstanceHealth(h); err != nil {
				t.Fatalf("upsert: %v", err)
			}
		}

		rows, err := s.ListInstanceHealth()
		if err != nil {
			t.Fatalf("list: %v", err)
		}
		if len(rows) != 1 {
			t.Fatalf("got %d rows, want 1 — one row per instance, not one per heartbeat", len(rows))
		}
		if rows[0].AuditDropped != 3 || rows[0].FlowDropped != 2 {
			t.Errorf("counters = audit %d / flow %d after five identical heartbeats, want 3 / 2 — these are cumulative gauges, so the upsert must REPLACE; adding them invents data loss that never happened",
				rows[0].AuditDropped, rows[0].FlowDropped)
		}
	})
}

// A later heartbeat with higher counters does update them — replace must not mean ignore.
func TestInstanceHealthTakesTheLatestReading(t *testing.T) {
	eachHealthStore(t, func(t *testing.T, s Store) {
		base := time.Now().UTC()
		mustUpsert(t, s, InstanceHealth{Instance: "fw-1", ReportedAt: base, AuditDropped: 1})
		mustUpsert(t, s, InstanceHealth{Instance: "fw-1", ReportedAt: base.Add(time.Minute), AuditDropped: 7})

		rows, _ := s.ListInstanceHealth()
		if len(rows) != 1 || rows[0].AuditDropped != 7 {
			t.Errorf("rows = %+v, want a single row carrying the latest count (7)", rows)
		}
	})
}

// THE ROW THAT MATTERS MOST MUST NOT BE HIDDEN.
//
// A replica that stopped reporting is the single most interesting row in this table — it
// is a dead firewall. Any "only recent instances" filter in the store would make exactly
// that row vanish from the view whose purpose is to notice it. The staleness judgement
// belongs to the caller, which knows the window.
func TestInstanceHealthKeepsSilentInstances(t *testing.T) {
	eachHealthStore(t, func(t *testing.T, s Store) {
		now := time.Now().UTC()
		mustUpsert(t, s, InstanceHealth{Instance: "fw-alive", ReportedAt: now})
		mustUpsert(t, s, InstanceHealth{Instance: "fw-dead", ReportedAt: now.Add(-72 * time.Hour)})

		rows, err := s.ListInstanceHealth()
		if err != nil {
			t.Fatalf("list: %v", err)
		}
		if len(rows) != 2 {
			t.Fatalf("got %d rows, want 2 — a silent instance must still be listed; it is the dead-firewall signal", len(rows))
		}
		// Newest first, so the console's "last seen" ordering is the store's, not a
		// re-sort the caller has to remember.
		if rows[0].Instance != "fw-alive" || rows[1].Instance != "fw-dead" {
			t.Errorf("order = %s, %s; want fw-alive first (newest heartbeat first)", rows[0].Instance, rows[1].Instance)
		}
	})
}

func mustUpsert(t *testing.T, s Store, h InstanceHealth) {
	t.Helper()
	if err := s.UpsertInstanceHealth(h); err != nil {
		t.Fatalf("upsert %s: %v", h.Instance, err)
	}
}

// The HTTP round trip: a firewall reports, an operator reads it back.
func TestHealthHTTP(t *testing.T) {
	srv := &server{store: newMemStore()}

	body := `{"instance":"fw-1","ecosystem":"npm","audit_dropped":4,"flow_dropped":1}`
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/v1/health", bytes.NewReader([]byte(body))))
	if rec.Code != http.StatusAccepted {
		t.Fatalf("POST /v1/health = %d, want 202", rec.Code)
	}

	rec = httptest.NewRecorder()
	srv.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v1/health", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /v1/health = %d, want 200", rec.Code)
	}
	var rows []InstanceHealth
	if err := json.Unmarshal(rec.Body.Bytes(), &rows); err != nil {
		t.Fatalf("decode: %v (body %s)", err, rec.Body.String())
	}
	if len(rows) != 1 || rows[0].Instance != "fw-1" || rows[0].AuditDropped != 4 {
		t.Fatalf("rows = %+v, want one fw-1 row with 4 audit drops", rows)
	}
	// ReportedAt is the SERVER's clock, not the client's — the body above sent none at
	// all, so a zero value here would mean the server trusted an absent client field.
	if rows[0].ReportedAt.IsZero() {
		t.Error("ReportedAt is zero; the server must stamp it, so a replica with a skewed clock cannot read as permanently fresh or permanently stale")
	}
}

// An unidentified heartbeat is refused: several replicas sharing one identity would let a
// live one mask a dead one, which is the failure this endpoint exists to catch.
func TestHealthRejectsMissingInstance(t *testing.T) {
	srv := &server{store: newMemStore()}
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/v1/health", bytes.NewReader([]byte(`{"audit_dropped":1}`))))
	if rec.Code != http.StatusBadRequest {
		t.Errorf("POST with no instance = %d, want 400", rec.Code)
	}
}

func TestHealthRejectsBadMethod(t *testing.T) {
	srv := &server{store: newMemStore()}
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, httptest.NewRequest(http.MethodDelete, "/v1/health", nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("DELETE /v1/health = %d, want 405", rec.Code)
	}
}

// An empty table returns [] rather than null, so a console can range over it unguarded.
func TestHealthEmptyIsArray(t *testing.T) {
	srv := &server{store: newMemStore()}
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v1/health", nil))
	if got := rec.Body.String(); got != "[]\n" {
		t.Errorf("empty body = %q, want \"[]\\n\"", got)
	}
}
