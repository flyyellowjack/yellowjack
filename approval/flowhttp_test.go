package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func postFlow(t *testing.T, srv *server, body string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/v1/flow", bytes.NewBufferString(body)))
	return rec
}

func getFlow(t *testing.T, srv *server, path string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
	return rec
}

// A batch survives ingest and comes back through every read.
func TestFlowIngestAndRead(t *testing.T) {
	srv := &server{store: newMemStore()}
	at := t0().Format(time.RFC3339)
	body := fmt.Sprintf(`{
		"instance":"fw-1",
		"packages":[
			{"bucket_start":%q,"ecosystem":"npm","package":"lodash","kind":"artifact","requests":2,"bytes_upstream":900,"bytes_client":900},
			{"bucket_start":%q,"ecosystem":"npm","package":"","kind":"infra","requests":1,"bytes_upstream":10,"bytes_client":10}
		],
		"sources":[
			{"bucket_start":%q,"ecosystem":"npm","source_ip":"10.0.0.5","requests":3,"bytes_upstream":910,"bytes_client":910}
		]}`, at, at, at)

	if rec := postFlow(t, srv, body); rec.Code != http.StatusAccepted {
		t.Fatalf("ingest = %d, want 202: %s", rec.Code, rec.Body)
	}

	rec := getFlow(t, srv, "/v1/flow/summary")
	var sum FlowSummary
	if err := json.NewDecoder(rec.Body).Decode(&sum); err != nil {
		t.Fatal(err)
	}
	if sum.Requests != 3 || sum.BytesClient != 910 {
		t.Errorf("summary = %+v, want 3 requests / 910 bytes", sum)
	}
	if sum.Packages != 1 {
		t.Errorf("Packages = %d, want 1 (the infra row is not a package)", sum.Packages)
	}

	rec = getFlow(t, srv, "/v1/flow/packages")
	var pkgs []FlowPackage
	if err := json.NewDecoder(rec.Body).Decode(&pkgs); err != nil {
		t.Fatal(err)
	}
	if len(pkgs) != 2 || pkgs[0].Package != "lodash" {
		t.Errorf("packages = %+v, want lodash first then the unattributed bucket", pkgs)
	}

	rec = getFlow(t, srv, "/v1/flow/sources")
	var srcs []FlowSource
	if err := json.NewDecoder(rec.Body).Decode(&srcs); err != nil {
		t.Fatal(err)
	}
	if len(srcs) != 1 || srcs[0].SourceIP != "10.0.0.5" || srcs[0].BytesClient != 910 {
		t.Errorf("sources = %+v, want one row for 10.0.0.5 with 910 bytes", srcs)
	}
}

// A batch with no instance is REFUSED. Without it every replica's rows collide on the
// same primary key and several firewalls are silently summed into one identity — a
// corruption that would be invisible on the dashboard.
func TestFlowIngestRequiresInstance(t *testing.T) {
	srv := &server{store: newMemStore()}
	body := fmt.Sprintf(`{"packages":[{"bucket_start":%q,"ecosystem":"npm","package":"x","kind":"artifact","requests":1}]}`,
		t0().Format(time.RFC3339))
	rec := postFlow(t, srv, body)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("ingest without instance = %d, want 400", rec.Code)
	}

	// And nothing was stored — a rejected batch must not half-apply.
	sum, _ := srv.store.FlowSummary(FlowFilter{})
	if sum.Requests != 0 {
		t.Errorf("stored %d requests from a rejected batch, want 0", sum.Requests)
	}
}

// The instance is stamped from the envelope, so a row cannot claim to be from another
// replica. Otherwise one firewall could overwrite (or inflate) another's counters.
func TestFlowIngestStampsInstance(t *testing.T) {
	srv := &server{store: newMemStore()}
	body := fmt.Sprintf(`{"instance":"fw-1","packages":[
		{"bucket_start":%q,"instance":"fw-EVIL","ecosystem":"npm","package":"x","kind":"artifact","requests":1,"bytes_client":5}]}`,
		t0().Format(time.RFC3339))
	if rec := postFlow(t, srv, body); rec.Code != http.StatusAccepted {
		t.Fatalf("ingest = %d", rec.Code)
	}

	claimed, _ := srv.store.FlowSummary(FlowFilter{Instance: "fw-EVIL"})
	if claimed.Requests != 0 {
		t.Errorf("a row claimed instance fw-EVIL and it was honoured; the envelope must win")
	}
	real, _ := srv.store.FlowSummary(FlowFilter{Instance: "fw-1"})
	if real.Requests != 1 {
		t.Errorf("row not attributed to the sending instance: %+v", real)
	}
}

// An unknown kind is filed under infra rather than losing the batch. Best-effort
// telemetry from a newer firewall should degrade, not disappear.
func TestFlowIngestNormalizesKind(t *testing.T) {
	srv := &server{store: newMemStore()}
	body := fmt.Sprintf(`{"instance":"fw-1","packages":[
		{"bucket_start":%q,"ecosystem":"npm","package":"x","kind":"SOMETHING-NEW","requests":1,"bytes_client":5}]}`,
		t0().Format(time.RFC3339))
	if rec := postFlow(t, srv, body); rec.Code != http.StatusAccepted {
		t.Fatalf("ingest = %d, want 202 — an unknown kind must not lose the batch", rec.Code)
	}
	sum, _ := srv.store.FlowSummary(FlowFilter{})
	if sum.BytesClient != 5 {
		t.Errorf("batch with unknown kind was dropped: %+v", sum)
	}
}

// A malformed filter is a 400, never a silently-unfiltered result. A dashboard showing
// the whole history while the operator believes it is scoped to an incident window is
// the same lie as an audit search that looks filtered and is not.
func TestFlowRejectsBadFilters(t *testing.T) {
	srv := &server{store: newMemStore()}
	for _, path := range []string{
		"/v1/flow/summary?from=yesterday",
		"/v1/flow/packages?to=not-a-time",
		"/v1/flow/packages?limit=-3",
		"/v1/flow/sources?limit=abc",
		"/v1/flow/series?step=fortnight",
		"/v1/flow/series?step=0s",
	} {
		if rec := getFlow(t, srv, path); rec.Code != http.StatusBadRequest {
			t.Errorf("GET %s = %d, want 400", path, rec.Code)
		}
	}
}

// The series guard: a huge window with a tiny step must be refused, not answered. The
// response size depends on the WINDOW and STEP the caller picked, not on how much
// traffic happened, so an unbounded request is a self-inflicted memory spike on an
// otherwise idle instance.
func TestFlowSeriesRefusesTooManyPoints(t *testing.T) {
	srv := &server{store: newMemStore()}
	from := t0().Format(time.RFC3339)
	to := t0().AddDate(1, 0, 0).Format(time.RFC3339) // a year of 1-second steps
	rec := getFlow(t, srv, fmt.Sprintf("/v1/flow/series?from=%s&to=%s&step=1s", from, to))
	if rec.Code != http.StatusBadRequest {
		t.Errorf("over-wide series = %d, want 400 (guarding ~31M points)", rec.Code)
	}

	// A sane request still works, and is gap-filled to exactly the requested steps.
	to = t0().Add(5 * time.Minute).Format(time.RFC3339)
	rec = getFlow(t, srv, fmt.Sprintf("/v1/flow/series?from=%s&to=%s&step=1m", from, to))
	if rec.Code != http.StatusOK {
		t.Fatalf("sane series = %d, want 200: %s", rec.Code, rec.Body)
	}
	var pts []FlowPoint
	if err := json.NewDecoder(rec.Body).Decode(&pts); err != nil {
		t.Fatal(err)
	}
	if len(pts) != 5 {
		t.Errorf("got %d points, want 5 zero-filled minutes even with no traffic", len(pts))
	}
}

// Only the methods that make sense are allowed; the flow endpoints are POST-to-ingest
// and GET-to-read, with no PUT/DELETE, mirroring the append-only audit surface.
func TestFlowMethodGuards(t *testing.T) {
	srv := &server{store: newMemStore()}
	cases := []struct{ method, path string }{
		{http.MethodGet, "/v1/flow"},
		{http.MethodPut, "/v1/flow"},
		{http.MethodDelete, "/v1/flow"},
		{http.MethodPost, "/v1/flow/summary"},
		{http.MethodDelete, "/v1/flow/packages"},
	}
	for _, c := range cases {
		rec := httptest.NewRecorder()
		srv.ServeHTTP(rec, httptest.NewRequest(c.method, c.path, nil))
		if rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("%s %s = %d, want 405", c.method, c.path, rec.Code)
		}
	}
}

// Retention with a zero duration is DISABLED, not "purge everything". Getting this
// backwards would silently delete an operator's entire history the moment they set 0
// meaning "unlimited" — the interpretation D88's "keep what your disk allows" implies.
func TestFlowRetentionZeroKeepsEverything(t *testing.T) {
	s := newMemStore()
	if err := s.AddFlow([]FlowBucket{bucket(t0().AddDate(-1, 0, 0), "ancient", "artifact", 1, 10, 10)}, nil); err != nil {
		t.Fatal(err)
	}
	startFlowRetention(s, 0, time.Millisecond)
	time.Sleep(20 * time.Millisecond)

	sum, _ := s.FlowSummary(FlowFilter{})
	if sum.Requests != 1 {
		t.Errorf("retention=0 purged data; 0 must mean 'keep everything', not 'keep nothing'")
	}
}

// And a real retention does sweep, on its own, without a request to trigger it.
func TestFlowRetentionSweeps(t *testing.T) {
	s := newMemStore()
	err := s.AddFlow([]FlowBucket{
		bucket(time.Now().UTC().Add(-72*time.Hour), "old", "artifact", 1, 10, 10),
		bucket(time.Now().UTC(), "new", "artifact", 1, 20, 20),
	}, nil)
	if err != nil {
		t.Fatal(err)
	}

	startFlowRetention(s, 24*time.Hour, time.Hour)
	// The sweep runs once immediately at startup rather than waiting a full interval.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if sum, _ := s.FlowSummary(FlowFilter{}); sum.Requests == 1 {
			return // the old bucket went, the new one stayed
		}
		time.Sleep(10 * time.Millisecond)
	}
	sum, _ := s.FlowSummary(FlowFilter{})
	t.Errorf("retention did not sweep on startup: %+v", sum)
}
