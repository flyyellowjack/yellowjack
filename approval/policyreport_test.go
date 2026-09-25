package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// postHeartbeat sends a raw heartbeat body and returns the status.
func postHeartbeat(t *testing.T, srv *server, body string) int {
	t.Helper()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/health", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	srv.ServeHTTP(rec, req)
	return rec.Code
}

func onlyHealth(t *testing.T, s Store) InstanceHealth {
	t.Helper()
	rows, err := s.ListInstanceHealth()
	if err != nil {
		t.Fatalf("list health: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("want exactly 1 health row, got %d", len(rows))
	}
	return rows[0]
}

// A reported policy is stored and its digest extracted for cheap comparison.
func TestHeartbeatStoresReportedPolicy(t *testing.T) {
	s := newMemStore()
	srv := &server{store: s}

	if code := postHeartbeat(t, srv, `{"instance":"fw-1","policy":{"digest":"abc123","chains":[],"values":{}}}`); code != http.StatusAccepted {
		t.Fatalf("POST /v1/health = %d, want 202", code)
	}

	h := onlyHealth(t, s)
	if h.PolicyDigest != "abc123" {
		t.Errorf("policy_digest = %q, want abc123 — without it, comparing replicas means deep-comparing three rule chains", h.PolicyDigest)
	}
	if len(h.Policy) == 0 {
		t.Error("the policy document was not stored")
	}
}

// OPAQUE STORAGE MUST NOT LOSE FIELDS IT DOES NOT KNOW.
//
// This is the reason the control plane stores the document verbatim rather than decoding
// it into a parallel struct. The firewall owns the policy's shape; if this service modelled
// it, then the day the firewall added a field, the control plane would silently drop it and
// the console would render an incomplete policy — with nothing anywhere reporting a
// problem.
//
// Sabotage check: decode into a typed struct and re-marshal on the way out, and the unknown
// field disappears here.
func TestReportedPolicyIsStoredVerbatim(t *testing.T) {
	s := newMemStore()
	srv := &server{store: s}

	const doc = `{"digest":"d1","chains":[],"values":{},"a_field_this_service_has_never_heard_of":{"nested":[1,2,3]}}`
	if code := postHeartbeat(t, srv, `{"instance":"fw-1","policy":`+doc+`}`); code != http.StatusAccepted {
		t.Fatalf("POST = %d, want 202", code)
	}

	h := onlyHealth(t, s)
	if !strings.Contains(string(h.Policy), "a_field_this_service_has_never_heard_of") {
		t.Errorf("an unknown field was dropped in storage; the control plane must not model the policy:\n got %s", h.Policy)
	}
	if !strings.Contains(string(h.Policy), `"nested":[1,2,3]`) {
		t.Errorf("nested unknown content was lost:\n got %s", h.Policy)
	}
}

// A POLICY WE CANNOT READ MUST NOT COST US THE HEARTBEAT.
//
// The policy is an optional, informational field; liveness is not. If an unparseable
// policy report caused the beat to be rejected, a firewall that was perfectly healthy — and
// still gating traffic correctly — would go silent, and C4b's instance_silent alert would
// fire a critical outage for a reporting bug. The failure has to stay confined to the field
// that failed.
//
// Sabotage check: return an error from policyDigestOf and reject the beat on it; this test
// then sees a 400 and no stored row.
func TestUnreadablePolicyStillLandsTheHeartbeat(t *testing.T) {
	s := newMemStore()
	srv := &server{store: s}

	// Valid JSON at the envelope level (or the whole body would be malformed), but the
	// policy is a string where a document is expected.
	if code := postHeartbeat(t, srv, `{"instance":"fw-1","audit_dropped":2,"policy":"not-a-policy-document"}`); code != http.StatusAccepted {
		t.Fatalf("POST = %d, want 202 — an unreadable policy must not cost the replica its liveness signal", code)
	}

	h := onlyHealth(t, s)
	if h.PolicyDigest != "" {
		t.Errorf("policy_digest = %q, want empty for an unreadable document", h.PolicyDigest)
	}
	if h.AuditDropped != 2 {
		t.Errorf("audit_dropped = %d, want 2 — the rest of the heartbeat must survive intact", h.AuditDropped)
	}
}

// A heartbeat with no policy is exactly the heartbeat we always had, and must not
// materialise an empty document.
func TestHeartbeatWithoutPolicyIsUnchanged(t *testing.T) {
	s := newMemStore()
	srv := &server{store: s}

	if code := postHeartbeat(t, srv, `{"instance":"fw-1","flow_dropped":3}`); code != http.StatusAccepted {
		t.Fatalf("POST = %d, want 202", code)
	}

	h := onlyHealth(t, s)
	if len(h.Policy) != 0 {
		t.Errorf("policy = %q, want absent — a replica that reported none must not look like it reported an empty one", h.Policy)
	}

	// ...and it must be OMITTED from the JSON, not rendered as null, so the console can
	// distinguish "not reported" from "reported nothing".
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v1/health", nil))
	if strings.Contains(rec.Body.String(), "policy") {
		t.Errorf("absent policy still appears in the response body: %s", rec.Body.String())
	}
}

// The whole point: what a replica reports must come back out, so the console can render it.
func TestReportedPolicyIsServedBack(t *testing.T) {
	s := newMemStore()
	srv := &server{store: s}
	postHeartbeat(t, srv, `{"instance":"fw-1","policy":{"digest":"d9","chains":[{"name":"verdict","default_action":"reject","rules":[]}],"values":{"score_threshold":"5"}}}`)

	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v1/health", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /v1/health = %d, want 200", rec.Code)
	}

	var rows []InstanceHealth
	if err := json.Unmarshal(rec.Body.Bytes(), &rows); err != nil {
		t.Fatalf("decode: %v (body %q)", err, rec.Body.String())
	}
	if len(rows) != 1 || rows[0].PolicyDigest != "d9" {
		t.Fatalf("digest did not survive the round trip: %s", rec.Body.String())
	}
	if !strings.Contains(string(rows[0].Policy), `"score_threshold":"5"`) {
		t.Errorf("policy values did not survive the round trip: %s", rows[0].Policy)
	}
}

// DIVERGENCE IS DETECTABLE FROM WHAT IS STORED. This is what D3's policy_divergent alert
// will read, so the data has to support the question before the alert is built — otherwise
// the alert gets written against a field that cannot answer it.
func TestReplicasWithDifferentPolicyAreDistinguishable(t *testing.T) {
	s := newMemStore()
	srv := &server{store: s}
	postHeartbeat(t, srv, `{"instance":"fw-1","policy":{"digest":"aaa"}}`)
	postHeartbeat(t, srv, `{"instance":"fw-2","policy":{"digest":"bbb"}}`)
	postHeartbeat(t, srv, `{"instance":"fw-3","policy":{"digest":"aaa"}}`)

	rows, err := s.ListInstanceHealth()
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	seen := map[string]int{}
	for _, h := range rows {
		seen[h.PolicyDigest]++
	}
	if len(seen) != 2 {
		t.Fatalf("want 2 distinct policies across 3 replicas, got %v", seen)
	}
	if seen["aaa"] != 2 || seen["bbb"] != 1 {
		t.Errorf("digests did not group as reported: %v", seen)
	}
}
