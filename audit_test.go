package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// With no approval URL, auditing is disabled: Emit is a harmless no-op and no
// background goroutine is started. This is what keeps every firewall test and any
// approval-less deployment running unchanged.
func TestAuditEmitterDisabled(t *testing.T) {
	a := newAuditEmitter("", nil, 8)
	if a.ch != nil {
		t.Error("empty approvalURL should leave the emitter disabled (nil channel)")
	}
	a.Emit(auditEvent{Package: "x", Action: auditActionAllow}) // must not panic or block
}

// An enabled emitter delivers the event to the approval service via a background
// POST, preserving the score pointer.
func TestAuditEmitterDelivers(t *testing.T) {
	got := make(chan auditEvent, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1/events" {
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
		}
		var e auditEvent
		json.NewDecoder(r.Body).Decode(&e)
		got <- e
		w.WriteHeader(http.StatusCreated)
	}))
	defer srv.Close()

	a := newAuditEmitter(srv.URL, srv.Client(), 8)
	score := 7.5
	a.Emit(auditEvent{Package: "left-pad", Ecosystem: "npm", Action: auditActionAllow, Score: &score, Reason: "ok", SourceIP: "203.0.113.5"})

	select {
	case e := <-got:
		if e.Package != "left-pad" || e.Action != auditActionAllow || e.Score == nil || *e.Score != 7.5 {
			t.Errorf("delivered event = %+v, want left-pad/allow/score=7.5", e)
		}
		if e.SourceIP != "203.0.113.5" {
			t.Errorf("delivered SourceIP = %q, want 203.0.113.5 (the source IP must survive the wire hop, #41)", e.SourceIP)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("emitter did not deliver the event within 2s")
	}
}

// auditVerdict must thread the observed source IP into the emitted event — the seam
// between the proxy (which sees the request) and the append-only log. A size-4
// buffer with no consumer lets us read exactly what was queued.
func TestAuditVerdictSetsSourceIP(t *testing.T) {
	a := &auditEmitter{ch: make(chan auditEvent, 4)}
	f := &Firewall{cfg: Config{Ecosystem: "npm"}, audit: a}

	f.auditVerdict("left-pad", "203.0.113.5", Decision{Allowed: true, Reason: "ok"})

	select {
	case e := <-a.ch:
		if e.Package != "left-pad" || e.Action != auditActionAllow {
			t.Errorf("queued event = %+v, want left-pad/allow", e)
		}
		if e.SourceIP != "203.0.113.5" {
			t.Errorf("queued SourceIP = %q, want 203.0.113.5", e.SourceIP)
		}
	default:
		t.Fatal("auditVerdict did not queue an event")
	}
}

// The core non-blocking guarantee: when the buffer is full, Emit drops and counts
// rather than blocking the caller. Constructed directly with a size-1 buffer and
// NO running consumer, so the second Emit deterministically hits the drop branch.
func TestAuditEmitterDropsWhenFull(t *testing.T) {
	a := &auditEmitter{ch: make(chan auditEvent, 1)}
	a.Emit(auditEvent{Package: "one", Action: auditActionAllow}) // fills the buffer
	a.Emit(auditEvent{Package: "two", Action: auditActionBlock}) // full -> dropped, not blocked
	if got := a.dropped.Load(); got != 1 {
		t.Errorf("dropped = %d, want 1 (second emit should drop on a full buffer)", got)
	}
}
