package main

import (
	"net/http"
	"testing"
)

// D346: npm's version filter refuses inside the relay, after Evaluate allowed the
// package. The one audit record for the request must say what the client got.

const pinBoth = `{"id":"MAL-NPM-ALL","ecosystem":"npm","name":"pkg","versions":["1.0.0","2.0.0"]}`

func onlyAuditEvent(t *testing.T, a *auditEmitter) auditEvent {
	t.Helper()
	evs := drainAudit(a)
	if len(evs) != 1 {
		t.Fatalf("audit events = %d, want exactly 1 per request: %+v", len(evs), evs)
	}
	return evs[0]
}

func TestNpmFilterRefusalReplacesTheAuditedAllow(t *testing.T) {
	up, _ := npmVersionedUpstream(t, "pkg", "1.0.0", "2.0.0")
	defer up.Close()
	p := pinnedProxy(t, up, pinBoth)
	a := captureAudit(p)

	if rec := getFrom(t, p, "/pkg"); rec.Code != http.StatusForbidden {
		t.Fatalf("a packument with every version pinned was not refused: %d", rec.Code)
	}
	e := onlyAuditEvent(t, a)
	if e.Action != auditActionBlock || e.Taken != auditActionBlock {
		t.Errorf("the client got a 403 and the record says action=%q taken=%q", e.Action, e.Taken)
	}
	if e.DenyKind != string(denyKnownMalware) || e.Rule != "MAL-NPM-ALL" {
		t.Errorf("the record does not carry the filter's verdict: %+v", e)
	}

	// CONTROL: with a compliant version left the packument is served, filtered, and the
	// record is Evaluate's allow -- the hold changes nothing on the path it does not own.
	up2, _ := npmVersionedUpstream(t, "pkg", "1.0.0", "2.0.0")
	defer up2.Close()
	p2 := pinnedProxy(t, up2, pinTwo)
	a2 := captureAudit(p2)
	if rec := getFrom(t, p2, "/pkg"); rec.Code != http.StatusOK {
		t.Fatalf("a packument with a compliant version left was refused: %d", rec.Code)
	}
	if e := onlyAuditEvent(t, a2); e.Action != auditActionAllow || e.DenyKind != "" {
		t.Errorf("a served packument was not recorded as an allow: %+v", e)
	}
}

// Under FW_MODE=report the unfiltered document is served, and the record says what the
// gate WOULD have done: action=block, taken=allow.
func TestNpmFilterRefusalUnderReportModeIsRecordedAsWouldBlock(t *testing.T) {
	up, _ := npmVersionedUpstream(t, "pkg", "1.0.0", "2.0.0")
	defer up.Close()
	feed := writeFeed(t, pinBoth)
	p := newTestProxy(t, up, func(c *Config) {
		c.MalwareListPath = feed
		c.UnscorablePolicy = "allow"
		c.Mode = modeReport
	})
	a := captureAudit(p)

	if rec := getFrom(t, p, "/pkg"); rec.Code != http.StatusOK {
		t.Fatalf("report mode refused the packument: %d", rec.Code)
	}
	e := onlyAuditEvent(t, a)
	if e.Action != auditActionBlock || e.Taken != auditActionAllow || e.Mode != modeReport {
		t.Errorf("report mode record = action %q taken %q mode %q, want block/allow/report", e.Action, e.Taken, e.Mode)
	}
}

// overruleVerdict is inert without an armed hold: a refusal reached on a path whose own
// control point already recorded a verdict must not rewrite that record.
func TestOverruleVerdictNeedsAnArmedHold(t *testing.T) {
	r, h := withVerdictHold(httptestRequest())
	if overruleVerdict(r, Decision{Allowed: false}) {
		t.Fatal("an unarmed hold was overruled")
	}
	h.armed, h.d = true, Decision{Allowed: true}
	if !overruleVerdict(r, Decision{Allowed: false}) || h.d.Allowed {
		t.Fatal("an armed hold was not overruled")
	}
	if overruleVerdict(httptestRequest(), Decision{}) {
		t.Fatal("a request with no hold reported an overrule")
	}
}

func httptestRequest() *http.Request {
	r, _ := http.NewRequest(http.MethodGet, "http://fw.local/pkg", nil)
	return r
}
