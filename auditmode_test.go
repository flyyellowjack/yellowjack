package main

import "testing"

// Tier 1 for #114: the audit record says what the gate DID beside what it DECIDED, and
// why the two differ, so a report-mode record is machine-distinguishable from a real
// block without reading a log line.

func TestAuditRecordDistinguishesReportModeFromARealBlock(t *testing.T) {
	refused := Decision{Allowed: false, Deny: denyScore, Rule: "terminal", Source: "policy x", Reason: "too low"}
	for _, tc := range []struct {
		name, mode, wantTaken, wantMode string
		d                               Decision
	}{
		{"enforce: a block is taken", "", "block", "enforce", refused},
		{"enforce: an allow is taken", "", "allow", "enforce", Decision{Allowed: true, Reason: "fine"}},
		{"report: a block is decided but NOT taken", modeReport, "allow", "report", refused},
		{"report: an allow is an allow", modeReport, "allow", "report", Decision{Allowed: true, Reason: "fine"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := &auditEmitter{ch: make(chan auditEvent, 2)}
			f := &Firewall{cfg: Config{Ecosystem: "npm", Mode: tc.mode}, audit: a}
			f.auditVerdict("pkg", "10.0.0.1", tc.d)
			ev := <-a.ch
			wantAction := "allow"
			if !tc.d.Allowed {
				wantAction = "block"
			}
			if ev.Action != wantAction {
				t.Errorf("action = %q, want the VERDICT %q -- report mode must not rewrite what was decided", ev.Action, wantAction)
			}
			if ev.Taken != tc.wantTaken || ev.Mode != tc.wantMode {
				t.Errorf("taken/mode = %q/%q, want %q/%q", ev.Taken, ev.Mode, tc.wantTaken, tc.wantMode)
			}
		})
	}
}
