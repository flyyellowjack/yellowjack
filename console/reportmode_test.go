package main

import (
	"strings"
	"testing"
	"time"
)

// #114 made a report-mode block distinguishable on the wire (action=block, taken=allow,
// mode=report). The control plane never stored those two fields (found by
// auditwire_test.go while fixing the same drop for deny_kind/rule/source), so this page
// showed a plain "block" for a package that was delivered. Now that they are stored, the
// row must say so -- and must NOT say so for a real block (the control).
func TestAReportModeBlockSaysItWasServed(t *testing.T) {
	f := &fakeApproval{events: []event{
		{ID: 1, Package: "left-pad", Action: "block", Taken: "allow", Mode: "report", At: time.Now()},
		{ID: 2, Package: "evil", Action: "block", Taken: "block", Mode: "enforce", At: time.Now()},
	}}
	body := auditPageAs(t, newTestServer(f), "", "")
	if n := strings.Count(body, "served — report mode"); n != 1 {
		t.Fatalf("%d row(s) marked served, want exactly 1: the report-mode block and not the enforced one", n)
	}
	// The marker must sit on the report-mode row, not merely somewhere on the page.
	rows := strings.Split(body, "<tr>")
	for _, row := range rows {
		if strings.Contains(row, ">left-pad<") && !strings.Contains(row, "served — report mode") {
			t.Error("the left-pad row (report mode, delivered) reads as a plain block")
		}
		if strings.Contains(row, ">evil<") && strings.Contains(row, "served — report mode") {
			t.Error("the evil row (enforced) is marked as served")
		}
	}
}
