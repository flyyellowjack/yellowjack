package main

import (
	"strings"
	"testing"
	"time"
)

// #154: the audit page marks a verdict whose score was a PARTIAL measurement, with the
// denominator and the checks it was computed without, and does not mark a full one.
func TestAPartialScoreIsMarkedOnTheAuditRow(t *testing.T) {
	s1, s2 := 6.2, 6.2
	f := &fakeApproval{events: []event{
		{ID: 1, Package: "partial-pkg", Action: "allow", Score: &s1, At: time.Now(),
			ScoredChecks: 15, TotalChecks: 18, ComputedWithout: []string{"CI-Tests", "Contributors", "License"}},
		{ID: 2, Package: "full-pkg", Action: "allow", Score: &s2, At: time.Now()},
	}}
	body := auditPageAs(t, newTestServer(f), "", "")
	if n := strings.Count(body, ">partial<"); n != 1 {
		t.Fatalf("%d row(s) marked partial, want exactly 1", n)
	}
	for _, row := range strings.Split(body, "<tr>") {
		switch {
		case strings.Contains(row, ">partial-pkg<"):
			if !strings.Contains(row, ">partial<") || !strings.Contains(row, "15 of 18 checks; without CI-Tests, Contributors, License") {
				t.Error("the partial-pkg row does not say what its 6.2 was computed over")
			}
		case strings.Contains(row, ">full-pkg<"):
			if strings.Contains(row, "partial") {
				t.Error("the full-pkg row (same 6.2, full coverage) is marked partial")
			}
		}
	}
}
