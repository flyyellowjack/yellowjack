package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// The verdict's inputs on the OPERATOR'S screen (#28), not only in the export.
//
// The export makes the record auditable months later; this makes it readable now.
// They are different jobs: a score of 4.2 with no bar beside it does not tell an
// operator whether that row was a near-miss or a landslide, which is the first
// question anyone scanning this table has.

func auditPage(t *testing.T, evs []event) string {
	t.Helper()
	rr := httptest.NewRecorder()
	newTestServer(&fakeApproval{events: evs}).ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/audit", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("audit status = %d, want 200", rr.Code)
	}
	return rr.Body.String()
}

// TestTheAuditPageShowsWhatTheScoreWasWeighedAgainst.
func TestTheAuditPageShowsWhatTheScoreWasWeighedAgainst(t *testing.T) {
	score, threshold := 4.2, 5.0
	body := auditPage(t, []event{{
		ID: 1, Package: "evil-pkg", Ecosystem: "npm", Action: "block",
		Score: &score, Threshold: &threshold, PolicyDigest: "1f1dc1072d3176a5",
		Reason: "score below threshold", At: time.Now(),
	}})

	for _, want := range []string{"4.2", "5.0", "1f1dc1072d3176a5", "Threshold", "Policy"} {
		if !strings.Contains(body, want) {
			t.Errorf("the audit page does not show %q — the operator sees a verdict without "+
				"the inputs that produced it, and has to open the export to check it", want)
		}
	}
}

// TestAVerdictWithNoThresholdShowsADashNotAZero — the same "no bare 0.0" discipline
// the existing score column already has, for the same reason. A known-malware refusal
// weighed no bar; rendering "0.0" would tell the operator the threshold was zero,
// i.e. that the gate lets everything through.
func TestAVerdictWithNoThresholdShowsADashNotAZero(t *testing.T) {
	body := auditPage(t, []event{{
		ID: 1, Package: "evil-pkg", Ecosystem: "npm", Action: "block",
		PolicyDigest: "1f1dc1072d3176a5", Reason: "listed as known malware", At: time.Now(),
	}})

	if strings.Contains(body, "0.0") {
		t.Error("a verdict that weighed no threshold rendered a numeric bar; an operator " +
			"reads that as a threshold of zero rather than as 'no threshold applied'")
	}
	// Anti-vacuity: the row must actually be on the page. Without this the assertion
	// above passes for a page that rendered no events at all.
	if !strings.Contains(body, "evil-pkg") || !strings.Contains(body, "badge block") {
		t.Fatal("the event is not on the page, so the assertion above proves nothing")
	}
}

// TestTwoVerdictsUnderDifferentPoliciesAreDistinguishable is the NEGATIVE CONTROL for
// showing the policy at all.
//
// If the column rendered a constant — or the same digest for every row — an operator
// scanning the log could not tell that the policy changed midway through an incident,
// which is exactly the question the column exists to answer.
func TestTwoVerdictsUnderDifferentPoliciesAreDistinguishable(t *testing.T) {
	body := auditPage(t, []event{
		{ID: 2, Package: "a-pkg", Action: "allow", PolicyDigest: "aaaa1111", At: time.Now()},
		{ID: 1, Package: "b-pkg", Action: "block", PolicyDigest: "bbbb2222", At: time.Now()},
	})
	if !strings.Contains(body, "aaaa1111") || !strings.Contains(body, "bbbb2222") {
		t.Error("two verdicts made under different policies render the same on the page, so " +
			"a policy change during an incident is invisible to the operator reading the log")
	}
}
