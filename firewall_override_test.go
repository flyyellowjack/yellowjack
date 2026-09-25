package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestBelowThresholdOverride verifies D11 (2026-07-08): a below-threshold score is
// no longer a hard block — it routes through the approval service, where a human
// can override (approve/deny), and an un-ruled one is queued (recorded pending).
func TestBelowThresholdOverride(t *testing.T) {
	verdict := "" // "", "approved", or "denied"
	putCount := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			if verdict == "" {
				http.Error(w, "not found", http.StatusNotFound) // no ruling yet
				return
			}
			_ = json.NewEncoder(w).Encode(approvalDecision{
				Package: r.URL.Query().Get("package"),
				Verdict: verdict,
			})
		case http.MethodPut:
			putCount++ // recordPending queued it
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer srv.Close()

	f := &Firewall{
		cfg:    Config{ScoreThreshold: 5.0, ApprovalURL: srv.URL},
		client: srv.Client(),
	}

	// At/above threshold: allowed, no human needed.
	if d := f.decideByScore("lodash", 7.7, ""); !d.Allowed {
		t.Fatalf("7.7 >= 5.0 should be allowed, got blocked: %s", d.Reason)
	}

	// Below threshold, no ruling yet: blocked AND queued for review.
	verdict = ""
	if d := f.decideByScore("axios", 4.9, ""); d.Allowed {
		t.Fatal("4.9 with no ruling should be blocked, got allowed")
	}
	if putCount == 0 {
		t.Fatal("a below-threshold block should queue the package (recordPending)")
	}

	// Below threshold, human approved: overridden to allow.
	verdict = "approved"
	if d := f.decideByScore("axios", 4.9, ""); !d.Allowed {
		t.Fatalf("4.9 approved-by-human should be allowed, got blocked: %s", d.Reason)
	}

	// Below threshold, human denied: stays blocked.
	verdict = "denied"
	if d := f.decideByScore("axios", 4.9, ""); d.Allowed {
		t.Fatal("4.9 denied-by-human should be blocked, got allowed")
	}
}

// TestHumanDenyOutranksAPassingScore is the DELIBERATE REVERSAL of
// TestHumanDenyIsNotConsultedWhenPolicyAllows, which !281 wrote to pin the
// pre-D272 behaviour so this ruling would arrive as a visible change rather than a
// silent one. That test asserted the opposite of every line below: that a package
// the policy allows is returned before the approval service is asked, so a human
// "denied" recorded for it was stored, displayed, and never enforced (#132,
// measured on the reference deployment 2026-09-15 — the console said
// "override recorded: is-number -> denied" and the gate kept serving is-number).
//
// D272 (2026-09-19): the project, asked whether a person's explicit block should override
// a package that passes on its score — "yes". So the gate now consults a RECORDED
// deny on the allow path too.
//
// The instrument check is kept from the old test and still earns its place: it
// proves the same fake refuses on the refuse path, so neither assertion below can
// pass because the harness refuses everything.
func TestHumanDenyOutranksAPassingScore(t *testing.T) {
	lookups := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			lookups++
			_ = json.NewEncoder(w).Encode(approvalDecision{Package: r.URL.Query().Get("package"), Verdict: "denied"})
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	f := &Firewall{cfg: Config{ScoreThreshold: 5.0, ApprovalURL: srv.URL}, client: srv.Client()}

	// Instrument check: the same fake DOES refuse the package on the refuse path.
	if d := f.decideByScore("is-number", 4.9, ""); d.Allowed || lookups == 0 {
		t.Fatalf("below threshold with a human deny on record should be refused after a lookup (allowed=%v, lookups=%d)", d.Allowed, lookups)
	}
	lookups = 0

	d := f.decideByScore("is-number", 7.5, "")
	if d.Allowed {
		t.Fatalf("7.5 >= 5.0 with a human deny on record must be REFUSED (D272 reverses D11 for this case); got allowed: %s", d.Reason)
	}
	if lookups != 1 {
		t.Fatalf("the allow path must consult the approval service exactly once; it made %d lookup(s)", lookups)
	}
	// The refusal has to be legible as a HUMAN deny, not mistakable for a score
	// block: the console, the audit export and the block-reason wire format all key
	// off these, and a refusal the operator cannot attribute to their own ruling is
	// the same defect #132 reported with the sign flipped.
	if d.Deny != denyHuman {
		t.Fatalf("deny kind = %q, want %q — a human deny must not be reported as a score block", d.Deny, denyHuman)
	}
	if d.Rule != "approval:denied" || d.Source != sourceApproval {
		t.Fatalf("rule/source = %q/%q, want %q/%q", d.Rule, d.Source, "approval:denied", sourceApproval)
	}
	if !strings.Contains(d.Reason, "DENIED by human") || !strings.Contains(d.Reason, "7.5") {
		t.Fatalf("reason %q should name the human deny AND the score it overrode", d.Reason)
	}
}

// TestAnAllowedPackageIsNotQueued is the guard that makes the #132 fix a fix rather
// than an outage. The issue estimated the work as "a one-line move in decideByScore"
// — moving applyHumanRuling above the allow — and that literal move is wrong,
// because applyHumanRuling calls recordPending for every package it finds no ruling
// for. On the refuse path that is the point (someone must decide). On the allow path
// it would queue nearly every package a customer installs.
//
// So: an allowed package with no ruling on record must produce exactly one GET and
// zero writes. The instrument check proves the same fake DOES record a pending row
// when the refuse path asks it to, so "zero writes" cannot pass by the fake ignoring
// writes altogether.
func TestAnAllowedPackageIsNotQueued(t *testing.T) {
	gets, writes := 0, 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			gets++
			http.Error(w, "not found", http.StatusNotFound) // no ruling on record
			return
		}
		writes++
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	f := &Firewall{cfg: Config{ScoreThreshold: 5.0, ApprovalURL: srv.URL}, client: srv.Client()}

	if d := f.decideByScore("lodash", 7.7, ""); !d.Allowed {
		t.Fatalf("7.7 >= 5.0 with no ruling on record is still an allow (D11's other half stands); got %s", d.Reason)
	}
	if gets != 1 || writes != 0 {
		t.Fatalf("an allowed package must cost one lookup and queue NOTHING; got %d lookup(s), %d write(s) — "+
			"a write here means the allow path is queueing every package the policy allows", gets, writes)
	}

	// Instrument check: the same fake records a pending row when the REFUSE path
	// asks, so writes==0 above is a property of the allow path, not of the fake.
	if d := f.decideByScore("axios", 4.9, ""); d.Allowed {
		t.Fatal("4.9 with no ruling should still be blocked")
	}
	if writes == 0 {
		t.Fatal("instrument check failed: the refuse path did not record a pending row, so the allow path's zero writes prove nothing")
	}
}

// TestAnApprovedRulingDoesNotRewriteAnAllow pins the narrowness of D272. The ruling
// was about a DENY outranking a passing score; it said nothing about an approval,
// and a package the policy already allows gains nothing from one. If the allow path
// honoured "approved" it would overwrite the policy's own reason with "APPROVED by
// human" in the audit trail, attributing to a person a decision the policy made.
func TestAnApprovedRulingDoesNotRewriteAnAllow(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			_ = json.NewEncoder(w).Encode(approvalDecision{Package: r.URL.Query().Get("package"), Verdict: "approved"})
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	f := &Firewall{cfg: Config{ScoreThreshold: 5.0, ApprovalURL: srv.URL}, client: srv.Client()}

	d := f.decideByScore("lodash", 7.7, "")
	if !d.Allowed {
		t.Fatalf("7.7 >= 5.0 with an approval on record is allowed; got %s", d.Reason)
	}
	if strings.Contains(d.Reason, "by human") {
		t.Fatalf("reason %q credits a human for an allow the policy made on its own", d.Reason)
	}
}

// TestAnUnreachableApprovalStillServesAnAllowedPackage pins the fail-safe the allow
// path inherits from the refuse path, and the cost of it. A gate that refused every
// install whenever the approval service blinked would be worse than the defect #132
// reported — so an unreachable approval falls back to policy.
//
// The consequence is real and is written down rather than discovered: while approval
// is unreachable, a recorded human deny on an otherwise-passing package is NOT in
// force. The deny list is the mechanism that survives that outage.
func TestAnUnreachableApprovalStillServesAnAllowedPackage(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	client := srv.Client()
	srv.Close() // nothing is listening: every lookup is a transport error

	f := &Firewall{cfg: Config{ScoreThreshold: 5.0, ApprovalURL: srv.URL}, client: client}
	if d := f.decideByScore("lodash", 7.7, ""); !d.Allowed {
		t.Fatalf("an unreachable approval service must not break a passing pull; got %s", d.Reason)
	}

	// And with approval disabled entirely, the allow path makes no call at all.
	off := &Firewall{cfg: Config{ScoreThreshold: 5.0}}
	if d := off.decideByScore("lodash", 7.7, ""); !d.Allowed {
		t.Fatalf("with FW_APPROVAL_URL unset the allow path must not consult anything; got %s", d.Reason)
	}
}
