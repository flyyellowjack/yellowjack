package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestLookupScore verifies the firewall reads the three L2 states correctly: a 404
// is cold (never scanned), a numeric score is a real result, and a null score is
// the negative "scanned-but-unscorable" marker.
func TestLookupScore(t *testing.T) {
	var body string // what the fake /v1/scores GET returns
	status := http.StatusOK
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if status != http.StatusOK {
			http.Error(w, "x", status)
			return
		}
		w.Write([]byte(body))
	}))
	defer srv.Close()

	f := &Firewall{cfg: Config{ApprovalURL: srv.URL}, client: srv.Client()}

	// Cold: 404 -> found=false.
	status = http.StatusNotFound
	if _, hasScore, found, _, err := f.lookupScore("github.com/a/b"); err != nil || found || hasScore {
		t.Fatalf("cold = (hasScore=%v, found=%v, err=%v), want (false,false,nil)", hasScore, found, err)
	}

	// Positive: a numeric score, with the write time carried through for the
	// freshness window (issue #12).
	status = http.StatusOK
	body = `{"repo":"github.com/a/b","score":7.5,"updatedAt":"2026-07-24T00:00:00Z"}`
	score, hasScore, found, updatedAt, err := f.lookupScore("github.com/a/b")
	if err != nil || !found || !hasScore || score != 7.5 {
		t.Fatalf("positive = (score=%v, hasScore=%v, found=%v, err=%v), want (7.5,true,true,nil)", score, hasScore, found, err)
	}
	if updatedAt.IsZero() {
		t.Error("positive lookup should parse updatedAt, got zero")
	}

	// Negative marker: null score, present row.
	body = `{"repo":"github.com/x/y","score":null}`
	if _, hasScore, found, _, err := f.lookupScore("github.com/x/y"); err != nil || !found || hasScore {
		t.Fatalf("negative = (hasScore=%v, found=%v, err=%v), want (false,true,nil)", hasScore, found, err)
	}
}

// TestRecordScore verifies the firewall PUTs the right body for both a successful
// score and the negative marker (nil score serializes to JSON null).
func TestRecordScore(t *testing.T) {
	var got scoreRecord
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut {
			t.Errorf("method = %s, want PUT", r.Method)
		}
		_ = json.NewDecoder(r.Body).Decode(&got)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	f := &Firewall{cfg: Config{ApprovalURL: srv.URL}, client: srv.Client()}

	f.recordScore("github.com/a/b", 8.0, scoreCoverage{})
	if got.Repo != "github.com/a/b" || got.Score == nil || *got.Score != 8.0 {
		t.Fatalf("recordScore sent %+v, want repo a/b score 8.0", got)
	}

	got = scoreRecord{}
	f.recordScoreUnscorable("github.com/x/y")
	if got.Repo != "github.com/x/y" || got.Score != nil {
		t.Fatalf("recordScoreUnscorable sent %+v, want repo x/y score nil", got)
	}
}

// TestLookupRefusesAForeignRecord pins the identity rule on both approval reads: a
// response about a DIFFERENT package (or repo) than the one asked about is a fault in
// the control plane, not a decision, and must never be applied.
//
// Why this test exists at all: the request key says what was ASKED and nothing about
// what came BACK, and for a long time nothing checked. The same shape as issue #67,
// one layer up — there a URL prefix was treated as authoritative about which bytes were
// served, here the query string would be authoritative about which ruling was returned.
//
// The pairs below are deliberately ordered so the MATCHING case runs first in each
// block. Without it the test would pass just as well against a client that refused
// everything, which is the vacuity an "assert it rejects" test invites.
func TestLookupRefusesAForeignRecord(t *testing.T) {
	var body string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(body))
	}))
	defer srv.Close()
	f := &Firewall{cfg: Config{ApprovalURL: srv.URL}, client: srv.Client()}

	t.Run("decisions", func(t *testing.T) {
		// Anti-vacuity: the honest answer is still accepted.
		body = `{"package":"left-pad","verdict":"approved"}`
		d, found, err := f.lookupApproval("left-pad")
		if err != nil || !found || d.Verdict != "approved" {
			t.Fatalf("matching record = (%+v, found=%v, err=%v), want it accepted", d, found, err)
		}

		// The defect: a ruling about another package must not become this one's.
		body = `{"package":"lodash","verdict":"approved"}`
		if _, found, err := f.lookupApproval("left-pad"); err == nil || found {
			t.Errorf("a record for lodash was accepted as a ruling on left-pad (found=%v, err=%v) — "+
				"this is the confused deputy: an approval for any package would open the gate for every package", found, err)
		} else if !strings.Contains(err.Error(), "left-pad") || !strings.Contains(err.Error(), "lodash") {
			t.Errorf("the error must name BOTH the package asked about and the one returned, or an operator "+
				"cannot tell which side is wrong; got %v", err)
		}

		// Empty is not a pass. An absent `package` field is not evidence the record is ours.
		body = `{"verdict":"approved"}`
		if _, found, err := f.lookupApproval("left-pad"); err == nil || found {
			t.Errorf("a record with NO package field was accepted for left-pad (found=%v, err=%v); "+
				"treating empty as a match is how !91's empty-deny-kind bug worked", found, err)
		}
	})

	t.Run("scores", func(t *testing.T) {
		body = `{"repo":"github.com/a/b","score":7.5}`
		score, hasScore, found, _, err := f.lookupScore("github.com/a/b")
		if err != nil || !found || !hasScore || score != 7.5 {
			t.Fatalf("matching record = (%v,%v,%v,%v), want it accepted", score, hasScore, found, err)
		}

		// Borrow-a-score (#10/D33) arriving through our own control plane instead of
		// through publisher metadata.
		body = `{"repo":"github.com/lodash/lodash","score":9.9}`
		if _, _, found, _, err := f.lookupScore("github.com/evil/pkg"); err == nil || found {
			t.Errorf("a score recorded against lodash was accepted for github.com/evil/pkg (found=%v, err=%v) — "+
				"that is borrow-a-score through the L2 cache", found, err)
		}
	})
}
