package main

import (
	"net/http"
	"strings"
	"testing"
	"time"
)

// A list whose NAMES were shed is not a list with no ENTRIES.
//
// The gate drops operator-list names from a heartbeat that would otherwise exceed the
// control plane's size cap (#139): it keeps the count in `omitted` and the digest, and
// sends no names. The page rendered its truncation note only inside `{{ if .Names }}`, so
// that report fell through to the empty-list branch and told the operator:
//
//	"Configured, but it loaded zero entries ... Check the file this replica mounted."
//
// for a list enforcing hundreds of entries. It was found by the two-binary rig
// (e2e/async_local.sh leg 28) and NOT by the unit tests that shipped with the shedding,
// which asserted the report's fields and never rendered them. This is that missing test.
func policyPageWithList(t *testing.T, l policyList) string {
	t.Helper()
	doc := shippedPolicyDoc("abc")
	doc.Lists = []policyList{l}
	rec := getPolicyPage(t, &fakeApproval{health: []instanceHealth{{
		Instance: "fw-1", Ecosystem: "npm", ReportedAt: time.Now().UTC(), PolicyDigest: "abc", Policy: doc,
	}}})
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /policy = %d, want 200", rec.Code)
	}
	return rec.Body.String()
}

const (
	zeroEntriesText = "loaded <strong>zero</strong> entries"
	shedText        = "entries are loaded and enforced"
	truncatedText   = "more not shown"
)

func TestAShedListIsNotRenderedAsAnEmptyOne(t *testing.T) {
	const digest = "0123456789abcdef0123456789abcdef"

	shed := policyPageWithList(t, policyList{Kind: "deny", Path: "/etc/yellowjack/lists/deny.txt", Omitted: 250, Digest: digest})
	if strings.Contains(shed, zeroEntriesText) {
		t.Error("a list with 250 entries loaded and no names reported is rendered as having loaded ZERO entries, " +
			"and the operator is sent to check a mount that is fine")
	}
	if !strings.Contains(shed, shedText) || !strings.Contains(shed, "<strong>250</strong>") {
		t.Errorf("the page must say HOW MANY entries are in force and that their names are withheld; got no such text")
	}
	if !strings.Contains(shed, "Enforcement is unaffected") {
		t.Error("the page must say enforcement is unaffected: the first question an operator has on seeing no names")
	}

	// CONTROLS: the two neighbouring states must keep their own rendering, or the new
	// branch has simply moved the wrong message somewhere else.
	empty := policyPageWithList(t, policyList{Kind: "deny", Path: "/etc/yellowjack/lists/deny.txt", Digest: digest})
	if !strings.Contains(empty, zeroEntriesText) || strings.Contains(empty, shedText) {
		t.Error("a list that really loaded zero entries must still say so, and must not claim entries are enforced")
	}
	truncated := policyPageWithList(t, policyList{Kind: "deny", Path: "/etc/yellowjack/lists/deny.txt",
		Names: []string{"left-pad", "event-stream"}, Omitted: 50, Digest: digest})
	if !strings.Contains(truncated, truncatedText) || !strings.Contains(truncated, "left-pad") ||
		strings.Contains(truncated, shedText) || strings.Contains(truncated, zeroEntriesText) {
		t.Error("a list reported WITH names and an omitted tail must show the names and the 'more not shown' note, and neither other message")
	}
}
