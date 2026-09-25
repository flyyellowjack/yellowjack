package main

import (
	"strings"
	"testing"
)

// The deny-list and known-malware reasons say "refused without contacting upstream".
// That is true on every 403 transport -- npm, Maven and OCI answer the request without
// a relay, and the reference deployment's registry stand-ins never see the name. It is
// FALSE on PyPI's index. A PyPI block is deliberately a RELAY of the real /simple/
// index with every release marked PEP 592 yanked (D22, !16), so pip prints the reason
// instead of silently backtracking other packages; that page cannot be built without
// fetching the version list. Measured 2026-09-13 in the reference deployment: the
// deny-listed package's /simple/ page was fetched from the customer's registry
// (82,826 bytes, from the gate's IP) while the header on the same response claimed
// no upstream contact. The artifact bytes were not fetched, which is the half that
// matters and the half the wording should say.
//
// The fix is at the one place the yank text is produced, not in the four reasons
// themselves: the log line and the audit record keep the verdict's own reason, and
// only the text DELIVERED on the yank transport is corrected to what that transport
// actually did.
func TestPypiYankReasonTellsTheTruthAboutUpstreamContact(t *testing.T) {
	const clause = "refused without contacting upstream"
	deny := `package "requests" is on this organisation's deny list; ` + clause +
		`. This is a local policy decision, not a published malware advisory -- ask whoever maintains the firewall's deny list`
	malware := `package "requests" is listed as known malware (MAL-2026-1); ` + clause
	plain := `package "requests" scored 2.1, below required 5.0`

	for _, tc := range []struct{ name, in string }{
		{"operator deny list", deny},
		{"known-malware feed", malware},
	} {
		got := yankDeliveredReason(tc.in)
		if strings.Contains(got, clause) {
			t.Errorf("%s: the delivered yank reason still claims %q, which is false on the yank "+
				"transport -- the index was fetched to list the releases to yank", tc.name, clause)
		}
		if !strings.Contains(got, "index was fetched") || !strings.Contains(got, "no artifact bytes") {
			t.Errorf("%s: the delivered reason must say what actually happened (index fetched, no "+
				"bytes), got %q", tc.name, got)
		}
		// The rest of the sentence -- who decided, what to do -- must survive intact.
		if !strings.Contains(got, `package "requests"`) {
			t.Errorf("%s: the package name was lost: %q", tc.name, got)
		}
	}
	if got := yankDeliveredReason(plain); got != plain {
		t.Errorf("a reason without the clause must pass through unchanged; got %q", got)
	}

	// Negative control: the RAW reasons really do carry the false clause, so the
	// assertions above are capable of failing. Without this, a future reword of the
	// deny reason that dropped the clause would leave every check here vacuous.
	for _, raw := range []string{deny, malware} {
		if !strings.Contains(raw, clause) {
			t.Fatalf("fixture no longer contains %q; this test proves nothing about the substitution", clause)
		}
	}
}
