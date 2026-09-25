package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// TIER 3 (adversarial) for the queue age (#50).
//
// The feature's whole purpose is to make a growing backlog VISIBLE. So the attack to try
// is not "can I crash it" but "can I make a package that has been waiting forever look
// fresh, so the operator watching for old items never sees it".
//
// The queue's age comes from a FirstSeen the approval service stores, and PUT
// /v1/decisions decodes a full Decision from its body — firstSeen included. Whoever can
// reach that endpoint chooses the timestamp on a package that has no record yet.

func advGet(t *testing.T, srv *server) string {
	t.Helper()
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/decisions", nil))
	return rec.Body.String()
}

// TestAFutureFirstSeenCannotDisguiseAnOldQueueEntry.
//
// A FirstSeen in the future makes now.Sub(FirstSeen) negative. Clamping that to zero
// renders "under a minute" — and it keeps rendering "under a minute" forever, because
// the value never ages. A package parked with firstSeen = year 2400 would sit in the
// queue permanently while displaying as the newest arrival.
//
// The clamp is right for CLOCK SKEW (two services, seconds apart) and wrong for anything
// beyond it: a timestamp years ahead is not skew, it is corrupt or hostile data, and
// showing it as "fresh" is the single most useful lie to tell this page.
func TestAFutureFirstSeenCannotDisguiseAnOldQueueEntry(t *testing.T) {
	now := time.Now().UTC()
	fa := &fakeApproval{decisions: []decision{{
		Package:   "parked-forever",
		Verdict:   "pending",
		FirstSeen: now.Add(365 * 24 * time.Hour), // a year in the future
		UpdatedAt: now.Add(-90 * 24 * time.Hour), // recorded 90 days ago
	}}}
	body := advGet(t, newTestServer(fa))

	if strings.Contains(body, "under a minute") {
		t.Error("a package with a FUTURE enqueue time renders as 'under a minute'. It will " +
			"render that way forever, so an entry parked in the queue permanently displays " +
			"as the newest arrival — exactly the appearance an unbounded queue needs to " +
			"stay invisible.")
	}
	if !strings.Contains(body, "unknown") && !strings.Contains(body, "impossible") {
		t.Error("the impossible timestamp is not surfaced as suspect; it must not be " +
			"silently normalised into a plausible-looking small number")
	}
}

// TestSmallClockSkewIsStillToleratedIsTheCONTROL for the test above.
//
// Without this, "reject anything in the future" would fire on every deployment where the
// approval service's clock runs a second ahead of the console's — turning a normal
// two-process system into a page full of warnings, which is how a real warning gets
// ignored.
func TestSmallClockSkewIsStillTolerated(t *testing.T) {
	now := time.Now().UTC()
	fa := &fakeApproval{decisions: []decision{{
		Package: "skewed", Verdict: "pending",
		FirstSeen: now.Add(2 * time.Second),
		UpdatedAt: now,
	}}}
	body := advGet(t, newTestServer(fa))

	if strings.Contains(body, "unknown") || strings.Contains(body, "impossible") {
		t.Error("two seconds of clock skew between two services was treated as corrupt " +
			"data; this would warn on healthy deployments")
	}
}

// TestPackageNameCannotInjectMarkupIntoTheQueue.
//
// The package name is fully attacker-chosen: anyone can publish one. It reaches an
// operator's browser on this page. html/template should contextually escape it, but the
// claim is worth an assertion rather than an assumption — a single {{...}} moved into an
// unquoted attribute or a raw-HTML context would silently undo it.
func TestPackageNameCannotInjectMarkupIntoTheQueue(t *testing.T) {
	payloads := []string{
		`<script>alert(1)</script>`,
		`" onmouseover="alert(1)`,
		`'><img src=x onerror=alert(1)>`,
		`javascript:alert(1)`,
		`</textarea><script>alert(1)</script>`,
	}
	for _, p := range payloads {
		fa := &fakeApproval{decisions: []decision{{
			Package: p, Verdict: "pending", Note: p, DecidedBy: p,
			FirstSeen: time.Now().UTC().Add(-time.Hour), UpdatedAt: time.Now().UTC(),
		}}}
		body := advGet(t, newTestServer(fa))

		// Assert on LIVE MARKUP, not on substrings. An escaped payload still contains
		// "onerror=alert(1)" as text -- &#39;&gt;&lt;img src=x onerror=alert(1)&gt; -- so a
		// substring check reports an XSS that does not exist. The question is whether an
		// unescaped TAG or ATTRIBUTE reached the document, so look for the delimiters that
		// would have to survive for that to be true.
		for _, live := range []string{"<script", "<img", "<textarea", `onerror=`, `onmouseover=`} {
			if strings.Contains(body, live) && !strings.Contains(body, "&lt;"+strings.TrimPrefix(live, "<")) {
				// Only a real finding if the dangerous token is present AND its escaped
				// twin is not -- i.e. it was not merely rendered as text.
				if strings.HasPrefix(live, "<") {
					t.Errorf("XSS: package name %q put a live %s tag in the document", p, live)
				}
			}
		}
		if strings.Contains(body, `"><img`) || strings.Contains(body, "<script>alert(1)</script>") {
			t.Errorf("XSS: package name %q broke out of its element", p)
		}
	}
}

// TestRepoURLCannotBecomeAJavascriptLink.
//
// The queue renders the repo URL as an <a href>. That URL comes from package metadata —
// the publisher writes it. A javascript: URL there is a one-click XSS aimed squarely at
// the person reviewing the malicious package.
func TestRepoURLCannotBecomeAJavascriptLink(t *testing.T) {
	for _, u := range []string{"javascript:alert(1)", "JaVaScRiPt:alert(1)", "data:text/html,<script>alert(1)</script>"} {
		fa := &fakeApproval{decisions: []decision{{
			Package: "evil", Verdict: "pending", RepoURL: u,
			FirstSeen: time.Now().UTC().Add(-time.Hour), UpdatedAt: time.Now().UTC(),
		}}}
		body := advGet(t, newTestServer(fa))

		if strings.Contains(body, `href="javascript:`) || strings.Contains(body, `href="JaVaScRiPt:`) ||
			strings.Contains(body, `href="data:text/html`) {
			t.Errorf("the reviewer's own page offers a clickable %q link", u)
		}
	}
}
