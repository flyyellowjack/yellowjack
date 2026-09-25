package main

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// TIER 3 (adversarial) for the developer package lookup (#73).
//
// The search box takes a string from a user and turns it into a request to the approval
// service. That is the shape of every SSRF and request-smuggling bug, so the questions
// are: can the typed string change WHICH endpoint we call, and can it change how the
// answer is READ once it comes back.

func lookupProbe(t *testing.T, fa *fakeApproval, rawQuery string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	srv := newTestServer(fa)
	srv.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/lookup?"+rawQuery, nil))
	return rec
}

// TestLookupCannotRedirectTheApprovalCall.
//
// The package name is concatenated into a URL. If it can inject a path segment, a query
// separator or a fragment, the operator's console can be aimed at a different endpoint —
// or a different host — by someone who only controls a search string.
func TestLookupCannotRedirectTheApprovalCall(t *testing.T) {
	attacks := []string{
		"../../v1/scores",
		"..%2f..%2fv1%2fscores",
		"x&package=other",
		"x#fragment",
		"x?injected=1",
		"http://evil.example/",
		"//evil.example/",
		"x\r\nHost: evil.example",
	}
	for _, a := range attacks {
		fa := &fakeApproval{statusOK: true}
		lookupProbe(t, fa, "package="+url.QueryEscape(a))

		// The client must have been asked for EXACTLY the string the user typed. If it
		// received something shorter or differently shaped, the input was reinterpreted
		// somewhere between the form and the request.
		if fa.statusPkg != a {
			t.Errorf("package %q reached the client as %q — the input was reinterpreted, "+
				"which is where a redirected call would come from", a, fa.statusPkg)
		}
		// And it must never have been read as a second parameter.
		if fa.statusEco != "" {
			t.Errorf("package %q also set the ecosystem to %q — one field bled into another",
				a, fa.statusEco)
		}
	}
}

// TestLookupEcosystemFilterCannotBeSmuggled: same question from the other field.
func TestLookupEcosystemFilterCannotBeSmuggled(t *testing.T) {
	fa := &fakeApproval{statusOK: true}
	lookupProbe(t, fa, "package=lodash&ecosystem="+url.QueryEscape("npm&package=other"))
	if fa.statusPkg != "lodash" {
		t.Errorf("the ecosystem field overwrote the package: got %q", fa.statusPkg)
	}
}

// TestLookupRendersHostileApprovalDataSafely.
//
// The approval service's answer is not trustworthy input either: every string in it
// originates in package metadata a publisher wrote. This is the page a developer opens
// to ASK ABOUT A SUSPICIOUS PACKAGE, so it is precisely where a malicious payload gets
// its best shot at a human.
func TestLookupRendersHostileApprovalDataSafely(t *testing.T) {
	evil := `<script>alert(1)</script>`
	fa := &fakeApproval{
		statusOK: true,
		status: packageStatus{
			Package:           evil,
			Ecosystem:         evil,
			ScoreAvailability: evil,
			Upstream:          evil,
			Cache:             evil,
			LastObserved:      &event{Action: evil, Reason: evil, At: time.Now()},
			RecentEvents:      []event{{Action: evil, Reason: evil, At: time.Now()}},
			Score:             &scoreRecord{Repo: "javascript:alert(1)", Score: f64(1.0), ScoredChecks: 1, TotalChecks: 2, ComputedWithout: []string{evil}},
		},
	}
	body := lookupProbe(t, fa, "package=evil").Body.String()

	if strings.Contains(body, "<script>alert(1)</script>") {
		t.Error("XSS: hostile approval data rendered as live markup on the page a " +
			"developer opens specifically to investigate a suspicious package")
	}
	if strings.Contains(body, `href="javascript:`) {
		t.Error("a javascript: repo URL became a clickable link")
	}
}

// TestUnknownAvailabilityMarkerIsShownVerbatimNotSwallowed.
//
// If the approval service starts reporting a state this console does not know, the page
// must say so. Rendering nothing is the dangerous default: a blank field on a security
// page reads as "no problem found", which is the opposite of "we do not understand the
// answer we were given".
func TestUnknownAvailabilityMarkerIsShownVerbatimNotSwallowed(t *testing.T) {
	fa := &fakeApproval{
		statusOK: true,
		status: packageStatus{
			Package:           "lodash",
			ScoreAvailability: "some-state-invented-after-this-console-shipped",
		},
	}
	body := lookupProbe(t, fa, "package=lodash").Body.String()
	if !strings.Contains(body, "some-state-invented-after-this-console-shipped") {
		t.Error("an unrecognized availability marker vanished from the page; an absent " +
			"explanation on a security console reads as 'nothing wrong here'")
	}
}

// TestAnEmptySearchCostsNothing — a trivially cheap DoS check. If every stray GET on
// /lookup fans out into an approval call, the console is a free amplifier against its
// own control plane.
func TestAnEmptySearchCostsNothing(t *testing.T) {
	for _, q := range []string{"", "package=", "package=%20", "ecosystem=npm"} {
		fa := &fakeApproval{statusOK: true}
		lookupProbe(t, fa, q)
		// Assert on the CALL COUNT, not on the package argument. Checking statusPkg != ""
		// cannot fail here: on an empty search the argument is "" whether or not the call
		// happened, so that version of this test was unfalsifiable — it stayed green with
		// the guard deliberately disabled. Caught by running the negative control.
		if fa.statusCalls != 0 {
			t.Errorf("query %q made %d approval call(s); an empty box must cost nothing, or "+
				"the console is a free amplifier against its own control plane",
				q, fa.statusCalls)
		}
	}
}
