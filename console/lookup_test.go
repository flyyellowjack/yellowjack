package main

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"
)

// Tests for the developer package lookup (#73 / D135 pillar 4).
//
// Most of these pin ONE property: the page reports what happened, and never presents it
// as what will happen. The approval service's own contract calls that "the difference
// between a report and a promise", and it is a security property — an operator who reads
// a stale "allow" as clearance has been actively misled by a security console.

func lookupGet(t *testing.T, srv *server, query string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/lookup"+query, nil))
	return rec
}

// TestLookupFirstLoadShowsFormOnly: an empty box must not look like a result.
func TestLookupFirstLoadShowsFormOnly(t *testing.T) {
	fa := &fakeApproval{}
	rec := lookupGet(t, newTestServer(fa), "")

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if fa.statusPkg != "" {
		t.Errorf("the handler queried the approval service for %q on an empty search — "+
			"an empty box must cost nothing", fa.statusPkg)
	}
	if body := rec.Body.String(); strings.Contains(body, "report about the past") {
		t.Error("the result banner rendered with no search performed")
	}
}

// TestLookupNeverRequestedIsNotACleanBill is the one a developer is most likely to
// misread, so it is pinned hardest.
//
// "We have never seen this package" and "we saw it and it was fine" are opposite
// situations. If the not-found state renders as an empty page, it reads as the latter.
func TestLookupNeverRequestedIsNotACleanBill(t *testing.T) {
	fa := &fakeApproval{statusOK: false}
	rec := lookupGet(t, newTestServer(fa), "?package=never-seen")
	body := rec.Body.String()

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 — 'never requested' is an answer, not an error", rec.Code)
	}
	if !strings.Contains(body, "Never requested through this deployment") {
		t.Error("the never-requested state is not stated explicitly")
	}
	if !strings.Contains(body, "not a clearance") {
		t.Error("the page does not say that 'never requested' is NOT a clearance — which is " +
			"exactly how an empty result gets misread")
	}
}

// TestLookupResultIsFramedAsAReportNotAVerdict.
func TestLookupResultIsFramedAsAReportNotAVerdict(t *testing.T) {
	fa := &fakeApproval{
		statusOK: true,
		status: packageStatus{
			Package:           "lodash",
			Ecosystem:         "npm",
			ScoreAvailability: "no-source-repo-known-for-this-package",
			Upstream:          "not-collected-by-this-service",
			Cache:             "not-implemented",
			LastObserved:      &event{Action: "allow", Reason: "score 7.5 >= threshold 5.0", At: time.Now()},
		},
	}
	rec := lookupGet(t, newTestServer(fa), "?package=lodash&ecosystem=npm")
	body := rec.Body.String()

	if !strings.Contains(body, "This is a report about the past, not a live verdict") {
		t.Error("the report/promise banner is missing. Without it the page presents a recorded " +
			"'allow' as though it were permission to pull now.")
	}
	if !strings.Contains(body, "Last observed decision") {
		t.Error(`the section is not labelled "Last observed" — the label is what carries the ` +
			`distinction on the page`)
	}
	// The word "allow" appears (it is the recorded action); what must NOT appear is a
	// present-tense claim about the package's current standing.
	for _, forbidden := range []string{"is allowed", "currently allowed", "Status: allow", "Verdict: allow"} {
		if strings.Contains(body, forbidden) {
			t.Errorf("the page states %q — a present-tense claim the endpoint explicitly cannot support", forbidden)
		}
	}
}

// TestLookupPassesQueryThrough: the filter the operator typed is the filter that is asked.
func TestLookupPassesQueryThrough(t *testing.T) {
	fa := &fakeApproval{statusOK: true}
	lookupGet(t, newTestServer(fa), "?package=%40scope%2Fname&ecosystem=npm")

	if fa.statusPkg != "@scope/name" {
		t.Errorf("package passed to the client = %q, want %q — scoped names must survive decoding",
			fa.statusPkg, "@scope/name")
	}
	if fa.statusEco != "npm" {
		t.Errorf("ecosystem passed to the client = %q, want npm", fa.statusEco)
	}
}

// TestLookupApprovalDownIsAnHonestError: a dead control plane must not render as
// "nothing known about this package".
func TestLookupApprovalDownIsAnHonestError(t *testing.T) {
	fa := &fakeApproval{statusErr: errors.New("connection refused")}
	rec := lookupGet(t, newTestServer(fa), "?package=lodash")

	if rec.Code != http.StatusBadGateway {
		t.Errorf("status = %d, want 502 — a transport failure must not be rendered as an empty "+
			"result, which reads as 'we have nothing on this package'", rec.Code)
	}
}

// TestLookupIsBehindTheConsoleCredential pins the EXPOSURE BOUNDARY as it stands today.
//
// D139 ruled anonymous read-only access for developers, but the console exposure boundary
// is still open (CONSOLE_MVP_SCOPE.md §4 Q3): anonymous read-only is a reconnaissance
// surface — who pulls what, what is blocked, and why. So this page sits inside the
// existing gate, and this test exists so that widening it is a DELIBERATE change that
// turns a test red, rather than a side effect of some later refactor.
func TestLookupIsBehindTheConsoleCredential(t *testing.T) {
	srv := newTestServer(&fakeApproval{})
	srv.auth = &basicAuth{user: "admin", pass: "secret"}

	rec := lookupGet(t, srv, "?package=lodash")
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401 when a credential is configured. If this page is meant "+
			"to be anonymous (D139), that is a security decision to take deliberately — "+
			"change this test on purpose, with the exposure question answered.", rec.Code)
	}
}

// TestExplainAvailabilityNeverSilentlyBlanks.
//
// The availability markers exist because "never requested" and "requested and could not
// be scored" are opposite situations a boolean would flatten. An unrecognized marker must
// be reported verbatim rather than swallowed — an absent explanation reads as "no problem
// found", which is the failure mode the endpoint's author called out by name.
func TestExplainAvailabilityNeverSilentlyBlanks(t *testing.T) {
	if got := explainAvailability("some-marker-added-upstream-later"); got == "" {
		t.Error("an unrecognized availability marker rendered as empty, which reads as 'fine'")
	}
	if got := explainAvailability("present"); got != "" {
		t.Errorf(`"present" should render no note, got %q`, got)
	}
}

// TestAvailabilityMarkersMatchTheAPI is a DRIFT check against the approval service.
//
// The console mirrors marker strings the approval service owns. If a new one is added
// there, this console renders it as a bare "Reported as: x" at best — and if the
// verbatim fallback were ever removed, as nothing at all. So the constants are read out
// of the API's source and every one is required to produce an explanation.
//
// Same shape as the config-reference drift test: the failure it prevents is silent.
func TestAvailabilityMarkersMatchTheAPI(t *testing.T) {
	const src = "../approval/packagestatus.go"
	b, err := os.ReadFile(src)
	if err != nil {
		t.Skipf("cannot read %s: %v", src, err)
	}
	// avail<Name> = "the-string"
	re := regexp.MustCompile(`avail\w+\s+=\s+"([^"]+)"`)
	found := re.FindAllStringSubmatch(string(b), -1)

	// ANTI-VACUITY: if the regex stops matching (the constants are renamed, moved, or
	// reformatted) this test would pass while checking nothing at all.
	if len(found) < 5 {
		t.Fatalf("extracted only %d availability markers from %s — the extraction is broken, "+
			"so this test is not checking anything", len(found), src)
	}

	for _, m := range found {
		marker := m[1]
		if marker == "present" {
			continue
		}
		// NOT just "non-empty": explainAvailability has a verbatim default branch, so a
		// non-empty check passes for EVERY string and the test could never fail. That was
		// caught by running the negative control -- disabling a real case left this green.
		// The marker must reach a case that explains it in operator English.
		got := explainAvailability(marker)
		if got == "" || strings.HasPrefix(got, "Reported as:") {
			t.Errorf("availability marker %q is defined by the approval service but the console "+
				"has no explanation for it (got %q). It would render as the raw marker, or as a "+
				"blank field, which reads as 'no problem found'.", marker, got)
		}
	}
}
