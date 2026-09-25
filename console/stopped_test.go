package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func stoppedFake(now time.Time) *fakeApproval {
	score, threshold := 3.8, 5.0
	return &fakeApproval{events: []event{
		{ID: 50, Package: "axios", Ecosystem: "npm", Action: "block", DenyKind: "known-malware", Rule: "MAL-2026-0990",
			Source: "known-malware feed", Reason: "axios@1.14.1 is listed as known malware", SourceIP: "10.0.0.1", At: now.Add(-time.Hour), Taken: "block"},
		{ID: 49, Package: "axios", Ecosystem: "npm", Action: "block", DenyKind: "known-malware", Rule: "MAL-2026-0990",
			SourceIP: "10.0.0.2", At: now.Add(-2 * time.Hour), Taken: "block"},
		// A substring neighbour of "axios": the store's package filter returns it.
		{ID: 48, Package: "axios-retry", Ecosystem: "npm", Action: "block", DenyKind: "unscorable", SourceIP: "10.9.9.9", At: now.Add(-3 * time.Hour), Taken: "block"},
		{ID: 47, Package: "colorama-helper", Ecosystem: "pypi", Action: "block", DenyKind: "operator-denied", Rule: "deny-list:colorama-helper", At: now.Add(-4 * time.Hour), Taken: "block"},
		{ID: 46, Package: "weak", Ecosystem: "npm", Action: "block", DenyKind: "score-below-threshold", Score: &score, Threshold: &threshold, At: now.Add(-5 * time.Hour), Taken: "block"},
		{ID: 45, Package: "reported", Ecosystem: "npm", Action: "block", DenyKind: "score-below-threshold", At: now.Add(-6 * time.Hour), Taken: "allow"},
	}}
}

func stoppedGet(t *testing.T, s *server, path string, auth bool) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	if auth {
		req.SetBasicAuth("admin", "secret")
	}
	rr := httptest.NewRecorder()
	s.ServeHTTP(rr, req)
	return rr
}

func TestStoppedViewKnownMalware(t *testing.T) {
	now := time.Now().UTC()
	s := &server{approval: stoppedFake(now), auth: newBasicAuth("admin", "secret"), lists: newFakeListStore(), listEcosystem: "npm"}
	rr := stoppedGet(t, s, "/stopped/view?id=50&package=axios", true)
	if rr.Code != http.StatusOK {
		t.Fatalf("= %d: %s", rr.Code, rr.Body.String())
	}
	body := rr.Body.String()
	for _, want := range []string{
		"Blocked · Known malware",
		"named on the known-malware list (MAL-2026-0990)",
		"On the gate, without contacting the registry",
		"Requested from 2 hosts", "10.0.0.1", "10.0.0.2",
		// The override that fits an advisory: a pinned release on the allow list (D312),
		// spelled for npm, with the version left to type -- the record does not name it.
		`name="kind" value="allow"`, `name="entry" value="axios@"`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("known-malware view lacks %q", want)
		}
	}
	if strings.Contains(body, "10.9.9.9") {
		t.Errorf("the page counted a host that asked for axios-retry, a different package")
	}
}

// Without a list store the override is explained, not offered.
func TestStoppedViewWithoutListsOffersNoPinForm(t *testing.T) {
	s := &server{approval: stoppedFake(time.Now().UTC()), auth: newBasicAuth("admin", "secret")}
	body := stoppedGet(t, s, "/stopped/view?id=50&package=axios", true).Body.String()
	if strings.Contains(body, `action="/lists"`) {
		t.Errorf("a list form is offered on a console that cannot edit lists")
	}
	if !strings.Contains(body, "List editing is not configured") {
		t.Errorf("the page does not say why no override is offered")
	}
}

func TestStoppedViewOperatorDenyOffersRemoval(t *testing.T) {
	s := &server{approval: stoppedFake(time.Now().UTC()), auth: newBasicAuth("admin", "secret"), lists: newFakeListStore(), listEcosystem: "npm"}
	body := stoppedGet(t, s, "/stopped/view?id=47&package=colorama-helper", true).Body.String()
	for _, want := range []string{"On your block list", `name="kind" value="deny"`, `name="action" value="remove"`, `name="entry" value="colorama-helper"`, "not a published advisory"} {
		if !strings.Contains(body, want) {
			t.Errorf("operator-deny view lacks %q", want)
		}
	}
	if strings.Contains(body, "known-malware list") {
		t.Errorf("an operator deny is described as an advisory")
	}
}

func TestStoppedViewScoreRefusalRoutesToDecisions(t *testing.T) {
	body := stoppedGet(t, newTestServer(stoppedFake(time.Now().UTC())), "/stopped/view?id=46&package=weak", false).Body.String()
	for _, want := range []string{"health score is 3.8, below your threshold of 5.0", `href="/decisions?pkg=weak"`} {
		if !strings.Contains(body, want) {
			t.Errorf("score view lacks %q", want)
		}
	}
	if strings.Contains(body, "malware") {
		t.Errorf("a score refusal mentions malware")
	}
}

// Report mode served the package: the page must not headline it as blocked.
func TestStoppedViewReportModeSaysServed(t *testing.T) {
	body := stoppedGet(t, newTestServer(stoppedFake(time.Now().UTC())), "/stopped/view?id=45&package=reported", false).Body.String()
	if !strings.Contains(body, "Logged · ") || strings.Contains(body, "Blocked · ") {
		t.Errorf("a served refusal is headlined as blocked")
	}
	if !strings.Contains(body, "logged and then served") {
		t.Errorf("the page does not say the package was served")
	}
}

func TestStoppedViewNamesExactlyOneRefusal(t *testing.T) {
	s := newTestServer(stoppedFake(time.Now().UTC()))
	// Event 48 is axios-retry's. Asked for as "axios", it is not axios's refusal.
	if rr := stoppedGet(t, s, "/stopped/view?id=48&package=axios", false); rr.Code != http.StatusNotFound {
		t.Errorf("another package's event under this name = %d, want 404", rr.Code)
	}
	if rr := stoppedGet(t, s, "/stopped/view?id=abc&package=axios", false); rr.Code != http.StatusBadRequest {
		t.Errorf("non-numeric id = %d, want 400", rr.Code)
	}
	if rr := stoppedGet(t, s, "/stopped/view?id=50", false); rr.Code != http.StatusBadRequest {
		t.Errorf("no package = %d, want 400", rr.Code)
	}
}

func TestStoppedListTabs(t *testing.T) {
	s := newTestServer(stoppedFake(time.Now().UTC()))
	body := stoppedGet(t, s, "/stopped?kind=operator", false).Body.String()
	if !strings.Contains(body, "colorama-helper") || strings.Contains(body, ">axios<") {
		t.Errorf("the operator tab does not show exactly the block-list refusals")
	}
	for _, want := range []string{`>All<span class="n">· 6</span>`, `>Known malware<span class="n">· 2</span>`, `>Your block list<span class="n">· 1</span>`, `>By policy<span class="n">· 3</span>`} {
		if !strings.Contains(body, want) {
			t.Errorf("tabs lack %q", want)
		}
	}
	if rr := stoppedGet(t, s, "/stopped?kind=bogus", false); rr.Code != http.StatusBadRequest {
		t.Errorf("?kind=bogus = %d, want 400 (a typo must not look like an empty result)", rr.Code)
	}
}

func TestPinTemplateSpellsEachEcosystem(t *testing.T) {
	for eco, want := range map[string]string{
		"npm": "axios@", "pypi": "requests==", "maven": "org.acme:lib:", "oci": "library/nginx@sha256:",
	} {
		name := map[string]string{"npm": "axios", "pypi": "requests", "maven": "org.acme:lib", "oci": "library/nginx"}[eco]
		if got := pinTemplate(eco, name); got != want {
			t.Errorf("pinTemplate(%s) = %q, want %q", eco, got, want)
		}
	}
}

// The Overview's refusals open this page.
func TestOverviewLinksRefusalsToTheirExplanation(t *testing.T) {
	body := getPage(t, newTestServer(stoppedFake(time.Now().UTC())), "/")
	if !strings.Contains(body, `href="/stopped/view?id=50&amp;package=axios"`) {
		t.Errorf("a recently stopped row does not link to its explanation")
	}
}
