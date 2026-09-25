package main

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestSummarizeGates(t *testing.T) {
	now := time.Date(2026, 9, 23, 12, 0, 0, 0, time.UTC)
	fresh := now.Add(-30 * time.Second)
	stale := now.Add(-staleAfter - time.Minute)
	enforce := &policyDoc{Values: map[string]string{"mode": "enforce"}}
	report := &policyDoc{Values: map[string]string{"mode": "report"}}

	cases := []struct {
		name, level, headline string
		rows                  []instanceHealth
	}{
		{"nothing reported", "", "No gate has reported", nil},
		{"all fresh and enforcing", "ok", "All 2 gates reporting", []instanceHealth{
			{Instance: "a", Ecosystem: "npm", ReportedAt: fresh, Policy: enforce},
			{Instance: "b", Ecosystem: "pypi", ReportedAt: fresh, Policy: enforce}}},
		{"one gate", "ok", "1 gate reporting", []instanceHealth{
			{Instance: "a", Ecosystem: "npm", ReportedAt: fresh, Policy: enforce}}},
		// A quiet replica must not hide behind a green card.
		{"one quiet", "warn", "1 of 2 gates not reporting", []instanceHealth{
			{Instance: "a", Ecosystem: "npm", ReportedAt: fresh, Policy: enforce},
			{Instance: "b", Ecosystem: "pypi", ReportedAt: stale, Policy: enforce}}},
		// Report mode serves what it blocks: "healthy" beside it would say the opposite.
		{"report mode", "warn", "1 gate in report mode", []instanceHealth{
			{Instance: "a", Ecosystem: "npm", ReportedAt: fresh, Policy: report},
			{Instance: "b", Ecosystem: "pypi", ReportedAt: fresh, Policy: enforce}}},
		{"all quiet", "bad", "No gate reporting", []instanceHealth{
			{Instance: "a", Ecosystem: "npm", ReportedAt: stale, Policy: enforce}}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := summarizeGates(c.rows, now)
			if got.Level != c.level || got.Headline != c.headline {
				t.Errorf("got %q / %q, want %q / %q", got.Level, got.Headline, c.level, c.headline)
			}
		})
	}

	// The detail names the ecosystems of the gates that ARE reporting, in people's spelling.
	got := summarizeGates([]instanceHealth{
		{Instance: "a", Ecosystem: "pypi", ReportedAt: fresh, Policy: enforce},
		{Instance: "b", Ecosystem: "oci", ReportedAt: fresh, Policy: enforce},
		{Instance: "c", Ecosystem: "maven", ReportedAt: stale, Policy: enforce}}, now)
	if !strings.Contains(got.Detail, "OCI · PyPI") || strings.Contains(got.Detail, "Maven") {
		t.Errorf("detail %q: want the reporting ecosystems only, spelled OCI and PyPI", got.Detail)
	}
}

func getPage(t *testing.T, s *server, path string) string {
	t.Helper()
	rr := httptest.NewRecorder()
	s.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, path, nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("GET %s = %d: %.200s", path, rr.Code, rr.Body.String())
	}
	return rr.Body.String()
}

// The Decisions badge counts PENDING decisions only; settled ones are not waiting.
func TestSidebarBadgeCountsPendingOnly(t *testing.T) {
	f := &fakeApproval{decisions: []decision{
		{Package: "a", Verdict: "pending"}, {Package: "b", Verdict: "pending"},
		{Package: "c", Verdict: "approved"}, {Package: "d", Verdict: "denied"},
	}}
	body := getPage(t, newTestServer(f), "/capacity")
	if !strings.Contains(body, `<span class="count" title="2 waiting">2</span>`) {
		t.Errorf("sidebar has no badge of 2 for two pending decisions")
	}
	// No pending at all: no badge, rather than a "0" that reads as a count to act on.
	f.decisions = []decision{{Package: "c", Verdict: "approved"}}
	if body := getPage(t, newTestServer(f), "/capacity"); strings.Contains(body, `class="count"`) {
		t.Errorf("sidebar renders a badge with nothing pending")
	}
}

// The sidebar is chrome. A page that works without the control plane must keep
// working when the badge and the gate card cannot be fetched.
func TestSidebarFailureDoesNotFailThePage(t *testing.T) {
	down := errors.New("connection refused")
	f := &fakeApproval{listErr: down, healthErr: down}
	body := getPage(t, newTestServer(f), "/lists")
	if strings.Contains(body, `class="count"`) {
		t.Errorf("an unknown pending count rendered as a badge")
	}
	if !strings.Contains(body, "Control plane unreachable") {
		t.Errorf("the gate card does not say the control plane is unreachable")
	}
}

// Every page marks exactly its own sidebar entry as current.
func TestSidebarMarksTheCurrentPage(t *testing.T) {
	s := &server{approval: galleryFake(time.Now().UTC())}
	for route, label := range map[string]string{
		"/":                "Overview",
		"/decisions":       "Decisions",
		"/stopped":         "Stopped",
		"/audit":           "Audit log",
		"/downloads":       "Audit log",
		"/false-positives": "Audit log",
		"/policy":          "Policy",
		"/lists":           "Allow &amp; block lists",
		"/lookup":          "Look up a package",
		"/capacity":        "Capacity",
	} {
		body := getPage(t, s, route)
		if n := strings.Count(body, `aria-current="page"><span>`); n != 1 {
			t.Errorf("%s marks %d sidebar entries current, want 1", route, n)
		}
		if !strings.Contains(body, `class="active" aria-current="page"><span>`+label+`</span>`) {
			t.Errorf("%s does not mark %q as the current page", route, label)
		}
	}
}
