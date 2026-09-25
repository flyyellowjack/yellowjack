package main

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// #142 on the console.

func fpRequest(user, pass, origin string, form url.Values) *http.Request {
	req := httptest.NewRequest(http.MethodPost, "/report-false-positive", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if origin != "" {
		req.Header.Set("Origin", origin)
	}
	if user != "" {
		req.SetBasicAuth(user, pass)
	}
	return req
}

func auditPageAs(t *testing.T, srv *server, user, pass string) string {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/audit", nil)
	if user != "" {
		req.SetBasicAuth(user, pass)
	}
	rr := httptest.NewRecorder()
	srv.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("GET /audit = %d", rr.Code)
	}
	return rr.Body.String()
}

// The report form appears on BLOCK rows when writes are enabled, and nowhere else. Both
// negatives matter: a form on an allow row would let an operator file nonsense, and a
// form with no identity behind it would file an unattributed report.
func TestTheReportFormIsOnBlockRowsOnlyAndOnlyWhenWritesAreEnabled(t *testing.T) {
	f := &fakeApproval{events: []event{
		{ID: 1, Package: "left-pad", Action: "block", Reason: "on the operator deny list", Source: "operator deny list", DenyKind: "operator", Rule: "deny-list:left-pad", At: time.Now()},
		{ID: 2, Package: "lodash", Action: "allow", At: time.Now()},
	}}
	// CONTROL first: no credential configured, no form anywhere.
	if body := auditPageAs(t, newTestServer(f), "", ""); strings.Contains(body, "/report-false-positive") {
		t.Fatal("the report form is rendered with writes DISABLED; a report filed here would carry no identity")
	}
	body := auditPageAs(t, newAuthedServer(f, "admin", "s3cret"), "admin", "s3cret")
	if n := strings.Count(body, `action="/report-false-positive"`); n != 1 {
		t.Fatalf("expected exactly one report form (one block row), found %d", n)
	}
	// The form carries the block's attribution, so the report says which list or feed
	// refused the package without a second lookup.
	for _, want := range []string{`name="event_id" value="1"`, `name="source" value="operator deny list"`, `name="rule" value="deny-list:left-pad"`, `name="deny_kind" value="operator"`} {
		if !strings.Contains(body, want) {
			t.Errorf("the form does not carry %s", want)
		}
	}
}

func TestReportingRefusedWithoutAuthAndCrossOrigin(t *testing.T) {
	f := &fakeApproval{}
	form := url.Values{"package": {"left-pad"}, "action": {"block"}}

	rr := httptest.NewRecorder()
	newTestServer(f).ServeHTTP(rr, fpRequest("", "", "http://example.com", form))
	if rr.Code != http.StatusForbidden {
		t.Errorf("no credential configured: %d, want 403", rr.Code)
	}
	srv := newAuthedServer(f, "admin", "s3cret")
	rr = httptest.NewRecorder()
	srv.ServeHTTP(rr, fpRequest("admin", "s3cret", "http://evil.example", form))
	if rr.Code != http.StatusForbidden {
		t.Errorf("cross-origin: %d, want 403", rr.Code)
	}
	rr = httptest.NewRecorder()
	srv.ServeHTTP(rr, fpRequest("admin", "s3cret", "http://example.com", url.Values{"package": {"lodash"}, "action": {"allow"}}))
	if rr.Code != http.StatusBadRequest {
		t.Errorf("a report against an ALLOW: %d, want 400", rr.Code)
	}
	if len(f.fpReports) != 0 {
		t.Fatalf("a refused request still reached the control plane: %+v", f.fpReports)
	}
}

func TestAReportIsAttributedAndCarriesTheBlocksSource(t *testing.T) {
	f := &fakeApproval{}
	srv := newAuthedServer(f, "admin", "s3cret")
	rr := httptest.NewRecorder()
	srv.ServeHTTP(rr, fpRequest("admin", "s3cret", "http://example.com", url.Values{
		"event_id": {"41"}, "package": {"left-pad"}, "ecosystem": {"npm"}, "action": {"block"},
		"reason": {"on the operator deny list"}, "source": {"operator deny list"}, "deny_kind": {"operator"},
		"rule": {"deny-list:left-pad"}, "note": {"we added it by mistake"},
	}))
	if rr.Code != http.StatusSeeOther || !strings.HasPrefix(rr.Header().Get("Location"), "/false-positives?saved=") {
		t.Fatalf("report = %d -> %q, want 303 to /false-positives?saved=", rr.Code, rr.Header().Get("Location"))
	}
	if len(f.fpReports) != 1 {
		t.Fatalf("want 1 report, got %d", len(f.fpReports))
	}
	got := f.fpReports[0]
	if got.ReportedBy != "admin" {
		t.Errorf("reported_by = %q, want the signed-in operator", got.ReportedBy)
	}
	if got.EventID != 41 || got.Source != "operator deny list" || got.Rule != "deny-list:left-pad" || got.Note != "we added it by mistake" || got.Ecosystem != "npm" {
		t.Errorf("the report lost a field: %+v", got)
	}
	if got.SourceKind() != "operator" {
		t.Errorf("SourceKind = %q", got.SourceKind())
	}
}

// The page's three empty states are different facts, and the two kinds of source must
// render as different words.
func TestFalsePositivesPageStates(t *testing.T) {
	get := func(srv *server, user, pass string) (int, string) {
		req := httptest.NewRequest(http.MethodGet, "/false-positives?saved=7", nil)
		if user != "" {
			req.SetBasicAuth(user, pass)
		}
		rr := httptest.NewRecorder()
		srv.ServeHTTP(rr, req)
		return rr.Code, rr.Body.String()
	}
	if code, body := get(newTestServer(&fakeApproval{}), "", ""); code != http.StatusOK || !strings.Contains(body, "none can be filed") {
		t.Errorf("writes off, no reports: %d; the page must say reporting is off, not merely 'none yet'", code)
	}
	if code, body := get(newAuthedServer(&fakeApproval{}, "a", "b"), "a", "b"); code != http.StatusOK || !strings.Contains(body, "No false positives reported yet") {
		t.Errorf("writes on, no reports: %d", code)
	}
	f := &fakeApproval{fps: []falsePositive{
		{ID: 7, Package: "evil", Source: "known-malware feed", Note: "our own internal tool, same name", ReportedBy: "alice@example.test", At: time.Now()},
		{ID: 6, Package: "left-pad", Source: "operator deny list", At: time.Now()},
	}}
	code, body := get(newAuthedServer(f, "a", "b"), "a", "b")
	if code != http.StatusOK {
		t.Fatalf("page = %d", code)
	}
	for _, want := range []string{`badge advisory">advisory`, `badge operator">operator`, "Report #7 recorded", "alice@example.test", "our own internal tool"} {
		if !strings.Contains(body, want) {
			t.Errorf("page lacks %q", want)
		}
	}
	if _, body := get(newTestServer(&fakeApproval{fpsErr: errBoom}), "", ""); !strings.Contains(body, "cannot reach the approval service") {
		t.Error("a control-plane failure must be a clean 502, not an empty page")
	}
}
