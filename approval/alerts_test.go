package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func alertNow() time.Time { return time.Date(2026, 7, 30, 12, 0, 0, 0, time.UTC) }

func kinds(as []Alert) []string {
	out := make([]string, 0, len(as))
	for _, a := range as {
		out = append(out, a.Kind)
	}
	return out
}

func hasKind(as []Alert, kind string) bool {
	for _, a := range as {
		if a.Kind == kind {
			return true
		}
	}
	return false
}

// A replica that has stopped reporting is the whole point of the heartbeat.
func TestAlertsFireOnSilentInstance(t *testing.T) {
	now := alertNow()
	p := defaultAlertParams()
	health := []InstanceHealth{{Instance: "fw-1", ReportedAt: now.Add(-p.SilentAfter - time.Minute)}}

	got := evaluateAlerts(now, health, FlowSummary{}, p)
	if !hasKind(got, AlertInstanceSilent) {
		t.Fatalf("kinds = %v, want %s", kinds(got), AlertInstanceSilent)
	}
	if got[0].Severity != SeverityCritical {
		t.Errorf("severity = %s, want critical — a firewall we cannot see is the serious case", got[0].Severity)
	}
	if got[0].Instance != "fw-1" {
		t.Errorf("instance = %q, want fw-1 — the alert must name WHICH replica, or an operator cannot act on it", got[0].Instance)
	}
}

// A replica that reported recently must NOT alert, or the alert is on permanently.
func TestAlertsQuietOnHealthyInstance(t *testing.T) {
	now := alertNow()
	health := []InstanceHealth{{Instance: "fw-1", ReportedAt: now.Add(-30 * time.Second)}}

	if got := evaluateAlerts(now, health, FlowSummary{}, defaultAlertParams()); len(got) != 0 {
		t.Errorf("got %v for a healthy deployment, want none", kinds(got))
	}
}

// FALSE-POSITIVE TRAP: a deployment where NO firewall has ever reported.
//
// A fresh install, or an approval service brought up before any firewall, has an empty
// health table. It is tempting to treat "no instances" as "nothing is alive" and raise
// the critical alert — but nothing has been deployed YET, which is not an outage. Getting
// this wrong means the very first thing a new operator sees is a critical alert about a
// firewall they have not installed, which is the worst possible introduction to an
// alerting system we are asking them to trust.
func TestAlertsSilentOnEmptyDeployment(t *testing.T) {
	if got := evaluateAlerts(alertNow(), nil, FlowSummary{}, defaultAlertParams()); len(got) != 0 {
		t.Errorf("got %v with no instances reporting, want none — nothing deployed yet is not an outage", kinds(got))
	}
}

// The two "we lost data" counters alert at any non-zero value, and stay quiet at zero.
func TestAlertsOnDroppedData(t *testing.T) {
	now := alertNow()
	fresh := now.Add(-time.Second)

	got := evaluateAlerts(now, []InstanceHealth{
		{Instance: "fw-1", ReportedAt: fresh, AuditDropped: 5},
		{Instance: "fw-2", ReportedAt: fresh, FlowDropped: 2},
	}, FlowSummary{}, defaultAlertParams())

	if !hasKind(got, AlertAuditDropping) || !hasKind(got, AlertMetricsDropping) {
		t.Fatalf("kinds = %v, want both drop alerts", kinds(got))
	}
	// Warnings, not critical: the GATE is unaffected by either — what suffers is the
	// completeness of the record. Calling these critical would rank a reporting gap
	// alongside a dead firewall.
	for _, a := range got {
		if a.Severity != SeverityWarning {
			t.Errorf("%s severity = %s, want warning (the gate keeps working; only the record is incomplete)", a.Kind, a.Severity)
		}
	}

	quiet := evaluateAlerts(now, []InstanceHealth{{Instance: "fw-1", ReportedAt: fresh}}, FlowSummary{}, defaultAlertParams())
	if len(quiet) != 0 {
		t.Errorf("got %v with zero drops, want none", kinds(quiet))
	}
}

// Transfer failures alert at any non-zero count in the window.
func TestAlertsOnTransferFailures(t *testing.T) {
	now := alertNow()
	got := evaluateAlerts(now, nil, FlowSummary{Truncated: 3, TransportErrors: 1}, defaultAlertParams())
	if !hasKind(got, AlertTransferFailing) {
		t.Fatalf("kinds = %v, want %s", kinds(got), AlertTransferFailing)
	}
	// The wording must not overclaim: we detect transport failures, never a
	// corrupt-but-complete artifact (we relay bytes verbatim and do not hash them).
	// D89 put real integrity verification on the roadmap; until then the alert text is
	// the only thing stopping "corruption" being read into this number.
	if d := got[0].Detail; !contains(d, "TRANSPORT") || !contains(d, "corrupt-but-complete") {
		t.Errorf("detail must scope the claim to transport failures and disclaim content integrity; got %q", d)
	}
}

// Critical outranks warning, so the console's first row is the thing to act on.
func TestAlertsOrderCriticalFirst(t *testing.T) {
	now := alertNow()
	p := defaultAlertParams()
	got := evaluateAlerts(now, []InstanceHealth{
		{Instance: "fw-warn", ReportedAt: now.Add(-time.Second), AuditDropped: 1},
		{Instance: "fw-dead", ReportedAt: now.Add(-2 * p.SilentAfter)},
	}, FlowSummary{}, p)

	if len(got) < 2 {
		t.Fatalf("want at least 2 alerts, got %v", kinds(got))
	}
	if got[0].Severity != SeverityCritical {
		t.Errorf("first alert = %s/%s, want the critical one first", got[0].Kind, got[0].Severity)
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

// windowSpy records the filter the handler asks for, so the test can assert on the
// QUESTION rather than only the answer.
type windowSpy struct {
	Store
	got FlowFilter
}

func (w *windowSpy) FlowSummary(f FlowFilter) (FlowSummary, error) {
	w.got = f
	return FlowSummary{}, nil
}

// NEGATIVE CONTROL for the un-clearable alert.
//
// If the handler asked for a LIFETIME summary, a single truncated download three months
// ago would raise the transfer-failure alert forever — and an alert that cannot be
// cleared is one the operator mutes, taking the real ones with it. So the assertion is on
// the filter the handler passes down, not merely on the alerts that come back: a lifetime
// query returns the same shape and would pass a result-only test.
func TestAlertsQueryABoundedWindow(t *testing.T) {
	spy := &windowSpy{Store: newMemStore()}
	srv := &server{store: spy}

	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v1/alerts", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /v1/alerts = %d, want 200", rec.Code)
	}

	if spy.got.From.IsZero() {
		t.Fatal("handler asked for a summary with no From — that is a LIFETIME count, so one old truncation would alert forever")
	}
	if window := time.Since(spy.got.From); window > 25*time.Hour {
		t.Errorf("window is %s wide; expected a recent window (default %s), not effectively-all-history", window, defaultAlertParams().Window)
	}
}

// The endpoint's shape: [] when quiet, 405 on a write.
func TestAlertsHTTP(t *testing.T) {
	srv := &server{store: newMemStore()}

	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v1/alerts", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET = %d, want 200", rec.Code)
	}
	var got []Alert
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v (body %q)", err, rec.Body.String())
	}
	if len(got) != 0 {
		t.Errorf("fresh store returned %v, want no alerts", kinds(got))
	}
	if body := rec.Body.String(); body != "[]\n" {
		t.Errorf("empty body = %q, want \"[]\\n\" (not null)", body)
	}

	rec = httptest.NewRecorder()
	srv.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/v1/alerts", nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST /v1/alerts = %d, want 405 — alerts are derived, there is nothing to write", rec.Code)
	}
}

// End to end through a real store: a heartbeat goes stale, the endpoint says so.
func TestAlertsFromRealStore(t *testing.T) {
	s := newMemStore()
	if err := s.UpsertInstanceHealth(InstanceHealth{
		Instance:   "fw-1",
		ReportedAt: time.Now().UTC().Add(-2 * defaultAlertParams().SilentAfter),
	}); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	srv := &server{store: s}

	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v1/alerts", nil))
	var got []Alert
	json.Unmarshal(rec.Body.Bytes(), &got)
	if !hasKind(got, AlertInstanceSilent) {
		t.Errorf("kinds = %v, want the silent-instance alert to surface through the endpoint", kinds(got))
	}
}
