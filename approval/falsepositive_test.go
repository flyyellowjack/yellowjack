package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// #142, and the defect found on the way in.

// TestTheGatesAttributionSurvivesTheStore: the gate has sent deny_kind, rule and source
// on every event since D182 and this service dropped them. Through BOTH backends and
// BOTH read paths (ListEvents and StreamEvents have separate column lists), because the
// export is what the "attributable without log correlation" claim was made about.
func TestTheGatesAttributionSurvivesTheStore(t *testing.T) {
	for name, store := range eventStores(t) {
		t.Run(name, func(t *testing.T) {
			in := AuditEvent{Package: "left-pad", Ecosystem: "npm", Action: ActionBlock,
				Reason: "on the operator deny list", DenyKind: "operator", Rule: "deny-list:left-pad", Source: "operator deny list",
				Taken: "allow", Mode: "report"}
			if _, err := store.AppendEvent(in); err != nil {
				t.Fatal(err)
			}
			got, err := store.ListEvents(EventFilter{Package: "left-pad"})
			if err != nil || len(got) == 0 {
				t.Fatalf("ListEvents: %v (%d rows)", err, len(got))
			}
			if got[0].DenyKind != in.DenyKind || got[0].Rule != in.Rule || got[0].Source != in.Source {
				t.Errorf("ListEvents dropped the attribution: deny_kind=%q rule=%q source=%q", got[0].DenyKind, got[0].Rule, got[0].Source)
			}
			if got[0].Taken != "allow" || got[0].Mode != "report" {
				t.Errorf("ListEvents dropped #114's report-mode fields (taken=%q mode=%q): a SERVED package reads as a real block", got[0].Taken, got[0].Mode)
			}
			var streamed []AuditEvent
			if err := store.StreamEvents(EventFilter{Package: "left-pad"}, func(e AuditEvent) error { streamed = append(streamed, e); return nil }); err != nil {
				t.Fatal(err)
			}
			if len(streamed) == 0 || streamed[len(streamed)-1].Source != in.Source || streamed[len(streamed)-1].Rule != in.Rule {
				t.Errorf("the EXPORT path dropped the attribution: %+v", streamed)
			}
		})
	}
}

// TestAttributionArrivesOverTheWire: the gate posts JSON with these keys; the handler's
// decode must keep them. A fixture written the way the gate's audit.go encodes it.
func TestAttributionArrivesOverTheWire(t *testing.T) {
	srv := &server{store: newMemStore()}
	body := `{"package":"evil","ecosystem":"npm","action":"block","reason":"known malware","deny_kind":"malware","rule":"feed:MAL-2026-1","source":"known-malware feed","at":"2026-09-21T00:00:00Z"}`
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/v1/events", strings.NewReader(body)))
	if rec.Code != http.StatusCreated {
		t.Fatalf("POST /v1/events = %d", rec.Code)
	}
	got, _ := srv.store.ListEvents(EventFilter{})
	if len(got) != 1 || got[0].Source != "known-malware feed" || got[0].DenyKind != "malware" {
		t.Fatalf("stored event lacks the wire's attribution: %+v", got)
	}
}

func TestFalsePositiveReportsRoundTripThroughEveryBackend(t *testing.T) {
	for name, store := range eventStores(t) {
		t.Run(name, func(t *testing.T) {
			if pg, ok := store.(*pgStore); ok {
				if _, err := pg.db.Exec("DELETE FROM false_positives"); err != nil {
					t.Fatal(err)
				}
			}
			first, err := store.AddFalsePositive(FalsePositiveReport{Package: "left-pad", Ecosystem: "npm",
				Reason: "on the operator deny list", Source: "operator deny list", DenyKind: "operator", Rule: "deny-list:left-pad",
				Note: "we added it by mistake", ReportedBy: "alice@example.test", EventID: 7})
			if err != nil {
				t.Fatal(err)
			}
			second, err := store.AddFalsePositive(FalsePositiveReport{Package: "evil", Source: "known-malware feed"})
			if err != nil {
				t.Fatal(err)
			}
			if first.ID == 0 || second.ID <= first.ID || first.At.IsZero() {
				t.Fatalf("ids/timestamps not assigned: %+v %+v", first, second)
			}
			got, err := store.ListFalsePositives(0)
			if err != nil || len(got) != 2 {
				t.Fatalf("ListFalsePositives: %v, %d rows", err, len(got))
			}
			if got[0].Package != "evil" {
				t.Errorf("not newest-first: %+v", got)
			}
			r := got[1]
			if r.Note != "we added it by mistake" || r.ReportedBy != "alice@example.test" || r.Rule != "deny-list:left-pad" ||
				r.Source != "operator deny list" || r.DenyKind != "operator" || r.EventID != 7 || r.Ecosystem != "npm" {
				t.Errorf("a field did not survive the round trip: %+v", r)
			}
			if got, err := store.ListFalsePositives(1); err != nil || len(got) != 1 {
				t.Errorf("limit not applied: %v, %d rows", err, len(got))
			}
		})
	}
}

// TestSourceKindSeparatesAdvisoryFromOperator is #142's second box at the data level: a
// false positive against a published advisory and one against the operator's own entry
// are different facts (D193) and must not collapse into one word.
func TestSourceKindSeparatesAdvisoryFromOperator(t *testing.T) {
	for source, want := range map[string]string{
		"known-malware feed": "advisory", "operator deny list": "operator", "approval service": "operator",
		"": "unattributed", "release window": "release window",
	} {
		if got := (FalsePositiveReport{Source: source}).SourceKind(); got != want {
			t.Errorf("SourceKind(%q) = %q, want %q", source, got, want)
		}
	}
}

// egressCounter counts round trips and refuses to make any.
type egressCounter struct{ n atomic.Int64 }

func (c *egressCounter) RoundTrip(r *http.Request) (*http.Response, error) {
	c.n.Add(1)
	return &http.Response{StatusCode: http.StatusAccepted, Body: http.NoBody, Request: r}, nil
}

func postFP(t *testing.T, srv *server, body string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/false-positives", strings.NewReader(body))
	srv.ServeHTTP(rec, req)
	return rec
}

// TestAnUnconfiguredInstallForwardsNothing is the load-bearing half of the forwarding
// box: with APPROVAL_FP_WEBHOOK empty, a report must produce NO outbound request. Proven
// by construction (the forwarder is nil) AND by observation: the only HTTP transport the
// test process could reach is replaced with a counter, and it stays at zero. The control
// beside it is the configured case, where the same counter moves.
func TestAnUnconfiguredInstallForwardsNothing(t *testing.T) {
	ct := &egressCounter{}
	prev := http.DefaultTransport
	http.DefaultTransport = ct
	t.Cleanup(func() { http.DefaultTransport = prev })

	if f := newFPForwarderTo("", &http.Client{Transport: ct}); f != nil {
		t.Fatal("an empty destination must produce a nil forwarder, not a client pointed nowhere")
	}
	srv := &server{store: newMemStore()} // fpForwarder nil: the shipped default
	rec := postFP(t, srv, `{"package":"left-pad","ecosystem":"npm","note":"oops"}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("POST = %d: %s", rec.Code, rec.Body.String())
	}
	if n := ct.n.Load(); n != 0 {
		t.Fatalf("an UNCONFIGURED install made %d outbound request(s) for a report; that is the phone-home D116 forbids", n)
	}
	if got, _ := srv.store.ListFalsePositives(0); len(got) != 1 || got[0].Package != "left-pad" {
		t.Fatalf("the report was not recorded locally: %+v", got)
	}

	// CONTROL: the same counter moves when a destination IS configured, so zero above
	// is an absence of egress and not an instrument that cannot see it.
	srv.fpForwarder = newFPForwarderTo("http://reports.internal.example/hook", &http.Client{Transport: ct})
	if rec := postFP(t, srv, `{"package":"left-pad","note":"again"}`); rec.Code != http.StatusCreated {
		t.Fatalf("POST = %d", rec.Code)
	}
	if n := ct.n.Load(); n != 1 {
		t.Fatalf("CONTROL: a configured destination saw %d request(s), want 1; the counter cannot see forwarding, so the zero above proves nothing", n)
	}
}

// TestForwardingCarriesTheReportAndItsKind: what a destination receives is the report plus
// the advisory/operator classification, as JSON, and a dead destination costs the local
// record nothing.
func TestForwardingCarriesTheReportAndItsKind(t *testing.T) {
	var got struct {
		Package    string `json:"package"`
		Source     string `json:"source"`
		SourceKind string `json:"source_kind"`
		ReportedBy string `json:"reported_by"`
	}
	hook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&got)
		w.WriteHeader(http.StatusAccepted)
	}))
	defer hook.Close()
	srv := &server{store: newMemStore(), fpForwarder: newFPForwarderTo(hook.URL, hook.Client())}
	postFP(t, srv, `{"package":"evil","source":"known-malware feed","reported_by":"bob"}`)
	if got.Package != "evil" || got.SourceKind != "advisory" || got.ReportedBy != "bob" {
		t.Fatalf("the destination received %+v", got)
	}

	dead := httptest.NewServer(http.NotFoundHandler())
	deadURL := dead.URL
	dead.Close()
	srv = &server{store: newMemStore(), fpForwarder: newFPForwarderTo(deadURL, &http.Client{Timeout: 2 * time.Second})}
	if rec := postFP(t, srv, `{"package":"p"}`); rec.Code != http.StatusCreated {
		t.Fatalf("a dead destination cost the operator their local record: %d", rec.Code)
	}
	if srv.fpForwarder.dropped.Load() != 1 {
		t.Errorf("an undeliverable forward was not counted")
	}
}

func TestFalsePositiveHTTPValidation(t *testing.T) {
	srv := &server{store: newMemStore()}
	for name, c := range map[string]struct {
		body string
		want int
	}{
		"no package":   {`{"note":"x"}`, http.StatusBadRequest},
		"not JSON":     {`{`, http.StatusBadRequest},
		"note too big": {`{"package":"p","note":"` + strings.Repeat("n", 5000) + `"}`, http.StatusBadRequest},
		"minimal":      {`{"package":"p"}`, http.StatusCreated},
	} {
		if rec := postFP(t, srv, c.body); rec.Code != c.want {
			t.Errorf("%s: %d, want %d (%s)", name, rec.Code, c.want, bytes.TrimSpace(rec.Body.Bytes()))
		}
	}
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v1/false-positives", nil))
	var list []FalsePositiveReport
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &list) != nil || len(list) != 1 {
		t.Fatalf("GET = %d %s", rec.Code, rec.Body.String())
	}
	rec = httptest.NewRecorder()
	srv.ServeHTTP(rec, httptest.NewRequest(http.MethodDelete, "/v1/false-positives", nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("DELETE = %d; the ledger has no delete", rec.Code)
	}
}
