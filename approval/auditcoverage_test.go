package main

import (
	"encoding/json"
	"net/http"
	"reflect"
	"strings"
	"testing"
)

// #154: the audit event carries what its score was computed over, through both read
// paths and out of the compliance export. Runs against memStore always and pgStore when
// APPROVAL_TEST_DSN is set; the Postgres leg is what proves the three columns.

func TestAuditCoverageRoundTripsThroughEveryBackend(t *testing.T) {
	for name, store := range eventStores(t) {
		t.Run(name, func(t *testing.T) {
			score := 6.2
			if _, err := store.AppendEvent(AuditEvent{
				Package: "partial-pkg", Ecosystem: "npm", Action: ActionAllow, Score: &score,
				Reason: "score 6.2 >= threshold 5.0", ScoredChecks: 15, TotalChecks: 18,
				ComputedWithout: []string{"CI-Tests", "Contributors", "License"},
			}); err != nil {
				t.Fatalf("AppendEvent: %v", err)
			}
			if _, err := store.AppendEvent(AuditEvent{
				Package: "full-pkg", Ecosystem: "npm", Action: ActionAllow, Score: &score, Reason: "full",
			}); err != nil {
				t.Fatalf("AppendEvent (full): %v", err)
			}

			check := func(path string, got []AuditEvent) {
				byName := map[string]AuditEvent{}
				for _, e := range got {
					byName[e.Package] = e
				}
				p, ok := byName["partial-pkg"]
				if !ok {
					t.Fatalf("%s lost the partial event", path)
				}
				if !p.Partial() || p.ScoredChecks != 15 || p.TotalChecks != 18 {
					t.Errorf("%s: coverage = %d of %d (partial=%v), want 15 of 18", path, p.ScoredChecks, p.TotalChecks, p.Partial())
				}
				if want := []string{"CI-Tests", "Contributors", "License"}; !reflect.DeepEqual(p.ComputedWithout, want) {
					t.Errorf("%s: computed_without = %v, want %v", path, p.ComputedWithout, want)
				}
				// Column-order canary, as in the decision-inputs test: an off-by-one
				// Scan still fills every field, with the wrong values.
				if p.Reason != "score 6.2 >= threshold 5.0" || p.Action != ActionAllow {
					t.Errorf("%s: an adjacent column came back wrong (reason=%q action=%q)", path, p.Reason, p.Action)
				}
				f := byName["full-pkg"]
				if f.Partial() || f.ComputedWithout != nil {
					t.Errorf("%s: an event with no coverage reads as partial or names checks: %+v", path, f)
				}
			}
			listed, err := store.ListEvents(EventFilter{})
			if err != nil {
				t.Fatalf("ListEvents: %v", err)
			}
			check("ListEvents", listed)
			var streamed []AuditEvent
			if err := store.StreamEvents(EventFilter{}, func(e AuditEvent) error {
				streamed = append(streamed, e)
				return nil
			}); err != nil {
				t.Fatalf("StreamEvents: %v", err)
			}
			check("StreamEvents (the export path)", streamed)
		})
	}
}

// TestTheExportCarriesTheCoverage: the NDJSON line for a partial score names the
// denominator; the line for a full one carries no coverage keys at all (unknown, not
// "0 of 0").
func TestTheExportCarriesTheCoverage(t *testing.T) {
	srv := &server{store: newMemStore()}
	score := 6.2
	srv.store.AppendEvent(AuditEvent{Package: "partial-pkg", Action: ActionAllow, Score: &score,
		ScoredChecks: 15, TotalChecks: 18, ComputedWithout: []string{"CI-Tests", "License"}})
	srv.store.AppendEvent(AuditEvent{Package: "full-pkg", Action: ActionAllow, Score: &score})

	rec := do(t, srv, http.MethodGet, "/v1/events/export", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("export = %d", rec.Code)
	}
	lines := nonEmptyLines(rec.Body.String())
	if len(lines) != 2 {
		t.Fatalf("export returned %d lines, want 2", len(lines))
	}
	for _, ln := range lines {
		var raw map[string]any
		if err := json.Unmarshal([]byte(ln), &raw); err != nil {
			t.Fatalf("export line is not JSON: %v", err)
		}
		_, hasScored := raw["scored_checks"]
		_, hasWithout := raw["computed_without"]
		switch raw["package"] {
		case "partial-pkg":
			if !hasScored || !hasWithout || !strings.Contains(ln, `"total_checks":18`) {
				t.Errorf("the partial event's export line does not say what 6.2 was computed over: %s", ln)
			}
		case "full-pkg":
			if hasScored || hasWithout {
				t.Errorf("an event with no coverage exports coverage keys: %s", ln)
			}
		}
	}
}
