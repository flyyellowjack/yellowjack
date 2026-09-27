package main

import (
	"encoding/json"
	"net/http"
	"testing"
)

// D363: the release a verdict concerned is stored, read back on both paths and exported.
// Runs against memStore always and pgStore when APPROVAL_TEST_DSN is set; the Postgres
// leg is what proves the column, its migration and the Scan order.

func TestAuditVersionRoundTripsThroughEveryBackend(t *testing.T) {
	for name, store := range eventStores(t) {
		t.Run(name, func(t *testing.T) {
			if _, err := store.AppendEvent(AuditEvent{
				Package: "org.example:widget", Ecosystem: "maven", Action: ActionBlock,
				Reason: "deny list", Version: "2.0", Override: "",
			}); err != nil {
				t.Fatalf("AppendEvent: %v", err)
			}
			if _, err := store.AppendEvent(AuditEvent{
				Package: "left-pad", Ecosystem: "npm", Action: ActionAllow, Reason: "packument",
			}); err != nil {
				t.Fatalf("AppendEvent (package-level): %v", err)
			}
			check := func(path string, got []AuditEvent) {
				byName := map[string]AuditEvent{}
				for _, e := range got {
					byName[e.Package] = e
				}
				m, ok := byName["org.example:widget"]
				if !ok {
					t.Fatalf("%s lost the versioned event", path)
				}
				if m.Version != "2.0" {
					t.Errorf("%s: version = %q, want 2.0", path, m.Version)
				}
				// Column-order canary: an off-by-one Scan fills every field, wrongly.
				if m.Reason != "deny list" || m.Action != ActionBlock || m.Override != "" {
					t.Errorf("%s: an adjacent column came back wrong: %+v", path, m)
				}
				if v := byName["left-pad"].Version; v != "" {
					t.Errorf("%s: a package-level event reads back with version %q", path, v)
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

// The export line names the release; a package-level line has no version key at all.
func TestTheExportCarriesTheVersion(t *testing.T) {
	srv := &server{store: newMemStore()}
	srv.store.AppendEvent(AuditEvent{Package: "pkg", Action: ActionBlock, Version: "2.0.0"})
	srv.store.AppendEvent(AuditEvent{Package: "whole", Action: ActionAllow})

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
		v, has := raw["version"]
		switch raw["package"] {
		case "pkg":
			if v != "2.0.0" {
				t.Errorf("the versioned event's export line does not name the release: %s", ln)
			}
		case "whole":
			if has {
				t.Errorf("a package-level event exports a version key: %s", ln)
			}
		}
	}
}
