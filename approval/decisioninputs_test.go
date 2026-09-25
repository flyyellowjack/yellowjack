package main

import (
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"testing"
)

// The verdict's inputs, on the wire an auditor actually reads (#28).
//
// The firewall-side tests prove the fields are STAMPED. These prove they SURVIVE —
// through the store and out of /v1/events/export as NDJSON. A field that is recorded
// and then dropped somewhere in the middle is worse than one that was never added:
// the code reads as though the record is complete.

// TestTheVerdictsInputsSurviveTheExport is the round trip in one test.
func TestTheVerdictsInputsSurviveTheExport(t *testing.T) {
	srv := &server{store: newMemStore()}
	score, threshold := 4.2, 5.0
	srv.store.AppendEvent(AuditEvent{
		Package:      "evil-pkg",
		Ecosystem:    "npm",
		Action:       ActionBlock,
		Score:        &score,
		Threshold:    &threshold,
		PolicyDigest: "1f1dc1072d3176a5",
		Reason:       "score 4.2 below threshold",
	})

	rec := do(t, srv, http.MethodGet, "/v1/events/export", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("export = %d, want 200", rec.Code)
	}
	lines := nonEmptyLines(rec.Body.String())
	if len(lines) != 1 {
		t.Fatalf("export returned %d lines, want 1", len(lines))
	}

	// Decoded as an auditor's tool would: from the exported bytes, not from the
	// struct we happen to hold in memory.
	var e AuditEvent
	if err := json.Unmarshal([]byte(lines[0]), &e); err != nil {
		t.Fatalf("exported line is not valid JSON: %v", err)
	}
	if e.Threshold == nil {
		t.Fatal("the exported record has no threshold: it was recorded at the firewall and " +
			"lost on the way out, so the export reads as though the verdict had no bar")
	}
	if *e.Threshold != 5.0 {
		t.Errorf("exported threshold = %v, want 5.0", *e.Threshold)
	}
	if e.PolicyDigest != "1f1dc1072d3176a5" {
		t.Errorf("exported policy_digest = %q, want the digest that was recorded", e.PolicyDigest)
	}
	// The whole point, restated as the check: the verdict is recomputable from the
	// exported line alone.
	if e.Score == nil || !(*e.Score < *e.Threshold) || e.Action != ActionBlock {
		t.Errorf("the exported record does not justify its own verdict: score=%v threshold=%v action=%q",
			e.Score, e.Threshold, e.Action)
	}

	// And the JSON field names are part of the contract — an auditor's tooling keys
	// off them, so a Go-side rename that kept the tests passing would still break them.
	for _, want := range []string{`"threshold"`, `"policy_digest"`} {
		if !strings.Contains(lines[0], want) {
			t.Errorf("exported JSON does not contain %s: %s", want, lines[0])
		}
	}
}

// TestAnUnscoredVerdictExportsNoThresholdAtAll — the omitempty behaviour, asserted on
// the bytes.
//
// A known-malware refusal weighed no threshold. If nil marshalled as `"threshold":0`
// the export would tell an auditor the bar was zero, i.e. that everything passes —
// precisely inverting what happened.
func TestAnUnscoredVerdictExportsNoThresholdAtAll(t *testing.T) {
	srv := &server{store: newMemStore()}
	srv.store.AppendEvent(AuditEvent{
		Package:      "evil-pkg",
		Ecosystem:    "npm",
		Action:       ActionBlock,
		PolicyDigest: "1f1dc1072d3176a5",
		Reason:       "listed as known malware (MAL-2024-1)",
	})

	line := nonEmptyLines(do(t, srv, http.MethodGet, "/v1/events/export", "").Body.String())[0]
	if strings.Contains(line, `"threshold"`) {
		t.Errorf("a verdict that weighed no threshold exported one anyway: %s", line)
	}
	// Anti-vacuity: the record must still be there and still be a block, otherwise the
	// assertion above is satisfied by an empty or absent line.
	var e AuditEvent
	if err := json.Unmarshal([]byte(line), &e); err != nil {
		t.Fatalf("exported line is not valid JSON: %v", err)
	}
	if e.Action != ActionBlock || e.PolicyDigest == "" {
		t.Errorf("the unscored refusal did not export as a policy-attributed block: %+v", e)
	}
}

// TestOlderEventsStillExport — the migration's honesty case.
//
// Rows written before these columns existed have no threshold and no policy digest.
// They must still export, and must not acquire invented values: an audit trail whose
// old rows silently gain a policy they were never made under is a falsified record,
// which is a worse failure than a missing field.
func TestOlderEventsStillExport(t *testing.T) {
	srv := &server{store: newMemStore()}
	srv.store.AppendEvent(AuditEvent{Package: "left-pad", Ecosystem: "npm", Action: ActionAllow})

	line := nonEmptyLines(do(t, srv, http.MethodGet, "/v1/events/export", "").Body.String())[0]
	var e AuditEvent
	if err := json.Unmarshal([]byte(line), &e); err != nil {
		t.Fatalf("a pre-existing-shape event failed to export: %v", err)
	}
	if e.Package != "left-pad" || e.Action != ActionAllow {
		t.Errorf("the event did not survive the export: %+v", e)
	}
	if e.Threshold != nil || e.PolicyDigest != "" {
		t.Errorf("an event recorded before these fields existed came back carrying them "+
			"(threshold=%v policy=%q) — the record would claim inputs that were never observed",
			e.Threshold, e.PolicyDigest)
	}
}

// eventStores runs one suite over every Store backend available in the environment —
// the same pattern (and the same reasoning) as flowStores in flowstore_test.go.
//
// This matters MORE for the audit schema than for anything else here. Everything
// above uses memStore, which is Go struct copying: the fields survive because Go
// copies structs, not because the SQL is right. The pgStore path has a hand-written
// column list in three places — INSERT, two SELECTs, and scanEvent's positional Scan
// — and getting one of them out of order or one short is a runtime error that NO
// memStore test can see. Without this, the tests above would report green for a
// deployment where the export throws on every row.
//
//	APPROVAL_TEST_DSN='postgres://user:pass@localhost:5432/yj_test?sslmode=disable' go test ./approval/
func eventStores(t *testing.T) map[string]Store {
	t.Helper()
	out := map[string]Store{"mem": newMemStore()}
	dsn := os.Getenv("APPROVAL_TEST_DSN")
	if dsn == "" {
		return out
	}
	pg, err := newPGStore(dsn)
	if err != nil {
		// A DSN deliberately provided but unusable is a failure, not a skip: falling
		// back to mem-only would report green for a backend never exercised.
		t.Fatalf("APPROVAL_TEST_DSN set but unusable: %v", err)
	}
	if _, err := pg.db.Exec("DELETE FROM events"); err != nil {
		t.Fatalf("clean events: %v", err)
	}
	out["pg"] = pg
	return out
}

// TestDecisionInputsRoundTripThroughEveryBackend is the one that actually exercises
// the SQL. It reads the event back through BOTH read paths, because ListEvents and
// StreamEvents have separate column lists that can drift apart independently — and
// StreamEvents is the one the compliance export uses.
func TestDecisionInputsRoundTripThroughEveryBackend(t *testing.T) {
	for name, store := range eventStores(t) {
		t.Run(name, func(t *testing.T) {
			score, threshold := 4.2, 5.0
			if _, err := store.AppendEvent(AuditEvent{
				Package: "evil-pkg", Ecosystem: "npm", Action: ActionBlock,
				Score: &score, Threshold: &threshold, PolicyDigest: "1f1dc1072d3176a5",
				Reason: "score 4.2 below threshold",
			}); err != nil {
				t.Fatalf("AppendEvent: %v", err)
			}
			// An unscored refusal alongside it: the NULL threshold must survive as nil,
			// which on the SQL path is a sql.NullFloat64 that memStore never exercises.
			if _, err := store.AppendEvent(AuditEvent{
				Package: "worse-pkg", Ecosystem: "npm", Action: ActionBlock,
				PolicyDigest: "1f1dc1072d3176a5", Reason: "known malware",
			}); err != nil {
				t.Fatalf("AppendEvent (unscored): %v", err)
			}

			check := func(path string, got []AuditEvent) {
				if len(got) != 2 {
					t.Fatalf("%s returned %d events, want 2", path, len(got))
				}
				byName := map[string]AuditEvent{}
				for _, e := range got {
					byName[e.Package] = e
				}
				scored, ok := byName["evil-pkg"]
				if !ok {
					t.Fatalf("%s lost the scored event", path)
				}
				if scored.Threshold == nil || *scored.Threshold != 5.0 {
					t.Errorf("%s: threshold = %v, want 5.0 — the column round trip dropped it",
						path, scored.Threshold)
				}
				if scored.PolicyDigest != "1f1dc1072d3176a5" {
					t.Errorf("%s: policy_digest = %q, want the stored digest", path, scored.PolicyDigest)
				}
				// Column-order canary: a positional Scan that is off by one still
				// populates every field, just with the wrong values. Asserting an
				// unrelated column still reads correctly catches that, where checking
				// only the new fields would not.
				if scored.Reason != "score 4.2 below threshold" || scored.Action != ActionBlock {
					t.Errorf("%s: an adjacent column came back wrong (reason=%q action=%q) — "+
						"the positional Scan and the SELECT list have drifted apart",
						path, scored.Reason, scored.Action)
				}
				unscored := byName["worse-pkg"]
				if unscored.Threshold != nil {
					t.Errorf("%s: a NULL threshold came back as %v rather than nil, so the export "+
						"will claim a bar that was never applied", path, *unscored.Threshold)
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
			check("StreamEvents (the compliance export path)", streamed)
		})
	}
}

// TestAnExistingDatabaseGainsTheNewColumns — the upgrade path, and the one this
// project has already got wrong once.
//
// `CREATE TABLE IF NOT EXISTS events (...)` is a NO-OP against a database that
// already has the table, so a column added only inside that statement never appears
// on a deployment that has been running. The comment beside source_ip in pgstore.go
// records exactly this: every INSERT naming the column then fails, on upgraded
// installs only, while every fresh install and every test passes.
//
// So this test builds the OLD table shape by hand, runs the migration over it, and
// asserts the new columns work. Fresh-database coverage cannot see this failure —
// TestDecisionInputsRoundTripThroughEveryBackend passes either way.
func TestAnExistingDatabaseGainsTheNewColumns(t *testing.T) {
	dsn := os.Getenv("APPROVAL_TEST_DSN")
	if dsn == "" {
		t.Skip("APPROVAL_TEST_DSN not set; this case is meaningless without a real Postgres")
	}
	pg, err := newPGStore(dsn)
	if err != nil {
		t.Fatalf("APPROVAL_TEST_DSN set but unusable: %v", err)
	}
	// Reconstruct the PRE-#28 table: drop what migrate() built and recreate the older
	// shape, so the ALTERs have something real to upgrade.
	if _, err := pg.db.Exec(`DROP TABLE IF EXISTS events`); err != nil {
		t.Fatalf("drop events: %v", err)
	}
	if _, err := pg.db.Exec(`
		CREATE TABLE events (
			id         BIGSERIAL PRIMARY KEY,
			package    TEXT NOT NULL,
			ecosystem  TEXT NOT NULL DEFAULT '',
			action     TEXT NOT NULL,
			score      DOUBLE PRECISION,
			reason     TEXT NOT NULL DEFAULT '',
			source_ip  TEXT NOT NULL DEFAULT '',
			at         TIMESTAMPTZ NOT NULL
		)`); err != nil {
		t.Fatalf("create the pre-#28 events table: %v", err)
	}
	// A row written by the old code, with no inputs recorded.
	if _, err := pg.db.Exec(
		`INSERT INTO events (package, ecosystem, action, reason, at) VALUES ($1,$2,$3,$4, now())`,
		"legacy-pkg", "npm", string(ActionAllow), "recorded before the inputs existed"); err != nil {
		t.Fatalf("insert a legacy row: %v", err)
	}

	// The upgrade.
	if err := pg.migrate(); err != nil {
		t.Fatalf("migrate over an existing events table: %v", err)
	}

	// Writing the new fields must now work. Before the ALTERs this INSERT is the
	// statement that fails in production.
	threshold := 5.0
	if _, err := pg.AppendEvent(AuditEvent{
		Package: "evil-pkg", Ecosystem: "npm", Action: ActionBlock,
		Threshold: &threshold, PolicyDigest: "1f1dc1072d3176a5", Reason: "below threshold",
	}); err != nil {
		t.Fatalf("AppendEvent after upgrading an existing database: %v — the columns were "+
			"created only inside CREATE TABLE IF NOT EXISTS, which is a no-op here", err)
	}

	got, err := pg.ListEvents(EventFilter{})
	if err != nil {
		t.Fatalf("ListEvents after upgrade: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("after upgrade the log holds %d events, want 2 (the legacy row must survive)", len(got))
	}
	byName := map[string]AuditEvent{}
	for _, e := range got {
		byName[e.Package] = e
	}
	// The legacy row must read back with NO inputs. Backfilling it with the current
	// policy would make the trail claim a configuration that row was never made under
	// — a falsified audit record, which is worse than an incomplete one.
	if l := byName["legacy-pkg"]; l.Threshold != nil || l.PolicyDigest != "" {
		t.Errorf("a pre-upgrade row came back carrying inputs (threshold=%v policy=%q); the "+
			"migration invented evidence for a decision made under an unknown policy",
			l.Threshold, l.PolicyDigest)
	}
	if n := byName["evil-pkg"]; n.Threshold == nil || *n.Threshold != 5.0 || n.PolicyDigest == "" {
		t.Errorf("the post-upgrade row lost its inputs: threshold=%v policy=%q", n.Threshold, n.PolicyDigest)
	}
}
