package main

import (
	"fmt"
	"os"
	"testing"
	"time"
)

// The flow dataset has TWO backends that must aggregate identically, and only one of
// them (memStore) can be tested without a database. So the suite below is written
// against the Store interface and run over every backend available in the environment:
// memStore always, and pgStore when APPROVAL_TEST_DSN points at a throwaway Postgres.
//
// Why bother rather than testing memStore alone: the two implementations express the
// same rules in different languages (Go map merging vs ON CONFLICT DO UPDATE, Go sorting
// vs ORDER BY, and a half-open window in both). Those are exactly the places a silent
// divergence hides — the dashboard would simply show different numbers depending on how
// the operator deployed us, with nothing failing. Running one suite over both is what
// makes that a test failure instead of a support ticket.
//
//	APPROVAL_TEST_DSN='postgres://user:pass@localhost:5432/yj_test?sslmode=disable' go test ./approval/
func flowStores(t *testing.T) map[string]Store {
	t.Helper()
	out := map[string]Store{"mem": newMemStore()}
	dsn := os.Getenv("APPROVAL_TEST_DSN")
	if dsn == "" {
		return out
	}
	pg, err := newPGStore(dsn)
	if err != nil {
		// A DSN that was deliberately provided but does not work is a failure, not a
		// skip: silently falling back to mem-only would report green for a backend that
		// was never exercised, which is the false confidence the project bans.
		t.Fatalf("APPROVAL_TEST_DSN set but unusable: %v", err)
	}
	// instance_health is cleaned here too: it is written by the same C4a heartbeat path
	// and a row left over from a previous test would make a liveness assertion pass for
	// the wrong reason.
	for _, table := range []string{"flow_buckets", "flow_ip_buckets", "instance_health"} {
		if _, err := pg.db.Exec("DELETE FROM " + table); err != nil {
			t.Fatalf("clean %s: %v", table, err)
		}
	}
	out["pg"] = pg
	return out
}

func t0() time.Time { return time.Date(2026, 7, 28, 10, 0, 0, 0, time.UTC) }

func bucket(at time.Time, pkg string, kind string, reqs, up, client int64) FlowBucket {
	return FlowBucket{
		BucketStart: at, Instance: "fw-1", Ecosystem: "npm", Package: pkg, Kind: kind,
		Requests: reqs, BytesUpstream: up, BytesClient: client,
	}
}

// A second report for the same key ADDS. This is the core ingest contract: replicas
// report the same bucket independently, and one replica re-flushes a bucket as it keeps
// accruing. An implementation that overwrote instead would silently discard every
// replica but the last — and the dashboard would just show a smaller number, with
// nothing to indicate it was wrong.
func TestAddFlowIsAdditive(t *testing.T) {
	for name, s := range flowStores(t) {
		t.Run(name, func(t *testing.T) {
			if err := s.AddFlow([]FlowBucket{bucket(t0(), "lodash", "artifact", 1, 100, 100)}, nil); err != nil {
				t.Fatal(err)
			}
			if err := s.AddFlow([]FlowBucket{bucket(t0(), "lodash", "artifact", 2, 200, 200)}, nil); err != nil {
				t.Fatal(err)
			}
			sum, err := s.FlowSummary(FlowFilter{})
			if err != nil {
				t.Fatal(err)
			}
			if sum.Requests != 3 || sum.BytesClient != 300 {
				t.Errorf("got %d requests / %d bytes, want 3 / 300 — the upsert must ADD, not replace", sum.Requests, sum.BytesClient)
			}
		})
	}
}

// The unattributed bucket is counted, and the per-package rows still sum to the headline
// total. If infrastructure traffic were dropped, an operator summing the ranking would
// get less than the summary tile and have no way to see why.
func TestFlowUnattributedReconciles(t *testing.T) {
	for name, s := range flowStores(t) {
		t.Run(name, func(t *testing.T) {
			err := s.AddFlow([]FlowBucket{
				bucket(t0(), "lodash", "artifact", 1, 500, 500),
				bucket(t0(), "", "infra", 4, 40, 40), // /v2/ handshakes, token endpoints
			}, nil)
			if err != nil {
				t.Fatal(err)
			}

			sum, err := s.FlowSummary(FlowFilter{})
			if err != nil {
				t.Fatal(err)
			}
			rows, err := s.FlowTopPackages(FlowFilter{}, 0)
			if err != nil {
				t.Fatal(err)
			}

			var rowTotal int64
			for _, r := range rows {
				rowTotal += r.BytesClient
			}
			if rowTotal != sum.BytesClient {
				t.Errorf("rows sum to %d but summary says %d — per-package rows must reconcile with the total", rowTotal, sum.BytesClient)
			}
			if sum.Packages != 1 {
				t.Errorf("Packages = %d, want 1 — the unattributed bucket is not a package", sum.Packages)
			}
			// Unattributed sorts last so real, actionable names lead the ranking.
			if len(rows) != 2 || rows[0].Package != "lodash" || rows[1].Package != "" {
				t.Errorf("ranking = %+v, want lodash first and the unattributed bucket last", rows)
			}
		})
	}
}

// Kinds collapse in the ranking: a package's metadata and artifact traffic is ONE row.
// Splitting them would push a package down the ranking by dividing its own total.
func TestFlowTopPackagesCollapsesKinds(t *testing.T) {
	for name, s := range flowStores(t) {
		t.Run(name, func(t *testing.T) {
			err := s.AddFlow([]FlowBucket{
				bucket(t0(), "react", "metadata", 1, 10, 10),
				bucket(t0(), "react", "artifact", 1, 90, 90),
				bucket(t0(), "vue", "artifact", 1, 50, 50),
			}, nil)
			if err != nil {
				t.Fatal(err)
			}
			rows, err := s.FlowTopPackages(FlowFilter{}, 0)
			if err != nil {
				t.Fatal(err)
			}
			if len(rows) != 2 {
				t.Fatalf("got %d rows, want 2 (one per package, kinds collapsed): %+v", len(rows), rows)
			}
			if rows[0].Package != "react" || rows[0].BytesClient != 100 {
				t.Errorf("top row = %+v, want react with 100 bytes (10 metadata + 90 artifact)", rows[0])
			}
		})
	}
}

// The time window is half-open [From, To). A bucket sitting exactly on To belongs to the
// NEXT window — otherwise two adjacent windows both count it and the sum of the parts
// exceeds the whole.
func TestFlowWindowIsHalfOpen(t *testing.T) {
	for name, s := range flowStores(t) {
		t.Run(name, func(t *testing.T) {
			start, mid := t0(), t0().Add(time.Hour)
			err := s.AddFlow([]FlowBucket{
				bucket(start, "a", "artifact", 1, 10, 10),
				bucket(mid, "b", "artifact", 1, 20, 20),
			}, nil)
			if err != nil {
				t.Fatal(err)
			}

			first, err := s.FlowSummary(FlowFilter{From: start, To: mid})
			if err != nil {
				t.Fatal(err)
			}
			second, err := s.FlowSummary(FlowFilter{From: mid, To: mid.Add(time.Hour)})
			if err != nil {
				t.Fatal(err)
			}
			whole, err := s.FlowSummary(FlowFilter{})
			if err != nil {
				t.Fatal(err)
			}

			if first.BytesClient != 10 {
				t.Errorf("first window = %d bytes, want 10 (the boundary bucket belongs to the next window)", first.BytesClient)
			}
			if second.BytesClient != 20 {
				t.Errorf("second window = %d bytes, want 20", second.BytesClient)
			}
			if first.BytesClient+second.BytesClient != whole.BytesClient {
				t.Errorf("adjacent windows sum to %d but the whole is %d — a boundary bucket is being double-counted",
					first.BytesClient+second.BytesClient, whole.BytesClient)
			}
		})
	}
}

// NEGATIVE CONTROL for the gap. A quiet step must come back as an explicit ZERO, not be
// omitted: a chart that skips empty steps draws a continuous line straight across an
// outage, which is the exact moment an operator is looking at it. An implementation that
// returned only non-empty steps returns 2 points here and fails.
func TestFlowSeriesFillsGapsWithZeros(t *testing.T) {
	for name, s := range flowStores(t) {
		t.Run(name, func(t *testing.T) {
			start := t0()
			// Traffic at minute 0 and minute 3; minutes 1 and 2 are silent.
			err := s.AddFlow([]FlowBucket{
				bucket(start, "a", "artifact", 1, 10, 10),
				bucket(start.Add(3*time.Minute), "a", "artifact", 1, 30, 30),
			}, nil)
			if err != nil {
				t.Fatal(err)
			}

			pts, err := s.FlowSeries(FlowFilter{From: start, To: start.Add(4 * time.Minute)}, time.Minute)
			if err != nil {
				t.Fatal(err)
			}
			if len(pts) != 4 {
				t.Fatalf("got %d points, want 4 (one per minute, gaps included as zeros): %+v", len(pts), pts)
			}
			want := []int64{10, 0, 0, 30}
			for i, w := range want {
				if pts[i].BytesClient != w {
					t.Errorf("point %d (%s) = %d bytes, want %d", i, pts[i].Start.Format(time.RFC3339), pts[i].BytesClient, w)
				}
			}
		})
	}
}

// The per-IP aggregation is its own dataset, and its totals must match the package side
// for the same traffic — they are two views of one flow, so a dashboard showing both
// must not show two different totals.
func TestFlowTopSources(t *testing.T) {
	for name, s := range flowStores(t) {
		t.Run(name, func(t *testing.T) {
			ips := []FlowIPBucket{
				{BucketStart: t0(), Instance: "fw-1", Ecosystem: "npm", SourceIP: "10.0.0.5", Requests: 3, BytesClient: 300, BytesUpstream: 300},
				{BucketStart: t0(), Instance: "fw-1", Ecosystem: "npm", SourceIP: "10.0.0.9", Requests: 1, BytesClient: 900, BytesUpstream: 900},
				{BucketStart: t0(), Instance: "fw-1", Ecosystem: "npm", SourceIP: "", Requests: 1, BytesClient: 50, BytesUpstream: 50},
			}
			if err := s.AddFlow(nil, ips); err != nil {
				t.Fatal(err)
			}
			rows, err := s.FlowTopSources(FlowFilter{}, 0)
			if err != nil {
				t.Fatal(err)
			}
			if len(rows) != 3 {
				t.Fatalf("got %d rows, want 3: %+v", len(rows), rows)
			}
			// Ranked by BYTES, not request count — the question is who is consuming the
			// pipe, and one big artifact pull outweighs many small metadata fetches.
			if rows[0].SourceIP != "10.0.0.9" {
				t.Errorf("top talker = %q, want 10.0.0.9 (most bytes, despite fewer requests)", rows[0].SourceIP)
			}
			if rows[len(rows)-1].SourceIP != "" {
				t.Errorf("last row = %q, want the unobserved bucket sorted last", rows[len(rows)-1].SourceIP)
			}
		})
	}
}

// A limit truncates the ranking but must never be applied to the summary — and limit <= 0
// must mean "everything", so the ranking can always be reconciled against the total.
func TestFlowTopPackagesLimit(t *testing.T) {
	for name, s := range flowStores(t) {
		t.Run(name, func(t *testing.T) {
			var buckets []FlowBucket
			for i := 0; i < 10; i++ {
				buckets = append(buckets, bucket(t0(), fmt.Sprintf("pkg-%02d", i), "artifact", 1, int64(i*10), int64(i*10)))
			}
			if err := s.AddFlow(buckets, nil); err != nil {
				t.Fatal(err)
			}

			top, err := s.FlowTopPackages(FlowFilter{}, 3)
			if err != nil {
				t.Fatal(err)
			}
			if len(top) != 3 {
				t.Fatalf("got %d rows, want 3", len(top))
			}
			if top[0].Package != "pkg-09" {
				t.Errorf("top = %q, want pkg-09 (most bytes)", top[0].Package)
			}

			all, err := s.FlowTopPackages(FlowFilter{}, 0)
			if err != nil {
				t.Fatal(err)
			}
			if len(all) != 10 {
				t.Errorf("limit 0 returned %d rows, want all 10 — 'give me everything' must be expressible", len(all))
			}
		})
	}
}

// Retention removes old buckets from BOTH tables and leaves newer ones alone.
func TestPurgeFlowBefore(t *testing.T) {
	for name, s := range flowStores(t) {
		t.Run(name, func(t *testing.T) {
			old, recent := t0(), t0().Add(48*time.Hour)
			err := s.AddFlow(
				[]FlowBucket{bucket(old, "a", "artifact", 1, 10, 10), bucket(recent, "b", "artifact", 1, 20, 20)},
				[]FlowIPBucket{
					{BucketStart: old, Instance: "fw-1", Ecosystem: "npm", SourceIP: "10.0.0.1", Requests: 1, BytesClient: 10},
					{BucketStart: recent, Instance: "fw-1", Ecosystem: "npm", SourceIP: "10.0.0.2", Requests: 1, BytesClient: 20},
				})
			if err != nil {
				t.Fatal(err)
			}

			n, err := s.PurgeFlowBefore(t0().Add(24 * time.Hour))
			if err != nil {
				t.Fatal(err)
			}
			if n != 2 {
				t.Errorf("purged %d rows, want 2 (one from each table)", n)
			}

			sum, err := s.FlowSummary(FlowFilter{})
			if err != nil {
				t.Fatal(err)
			}
			if sum.BytesClient != 20 {
				t.Errorf("after purge summary = %d bytes, want 20 (only the recent bucket survives)", sum.BytesClient)
			}
			srcs, err := s.FlowTopSources(FlowFilter{}, 0)
			if err != nil {
				t.Fatal(err)
			}
			if len(srcs) != 1 || srcs[0].SourceIP != "10.0.0.2" {
				t.Errorf("after purge sources = %+v, want only 10.0.0.2", srcs)
			}
		})
	}
}

// Filters compose, and an ecosystem filter must not leak another ecosystem's traffic into
// a scoped view.
func TestFlowFilterByEcosystemAndInstance(t *testing.T) {
	for name, s := range flowStores(t) {
		t.Run(name, func(t *testing.T) {
			npm := bucket(t0(), "lodash", "artifact", 1, 100, 100)
			pypi := bucket(t0(), "requests", "artifact", 1, 200, 200)
			pypi.Ecosystem = "pypi"
			other := bucket(t0(), "lodash", "artifact", 1, 400, 400)
			other.Instance = "fw-2"
			if err := s.AddFlow([]FlowBucket{npm, pypi, other}, nil); err != nil {
				t.Fatal(err)
			}

			byEco, err := s.FlowSummary(FlowFilter{Ecosystem: "pypi"})
			if err != nil {
				t.Fatal(err)
			}
			if byEco.BytesClient != 200 {
				t.Errorf("pypi window = %d bytes, want 200", byEco.BytesClient)
			}

			byInstance, err := s.FlowSummary(FlowFilter{Instance: "fw-2"})
			if err != nil {
				t.Fatal(err)
			}
			if byInstance.BytesClient != 400 {
				t.Errorf("fw-2 window = %d bytes, want 400", byInstance.BytesClient)
			}

			all, err := s.FlowSummary(FlowFilter{})
			if err != nil {
				t.Fatal(err)
			}
			if all.BytesClient != 700 {
				t.Errorf("unfiltered = %d bytes, want 700 (every instance and ecosystem summed)", all.BytesClient)
			}
		})
	}
}
