package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

// NEGATIVE CONTROL for the reset half of Drain.
//
// The sink ADDS each batch to what it already holds (its upsert is additive because
// replicas report independently). So if Drain returned the counters without clearing
// them, every flush would re-send the running total and the stored numbers would grow
// QUADRATICALLY — a dashboard that looks plausible for the first few minutes and is
// wildly wrong an hour later, with nothing failing anywhere. This is the trap that
// motivates Drain existing at all, separate from Snapshot.
func TestDrainResetsCounters(t *testing.T) {
	f := newFlowRecorder("npm")
	id := flowID{Package: "lodash", Kind: flowArtifact}
	f.recordRequest(id)
	f.recordBytes(id, 100, 100)
	f.recordIPRequest("10.0.0.5")
	f.recordIPBytes("10.0.0.5", 100, 100)

	pkgs, ips := f.Drain()
	if len(pkgs) != 1 || pkgs[0].BytesClient != 100 {
		t.Fatalf("first drain = %+v, want one row with 100 bytes", pkgs)
	}
	if len(ips) != 1 || ips[0].BytesClient != 100 {
		t.Fatalf("first drain IPs = %+v, want one row with 100 bytes", ips)
	}

	// Nothing happened in between, so the next drain must be EMPTY.
	pkgs, ips = f.Drain()
	if len(pkgs) != 0 || len(ips) != 0 {
		t.Errorf("second drain returned %d package / %d ip rows, want 0 — Drain must RESET, or every flush re-sends the running total and the sink's additive upsert compounds it", len(pkgs), len(ips))
	}
}

// Traffic after a drain is counted fresh, not lost. (The mirror of the test above: reset
// must clear, but it must not swallow what arrives next.)
func TestDrainKeepsCountingAfterReset(t *testing.T) {
	f := newFlowRecorder("npm")
	id := flowID{Package: "react", Kind: flowMetadata}
	f.recordBytes(id, 10, 10)
	f.Drain()

	f.recordBytes(id, 25, 25)
	pkgs, _ := f.Drain()
	if len(pkgs) != 1 || pkgs[0].BytesClient != 25 {
		t.Errorf("post-reset drain = %+v, want a single row of exactly 25 bytes", pkgs)
	}
}

// NEGATIVE CONTROL for the single-lock invariant.
//
// relay updates the package aggregation and the IP aggregation for the SAME response. If
// it did that in two separate lock acquisitions, a concurrent Drain could land between
// them and split one relay across two batches — its bytes counted against the package in
// one interval and against the source host in the next. The two panels of the dashboard
// would then disagree for those intervals with nothing to explain it.
//
// The assertion has to be PER BATCH, not on the final totals: a split relay still shows
// up in both running totals eventually, so summing everything at the end reconciles even
// when the invariant is broken. (Learned the hard way — the first version of this test
// checked totals and passed happily against a deliberately broken implementation.)
func TestDrainKeepsAggregationsConsistent(t *testing.T) {
	f := newFlowRecorder("npm")
	var wg sync.WaitGroup
	stop := make(chan struct{})

	var mu sync.Mutex
	var mismatches, batches int

	wg.Add(1)
	go func() { // the flusher
		defer wg.Done()
		check := func() {
			p, i := f.Drain()
			var pkg, ip int64
			for _, r := range p {
				pkg += r.BytesClient
			}
			for _, r := range i {
				ip += r.BytesClient
			}
			if pkg == 0 && ip == 0 {
				return // idle drain, nothing to compare
			}
			mu.Lock()
			batches++
			if pkg != ip {
				mismatches++
			}
			mu.Unlock()
		}
		for {
			select {
			case <-stop:
				check()
				return
			default:
				check()
			}
		}
	}()

	for i := 0; i < 500; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			// Exactly what relay does: one call updating both aggregations atomically.
			f.recordRelayBytes(flowID{Package: "p", Kind: flowArtifact}, "10.0.0.1", 5, 5)
		}()
	}

	time.Sleep(100 * time.Millisecond)
	close(stop)
	wg.Wait()

	mu.Lock()
	defer mu.Unlock()
	if batches == 0 {
		t.Fatal("no non-empty batches observed; the test did not exercise the race")
	}
	if mismatches != 0 {
		t.Errorf("%d of %d batches had package bytes != ip bytes — a relay was split across two batches; both maps must be updated under a single lock", mismatches, batches)
	}
}

// The emitter posts what it drained, stamped with the instance and the bucket it covers.
func TestFlowEmitterPostsBatch(t *testing.T) {
	var got flowBatchDTO
	var mu sync.Mutex
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		json.Unmarshal(body, &got)
		mu.Unlock()
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()

	rec := newFlowRecorder("npm")
	rec.recordRequest(flowID{Package: "lodash", Kind: flowArtifact})
	rec.recordBytes(flowID{Package: "lodash", Kind: flowArtifact}, 500, 500)
	rec.recordIPBytes("10.0.0.7", 500, 500)

	// interval 0 would disable the loop; construct with a real one but flush by hand so
	// the test does not sleep on a wall-clock boundary.
	e := newFlowEmitter(srv.URL, "fw-test", srv.Client(), rec, time.Hour, nil)
	bucket := time.Date(2026, 7, 29, 10, 0, 0, 0, time.UTC)
	e.flush(bucket)

	mu.Lock()
	defer mu.Unlock()
	if got.Instance != "fw-test" {
		t.Errorf("Instance = %q, want fw-test", got.Instance)
	}
	if len(got.Packages) != 1 || got.Packages[0].Package != "lodash" || got.Packages[0].BytesClient != 500 {
		t.Errorf("packages = %+v, want one lodash row of 500 bytes", got.Packages)
	}
	if !got.Packages[0].BucketStart.Equal(bucket) {
		t.Errorf("BucketStart = %s, want %s (the interval that just ended, not 'now')", got.Packages[0].BucketStart, bucket)
	}
	if len(got.Sources) != 1 || got.Sources[0].SourceIP != "10.0.0.7" {
		t.Errorf("sources = %+v, want one row for 10.0.0.7", got.Sources)
	}
}

// A failed delivery is DROPPED and counted, never retried: the sink's upsert is additive,
// so a retry would double-count. Under-reporting never invents traffic; over-reporting
// does. The drop counter is what lets an operator tell "quiet" from "we lost the numbers".
func TestFlowEmitterDropsRatherThanRetries(t *testing.T) {
	// Counted PER PATH: the emitter also sends a heartbeat to /v1/health on every flush,
	// and lumping the two together would let a heartbeat be mistaken for a retry of the
	// flow batch (or hide one).
	posts := map[string]int{}
	var mu sync.Mutex
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		posts[r.URL.Path]++
		mu.Unlock()
		http.Error(w, "nope", http.StatusInternalServerError)
	}))
	defer srv.Close()

	rec := newFlowRecorder("npm")
	rec.recordBytes(flowID{Package: "x", Kind: flowArtifact}, 10, 10)

	e := newFlowEmitter(srv.URL, "fw-test", srv.Client(), rec, time.Hour, nil)
	e.flush(time.Now().UTC().Truncate(time.Minute))

	mu.Lock()
	defer mu.Unlock()
	if posts["/v1/flow"] != 1 {
		t.Errorf("upstream saw %d flow posts, want exactly 1 — a failed flush must NOT be retried (the sink's upsert is additive, so a retry double-counts)", posts["/v1/flow"])
	}
	if e.Dropped() != 1 {
		t.Errorf("Dropped() = %d, want 1 — a lost batch must be counted so the dashboard can admit it is short", e.Dropped())
	}
}

// The recorder is drained even when the control plane is unreachable. Counters that are
// never drained grow per distinct package, without bound, on a busy instance — losing a
// batch is the accepted failure; leaking memory because approval is down is not.
func TestFlowEmitterDrainsEvenWhenSinkIsDown(t *testing.T) {
	rec := newFlowRecorder("npm")
	rec.recordBytes(flowID{Package: "x", Kind: flowArtifact}, 10, 10)

	// An endpoint that refuses connections outright.
	e := newFlowEmitter("http://127.0.0.1:1", "fw-test", &http.Client{Timeout: time.Second}, rec, time.Hour, nil)
	e.flush(time.Now().UTC().Truncate(time.Minute))

	if pkgs, _ := rec.Drain(); len(pkgs) != 0 {
		t.Errorf("recorder still holds %d rows after a failed flush; it must drain regardless or memory grows unbounded while the sink is down", len(pkgs))
	}
}

// With no approval URL the emitter is inert but still drains, so a deployment with no
// control plane behaves exactly as before and does not accumulate counters forever.
func TestFlowEmitterDisabledStillDrains(t *testing.T) {
	rec := newFlowRecorder("npm")
	rec.recordBytes(flowID{Package: "x", Kind: flowArtifact}, 10, 10)

	e := newFlowEmitter("", "fw-test", http.DefaultClient, rec, time.Hour, nil)
	e.flush(time.Now().UTC().Truncate(time.Minute))

	if pkgs, _ := rec.Drain(); len(pkgs) != 0 {
		t.Errorf("disabled emitter left %d rows in the recorder; it must still drain", len(pkgs))
	}
	if e.Dropped() != 0 {
		t.Errorf("Dropped() = %d, want 0 — emission being switched off is not a lost batch", e.Dropped())
	}
}

// An idle interval sends NO FLOW BATCH — but it does send a HEARTBEAT, and that split is
// the whole point of C4a. An idle firewall and a dead one are indistinguishable in the
// flow data (both contribute nothing), so liveness has to be reported separately or the
// "is it alive?" alert would fire every quiet weekend. If the heartbeat were inside the
// "nothing moved" early return, reporting would stop exactly when it started mattering.
func TestFlowEmitterIdleIntervalSendsHeartbeatOnly(t *testing.T) {
	posts := map[string]int{}
	var mu sync.Mutex
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		posts[r.URL.Path]++
		mu.Unlock()
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()

	e := newFlowEmitter(srv.URL, "fw-test", srv.Client(), newFlowRecorder("npm"), time.Hour, nil)
	e.flush(time.Now().UTC().Truncate(time.Minute))

	mu.Lock()
	defer mu.Unlock()
	if posts["/v1/flow"] != 0 {
		t.Errorf("posted %d flow batches for an idle interval, want 0", posts["/v1/flow"])
	}
	if posts["/v1/health"] != 1 {
		t.Errorf("posted %d heartbeats for an idle interval, want 1 — liveness must be reported precisely when there is no traffic to infer it from", posts["/v1/health"])
	}
}
