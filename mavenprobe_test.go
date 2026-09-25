package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestMavenProbeCoalescesConcurrent is the singleflight half of the D25 fan-out fix
// (item c). The URL cache only helps the SECOND fetch of a URL; a cold resolve where
// many artifacts' parent walks race to the SAME parent POM before any of them has
// cached it still bursts. The gate must collapse that burst so exactly ONE goroutine
// hits the upstream and the rest share its result.
//
// The server's handler blocks until the test releases it, so every caller is still
// in flight when we check: one became the leader (reached the handler), the rest are
// parked in do(). With coalescing, the upstream sees exactly one GET.
func TestMavenProbeCoalescesConcurrent(t *testing.T) {
	var hits int32
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		<-release // hold the leader in flight so followers pile up behind it
		w.Write([]byte("body"))
	}))
	defer srv.Close()

	// nil cache: isolate the singleflight — nothing may be masked by a cache hit.
	// concurrency 0: unbounded semaphore, so only coalescing is under test here.
	e := mavenEcosystem{base: srv.URL, gate: newMavenProbeGate(0)}
	url := srv.URL + "/org/apache/apache/16/apache-16.pom"

	const n = 25
	start := make(chan struct{})
	var wg sync.WaitGroup
	bodies := make([][]byte, n)
	errs := make([]error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start // fire all ~simultaneously so they overlap in do()
			bodies[i], errs[i] = e.fetchBody(srv.Client(), url, "pom fetch")
		}(i)
	}
	close(start)
	// Give every goroutine time to enter do() and block: one on the handler, the
	// rest on the leader's WaitGroup. The leader can't return until we release.
	time.Sleep(150 * time.Millisecond)
	if got := atomic.LoadInt32(&hits); got != 1 {
		close(release) // avoid leaking blocked goroutines before we fail
		wg.Wait()
		t.Fatalf("upstream saw %d GETs while the leader was in flight, want 1", got)
	}
	close(release)
	wg.Wait()

	if got := atomic.LoadInt32(&hits); got != 1 {
		t.Errorf("upstream saw %d GETs total, want 1 (concurrent identical probes must coalesce)", got)
	}
	for i := 0; i < n; i++ {
		if errs[i] != nil {
			t.Errorf("caller %d: unexpected error %v", i, errs[i])
			continue
		}
		if string(bodies[i]) != "body" {
			t.Errorf("caller %d: body = %q, want %q (followers must share the leader's result)", i, bodies[i], "body")
		}
	}
}

// TestMavenProbeConcurrencyBounded is the semaphore half of item c: even across
// DISTINCT URLs (which do NOT coalesce), no more than mavenProbeConcurrency probes
// may hit the upstream at once, so a cold resolve's burst is smoothed under the
// upstream's rate window. The handler records the peak concurrency it ever observes.
func TestMavenProbeConcurrencyBounded(t *testing.T) {
	const bound = 3
	var cur, max, hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		n := atomic.AddInt32(&cur, 1)
		for { // record the running maximum
			m := atomic.LoadInt32(&max)
			if n <= m || atomic.CompareAndSwapInt32(&max, m, n) {
				break
			}
		}
		time.Sleep(40 * time.Millisecond) // hold the slot so concurrency can build
		atomic.AddInt32(&cur, -1)
		w.Write([]byte("body"))
	}))
	defer srv.Close()

	e := mavenEcosystem{base: srv.URL, gate: newMavenProbeGate(bound)}

	const n = 15
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			// Distinct URL per caller: nothing coalesces, so all n reach the gate.
			url := fmt.Sprintf("%s/g/a%d/1.0/a%d-1.0.pom", srv.URL, i, i)
			if _, err := e.fetchBody(srv.Client(), url, "pom fetch"); err != nil {
				t.Errorf("caller %d: unexpected error %v", i, err)
			}
		}(i)
	}
	wg.Wait()

	if got := atomic.LoadInt32(&hits); got != n {
		t.Errorf("upstream saw %d GETs, want %d (distinct URLs must NOT coalesce)", got, n)
	}
	if got := atomic.LoadInt32(&max); got > bound {
		t.Errorf("peak concurrent probes = %d, want <= %d (semaphore must bound outbound probes)", got, bound)
	}
	if got := atomic.LoadInt32(&max); got < 2 {
		t.Errorf("peak concurrent probes = %d; expected the burst to actually run concurrently — test may not be exercising the bound", got)
	}
}

// TestMavenProbeGateDisabled pins the two "off" modes, mirroring the cache's
// nil-safe / zero-disabled contract so the firewall runs without any caller-side
// nil checks: a nil gate runs fn directly and acquire is a no-op; a gate built with
// concurrency <= 0 still coalesces but leaves outbound probes unbounded.
func TestMavenProbeGateDisabled(t *testing.T) {
	var nilGate *mavenProbeGate
	called := false
	body, err := nilGate.do("k", func() ([]byte, error) { called = true; return []byte("x"), nil })
	if err != nil || string(body) != "x" || !called {
		t.Fatalf("nil gate do: got body=%q err=%v called=%v, want fn run directly", body, err, called)
	}
	nilGate.acquire()() // must not panic (no-op release)

	unbounded := newMavenProbeGate(0)
	if unbounded.sem != nil {
		t.Error("concurrency <= 0 should leave the semaphore nil (unbounded)")
	}
	unbounded.acquire()() // no-op release, must not block or panic
}
