package main

import (
	"errors"
	"fmt"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// awaitWaiters blocks until key's flight has at least n followers attached, so a
// coalescing test can synchronize on "the herd has actually gathered" instead of
// sleeping. Returns false on timeout — the caller lets the leader finish anyway, so
// a broken guard fails the assertion loudly instead of hanging the test.
func awaitWaiters[T any](g *flightGroup[T], key string, n int) bool {
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if g.waiters(key) >= n {
			return true
		}
		runtime.Gosched()
	}
	return false
}

// TestFlightGroupCoalesces is the core guarantee: N concurrent calls for the same
// key run the work ONCE and all receive that one result. This is the invariant the
// npm/PyPI/deps.dev thundering-herd guard rests on (issue #16).
func TestFlightGroupCoalesces(t *testing.T) {
	const followers = 32

	g := newFlightGroup[string]()
	var calls atomic.Int32

	results := make(chan string, followers+1)
	var wg sync.WaitGroup

	// Leader: runs the work, and does not return until every follower has attached.
	// It signals from INSIDE fn — by then its flight is registered, so every
	// follower launched after this is guaranteed to attach rather than race the
	// leader to the key and legitimately start a second flight.
	leaderInFlight := make(chan struct{})
	wg.Add(1)
	go func() {
		defer wg.Done()
		v, err := g.do("pkg", func() (string, error) {
			calls.Add(1)
			close(leaderInFlight)
			if !awaitWaiters(g, "pkg", followers) {
				t.Errorf("only %d followers attached, want %d", g.waiters("pkg"), followers)
			}
			return "one-result", nil
		})
		if err != nil {
			t.Errorf("leader: unexpected error: %v", err)
		}
		results <- v
	}()
	<-leaderInFlight

	for i := 0; i < followers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			v, err := g.do("pkg", func() (string, error) {
				calls.Add(1) // must never run: the leader owns this key
				return "duplicate-call", nil
			})
			if err != nil {
				t.Errorf("follower: unexpected error: %v", err)
			}
			results <- v
		}()
	}
	wg.Wait()
	close(results)

	if got := calls.Load(); got != 1 {
		t.Errorf("underlying work ran %d times, want exactly 1", got)
	}
	for v := range results {
		if v != "one-result" {
			t.Errorf("caller got %q, want the leader's result", v)
		}
	}
}

// TestFlightGroupDistinctKeysDoNotCoalesce is the negative control for the test
// above: coalescing must key on the package/repo, not collapse everything into one
// call. Without this, a guard that always returned the first result would pass the
// "exactly 1 call" test while serving every package the same score.
func TestFlightGroupDistinctKeysDoNotCoalesce(t *testing.T) {
	const keys = 8

	g := newFlightGroup[string]()
	var calls atomic.Int32

	// Every key's work blocks until ALL keys are in flight, so the calls genuinely
	// overlap in time — the exact condition under which a same-key guard coalesces.
	var started sync.WaitGroup
	started.Add(keys)
	release := make(chan struct{})

	var wg sync.WaitGroup
	got := make([]string, keys)
	for i := 0; i < keys; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			v, err := g.do(fmt.Sprintf("pkg%d", i), func() (string, error) {
				calls.Add(1)
				started.Done()
				<-release
				return fmt.Sprintf("score%d", i), nil
			})
			if err != nil {
				t.Errorf("pkg%d: unexpected error: %v", i, err)
			}
			got[i] = v
		}(i)
	}
	started.Wait()
	close(release)
	wg.Wait()

	if n := calls.Load(); n != keys {
		t.Errorf("work ran %d times for %d distinct keys, want %d", n, keys, keys)
	}
	for i := 0; i < keys; i++ {
		if want := fmt.Sprintf("score%d", i); got[i] != want {
			t.Errorf("pkg%d got %q, want %q — results crossed between keys", i, got[i], want)
		}
	}
}

// TestFlightGroupErrorsAreSharedNotCached pins the semantics the issue calls out:
// an error reaches the followers that were already waiting (they asked for the same
// thing at the same time), but nothing is retained — the NEXT call re-runs the work.
// This is what keeps getScore's "failures are not cached, next pull retries"
// contract intact.
func TestFlightGroupErrorsAreSharedNotCached(t *testing.T) {
	const followers = 8

	g := newFlightGroup[int]()
	var calls atomic.Int32
	wantErr := errors.New("deps.dev is down")

	var wg sync.WaitGroup
	leaderInFlight := make(chan struct{})
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, err := g.do("repo", func() (int, error) {
			calls.Add(1)
			close(leaderInFlight) // flight registered: followers can now attach
			awaitWaiters(g, "repo", followers)
			return 0, wantErr
		})
		if !errors.Is(err, wantErr) {
			t.Errorf("leader err = %v, want %v", err, wantErr)
		}
	}()
	<-leaderInFlight
	for i := 0; i < followers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := g.do("repo", func() (int, error) {
				calls.Add(1)
				return 0, nil
			})
			if !errors.Is(err, wantErr) {
				t.Errorf("follower err = %v, want the leader's error %v", err, wantErr)
			}
		}()
	}
	wg.Wait()

	if n := calls.Load(); n != 1 {
		t.Fatalf("work ran %d times during the failed flight, want 1", n)
	}

	// The flight is over: a later caller must run the work again, not inherit the
	// failure. (A cache would return the error here; a singleflight must not.)
	v, err := g.do("repo", func() (int, error) {
		calls.Add(1)
		return 42, nil
	})
	if err != nil || v != 42 {
		t.Errorf("after the failed flight: got (%d, %v), want (42, nil) — the error was cached", v, err)
	}
	if n := calls.Load(); n != 2 {
		t.Errorf("work ran %d times total, want 2 (the failure must not be cached)", n)
	}
}

// TestFlightGroupNilIsDirect: a nil group degrades to a direct call, so hand-built
// test Firewalls (which never construct the groups) keep working without nil checks
// at every call site — the same "nil = feature off" idiom as scoreCache.
func TestFlightGroupNilIsDirect(t *testing.T) {
	var g *flightGroup[int]
	ran := false
	v, err := g.do("k", func() (int, error) {
		ran = true
		return 7, nil
	})
	if !ran || v != 7 || err != nil {
		t.Errorf("nil group: got (%d, %v) ran=%v, want (7, nil) ran=true", v, err, ran)
	}
	if n := g.waiters("k"); n != 0 {
		t.Errorf("nil group waiters = %d, want 0", n)
	}
}

// TestFlightGroupLeaderPanicReleasesFollowers: if the leader's work panics, the
// followers must NOT block forever (that would hang a request and leak a goroutine
// per follower). They get the abandoned sentinel — which wraps
// errUpstreamUnavailable, so the D17 taxonomy routes them to a retryable 503 — and
// the key is left clean for the next caller.
func TestFlightGroupLeaderPanicReleasesFollowers(t *testing.T) {
	const followers = 4

	g := newFlightGroup[int]()
	var wg sync.WaitGroup

	leaderInFlight := make(chan struct{})
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer func() { _ = recover() }() // the panic still reaches the leader
		_, _ = g.do("boom", func() (int, error) {
			close(leaderInFlight) // flight registered: followers can now attach
			awaitWaiters(g, "boom", followers)
			panic("upstream client blew up")
		})
	}()
	<-leaderInFlight
	for i := 0; i < followers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := g.do("boom", func() (int, error) { return 1, nil })
			if !errors.Is(err, errFlightAbandoned) {
				t.Errorf("follower err = %v, want errFlightAbandoned", err)
			}
			if !errors.Is(err, errUpstreamUnavailable) {
				t.Errorf("follower err = %v, want it to route as a transient 503", err)
			}
		}()
	}

	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("followers deadlocked after the leader panicked")
	}

	// The poisoned flight was dropped, so the key still works.
	if v, err := g.do("boom", func() (int, error) { return 5, nil }); v != 5 || err != nil {
		t.Errorf("after a panicked flight: got (%d, %v), want (5, nil)", v, err)
	}
}
