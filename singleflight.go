package main

import (
	"fmt"
	"sync"
)

// flightGroup is request coalescing ("singleflight"): concurrent calls for the
// SAME key run the underlying work exactly once and every caller shares that one
// result. It is the thundering-herd guard for our upstream lookups.
//
// Why we need it (issue #16). Every cache in this codebase — the L1 score cache,
// the repo cache, the maven URL cache — only helps the SECOND lookup of a key. A
// cold `npm install` fans a tree of packages into many concurrent requests, and
// for a single package the metadata request plus each tarball request all land
// before anything has been cached. Without coalescing, N identical requests become
// N identical calls to the registry / deps.dev — precisely the burst that earns a
// 429 (D25) and the fan-out D12 first named. Maven already had this guard
// (mavenProbeGate); npm, PyPI and the deps.dev score lookup did not.
//
// This type is the coalescing half of mavenProbeGate, lifted out and made generic
// so every hot path can share one reviewed implementation. Deliberately NOT
// golang.org/x/sync/singleflight: this is ~40 lines of standard-library sync, and
// per CLAUDE.md every third-party dependency in a security tool is our own attack
// surface. (x/sync is only an indirect dependency via pgx today; taking it direct
// would promote it to something we ship on purpose.)
//
// What it is NOT: a cache. The entry is removed the moment the leader finishes, so
// only callers that overlapped IN TIME share a result. A caller that arrives after
// the flight completes runs its own. That is what keeps error semantics unchanged —
// errors are shared with the concurrent followers but never cached, so the next
// request retries (the existing getScore contract).
type flightGroup[T any] struct {
	mu       sync.Mutex
	inflight map[string]*flightCall[T]
}

// flightCall is one in-flight operation that concurrent callers for the same key
// wait on. val/err are written once by the leader BEFORE wg is released and only
// read by followers AFTER wg.Wait() returns — the WaitGroup is the happens-before
// edge that makes that unsynchronized-looking access safe (and race-clean).
type flightCall[T any] struct {
	wg  sync.WaitGroup
	val T
	err error
	// waiting counts followers currently attached to this flight — i.e. upstream
	// calls this coalescing has avoided. Written and read only under the group's
	// mutex (which followers already hold when they attach), so it costs nothing
	// extra. Exposed via waiters(); used by the concurrency tests to synchronize on
	// "the herd has actually gathered" instead of sleeping, which is what makes
	// those tests deterministic rather than timing-dependent.
	waiting int
}

func newFlightGroup[T any]() *flightGroup[T] {
	return &flightGroup[T]{inflight: make(map[string]*flightCall[T])}
}

// errFlightAbandoned is what followers receive if the leader's fn PANICS. Without
// it the leader would unwind without ever publishing a result and every follower
// would block forever — a hung request per follower plus a leaked goroutine, from
// a bug that would otherwise have been one recovered handler panic. It wraps
// errUpstreamUnavailable so the existing taxonomy (D17) routes followers to a
// retryable 503 — "we could not consult our sources" — rather than to a verdict.
var errFlightAbandoned = fmt.Errorf("lookup abandoned (leader failed): %w", errUpstreamUnavailable)

// do runs fn for key, coalescing concurrent calls so fn executes once and all
// callers get its result.
//
// A nil group degrades to a direct fn() call — no coalescing, never a panic — so
// hand-built test Firewalls and ecosystems need no nil checks. Same "nil = feature
// off" idiom as scoreCache/inflightScans.
func (g *flightGroup[T]) do(key string, fn func() (T, error)) (T, error) {
	if g == nil {
		return fn()
	}

	g.mu.Lock()
	if call, ok := g.inflight[key]; ok {
		// A leader is already doing this exact work; wait and share its result.
		call.waiting++
		g.mu.Unlock()
		call.wg.Wait()
		return call.val, call.err
	}
	// We are the leader for this key.
	call := &flightCall[T]{err: errFlightAbandoned} // pessimistic until fn returns
	call.wg.Add(1)
	g.inflight[key] = call
	g.mu.Unlock()

	// Deferred so that a panic in fn still (a) releases the followers — with the
	// pessimistic error above, since the assignment below never ran — and (b) drops
	// the entry, so a later call re-runs instead of inheriting a poisoned flight.
	// The panic itself still propagates to the leader; we only stop it becoming a
	// deadlock for everyone else.
	defer func() {
		call.wg.Done() // publish to followers before they are allowed to read
		g.mu.Lock()
		delete(g.inflight, key)
		g.mu.Unlock()
	}()

	call.val, call.err = fn()
	return call.val, call.err
}

// waiters reports how many callers are currently attached to key's in-flight call
// (0 if there is no flight for key, or the group is nil). That is exactly the
// number of duplicate upstream calls this guard is suppressing right now.
func (g *flightGroup[T]) waiters(key string) int {
	if g == nil {
		return 0
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if call, ok := g.inflight[key]; ok {
		return call.waiting
	}
	return 0
}
