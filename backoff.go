package main

import (
	"sync"
	"time"
)

// backoffCache is a short-TTL circuit breaker for upstream rate limiting (HTTP
// 429). When a scoring probe for a package is rate-limited, we record a marker
// here; while it is live, later pulls of that SAME package short-circuit to a
// retryable 503 WITHOUT re-probing upstream.
//
// Why this exists (D25): a rate-limited repo lookup caches nothing — repoCache
// only stores a *successful* result — so every mvn retry re-runs the package's
// full probe fan-out (maven-metadata + POM + parent POMs), amplifying the very
// 429 storm we're already being throttled by. This marker breaks that loop.
//
// It is deliberately NOT a verdict cache: it stores no score and no allow/block,
// only "this package's sources were throttling us less than <ttl> ago". The TTL
// is seconds (not the score cache's hours), so a genuine recovery is picked up
// almost immediately and a package can never be pinned unavailable. It is also
// DISTINCT from the Phase-5 repository cache (a separate service, a project
// decision) — this is only an in-memory, per-replica burst guard.
//
// Same concurrency + nil contract as scoreCache/repoCache: mutated by concurrent
// requests, so every access is mutex-guarded (RLock read, Lock write), and a nil
// cache is a no-op so hand-built Firewalls in tests need no backoff wiring.
type backoffCache struct {
	mu  sync.RWMutex
	ttl time.Duration
	m   map[string]time.Time // key -> expiry
}

func newBackoffCache(ttl time.Duration) *backoffCache {
	return &backoffCache{ttl: ttl, m: make(map[string]time.Time)}
}

// active reports whether key is currently backed off (marked and not expired). A
// nil cache is always inactive, so callers never need a nil check.
func (c *backoffCache) active(key string) bool {
	if c == nil {
		return false
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	expiry, ok := c.m[key]
	return ok && time.Now().Before(expiry)
}

// mark records key as backed off for the configured TTL. A nil cache or a
// ttl <= 0 disables backoff, so mark becomes a no-op and active always misses.
func (c *backoffCache) mark(key string) {
	if c == nil || c.ttl <= 0 {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.m[key] = time.Now().Add(c.ttl)
}
