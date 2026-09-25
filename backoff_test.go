package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// TestEvaluateRateLimitBackoffSkipsUpstream is the D25 circuit-breaker assertion:
// once a package's scoring probe is rate-limited (429), a second pull within the
// backoff TTL must return the retryable 503 WITHOUT re-hitting upstream — otherwise
// every mvn retry re-runs the probe fan-out and amplifies the 429 storm. The
// control (TTL disabled) proves the skip is the backoff and not some other cache.
func TestEvaluateRateLimitBackoffSkipsUpstream(t *testing.T) {
	var hits int64
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&hits, 1)
		w.WriteHeader(http.StatusTooManyRequests) // throttle everything: the storm
	}))
	t.Cleanup(up.Close)

	newFW := func(backoff time.Duration) *Firewall {
		// ScoreCacheTTL is left 0 so the repo/score caches are disabled: the ONLY
		// thing that can suppress a re-probe here is the rate-limit backoff, which
		// isolates exactly what this test is about.
		f, err := NewFirewall(Config{
			Ecosystem:           "maven",
			UpstreamRegistry:    up.URL,
			ScorecardMode:       "stub",
			ScoreThreshold:      5.0,
			UnscorablePolicy:    "block",
			RateLimitBackoffTTL: backoff,
		})
		if err != nil {
			t.Fatalf("NewFirewall: %v", err)
		}
		return f
	}

	// Backoff ENABLED: the first pull probes upstream and is rate-limited; a second
	// pull inside the TTL must add zero upstream hits and still read as a rate-limit.
	f := newFW(time.Minute)
	d := f.Evaluate("org.example:widget")
	if !d.Unavailable {
		t.Fatalf("first pull: Unavailable=%v, want true (reason: %s)", d.Unavailable, d.Reason)
	}
	after1 := atomic.LoadInt64(&hits)
	if after1 == 0 {
		t.Fatal("first pull should have probed upstream at least once")
	}

	d = f.Evaluate("org.example:widget")
	if !d.Unavailable {
		t.Fatalf("second pull: Unavailable=%v, want true", d.Unavailable)
	}
	if !strings.Contains(d.Reason, "rate limited") || !strings.Contains(d.Reason, "429") {
		t.Errorf("backed-off reason = %q, want it to name the rate limit + HTTP 429", d.Reason)
	}
	if got := atomic.LoadInt64(&hits); got != after1 {
		t.Errorf("second pull hit upstream %d extra time(s); backoff must serve it without re-probing", got-after1)
	}

	// Control: backoff DISABLED (ttl 0) — the second pull MUST re-probe, proving the
	// skip above is the circuit breaker and not some other caching path.
	atomic.StoreInt64(&hits, 0)
	g := newFW(0)
	g.Evaluate("org.example:widget")
	afterCtl1 := atomic.LoadInt64(&hits)
	g.Evaluate("org.example:widget")
	if got := atomic.LoadInt64(&hits); got <= afterCtl1 {
		t.Errorf("with backoff disabled, the second pull should re-probe upstream (hits %d -> %d)", afterCtl1, got)
	}
}

// TestBackoffCacheExpiryAndNilSafety covers the marker type directly: a mark is
// active until the TTL lapses then not, a ttl<=0 cache never marks, and a nil
// cache is a safe no-op (hand-built Firewalls carry no backoff).
func TestBackoffCacheExpiryAndNilSafety(t *testing.T) {
	c := newBackoffCache(40 * time.Millisecond)
	if c.active("k") {
		t.Fatal("fresh cache must not report a key active")
	}
	c.mark("k")
	if !c.active("k") {
		t.Fatal("key must be active immediately after mark")
	}
	time.Sleep(60 * time.Millisecond)
	if c.active("k") {
		t.Error("key must expire once the TTL lapses")
	}

	disabled := newBackoffCache(0)
	disabled.mark("k")
	if disabled.active("k") {
		t.Error("ttl<=0 must disable backoff (mark is a no-op)")
	}

	var nilCache *backoffCache
	nilCache.mark("k") // must not panic
	if nilCache.active("k") {
		t.Error("nil cache must always be inactive")
	}
}
