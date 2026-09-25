package main

import (
	"fmt"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

// resp builds a cachedResponse with an exactly-known size: an empty (non-nil)
// header set contributes zero bytes, so size() == len(body). Tests can therefore
// reason about the byte budget in whole bodies.
func resp(body string) cachedResponse {
	return cachedResponse{status: http.StatusOK, header: http.Header{}, body: []byte(body)}
}

// expire forces an already-stored entry to look old, so TTL behaviour can be tested
// without sleeping (sleep-based expiry tests are the classic CI flake).
func expire(t *testing.T, s *respStore, key string) {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	el, ok := s.m[key]
	if !ok {
		t.Fatalf("expire: key %q not in store", key)
	}
	el.Value.(*entry).expiry = time.Now().Add(-time.Second)
}

func TestStoreHitAndMiss(t *testing.T) {
	s := newRespStore(time.Minute, 1<<20)

	if _, ok := s.get("absent"); ok {
		t.Fatal("empty store returned a hit")
	}

	s.put("k", resp("hello"))
	got, ok := s.get("k")
	if !ok {
		t.Fatal("stored entry did not come back")
	}
	if string(got.body) != "hello" {
		t.Fatalf("body = %q, want %q", got.body, "hello")
	}
}

// An entry past its TTL must read as a miss AND be dropped, so expired bodies don't
// linger in memory waiting for eviction pressure.
func TestStoreExpiryEvictsOnRead(t *testing.T) {
	s := newRespStore(time.Minute, 1<<20)
	s.put("k", resp("stale-metadata"))

	expire(t, s, "k")

	if _, ok := s.get("k"); ok {
		t.Fatal("expired entry was served as a hit")
	}
	if n, bytes := s.stats(); n != 0 || bytes != 0 {
		t.Fatalf("expired entry not reclaimed: entries=%d bytes=%d, want 0/0", n, bytes)
	}
}

// The TTL must actually come from the configured duration, not a constant.
func TestStoreExpiryUsesConfiguredTTL(t *testing.T) {
	s := newRespStore(2*time.Hour, 1<<20)
	s.put("k", resp("x"))

	s.mu.Lock()
	got := s.m["k"].Value.(*entry).expiry
	s.mu.Unlock()

	want := time.Now().Add(2 * time.Hour)
	if d := got.Sub(want); d > time.Minute || d < -time.Minute {
		t.Fatalf("expiry = %v, want ~%v", got, want)
	}
}

// Total held bytes must stay inside the budget, and the entry evicted must be the
// least RECENTLY USED one — not merely the oldest-inserted.
func TestStoreEvictsLeastRecentlyUsed(t *testing.T) {
	const body = 100
	s := newRespStore(time.Minute, 3*body) // room for exactly three entries

	s.put("a", resp(strings.Repeat("a", body)))
	s.put("b", resp(strings.Repeat("b", body)))
	s.put("c", resp(strings.Repeat("c", body)))

	if n, bytes := s.stats(); n != 3 || bytes != 3*body {
		t.Fatalf("before eviction: entries=%d bytes=%d, want 3/%d", n, bytes, 3*body)
	}

	// Touch "a" so "b" becomes the least recently used.
	if _, ok := s.get("a"); !ok {
		t.Fatal("a should still be cached")
	}

	s.put("d", resp(strings.Repeat("d", body)))

	if n, bytes := s.stats(); n != 3 || bytes != 3*body {
		t.Fatalf("after eviction: entries=%d bytes=%d, want 3/%d (budget exceeded)", n, bytes, 3*body)
	}
	if _, ok := s.get("b"); ok {
		t.Fatal("b was least recently used and should have been evicted")
	}
	for _, k := range []string{"a", "c", "d"} {
		if _, ok := s.get(k); !ok {
			t.Fatalf("%q should have survived eviction", k)
		}
	}
}

// A response larger than the whole budget is not cached at all — caching it would
// evict everything else for something that can't be kept anyway.
func TestStoreSkipsOversizedResponse(t *testing.T) {
	s := newRespStore(time.Minute, 100)
	s.put("small", resp(strings.Repeat("s", 50)))
	s.put("huge", resp(strings.Repeat("h", 500)))

	if _, ok := s.get("huge"); ok {
		t.Fatal("oversized response should not be cached")
	}
	if _, ok := s.get("small"); !ok {
		t.Fatal("oversized put must not evict existing entries")
	}
	if n, bytes := s.stats(); n != 1 || bytes != 50 {
		t.Fatalf("entries=%d bytes=%d, want 1/50", n, bytes)
	}
}

// Re-putting a key must replace it, not double-count its bytes — otherwise the
// budget leaks and the cache slowly starves itself.
func TestStoreReplaceDoesNotLeakBytes(t *testing.T) {
	s := newRespStore(time.Minute, 1<<20)

	s.put("k", resp(strings.Repeat("x", 100)))
	s.put("k", resp(strings.Repeat("y", 30)))

	n, bytes := s.stats()
	if n != 1 || bytes != 30 {
		t.Fatalf("entries=%d bytes=%d, want 1/30", n, bytes)
	}
	got, _ := s.get("k")
	if string(got.body) != strings.Repeat("y", 30) {
		t.Fatal("replacement body was not stored")
	}
}

// A non-positive TTL or budget disables caching outright: the service degrades to
// pass-through rather than serving unbounded or never-expiring entries.
func TestStoreDisabled(t *testing.T) {
	for _, tc := range []struct {
		name     string
		ttl      time.Duration
		maxBytes int64
	}{
		{"zero ttl", 0, 1 << 20},
		{"negative ttl", -time.Second, 1 << 20},
		{"zero bytes", time.Minute, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := newRespStore(tc.ttl, tc.maxBytes)
			if s.enabled() {
				t.Fatal("store should be disabled")
			}
			s.put("k", resp("v"))
			if _, ok := s.get("k"); ok {
				t.Fatal("disabled store returned a hit")
			}
			if n, _ := s.stats(); n != 0 {
				t.Fatalf("disabled store held %d entries", n)
			}
		})
	}
}

// A nil store must be safe to call, matching the firewall's nil-safe cache types.
func TestStoreNilSafe(t *testing.T) {
	var s *respStore
	if s.enabled() {
		t.Fatal("nil store reported enabled")
	}
	if _, ok := s.get("k"); ok {
		t.Fatal("nil store returned a hit")
	}
	s.put("k", resp("v")) // must not panic
	if n, bytes := s.stats(); n != 0 || bytes != 0 {
		t.Fatalf("nil store stats = %d/%d, want 0/0", n, bytes)
	}
}

// The store is hammered by concurrent request goroutines, so run the mixed
// read/write/evict path under -race. The byte total must remain consistent with the
// entries actually held — the accounting bug this guards against (curBytes drifting
// from reality) would silently disable or over-evict the cache.
func TestStoreConcurrentAccess(t *testing.T) {
	const body = 100
	s := newRespStore(time.Minute, 10*body)

	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				key := fmt.Sprintf("key-%d", (i+j)%40) // 40 keys over a 10-entry budget: constant eviction
				s.put(key, resp(strings.Repeat("v", body)))
				s.get(key)
				s.stats()
			}
		}(i)
	}
	wg.Wait()

	n, bytes := s.stats()
	if bytes != int64(n)*body {
		t.Fatalf("byte accounting drifted: entries=%d bytes=%d, want bytes=%d", n, bytes, n*body)
	}
	if bytes > 10*body {
		t.Fatalf("budget exceeded: bytes=%d, want <= %d", bytes, 10*body)
	}
}
