package main

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

// expireNow backdates an existing entry so expiry can be tested without sleeping.
// It reaches into the LRU because that is the only way to age an entry deterministically;
// a sleep-based test of a TTL is a flake waiting for a slow CI runner.
func expireNow[V any](c *ttlLRU[V], key string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if el, ok := c.m[key]; ok {
		el.Value.(*lruEntry[V]).expiry = time.Now().Add(-time.Minute)
	}
}

func TestScoreCache(t *testing.T) {
	c := newTTLLRU[float64](time.Hour, 1000)

	// Empty cache misses.
	if _, ok := c.get("github.com/a/b"); ok {
		t.Fatal("empty cache should miss")
	}

	// After put, a fresh entry hits with the stored score.
	c.put("github.com/a/b", 7.5)
	if s, ok := c.get("github.com/a/b"); !ok || s != 7.5 {
		t.Fatalf("expected hit 7.5, got (%v, %v)", s, ok)
	}

	// An expired entry misses.
	c.put("github.com/x/y", 9.0)
	expireNow(c, "github.com/x/y")
	if _, ok := c.get("github.com/x/y"); ok {
		t.Fatal("expired entry should miss")
	}
}

func TestScoreCacheDisabled(t *testing.T) {
	// ttl <= 0 disables caching entirely: put is a no-op, get always misses.
	c := newTTLLRU[float64](0, 1000)
	c.put("github.com/a/b", 7.5)
	if _, ok := c.get("github.com/a/b"); ok {
		t.Fatal("ttl<=0 should not cache")
	}
}

// TestZeroMaxUsesTheDefaultCap pins the three-way distinction a zero cap could mean, and
// which one was chosen.
//
// It is NOT "unlimited" — that would restore the unbounded growth #61 exists to remove.
// It is NOT "cache nothing" either, which the first draft did: eleven existing fixtures
// build a Config literal setting only ScoreCacheTTL, so a zero cap silently disabled L1
// caching in all of them. One caught it (deps.dev calls went 2 -> 12); the rest kept
// passing while measuring something else.
//
// It applies the BUILT-IN DEFAULT, matching how f.ruleset() and f.byteRuleset() treat a
// zero value here. "Off" keeps exactly one spelling: the TTL.
func TestZeroMaxUsesTheDefaultCap(t *testing.T) {
	c := newTTLLRU[float64](time.Hour, 0)
	c.put("github.com/a/b", 7.5)
	if _, ok := c.get("github.com/a/b"); !ok {
		t.Fatal("a zero cap must fall back to the default, not disable the cache — every " +
			"hand-built Config predating this field would otherwise stop caching silently")
	}
	if c.max != defaultCacheMaxEntries {
		t.Errorf("cap = %d, want the default %d", c.max, defaultCacheMaxEntries)
	}

	// ...and it is still a real bound, not unlimited.
	for i := 0; i < defaultCacheMaxEntries+500; i++ {
		c.put(fmt.Sprintf("repo%d", i), 1)
	}
	if n := c.len(); n > defaultCacheMaxEntries {
		t.Errorf("cache holds %d entries, exceeding the default cap %d", n, defaultCacheMaxEntries)
	}
}

// TestCacheIsBoundedByEntryCount is the core of #61: the map must not grow without limit.
//
// It inserts far more distinct keys than the cap — the real workload being modelled is a
// build agent pulling the long tail of transitive dependencies, where every key is seen
// exactly once and never again.
func TestCacheIsBoundedByEntryCount(t *testing.T) {
	const max = 50
	c := newTTLLRU[float64](time.Hour, max)

	for i := 0; i < max*20; i++ {
		c.put(fmt.Sprintf("github.com/o/r%d", i), float64(i%10))
	}

	if n := c.len(); n > max {
		t.Errorf("cache holds %d entries with a cap of %d — the bound does not hold, which is "+
			"the unbounded growth #61 is about", n, max)
	}
	// The most recent insert must have survived; the first must not. Without both, a
	// cache that simply dropped everything would pass the assertion above.
	if _, ok := c.get(fmt.Sprintf("github.com/o/r%d", max*20-1)); !ok {
		t.Error("the most recently inserted entry was evicted — the cache is not caching")
	}
	if _, ok := c.get("github.com/o/r0"); ok {
		t.Error("the oldest entry survived eviction of 1000 later ones")
	}
}

// TestCacheEvictsLeastRecentlyUsed pins that it is an LRU and not a FIFO. The distinction
// matters for the real traffic shape: a handful of hot packages are requested throughout a
// build while the long tail is touched once, and a FIFO would evict the hot ones on
// schedule regardless of how often they were used.
func TestCacheEvictsLeastRecentlyUsed(t *testing.T) {
	const max = 10
	c := newTTLLRU[float64](time.Hour, max)

	for i := 0; i < max; i++ {
		c.put(fmt.Sprintf("repo%d", i), float64(i))
	}
	// Touch repo0 so it is the most recently USED while still the oldest INSERTED.
	if _, ok := c.get("repo0"); !ok {
		t.Fatal("fixture: repo0 should still be present before the eviction pressure")
	}
	// One more insert forces exactly one eviction.
	c.put("repoNew", 99)

	if _, ok := c.get("repo0"); !ok {
		t.Error("repo0 was evicted despite being the most recently USED — this is a FIFO, not an LRU")
	}
	if _, ok := c.get("repo1"); ok {
		t.Error("repo1 survived; it was the least recently used and should have been evicted")
	}
}

// TestExpiredEntriesAreReclaimedNotJustMissed is item 2 of #61, and the half that is
// invisible from the outside: an implementation that reports a miss for an expired entry
// while keeping it in memory behaves identically to one that frees it, which is precisely
// why this went unnoticed. So the assertion is on the OCCUPANCY, not on the miss.
func TestExpiredEntriesAreReclaimedNotJustMissed(t *testing.T) {
	c := newTTLLRU[float64](time.Hour, 100)
	c.put("github.com/a/b", 7.5)
	expireNow(c, "github.com/a/b")

	if n := c.len(); n != 1 {
		t.Fatalf("fixture: expected the expired entry to still occupy a slot before the read, got %d", n)
	}
	if _, ok := c.get("github.com/a/b"); ok {
		t.Fatal("expired entry should miss")
	}
	if n := c.len(); n != 0 {
		t.Errorf("after reading an expired entry the cache still holds %d entries — it was reported "+
			"as a miss but never freed, which is the leak, not the fix", n)
	}
}

// TestRepoCacheCachesTheEmptyRepo guards a property the type comment claims and that a
// naive "treat the zero value as absent" implementation would silently break: "" is a real
// cached value meaning "this package declares no usable repo", and re-fetching metadata
// for it on every request is the fan-out this cache exists to prevent.
func TestRepoCacheCachesTheEmptyRepo(t *testing.T) {
	c := newRepoCache(time.Hour, 100)
	c.put("some-package", "")
	repo, ok := c.get("some-package")
	if !ok {
		t.Fatal(`the empty repo string must be a cacheable value, not read as "absent"`)
	}
	if repo != "" {
		t.Errorf("got %q, want the empty string", repo)
	}
}

// TestCacheIsSafeUnderConcurrency exists because the bound made every read a WRITE (the
// LRU reorders on get), so the RWMutex became a Mutex. Run under -race, this is what
// proves that change was carried through rather than left half-done.
func TestCacheIsSafeUnderConcurrency(t *testing.T) {
	c := newTTLLRU[float64](time.Hour, 64)
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				k := fmt.Sprintf("repo%d", (n*j)%128)
				c.put(k, float64(j))
				c.get(k)
			}
		}(i)
	}
	wg.Wait()
	if n := c.len(); n > 64 {
		t.Errorf("cache holds %d entries under concurrent load, cap is 64", n)
	}
}
