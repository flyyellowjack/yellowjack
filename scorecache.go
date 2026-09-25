package main

import (
	"container/list"
	"sync"
	"time"
)

// The firewall's L1 caches: short-TTL, per-replica, ephemeral fan-out guards (D18).
//
// WHY THEY ARE BOUNDED (issue #61). Both were TTL-only, which is not a bound at all:
//
//  1. nothing capped the ENTRY COUNT, and the cardinality is the number of distinct
//     packages/repos this process ever proxies — unbounded over the lifetime of a
//     long-lived service, because build agents pull the long tail of transitive deps;
//  2. an expired entry was treated as a miss but never DELETED, so a 10-minute entry
//     created at hour 0 still occupied memory at hour 500.
//
// Entries are small, so it was a slow leak — but a genuinely unbounded one in a service
// explicitly designed to run forever in Kubernetes. This is the same defect
// `cache/store.go` documents ("a map that never evicted and never expired, so a
// long-running cache grew until it…"); #15 fixed it for the response cache and stopped
// at that tier. This is that fix, applied to L1.

// ttlLRU is a TTL-bounded, entry-count-bounded LRU cache.
//
// ONE GENERIC RATHER THAN TWO COPIES, which reverses the original note here that "a
// separate tiny type keeps both caches trivially readable". That was true while the
// bodies were four lines each; eviction and reclaim are not four lines, and two hand-
// maintained copies of an eviction policy is precisely how the two caches would come to
// bound differently — with the difference showing up as an unexplained RSS curve months
// later. The codebase already carries a generic for exactly this reason (flightGroup).
//
// Bounded by ENTRY COUNT, not bytes, unlike respStore. Its entries are HTTP bodies of
// wildly varying size, so only a byte budget bounds its memory; these hold a float64 or
// a short repo string, so entries are near-uniform and a count is both a true bound and
// one an operator can reason about.
type ttlLRU[V any] struct {
	// A plain Mutex, not RWMutex: a read REORDERS the LRU list, so there is no
	// read-only fast path to protect. An RLock here would be a lie about mutation —
	// the same reasoning respStore records.
	mu  sync.Mutex
	ttl time.Duration
	max int
	ll  *list.List               // front = most recently used
	m   map[string]*list.Element // key -> element in ll
}

// lruEntry holds the key alongside the value because eviction runs from the LRU list,
// which yields an element, and removing it also has to delete the map key.
type lruEntry[V any] struct {
	key    string
	val    V
	expiry time.Time
}

func newTTLLRU[V any](ttl time.Duration, max int) *ttlLRU[V] {
	if max <= 0 {
		max = defaultCacheMaxEntries
	}
	return &ttlLRU[V]{ttl: ttl, max: max, ll: list.New(), m: make(map[string]*list.Element)}
}

// enabled reports whether this cache stores anything. Only the TTL decides: a
// non-positive TTL disables caching, which is the pre-existing contract and the one
// operators already know.
//
// The cap deliberately does NOT disable. An earlier draft made a non-positive cap mean
// "cache nothing", which is arguably the more principled reading — and it silently
// disabled the L1 caches in ELEVEN existing test fixtures, because each builds a Config
// literal that sets ScoreCacheTTL and knew nothing about a field that did not exist when
// it was written. One of them caught it (a deps.dev call-count assertion went from 2 to
// 12); the rest would have gone on passing while measuring something else.
//
// A default that every hand-built literal must remember forever is a trap, not a
// contract. So a non-positive cap falls back to the built-in default, matching how
// f.ruleset() and f.byteRuleset() already treat a zero value in this codebase — and
// "turn the cache off" keeps exactly one spelling, the TTL.
func (c *ttlLRU[V]) enabled() bool {
	return c != nil && c.ttl > 0 && c.max > 0
}

// defaultCacheMaxEntries is the cap applied when none is configured. ~10k entries at
// roughly 100 B each is about a megabyte per cache: far above any single build's working
// set, so it acts as a safety ceiling rather than something normal traffic runs into.
const defaultCacheMaxEntries = 10000

// get returns the value if present and fresh. An EXPIRED entry is deleted rather than
// merely reported as a miss — that is item 2 of #61, and without it an expired entry
// keeps its slot until eviction pressure happens to reach it.
func (c *ttlLRU[V]) get(key string) (V, bool) {
	var zero V
	if c == nil {
		return zero, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	el, ok := c.m[key]
	if !ok {
		return zero, false
	}
	e := el.Value.(*lruEntry[V])
	if time.Now().After(e.expiry) {
		c.removeElement(el)
		return zero, false
	}
	c.ll.MoveToFront(el)
	return e.val, true
}

// put stores a value under the configured TTL, then enforces the cap by dropping the
// least recently used entries.
func (c *ttlLRU[V]) put(key string, val V) {
	if !c.enabled() {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	exp := time.Now().Add(c.ttl)
	if el, ok := c.m[key]; ok {
		e := el.Value.(*lruEntry[V])
		e.val, e.expiry = val, exp
		c.ll.MoveToFront(el)
		return
	}
	c.m[key] = c.ll.PushFront(&lruEntry[V]{key: key, val: val, expiry: exp})

	// Reclaim expired entries before evicting live ones. Without this, a burst of
	// long-tail packages would push out entries that are still fresh and useful while
	// stale ones sat in the middle of the list — the cap would hold, but the cache
	// would be worse than it needs to be. Bounded to a few probes from the back so put
	// stays O(1) amortized rather than walking the whole list under the lock.
	now := time.Now()
	for i := 0; i < 4; i++ {
		back := c.ll.Back()
		if back == nil || back == c.ll.Front() {
			break
		}
		if !now.After(back.Value.(*lruEntry[V]).expiry) {
			break
		}
		c.removeElement(back)
	}

	for c.ll.Len() > c.max {
		if back := c.ll.Back(); back != nil {
			c.removeElement(back)
		}
	}
}

// removeElement drops one element from both the list and the map. Callers hold the lock.
func (c *ttlLRU[V]) removeElement(el *list.Element) {
	c.ll.Remove(el)
	delete(c.m, el.Value.(*lruEntry[V]).key)
}

// len reports the number of entries held, expired ones included. Used by tests to prove
// the bound and the reclaim actually happen — a cache that merely *reports* a miss for an
// expired entry looks identical from the outside to one that freed it, which is why #61
// went unnoticed.
func (c *ttlLRU[V]) len() int {
	if c == nil {
		return 0
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.ll.Len()
}

// scoreCache caches OpenSSF Scorecard scores, keyed by repo ("github.com/owner/name").
// The firewall scores a package on every request (metadata + each file/tarball), so
// without this a single install fans out into many identical scoring calls. Caching the
// *score* (not the allow/block decision) keeps the approval-consult + threshold logic
// running each request, so a freshly-approved package still takes effect immediately.
//
// L1 per D18: short-TTL, per-replica, ephemeral — a fan-out guard, NOT the durable
// memory. The durable L2 is the approval-DB score cache (D12); the two compose.
type scoreCache = ttlLRU[cachedScore]

// cachedScore is what the L1 cache holds per repo: the number and what it was
// computed over (#154). Coverage rides with the score everywhere the score goes --
// scanner, L1, L2, decision, audit event -- so a partial score that passed the D271
// floor is never again reduced to a bare number one hop later.
type cachedScore struct {
	Score    float64
	Coverage scoreCoverage
}

func newScoreCache(ttl time.Duration, max int) *scoreCache {
	return newTTLLRU[cachedScore](ttl, max)
}

// repoCache caches package -> normalized-repo lookups — the OTHER per-request upstream
// fan-out (without it, the metadata request AND every tarball of every install re-fetches
// the package's metadata).
//
// The empty string is a cacheable value: "this package definitively declares no usable
// repo". Caching it only skips the metadata REFETCH — the unscorable/approval flow still
// runs on every request, so a human ruling (approve, deny, supply-repo) still takes
// effect immediately.
type repoCache = ttlLRU[string]

func newRepoCache(ttl time.Duration, max int) *repoCache {
	return newTTLLRU[string](ttl, max)
}
