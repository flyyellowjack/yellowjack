package main

import (
	"container/list"
	"net/http"
	"sync"
	"time"
)

// cachedResponse is a stored upstream response: the status, headers, and the full
// body. We keep the whole thing so a cache hit can be replayed byte-for-byte
// without contacting the firewall.
type cachedResponse struct {
	status int
	header http.Header
	body   []byte
}

// size approximates the heap cost of holding this response, for the store's byte
// budget. The body dominates, but headers are counted too so a response with many
// or large headers isn't accounted as free.
func (cr cachedResponse) size() int64 {
	n := int64(len(cr.body))
	for k, vals := range cr.header {
		n += int64(len(k))
		for _, v := range vals {
			n += int64(len(v))
		}
	}
	return n
}

// entry is one cache record: the response plus the metadata the store needs to
// expire it (expiry) and to evict it — key, so an eviction driven from the LRU list
// can find and delete the map entry, and size, so the running byte total can be
// decremented without re-measuring.
type entry struct {
	key    string
	resp   cachedResponse
	expiry time.Time
	size   int64
}

// respStore is the cache's in-memory storage: a TTL- and byte-bounded LRU, keyed by
// method+URI+the variant headers (see cacheKey). Before issue #15 this was a plain
// map that never evicted and never expired, so a long-running cache grew until it
// OOMed, and kept serving metadata after upstream had yanked or updated a version.
//
// The two bounds are independent because they fix different failure modes:
//   - ttl bounds STALENESS: an entry is dead once older than ttl, checked on read.
//   - maxBytes bounds MEMORY: the least-recently-used entries are dropped once the
//     total exceeds the budget.
//
// Bounding by BYTES rather than entry count is deliberate: cached responses range
// from a few KB of metadata to multi-MB tarballs, so any count cap generous enough
// for normal metadata traffic would still permit unbounded memory growth.
//
// Like the approval service's store (and unlike the stateless firewall), this map is
// mutated by concurrent requests. It uses a full sync.Mutex rather than an RWMutex
// because a cache *hit* is itself a write here — it moves the entry to the front of
// the LRU list — so there is no read-only fast path left to optimize.
type respStore struct {
	mu       sync.Mutex
	ttl      time.Duration
	maxBytes int64
	curBytes int64
	ll       *list.List               // front = most recently used
	m        map[string]*list.Element // key -> element carrying *entry
}

func newRespStore(ttl time.Duration, maxBytes int64) *respStore {
	return &respStore{
		ttl:      ttl,
		maxBytes: maxBytes,
		ll:       list.New(),
		m:        make(map[string]*list.Element),
	}
}

// enabled reports whether the store should hold anything at all. A non-positive ttl
// or byte budget disables caching entirely (the service degrades to pure
// pass-through) — the same convention as the firewall's scoreCache, and the safe
// direction: a misconfigured cache serves fresh responses rather than stale ones.
func (s *respStore) enabled() bool {
	return s != nil && s.ttl > 0 && s.maxBytes > 0
}

// get returns a cached response if one is present and still fresh. An entry found
// past its TTL is deleted on the spot rather than merely reported as a miss, so
// expired bodies don't sit in memory waiting for eviction pressure.
func (s *respStore) get(key string) (cachedResponse, bool) {
	if !s.enabled() {
		return cachedResponse{}, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	el, ok := s.m[key]
	if !ok {
		return cachedResponse{}, false
	}
	e := el.Value.(*entry)
	if time.Now().After(e.expiry) {
		s.removeElement(el)
		return cachedResponse{}, false
	}
	s.ll.MoveToFront(el)
	return e.resp, true
}

// put stores a response under the configured TTL, then evicts least-recently-used
// entries until the store is back inside its byte budget.
func (s *respStore) put(key string, r cachedResponse) {
	if !s.enabled() {
		return
	}
	sz := r.size()

	s.mu.Lock()
	defer s.mu.Unlock()

	// A single response bigger than the entire budget can't be held without evicting
	// everything else for something we'd have to drop immediately anyway, so don't
	// cache it at all. It still streams to the client — just uncached.
	if sz > s.maxBytes {
		return
	}

	// Replacing an existing key: drop the old record first, so curBytes tracks the new
	// body's size instead of accumulating both.
	if el, ok := s.m[key]; ok {
		s.removeElement(el)
	}

	s.m[key] = s.ll.PushFront(&entry{
		key:    key,
		resp:   r,
		expiry: time.Now().Add(s.ttl),
		size:   sz,
	})
	s.curBytes += sz

	for s.curBytes > s.maxBytes {
		back := s.ll.Back()
		if back == nil { // defensive: byte accounting and list can't actually disagree
			break
		}
		s.removeElement(back)
	}
}

// removeElement drops one record from both the list and the map and credits its
// bytes back to the budget. The caller must already hold s.mu.
func (s *respStore) removeElement(el *list.Element) {
	e := el.Value.(*entry)
	s.ll.Remove(el)
	delete(s.m, e.key)
	s.curBytes -= e.size
}

// stats reports the current entry count and byte total, for the startup/periodic log
// line and for assertions in tests.
func (s *respStore) stats() (entries int, bytes int64) {
	if s == nil {
		return 0, 0
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.m), s.curBytes
}
