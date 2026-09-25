package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// newTestCache wires a cacheServer to a stub "firewall" upstream and returns both
// the server and a counter of how many requests actually reached that upstream —
// which is how these tests tell a cache hit from a miss.
func newTestCache(t *testing.T, h http.HandlerFunc) (*cacheServer, *atomic.Int64) {
	t.Helper()
	var upstreamHits atomic.Int64
	fw := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamHits.Add(1)
		h(w, r)
	}))
	t.Cleanup(fw.Close)

	return &cacheServer{
		upstream: fw.URL,
		client:   fw.Client(),
		store:    newRespStore(time.Minute, 1<<20),
	}, &upstreamHits
}

// do issues one GET through the cache and returns the status and body.
func do(t *testing.T, c *cacheServer, path string, headers map[string]string) (int, string) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	c.ServeHTTP(rec, req)

	res := rec.Result()
	defer res.Body.Close()
	body, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatalf("reading response: %v", err)
	}
	return res.StatusCode, string(body)
}

const (
	abbreviated = "application/vnd.npm.install-v1+json"
	full        = "application/json"
)

// The bug from issue #15: npm selects the abbreviated vs. full packument with the
// Accept header on the SAME URL, so a header-blind key served whichever shape landed
// in the cache first to every client. Each shape must cache independently.
func TestAcceptHeaderVariantsDoNotCollide(t *testing.T) {
	c, hits := newTestCache(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", r.Header.Get("Accept"))
		io.WriteString(w, "shape="+r.Header.Get("Accept"))
	})

	if _, body := do(t, c, "/lodash", map[string]string{"Accept": abbreviated}); body != "shape="+abbreviated {
		t.Fatalf("abbreviated request got %q", body)
	}
	if got := hits.Load(); got != 1 {
		t.Fatalf("upstream hits = %d, want 1", got)
	}

	// Same URL, different Accept: must NOT be served the abbreviated body.
	if _, body := do(t, c, "/lodash", map[string]string{"Accept": full}); body != "shape="+full {
		t.Fatalf("full request got %q — served the wrong metadata shape from cache", body)
	}
	if got := hits.Load(); got != 2 {
		t.Fatalf("upstream hits = %d, want 2 (the variant must miss)", got)
	}

	// Repeating either variant is now a hit: upstream count must not move.
	if _, body := do(t, c, "/lodash", map[string]string{"Accept": abbreviated}); body != "shape="+abbreviated {
		t.Fatalf("repeat abbreviated got %q", body)
	}
	if _, body := do(t, c, "/lodash", map[string]string{"Accept": full}); body != "shape="+full {
		t.Fatalf("repeat full got %q", body)
	}
	if got := hits.Load(); got != 2 {
		t.Fatalf("upstream hits = %d, want 2 (repeats must be cache hits)", got)
	}
}

// The security-critical invariant: a block must never be cached, so a package that
// is blocked now and approved later is not masked by a stale 403.
func TestBlocksAreNeverCached(t *testing.T) {
	var allow atomic.Bool
	c, hits := newTestCache(t, func(w http.ResponseWriter, r *http.Request) {
		if allow.Load() {
			w.WriteHeader(http.StatusOK)
			io.WriteString(w, "tarball-bytes")
			return
		}
		w.WriteHeader(http.StatusForbidden)
		io.WriteString(w, "blocked: score 2.1 below threshold")
	})

	for i := 1; i <= 2; i++ {
		status, _ := do(t, c, "/evil-pkg", nil)
		if status != http.StatusForbidden {
			t.Fatalf("request %d: status = %d, want 403", i, status)
		}
		if got := hits.Load(); got != int64(i) {
			t.Fatalf("request %d: upstream hits = %d, want %d — the block was cached", i, got, i)
		}
	}
	if n, _ := c.store.stats(); n != 0 {
		t.Fatalf("store holds %d entries after blocks; want 0", n)
	}

	// A later approval must take effect immediately.
	allow.Store(true)
	status, body := do(t, c, "/evil-pkg", nil)
	if status != http.StatusOK || body != "tarball-bytes" {
		t.Fatalf("after approval: status=%d body=%q, want 200/tarball-bytes", status, body)
	}
}

// Non-200 successes and errors are equally not cacheable; only 200 is stored.
func TestOnlyOKResponsesAreCached(t *testing.T) {
	for _, status := range []int{http.StatusNotFound, http.StatusInternalServerError, http.StatusAccepted} {
		c, hits := newTestCache(t, func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(status)
		})
		do(t, c, "/pkg", nil)
		do(t, c, "/pkg", nil)
		if got := hits.Load(); got != 2 {
			t.Fatalf("status %d: upstream hits = %d, want 2 (must not be cached)", status, got)
		}
	}
}

// /healthz must be answered locally and never consult the firewall.
func TestHealthzIsNotProxied(t *testing.T) {
	c, hits := newTestCache(t, func(w http.ResponseWriter, r *http.Request) {
		t.Error("healthz should not reach upstream")
	})
	status, _ := do(t, c, "/healthz", nil)
	if status != http.StatusOK {
		t.Fatalf("healthz status = %d, want 200", status)
	}
	if got := hits.Load(); got != 0 {
		t.Fatalf("upstream hits = %d, want 0", got)
	}
}

func TestCacheKeyVariants(t *testing.T) {
	key := func(path string, headers map[string]string) string {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		for k, v := range headers {
			req.Header.Set(k, v)
		}
		return cacheKey(req)
	}

	base := key("/lodash", map[string]string{"Accept": abbreviated})

	if got := key("/lodash", map[string]string{"Accept": abbreviated}); got != base {
		t.Fatal("identical requests produced different keys")
	}
	if got := key("/lodash", map[string]string{"Accept": full}); got == base {
		t.Fatal("differing Accept produced the same key")
	}
	if got := key("/lodash", map[string]string{"Accept": abbreviated, "Accept-Encoding": "gzip"}); got == base {
		t.Fatal("differing Accept-Encoding produced the same key")
	}
	if got := key("/express", map[string]string{"Accept": abbreviated}); got == base {
		t.Fatal("differing path produced the same key")
	}
	if got := key("/lodash?v=1", map[string]string{"Accept": abbreviated}); got == base {
		t.Fatal("differing query produced the same key")
	}

	// Header values must not be able to forge another request's key: labelled,
	// newline-separated fields mean a value containing a header name is still inert.
	forged := key("/lodash", map[string]string{"Accept": abbreviated + "\nAccept-Encoding:gzip"})
	if forged == key("/lodash", map[string]string{"Accept": abbreviated, "Accept-Encoding": "gzip"}) {
		t.Fatal("a crafted header value collided with a genuine variant's key")
	}
	if strings.Count(base, "\n") != len(varyHeaders) {
		t.Fatalf("key has %d separators, want %d", strings.Count(base, "\n"), len(varyHeaders))
	}
}
