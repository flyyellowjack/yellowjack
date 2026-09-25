package main

import (
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

// Cache bounds (issue #15). Defaults are deliberately modest: the cache is an
// optional accelerator, so it should never be the reason a container gets OOM-killed.
const (
	// defaultTTL bounds how long a cached response may be served after upstream may
	// have changed it (a yanked or republished version). Short, because the firewall
	// behind us is cheap to re-ask relative to serving wrong metadata.
	defaultTTL = 5 * time.Minute
	// defaultMaxBytes is the total body+header budget across all entries: 256 MiB.
	defaultMaxBytes int64 = 256 << 20
)

// The cache is Yellow Jack's OPTIONAL front door. Clients that want caching point
// here; the cache forwards every request to its upstream — which is the FIREWALL,
// not the public registry — so the firewall still makes every allow/block
// decision. Clients that want firewalling only can skip the cache and point
// directly at the firewall. This layer (5.1) is pure pass-through: no storage yet.
func main() {
	addr := getEnv("CACHE_LISTEN_ADDR", ":8070")
	upstream := strings.TrimRight(getEnv("CACHE_UPSTREAM", "http://localhost:8080"), "/")
	ttl := getEnvDuration("CACHE_TTL", defaultTTL)
	maxBytes := getEnvInt64("CACHE_MAX_BYTES", defaultMaxBytes)

	c := &cacheServer{
		upstream: upstream,
		// Generous timeout: the upstream here is the firewall, which itself may be
		// fetching a large tarball from the real registry.
		client: &http.Client{Timeout: 60 * time.Second},
		store:  newRespStore(ttl, maxBytes),
	}

	log.Printf("Yellow Jack cache starting on %s", addr)
	log.Printf("  upstream (firewall): %s", upstream)
	log.Printf("  ttl: %s   max bytes: %d", ttl, maxBytes)
	if !c.store.enabled() {
		log.Printf("  caching DISABLED (ttl and max bytes must both be > 0) — pure pass-through")
	}
	if err := http.ListenAndServe(addr, c); err != nil {
		log.Fatalf("cache failed: %v", err)
	}
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// getEnvDuration parses a Go duration string (e.g. "5m", "1h", "0"). Unset or
// unparseable falls back rather than crashing startup — same convention as the
// firewall's config.go. (Duplicated rather than shared because the cache is a
// separate service/binary with no import path into the firewall package.)
func getEnvDuration(key string, fallback time.Duration) time.Duration {
	if v := os.Getenv(key); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
	}
	return fallback
}

// getEnvInt64 parses a plain byte count. Unset or unparseable falls back.
func getEnvInt64(key string, fallback int64) int64 {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil {
			return n
		}
	}
	return fallback
}

// varyHeaders are the request headers that decide WHICH response you get back for
// the same URI, so they have to be part of the cache key (issue #15 — the old key
// was method+URI only):
//
//   - Accept: npm uses it to select the abbreviated packument
//     ("application/vnd.npm.install-v1+json") versus the full one at the SAME URL.
//     A header-blind key served whichever shape was cached first to every client,
//     so a client could be handed metadata in a shape it didn't ask for.
//   - Accept-Encoding: cached headers are replayed verbatim, so a gzipped body
//     stored for a client that advertised gzip must not be replayed to one that
//     can't decode it.
//
// This is the request-side half of HTTP's Vary contract. We hardcode the list
// rather than honouring upstream's Vary response header: the set is small, known,
// and auditable, and a registry that omits or over-broadens Vary can't silently
// change our keying.
var varyHeaders = []string{"Accept", "Accept-Encoding"}

// cacheKey builds the storage key for a request: method, URI, then each variant
// header. Fields are newline-separated and name-labelled so no combination of
// header values can be crafted to collide with a different request's key.
func cacheKey(r *http.Request) string {
	var b strings.Builder
	b.WriteString(r.Method)
	b.WriteByte(' ')
	b.WriteString(r.URL.RequestURI())
	for _, h := range varyHeaders {
		b.WriteByte('\n')
		b.WriteString(h)
		b.WriteByte(':')
		b.WriteString(r.Header.Get(h))
	}
	return b.String()
}

// cacheServer forwards requests to the firewall, caches allowed (200) GET
// responses, and serves repeats from memory without re-contacting the firewall.
type cacheServer struct {
	upstream string
	client   *http.Client
	store    *respStore
}

func (c *cacheServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/healthz" {
		w.WriteHeader(http.StatusOK)
		io.WriteString(w, "ok\n")
		return
	}

	// Only GETs are cacheable. The key covers method+URI+variant headers so neither
	// different paths/queries nor different metadata shapes collide. A hit is served
	// straight from memory — the firewall isn't touched.
	key := cacheKey(r)
	if r.Method == http.MethodGet {
		if cr, ok := c.store.get(key); ok {
			// Log the URI, not the key: the key is multi-line by construction.
			log.Printf("HIT  %s %s", r.Method, r.URL.RequestURI())
			writeResponse(w, cr)
			return
		}
	}

	c.forward(w, r, key)
}

// forward relays the request to the upstream firewall, reads the full response,
// caches it if it's a cacheable success, and writes it back to the client.
func (c *cacheServer) forward(w http.ResponseWriter, r *http.Request, key string) {
	target := c.upstream + r.URL.Path
	if r.URL.RawQuery != "" {
		target += "?" + r.URL.RawQuery
	}

	log.Printf("MISS %s %s -> %s", r.Method, r.URL.RequestURI(), target)

	req, err := http.NewRequest(r.Method, target, r.Body)
	if err != nil {
		http.Error(w, "failed to build upstream request", http.StatusInternalServerError)
		return
	}
	req.Header = r.Header.Clone()

	resp, err := c.client.Do(req)
	if err != nil {
		http.Error(w, "firewall unreachable", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	// Read the whole body so we can both cache and replay it. (Buffers in memory —
	// fine for an MVP; disk-backed storage for large artifacts is future work.)
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		http.Error(w, "failed reading upstream response", http.StatusBadGateway)
		return
	}

	cr := cachedResponse{status: resp.StatusCode, header: resp.Header.Clone(), body: body}

	// Cache only successful GETs. Blocks (403) and errors are deliberately NOT
	// cached, so the firewall re-evaluates them until allowed (e.g. after a human
	// approval) — a stale cached block must never mask a later allow.
	if r.Method == http.MethodGet && resp.StatusCode == http.StatusOK {
		c.store.put(key, cr)
	}

	writeResponse(w, cr)
}

// writeResponse replays a (possibly cached) response to the client.
func writeResponse(w http.ResponseWriter, cr cachedResponse) {
	for k, vals := range cr.header {
		for _, v := range vals {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(cr.status)
	w.Write(cr.body)
}
