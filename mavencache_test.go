package main

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

// TestMavenFetchCache covers the small building block behind the D25 fan-out fix:
// a URL-keyed byte cache with the same nil-safe / TTL-disabled idiom as
// scoreCache/repoCache. Wiring it into the maven fetches is a separate increment;
// here we just pin the cache's own contract.
func TestMavenFetchCache(t *testing.T) {
	url := "https://repo.maven.apache.org/maven2/org/apache/apache/16/apache-16.pom"
	body := []byte("<project/>")

	c := newMavenFetchCache(time.Minute)

	// Miss before put.
	if _, ok := c.get(url); ok {
		t.Error("get before put: want miss")
	}
	// Hit after put, same bytes.
	c.put(url, body)
	got, ok := c.get(url)
	if !ok {
		t.Fatal("get after put: want hit")
	}
	if string(got) != string(body) {
		t.Errorf("cached body = %q, want %q", got, body)
	}
	// A different URL still misses (keying is exact).
	if _, ok := c.get(url + ".sha1"); ok {
		t.Error("get other url: want miss")
	}
}

// TestMavenFetchCacheExpiry verifies an entry past its TTL reads as a miss, so a
// stale POM/metadata body is never served indefinitely.
func TestMavenFetchCacheExpiry(t *testing.T) {
	c := newMavenFetchCache(20 * time.Millisecond)
	c.put("u", []byte("x"))
	if _, ok := c.get("u"); !ok {
		t.Fatal("fresh entry should hit")
	}
	time.Sleep(40 * time.Millisecond)
	if _, ok := c.get("u"); ok {
		t.Error("expired entry should miss")
	}
}

// TestMavenFetchCacheDisabled verifies the two "off" modes: a nil cache always
// misses (and put never panics), and a ttl <= 0 makes put a no-op. Both let the
// firewall run with maven caching disabled without any caller-side nil checks.
func TestMavenFetchCacheDisabled(t *testing.T) {
	var nilCache *mavenFetchCache
	nilCache.put("u", []byte("x")) // must not panic
	if _, ok := nilCache.get("u"); ok {
		t.Error("nil cache: want miss")
	}

	zero := newMavenFetchCache(0)
	zero.put("u", []byte("x"))
	if _, ok := zero.get("u"); ok {
		t.Error("ttl<=0 cache: put should be a no-op, want miss")
	}
}

// TestMavenSharedParentFetchedOnce is the D25 fan-out reduction in miniature: two
// DIFFERENT child artifacts inherit their <scm> from the SAME parent POM. Without the
// URL cache each child's parent walk re-fetches that identical parent, so a cold
// resolve of dozens of artifacts stampedes the shared parents and trips the upstream
// rate limit. With the cache, the shared parent is fetched exactly ONCE across both
// lookups — while each child's own metadata/POM is still fetched (distinct URLs).
func TestMavenSharedParentFetchedOnce(t *testing.T) {
	var mu sync.Mutex
	gets := map[string]int{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		gets[r.URL.Path]++
		mu.Unlock()
		switch r.URL.Path {
		case "/org/example/child-a/maven-metadata.xml",
			"/org/example/child-b/maven-metadata.xml":
			w.Write([]byte(`<metadata><versioning><release>1.0</release></versioning></metadata>`))
		case "/org/example/child-a/1.0/child-a-1.0.pom",
			"/org/example/child-b/1.0/child-b-1.0.pom":
			// Child declares no <scm>; inherits from the shared parent.
			w.Write([]byte(`<project><parent><groupId>org.example</groupId><artifactId>shared</artifactId><version>1.0</version></parent></project>`))
		case "/org/example/shared/1.0/shared-1.0.pom":
			// The shared parent carries the SCM both children resolve to.
			w.Write([]byte(`<project><scm><url>https://github.com/example/project</url></scm></project>`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	e := mavenEcosystem{base: srv.URL, cache: newMavenFetchCache(time.Minute)}
	for _, pkg := range []string{"org.example:child-a", "org.example:child-b"} {
		repo, err := e.LookupRepo(srv.Client(), pkg)
		if err != nil {
			t.Fatalf("LookupRepo(%q): %v", pkg, err)
		}
		if repo != "github.com/example/project" {
			t.Errorf("LookupRepo(%q) = %q, want github.com/example/project", pkg, repo)
		}
	}

	mu.Lock()
	defer mu.Unlock()
	if n := gets["/org/example/shared/1.0/shared-1.0.pom"]; n != 1 {
		t.Errorf("shared parent POM fetched %d times, want 1 (cache should dedup it across children)", n)
	}
	// Sanity: each child's own POM is a distinct URL, so both were still fetched.
	if n := gets["/org/example/child-a/1.0/child-a-1.0.pom"]; n != 1 {
		t.Errorf("child-a POM fetched %d times, want 1", n)
	}
	if n := gets["/org/example/child-b/1.0/child-b-1.0.pom"]; n != 1 {
		t.Errorf("child-b POM fetched %d times, want 1", n)
	}
}
